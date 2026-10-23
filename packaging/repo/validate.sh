#!/usr/bin/env bash
# End-to-end proof with a THROWAWAY key: serve the built repo over local static
# HTTP and run the real apt / yum client in target-distro containers, incl.
# tampered copies that the client must refuse.
#
#   packaging/repo/validate.sh apt <image> <minor> [ok|tamper]
#   packaging/repo/validate.sh yum <el7|el8|el9> <minor> [ok|tamper]
#
# Prereqs: packaging/repo/gen-throwaway-key.sh, build-apt-repo.sh, build-yum-repo.sh
# run with that key (packaging/out/repo/{apt,yum}). `tamper` runs every tampered
# variant. Local test transport is plain http on a private docker network;
# production is HTTPS-only (https://pkg.howdah.org). Needs network (Surý/Remi).
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO_ROOT/packaging/out"
HERE="$REPO_ROOT/packaging/repo"
KIND="${1:?apt|yum}"; TARGET="${2:?image or el version}"; MINOR="${3:?php minor}"; WHICH="${4:-ok}"
NET=howdah-val; SRV=howdah-repo-srv
SERVE="$OUT/repo-serve"

rm -rf "$SERVE"; mkdir -p "$SERVE/ok"
cp -a "$OUT/repo/$KIND" "$SERVE/ok/$KIND"
flip() { printf '\xff' | dd of="$1" bs=1 seek="$2" conv=notrunc 2>/dev/null; }
if [ "$KIND" = apt ]; then
  VARIANTS="t-packages t-deb t-inrelease"
  for v in $VARIANTS; do mkdir -p "$SERVE/$v"; cp -a "$OUT/repo/apt" "$SERVE/$v/apt"; done
  for f in Packages Packages.gz; do flip "$SERVE/t-packages/apt/dists/stable/main/binary-amd64/$f" 150; done
  flip "$(ls "$SERVE"/t-deb/apt/pool/main/p/php"$MINOR"-howdah/*_amd64.deb)" 3000
  sed -i 's/^Suite: stable/Suite: stabIe/' "$SERVE/t-inrelease/apt/dists/stable/InRelease"
else
  VARIANTS="t-repomd t-rpm"
  for v in $VARIANTS; do mkdir -p "$SERVE/$v"; cp -a "$OUT/repo/yum" "$SERVE/$v/yum"; done
  sed -i 's#<revision>[0-9]*</revision>#<revision>1</revision>#' "$SERVE/t-repomd/yum/repodata/repomd.xml"
  rpmf="$(ls "$SERVE"/t-rpm/yum/php"${MINOR//./}"-howdah-*.x86_64.rpm)"
  flip "$rpmf" $(( $(stat -c %s "$rpmf") - 200 ))
fi

docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET" >/dev/null
docker rm -f "$SRV" >/dev/null 2>&1 || true
docker run -d --rm --name "$SRV" --network "$NET" --network-alias repo -v "$SERVE":/srv:ro \
  python:3-alpine python -m http.server -d /srv 80 >/dev/null
trap 'docker rm -f "$SRV" >/dev/null 2>&1 || true' EXIT
sleep 2

run_apt() { # <variant> <mode>
  docker run --rm --network "$NET" -v "$HERE/validate-apt-in-container.sh":/v.sh:ro \
    -v "$OUT/throwaway-key.asc":/key.asc:ro "$TARGET" sh /v.sh "$MINOR" "http://repo/$1/apt" "$2"; }
run_yum() {
  case "$TARGET" in el7) IMG=centos:7 ;; el8) IMG=almalinux:8 ;; el9) IMG=almalinux:9 ;; esac
  docker run --rm --network "$NET" -v "$HERE/validate-yum-in-container.sh":/v.sh:ro \
    -v "$OUT/throwaway-key.asc":/key.asc:ro -v "$HERE/howdah.repo":/howdah.repo:ro \
    "$IMG" sh /v.sh "${TARGET#el}" "$MINOR" "http://repo/$1/yum" "$2"; }

if [ "$WHICH" = ok ]; then
  echo "=========== $KIND $TARGET php$MINOR : GENUINE repo ==========="
  "run_$KIND" ok ok
else
  for v in $VARIANTS; do
    echo "=========== $KIND $TARGET php$MINOR : TAMPERED ($v) ==========="
    "run_$KIND" "$v" tamper
  done
fi
