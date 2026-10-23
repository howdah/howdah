#!/usr/bin/env bash
# Assemble a signed yum repo from the .rpms in packaging/out/ (flat layout:
# yum/*.rpm + yum/repodata/). Packages are signed (gpgcheck=1) and
# repodata/repomd.xml gets a detached signature (repo_gpgcheck=1).
#
#   HOWDAH_GPG_KEYID=<fingerprint|keyid> HOWDAH_GNUPGHOME=<dir> \
#     [HOWDAH_YUM_SEED=<dir>] packaging/repo/build-yum-repo.sh [RPM_DIR] [OUT_DIR]
#
# Same env/args as build-apt-repo.sh. Result:
#   OUT_DIR/yum/<pkgs>.rpm  OUT_DIR/yum/repodata/{repomd.xml,repomd.xml.asc,...}
# Metadata is gzip + sha256 (readable by CentOS 7 yum).
# Both x86_64 and aarch64 rpms live in the one flat repo; clients pick their arch.
#
#   HOWDAH_YUM_SEED  optional. A directory of existing, ALREADY-SIGNED *.rpm (as
#                    downloaded from R2). They are copied in alongside the new
#                    rpms so createrepo_c indexes every published version. The
#                    seeded rpms are NOT re-signed: re-signing rewrites the
#                    signature header (non-deterministic bytes) and would break
#                    publish-r2.sh --immutable on re-upload. Only the NEW rpms
#                    (from RPM_DIR) are signed. Unset/empty => first publish.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEYID="${HOWDAH_GPG_KEYID:?set HOWDAH_GPG_KEYID}"
GNUPGHOME_HOST="${HOWDAH_GNUPGHOME:?set HOWDAH_GNUPGHOME}"
RPM_DIR="$(cd "${1:-$REPO_ROOT/packaging/out}" && pwd)"
OUT_DIR="${2:-$REPO_ROOT/packaging/out/repo}"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"
ls "$RPM_DIR"/*.rpm >/dev/null 2>&1 || { echo "FATAL: no .rpm in $RPM_DIR" >&2; exit 1; }
rm -rf "$OUT_DIR/yum"; mkdir -p "$OUT_DIR/yum"

SEED_ARGS=()
if [ -n "${HOWDAH_YUM_SEED:-}" ] && [ -d "$HOWDAH_YUM_SEED" ]; then
  SEED_ABS="$(cd "$HOWDAH_YUM_SEED" && pwd)"
  SEED_ARGS=(-v "$SEED_ABS":/seed:ro)
  echo "== yum seed: $SEED_ABS"
else
  echo "== yum seed: (none — first publish)"
fi

docker run --rm -e KEYID="$KEYID" -e HOSTUID="$(id -u):$(id -g)" \
  -v "$RPM_DIR":/new:ro -v "$OUT_DIR/yum":/repo -v "$GNUPGHOME_HOST":/gnupg-src:ro \
  "${SEED_ARGS[@]}" \
  almalinux:9 sh -ec '
    dnf install -y -q createrepo_c rpm-sign gnupg2 >/dev/null 2>&1
    cp -a /gnupg-src /tmp/gnupg; chmod 700 /tmp/gnupg; export GNUPGHOME=/tmp/gnupg
    printf "personal-digest-preferences SHA256\ncert-digest-algo SHA256\n" > $GNUPGHOME/gpg.conf

    # 1. copy seeded rpms (already signed) verbatim, then the new rpms (new wins
    #    on a same-version re-publish). Only the new rpms are signed below.
    if [ -d /seed ]; then
      for r in /seed/*.rpm; do [ -e "$r" ] || continue; cp -p "$r" /repo/; done
    fi
    for r in /new/*.rpm; do cp -p "$r" /repo/; done

    # 2. sign ONLY the new rpms (rpm v4 RSA signature, SHA256). NEVER re-sign the
    #    seeded ones — it changes their bytes and breaks --immutable re-upload.
    for r in /new/*.rpm; do
      rpmsign --addsign -D "_gpg_name $KEYID" -D "_gpg_path $GNUPGHOME" "/repo/$(basename "$r")" >/dev/null
    done

    # 3. metadata over ALL rpms; gz + sha256 so a CentOS 7 yum can read it
    createrepo_c --quiet --general-compress-type gz --checksum sha256 /repo
    # 4. detached, armored signature of repomd.xml
    gpg --batch --yes --armor --digest-algo SHA256 -u "$KEYID" --detach-sign \
        -o /repo/repodata/repomd.xml.asc /repo/repodata/repomd.xml
    gpg --batch --verify /repo/repodata/repomd.xml.asc /repo/repodata/repomd.xml
    chown -R "$HOSTUID" /repo'
echo "== yum repo: $OUT_DIR/yum"
( cd "$OUT_DIR/yum" && find . -type f | sort )
