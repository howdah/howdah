#!/usr/bin/env bash
# Assemble a signed apt repo from the .debs in packaging/out/ using
# apt-ftparchive in a Debian container, seeding the pool from the existing
# published pool so EVERY published version stays in the index.
#
#   HOWDAH_GPG_KEYID=<fingerprint|keyid[!]> HOWDAH_GNUPGHOME=<dir> \
#     [HOWDAH_APT_SEED=<dir>] packaging/repo/build-apt-repo.sh [DEB_DIR] [OUT_DIR]
#
#   HOWDAH_GPG_KEYID   required. Signing key (CI passes the real signing subkey;
#                      local validation passes the throwaway from gen-throwaway-key.sh).
#   HOWDAH_GNUPGHOME   required. GNUPGHOME dir holding that PASSPHRASELESS secret
#                      key (the CI import step makes ~/.gnupg). Mounted read-only
#                      and copied inside the container.
#   HOWDAH_APT_SEED    optional. A directory holding the existing published pool
#                      (as downloaded from R2). Every *.deb found underneath it is
#                      copied into the pool before the new ones, so the generated
#                      index lists all prior versions too. Unset/empty => first
#                      publish (seed is empty). Seeded .deb bytes are copied
#                      verbatim, so re-upload is a no-op under publish-r2.sh --immutable.
#   DEB_DIR  default packaging/out        OUT_DIR default packaging/out/repo
#
# Result: OUT_DIR/apt/{dists/stable/{InRelease,Release,Release.gpg,main/binary-{amd64,arm64}/{Packages,Packages.gz,Release}},pool/main/...}
# Suite/codename `stable` (not tied to any distro codename), component `main`,
# architectures amd64 arm64. RSA key + SHA256 digest so xenial's apt verifies it.
# apt-ftparchive lists EVERY .deb present (all versions), unlike reprepro which
# keeps only the newest; the top Release carries both MD5Sum and SHA256 sections.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="$REPO_ROOT/packaging/repo"
KEYID="${HOWDAH_GPG_KEYID:?set HOWDAH_GPG_KEYID}"
GNUPGHOME_HOST="${HOWDAH_GNUPGHOME:?set HOWDAH_GNUPGHOME}"
DEB_DIR="$(cd "${1:-$REPO_ROOT/packaging/out}" && pwd)"
OUT_DIR="${2:-$REPO_ROOT/packaging/out/repo}"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"
ls "$DEB_DIR"/*.deb >/dev/null 2>&1 || { echo "FATAL: no .deb in $DEB_DIR" >&2; exit 1; }
rm -rf "$OUT_DIR/apt"; mkdir -p "$OUT_DIR/apt"

# Optional seed: a dir holding an existing pool (any layout; we re-derive the
# canonical pool path from each deb, so the exact path reprepro used is kept).
SEED_ARGS=()
if [ -n "${HOWDAH_APT_SEED:-}" ] && [ -d "$HOWDAH_APT_SEED" ]; then
  SEED_ABS="$(cd "$HOWDAH_APT_SEED" && pwd)"
  SEED_ARGS=(-v "$SEED_ABS":/seed:ro)
  echo "== apt seed: $SEED_ABS"
else
  echo "== apt seed: (none — first publish)"
fi

docker run --rm -e KEYID="$KEYID" -e HOSTUID="$(id -u):$(id -g)" \
  -v "$DEB_DIR":/debs:ro -v "$OUT_DIR/apt":/repo -v "$GNUPGHOME_HOST":/gnupg-src:ro \
  -v "$HERE/apt-ftparchive-in-container.sh":/build.sh:ro \
  "${SEED_ARGS[@]}" \
  debian:bookworm sh /build.sh
echo "== apt repo: $OUT_DIR/apt"
( cd "$OUT_DIR/apt" && find . -type f | sort )
