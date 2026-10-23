#!/usr/bin/env bash
# Assemble a signed apt repo from the .debs in packaging/out/ using reprepro in
# a Debian container.
#
#   HOWDAH_GPG_KEYID=<fingerprint|keyid[!]> HOWDAH_GNUPGHOME=<dir> \
#     packaging/repo/build-apt-repo.sh [DEB_DIR] [OUT_DIR]
#
#   HOWDAH_GPG_KEYID   required. Signing key (CI passes the real signing subkey;
#                      local validation passes the throwaway from gen-throwaway-key.sh).
#   HOWDAH_GNUPGHOME   required. GNUPGHOME dir holding that PASSPHRASELESS secret
#                      key (the CI import step makes ~/.gnupg). Mounted read-only
#                      and copied inside the container.
#   DEB_DIR  default packaging/out        OUT_DIR default packaging/out/repo
#
# Result: OUT_DIR/apt/{dists/stable/{InRelease,Release,Release.gpg,main/binary-{amd64,arm64}/Packages*},pool/main/...}
# Suite/codename `stable` (not tied to any distro codename), component `main`,
# architectures amd64 arm64. RSA key + SHA256 digest so xenial's apt verifies it.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEYID="${HOWDAH_GPG_KEYID:?set HOWDAH_GPG_KEYID}"
GNUPGHOME_HOST="${HOWDAH_GNUPGHOME:?set HOWDAH_GNUPGHOME}"
DEB_DIR="$(cd "${1:-$REPO_ROOT/packaging/out}" && pwd)"
OUT_DIR="${2:-$REPO_ROOT/packaging/out/repo}"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"
ls "$DEB_DIR"/*.deb >/dev/null 2>&1 || { echo "FATAL: no .deb in $DEB_DIR" >&2; exit 1; }
rm -rf "$OUT_DIR/apt"; mkdir -p "$OUT_DIR/apt"

docker run --rm -e KEYID="$KEYID" -e HOSTUID="$(id -u):$(id -g)" \
  -v "$DEB_DIR":/debs:ro -v "$OUT_DIR/apt":/repo -v "$GNUPGHOME_HOST":/gnupg-src:ro \
  debian:bookworm sh -ec '
    apt-get update -qq >/dev/null
    apt-get install -y -qq reprepro gnupg >/dev/null 2>&1
    cp -a /gnupg-src /tmp/gnupg; chmod 700 /tmp/gnupg; export GNUPGHOME=/tmp/gnupg
    mkdir -p /repo/conf
    cat > /repo/conf/distributions <<EOT
Origin: Howdah
Label: Howdah
Suite: stable
Codename: stable
Description: Howdah - defensive WAF for PHP
Architectures: amd64 arm64
Components: main
SignWith: $KEYID
EOT
    # SHA256 digest for the signatures (old gpg/apt friendly)
    printf "personal-digest-preferences SHA256\ncert-digest-algo SHA256\n" > $GNUPGHOME/gpg.conf
    for d in /debs/*.deb; do reprepro -b /repo includedeb stable "$d"; done
    reprepro -b /repo export stable
    # conf + db are build state, not part of the served tree.
    rm -rf /repo/conf /repo/db
    chown -R "$HOSTUID" /repo'
echo "== apt repo: $OUT_DIR/apt"
( cd "$OUT_DIR/apt" && find . -type f | sort )
