#!/usr/bin/env bash
# Assemble a signed yum repo from the .rpms in packaging/out/ (flat layout:
# yum/*.rpm + yum/repodata/). Packages are signed (gpgcheck=1) and
# repodata/repomd.xml gets a detached signature (repo_gpgcheck=1).
#
#   HOWDAH_GPG_KEYID=<fingerprint|keyid> HOWDAH_GNUPGHOME=<dir> \
#     packaging/repo/build-yum-repo.sh [RPM_DIR] [OUT_DIR]
#
# Same env/args as build-apt-repo.sh. Result:
#   OUT_DIR/yum/<pkgs>.rpm  OUT_DIR/yum/repodata/{repomd.xml,repomd.xml.asc,...}
# Metadata is gzip + sha256 (readable by CentOS 7 yum).
# Both x86_64 and aarch64 rpms live in the one flat repo; clients pick their arch.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEYID="${HOWDAH_GPG_KEYID:?set HOWDAH_GPG_KEYID}"
GNUPGHOME_HOST="${HOWDAH_GNUPGHOME:?set HOWDAH_GNUPGHOME}"
RPM_DIR="$(cd "${1:-$REPO_ROOT/packaging/out}" && pwd)"
OUT_DIR="${2:-$REPO_ROOT/packaging/out/repo}"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"
ls "$RPM_DIR"/*.rpm >/dev/null 2>&1 || { echo "FATAL: no .rpm in $RPM_DIR" >&2; exit 1; }
rm -rf "$OUT_DIR/yum"; mkdir -p "$OUT_DIR/yum"; cp "$RPM_DIR"/*.rpm "$OUT_DIR/yum/"

docker run --rm -e KEYID="$KEYID" -e HOSTUID="$(id -u):$(id -g)" \
  -v "$OUT_DIR/yum":/repo -v "$GNUPGHOME_HOST":/gnupg-src:ro \
  almalinux:9 sh -ec '
    dnf install -y -q createrepo_c rpm-sign gnupg2 >/dev/null 2>&1
    cp -a /gnupg-src /tmp/gnupg; chmod 700 /tmp/gnupg; export GNUPGHOME=/tmp/gnupg
    printf "personal-digest-preferences SHA256\ncert-digest-algo SHA256\n" > $GNUPGHOME/gpg.conf
    # 1. sign every package (rpm v4 RSA signature, SHA256)
    for r in /repo/*.rpm; do
      rpmsign --addsign -D "_gpg_name $KEYID" -D "_gpg_path $GNUPGHOME" "$r" >/dev/null
    done
    # 2. metadata; gz + sha256 so a CentOS 7 yum can read it
    createrepo_c --quiet --general-compress-type gz --checksum sha256 /repo
    # 3. detached, armored signature of repomd.xml
    gpg --batch --yes --armor --digest-algo SHA256 -u "$KEYID" --detach-sign \
        -o /repo/repodata/repomd.xml.asc /repo/repodata/repomd.xml
    gpg --batch --verify /repo/repodata/repomd.xml.asc /repo/repodata/repomd.xml
    chown -R "$HOSTUID" /repo'
echo "== yum repo: $OUT_DIR/yum"
( cd "$OUT_DIR/yum" && find . -type f | sort )
