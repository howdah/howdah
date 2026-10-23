#!/bin/sh
# Runs INSIDE a debian:bookworm container (driven by build-apt-repo.sh). Builds
# the apt index over the union of the seeded pool (/seed, optional) and the new
# debs (/debs), then signs it. Needs: KEYID, HOSTUID in the env; /repo is the
# output apt/ tree; /gnupg-src is the signing GNUPGHOME (copied in).
set -e
apt-get update -qq >/dev/null
apt-get install -y -qq apt-utils gnupg >/dev/null 2>&1
cp -a /gnupg-src /tmp/gnupg; chmod 700 /tmp/gnupg; export GNUPGHOME=/tmp/gnupg
# SHA256 digest for the signatures (old gpg/apt friendly)
printf 'personal-digest-preferences SHA256\ncert-digest-algo SHA256\n' > "$GNUPGHOME/gpg.conf"

# 1. assemble the pool. Each deb goes to pool/main/<L>/<pkg>/<basename>, where
#    <pkg> is its Package: control field and <L> is the first char (p for php*).
#    Seed first, then the new debs (new wins on a same-version re-publish). Bytes
#    are copied verbatim so a seeded deb re-uploads as a no-op under --immutable.
place() { # <deb>
  pkg=$(dpkg-deb -f "$1" Package)
  [ -n "$pkg" ] || { echo "FATAL: no Package field in $1" >&2; exit 1; }
  l=$(printf %.1s "$pkg")
  d="/repo/pool/main/$l/$pkg"
  mkdir -p "$d"
  cp -p "$1" "$d/$(basename "$1")"
}
if [ -d /seed ]; then
  find /seed -type f -name '*.deb' | sort | while IFS= read -r f; do place "$f"; done
fi
for d in /debs/*.deb; do place "$d"; done

cd /repo
# 2. one scan of the pool -> every version of every arch, then split the stanzas
#    per architecture into dists/stable/main/binary-<arch>/Packages.
apt-ftparchive packages pool > /tmp/Packages.all
for arch in amd64 arm64; do
  bd="dists/stable/main/binary-$arch"
  mkdir -p "$bd"
  awk -v want="Architecture: $arch" '
    BEGIN { RS=""; ORS="\n\n" }
    {
      ok=0
      n=split($0, L, "\n")
      for (i=1;i<=n;i++) if (L[i]==want) { ok=1; break }
      if (ok) print
    }' /tmp/Packages.all > "$bd/Packages"
  gzip -9 -c "$bd/Packages" > "$bd/Packages.gz"
  cat > "$bd/Release" <<EOT
Archive: stable
Suite: stable
Component: main
Origin: Howdah
Label: Howdah
Architecture: $arch
EOT
done

# 3. top dists/stable/Release (MD5Sum + SHA1 + SHA256 sections), with fields that
#    match the current repo so existing client configs keep working.
apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=Howdah \
  -o APT::FTPArchive::Release::Label=Howdah \
  -o APT::FTPArchive::Release::Suite=stable \
  -o APT::FTPArchive::Release::Codename=stable \
  -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
  -o APT::FTPArchive::Release::Components=main \
  -o "APT::FTPArchive::Release::Description=Howdah - defensive WAF for PHP" \
  release dists/stable > dists/stable/Release

# 4. sign: InRelease (clearsigned) + Release.gpg (detached, armored), SHA256.
gpg --batch --yes --digest-algo SHA256 -u "$KEYID" \
    --clearsign -o dists/stable/InRelease dists/stable/Release
gpg --batch --yes --digest-algo SHA256 -u "$KEYID" --armor \
    --detach-sign -o dists/stable/Release.gpg dists/stable/Release
gpg --batch --verify dists/stable/Release.gpg dists/stable/Release
gpg --batch --verify dists/stable/InRelease

chown -R "$HOSTUID" /repo
