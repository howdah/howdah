#!/usr/bin/env bash
# Generate a THROWAWAY RSA-4096 signing key (passphraseless) for local repo
# validation. NEVER the real key. Output (gitignored, under packaging/out/):
#   packaging/out/throwaway-gnupg/   GNUPGHOME holding the secret key
#   packaging/out/throwaway-key.asc  its armored PUBLIC key
#   packaging/out/throwaway-keyid    its 40-hex fingerprint
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO_ROOT/packaging/out"
rm -rf "$OUT/throwaway-gnupg"; mkdir -p "$OUT/throwaway-gnupg"; chmod 700 "$OUT/throwaway-gnupg"
docker run --rm -e HOSTUID="$(id -u):$(id -g)" -v "$OUT":/out debian:bookworm sh -ec '
  apt-get update -qq >/dev/null; apt-get install -y -qq gnupg >/dev/null 2>&1
  export GNUPGHOME=/out/throwaway-gnupg
  gpg --batch --pinentry-mode loopback --passphrase "" \
      --quick-gen-key "Howdah THROWAWAY (validation only) <throwaway@invalid>" rsa4096 sign never 2>/dev/null
  fpr=$(gpg --list-keys --with-colons | awk -F: "/^fpr/{print \$10; exit}")
  echo "$fpr" > /out/throwaway-keyid
  gpg --armor --export "$fpr" > /out/throwaway-key.asc
  gpgconf --kill gpg-agent || true
  chown -R "$HOSTUID" /out/throwaway-gnupg /out/throwaway-keyid /out/throwaway-key.asc'
echo "throwaway key: $(cat "$OUT/throwaway-keyid")"
