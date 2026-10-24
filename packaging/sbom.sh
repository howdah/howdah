#!/usr/bin/env bash
# Write the CycloneDX SBOM of the release howdah.so: the Rust dependency
# closure of howdah-ext for one target, from Cargo.lock at this commit.
#
#   packaging/sbom.sh <out.cdx.json> [target]     target default x86_64-unknown-linux-gnu
#
# What it lists: every crate compiled into howdah.so (scope "required") and the
# build-time crates that generate part of it, bindgen, cc and their
# dependencies (scope "excluded": run at build time, not linked in). Dev
# dependencies are not listed. Features: all of them (php5, php7, php8 resolve
# to the same crates), so one SBOM covers every PHP minor of an arch.
# What it does not list: the C toolchain, libclang and the PHP headers used at
# build time (packaging/release.Dockerfile pins those), and the C shim, which
# is part of howdah-sys.
#
# The tool is cargo-cyclonedx, a pinned release binary verified by sha256
# before it runs (CARGO_CYCLONEDX=<path> uses a local copy instead).
# SOURCE_DATE_EPOCH (default: the commit date) sets the SBOM timestamp.
# release.yml and publish-repos.yml attest the result against the tarballs and
# packages (actions/attest); see docs/verify.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:?usage: sbom.sh <out.cdx.json> [target]}"
TARGET="${2:-x86_64-unknown-linux-gnu}"
# shellcheck source=packaging/reproducible.sh
. "$REPO_ROOT/packaging/reproducible.sh"
SOURCE_DATE_EPOCH="$(howdah_source_date_epoch "$REPO_ROOT")"
export SOURCE_DATE_EPOCH

CDX_VERSION=0.5.9
CDX_SHA256=fb8dbee9f182173e062a64a387b21a0badc6fab8b2abf9294973f012972bf6d8   # cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

CDX="${CARGO_CYCLONEDX:-}"
if [ -z "$CDX" ]; then
  [ "$(uname -m)" = x86_64 ] || { echo "FATAL: the pinned cargo-cyclonedx is x86_64; set CARGO_CYCLONEDX" >&2; exit 1; }
  url="https://github.com/CycloneDX/cyclonedx-rust-cargo/releases/download/cargo-cyclonedx-$CDX_VERSION/cargo-cyclonedx-x86_64-unknown-linux-gnu.tar.xz"
  curl -fsSL --retry 3 -o "$WORK/cdx.tar.xz" "$url"
  echo "$CDX_SHA256  $WORK/cdx.tar.xz" | sha256sum -c - >/dev/null \
    || { echo "FATAL: cargo-cyclonedx $CDX_VERSION does not match the pinned sha256" >&2; exit 1; }
  tar -C "$WORK" -xJf "$WORK/cdx.tar.xz"
  CDX="$(find "$WORK" -type f -name cargo-cyclonedx | head -1)"
fi
[ -x "$CDX" ] || { echo "FATAL: no cargo-cyclonedx binary at '$CDX'" >&2; exit 1; }

# cargo-cyclonedx writes <name>.json next to every workspace member's
# Cargo.toml; use a name nothing else uses, keep howdah-ext's, drop the rest.
name="howdah-sbom-$$"
"$CDX" cyclonedx --manifest-path "$REPO_ROOT/crates/howdah-ext/Cargo.toml" \
  --all-features --target "$TARGET" --spec-version 1.5 --format json \
  --override-filename "$name" -q
mkdir -p "$(dirname "$OUT")"
mv "$REPO_ROOT/crates/howdah-ext/$name.json" "$OUT"
find "$REPO_ROOT/crates" -maxdepth 2 -name "$name.json" -delete

# Sanity: a CycloneDX document whose subject is howdah-ext and which lists
# the crates we know are linked in.
grep -q '"bomFormat": *"CycloneDX"' "$OUT" || { echo "FATAL: $OUT is not CycloneDX" >&2; exit 1; }
for c in howdah-core serde_json toml; do
  grep -q "\"name\": *\"$c\"" "$OUT" || { echo "FATAL: $OUT does not list $c" >&2; exit 1; }
done
echo "== SBOM for howdah-ext ($TARGET): $OUT ($(grep -c '"bom-ref"' "$OUT") bom-refs)"
