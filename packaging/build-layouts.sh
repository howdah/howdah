#!/usr/bin/env bash
# Build the panel and stock-EL packages for one PHP minor + one arch, wrapping
# the SAME glibc-2.17 howdah.so and howdah.ini as the Surý/Remi packages (the
# per-minor release tarball from packaging/build-release.sh; nothing is
# rebuilt). One package per row of packaging/layouts.tsv whose arches include
# <arch>: only install paths, ini drop-ins, name and dependencies differ.
#
#   packaging/build-layouts.sh <minor> <x86_64|aarch64> [path/to/release-tarball.tar.gz]
#
# Input: howdah-<ver>-php<minor>-<api>-linux-<arch>.tar.gz. If no tarball is
# given it is taken from packaging/out/; if absent there it is built via
# HOWDAH_ARCH=<arch> packaging/build-release.sh <minor> (HOWDAH_NO_BUILD=1
# fails instead).
#
# Env:
#   HOWDAH_VERSION       default: workspace version
#   HOWDAH_RPM_REL       rpm Release / deb revision (@REL@), default 1
#   HOWDAH_LAYOUTS       space-separated layout names to build (default: every row)
#   HOWDAH_LAYOUT_RENDER=<dir>  render the spec/control/ini files for each row
#                        into <dir> and stop (no docker, no packages). Used by
#                        packaging/layouts.test.sh and to review a new row.
#
# Output mirrors the repository paths under https://pkg.howdah.org/:
#   packaging/out/layouts/<repo>/yum/<name>-<ver>-<release>.<arch>.rpm
#   packaging/out/layouts/<repo>/apt/<name>_<ver>-<release>_<amd64|arm64>.deb
# e.g. layouts/cpanel/yum/ea-php74-php-howdah-1.3.0-1.x86_64.rpm and
#      layouts/el/php7.4/yum/php-howdah-1.3.0-1.php74.x86_64.rpm.
# It never writes packaging/out/*.deb or *.rpm, the inputs of the Surý/Remi
# repos (packaging/repo/build-{apt,yum}-repo.sh), so those stay exactly as the
# unchanged build-deb.sh / build-rpm.sh make them. Packages are unsigned; repo
# signing is a separate CI step (packaging/repo/build-layout-repos.sh).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO_ROOT/packaging/out"
TABLE="$REPO_ROOT/packaging/layouts.tsv"
SPEC_IN="$REPO_ROOT/packaging/rpm/layout.spec.in"
CONTROL_IN="$REPO_ROOT/packaging/deb/layout-control.in"

MINOR="${1:?usage: build-layouts.sh <minor> <x86_64|aarch64> [tarball]}"
ARCH="${2:?usage: build-layouts.sh <minor> <x86_64|aarch64> [tarball]}"
TARBALL="${3:-}"
case "$MINOR" in 5.[456]|7.[0-4]|8.[0-5]) ;; *) echo "FATAL: unsupported PHP minor '$MINOR'" >&2; exit 2 ;; esac
case "$ARCH" in
  x86_64)  DEBARCH=amd64; want_elf='x86-64' ;;
  aarch64) DEBARCH=arm64; want_elf='ARM aarch64' ;;
  *) echo "FATAL: arch must be x86_64|aarch64 (got '$ARCH')" >&2; exit 2 ;;
esac
VERSION="${HOWDAH_VERSION:-$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')}"
REL="${HOWDAH_RPM_REL:-1}"
XY="${MINOR//./}"
RENDER="${HOWDAH_LAYOUT_RENDER:-}"

# ---- 1. locate (or build) the release tarball -------------------------------
if [ -z "$TARBALL" ]; then
  TARBALL="$(ls "$OUT"/howdah-"$VERSION"-php"$MINOR"-*-linux-"$ARCH".tar.gz 2>/dev/null | head -1 || true)"
  if [ -z "$TARBALL" ]; then
    [ "${HOWDAH_NO_BUILD:-0}" = 1 ] && { echo "FATAL: no release tarball for php$MINOR $ARCH in $OUT" >&2; exit 1; }
    echo "== no tarball yet; building via packaging/build-release.sh ($ARCH)"
    HOWDAH_ARCH="$ARCH" HOWDAH_VERSION="$VERSION" KEEP_IMAGE="${KEEP_IMAGE:-1}" \
      "$REPO_ROOT/packaging/build-release.sh" "$MINOR"
    TARBALL="$(ls "$OUT"/howdah-"$VERSION"-php"$MINOR"-*-linux-"$ARCH".tar.gz | head -1)"
  fi
fi
[ -f "$TARBALL" ] || { echo "FATAL: tarball not found: $TARBALL" >&2; exit 1; }
API="$(basename "$TARBALL" | sed -nE "s/.*-php${MINOR//./\\.}-([0-9]{8})-linux-${ARCH}\.tar\.gz$/\1/p")"
[ -n "$API" ] || { echo "FATAL: cannot read API from tarball name '$(basename "$TARBALL")'" >&2; exit 1; }
echo "== php$MINOR $ARCH: api $API, tarball $(basename "$TARBALL")"

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/x" "$WORK/rpm" "$WORK/deb"
tar -C "$WORK/x" -xzf "$TARBALL"
SRC="$(ls -d "$WORK"/x/howdah-*-php"$MINOR" | head -1)"
[ -f "$SRC/howdah.so" ] && [ -f "$SRC/howdah.ini" ] || { echo "FATAL: tarball lacks howdah.so/howdah.ini" >&2; exit 1; }
if [ -z "$RENDER" ]; then
  file "$SRC/howdah.so" | grep -q "$want_elf" || { echo "FATAL: howdah.so is not $want_elf: $(file "$SRC/howdah.so")" >&2; exit 1; }
fi
# The ini's load line is rewritten per row (`ext` column); refuse to guess if
# the shipped ini ever stops carrying exactly one `extension=howdah.so` line.
[ "$(grep -c '^extension=howdah\.so$' "$SRC/howdah.ini")" = 1 ] \
  || { echo "FATAL: howdah.ini must contain exactly one 'extension=howdah.so' line" >&2; exit 1; }

# ---- 2. render one row -------------------------------------------------------
tok() { # substitute the per-minor tokens in "$1"
  local s="$1"
  s="${s//@XY@/$XY}"; s="${s//@MINOR@/$MINOR}"; s="${s//@API@/$API}"; s="${s//@REL@/$REL}"
  printf '%s' "$s"
}
# fill <template>: @NAME@ tokens from the current row; the block tokens
# (@REQUIRES@, @INSTALL_INIS@, @FILES_INIS@) replace a line of their own.
fill() {
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      @REQUIRES@)     printf '%s\n' "${req_lines[@]}" ;;
      @INSTALL_INIS@) printf '%s\n' "${install_lines[@]}" ;;
      @FILES_INIS@)   printf '%s\n' "${files_lines[@]}" ;;
      *)
        line="${line//@PKG@/$pkg}"; line="${line//@VERSION@/$VERSION}"
        line="${line//@RELEASE@/$release}"; line="${line//@MINOR@/$MINOR}"
        line="${line//@API@/$API}"; line="${line//@LABEL@/$label}"
        line="${line//@MODDIR@/$moddir}"; line="${line//@ARCH@/$DEBARCH}"
        line="${line//@DEPENDS@/$depends}"; line="${line//@SIZE@/${size:-0}}"
        printf '%s\n' "$line" ;;
    esac
  done < "$1"
}

built=()
while IFS=$'\t' read -r layout fmt arches pkg release moddir ext inis reqs repo label; do
  case "$layout" in ''|'#'*) continue ;; esac
  case ",$arches," in *",$ARCH,"*) ;; *) continue ;; esac
  if [ -n "${HOWDAH_LAYOUTS:-}" ]; then
    case " $HOWDAH_LAYOUTS " in *" $layout "*) ;; *) continue ;; esac
  fi
  pkg="$(tok "$pkg")"; release="$(tok "$release")"; moddir="$(tok "$moddir")"
  ext="$(tok "$ext")"; ext="${ext//@MODDIR@/$moddir}"; inis="$(tok "$inis")"
  reqs="$(tok "$reqs")"; repo="$(tok "$repo")"; label="$(tok "$label")"
  IFS=',' read -r -a ini_list <<< "$inis"
  IFS=',' read -r -a req_list <<< "$reqs"
  kind=yum; [ "$fmt" = deb ] && kind=apt
  # the ini: the tarball's howdah.ini, byte for byte, except the load line
  ini_body="$(sed "s|^extension=howdah\.so\$|extension=$ext|" "$SRC/howdah.ini")"

  if [ "$fmt" = rpm ]; then
    top="$WORK/rpm/$layout-$pkg"; mkdir -p "$top/SOURCES"
    cp "$SRC/howdah.so" "$top/SOURCES/howdah.so"
    printf '%s\n' "$ini_body" > "$top/SOURCES/howdah.ini"
    req_lines=(); install_lines=(); files_lines=()
    for r in "${req_list[@]}"; do req_lines+=("Requires:       $r"); done
    for i in "${ini_list[@]}"; do
      install_lines+=("install -D -m 0644 %{SOURCE1} %{buildroot}$i")
      files_lines+=("%config(noreplace) $i")
    done
    depends=""; size=""
    fill "$SPEC_IN" > "$top/howdah.spec"
    echo "$repo/$kind" > "$top/dest"
  else
    stage="$WORK/deb/$layout-$pkg/stage"
    install -d -m 0755 "$stage/DEBIAN" "$stage/$moddir" "$stage/usr/share/doc/$pkg"
    install -m 0644 "$SRC/howdah.so" "$stage/$moddir/howdah.so"
    : > "$stage/DEBIAN/conffiles"
    for i in "${ini_list[@]}"; do
      install -d -m 0755 "$stage$(dirname "$i")"
      printf '%s\n' "$ini_body" > "$stage$i"; chmod 0644 "$stage$i"
      echo "$i" >> "$stage/DEBIAN/conffiles"
    done
    cat > "$stage/usr/share/doc/$pkg/copyright" <<EOF2
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Howdah
Source: https://github.com/howdah/howdah

Files: *
Copyright: 2026 Howdah contributors
License: MIT or Apache-2.0
 Dual-licensed under the MIT License or the Apache License 2.0, at your option.
 See LICENSE-MIT and LICENSE-APACHE in the source repository; the Apache-2.0
 text is also at /usr/share/common-licenses/Apache-2.0 on Debian systems.
EOF2
    chmod 0644 "$stage/usr/share/doc/$pkg/copyright"
    depends="$(printf '%s' "$reqs" | sed 's/,/, /g')"
    size="$(du -sk --exclude=DEBIAN "$stage" | cut -f1)"
    req_lines=(); install_lines=(); files_lines=()
    fill "$CONTROL_IN" > "$stage/DEBIAN/control"
    echo "$repo/$kind" > "$WORK/deb/$layout-$pkg/dest"
  fi

  if [ -n "$RENDER" ]; then
    d="$RENDER/$repo/$kind/$pkg"; mkdir -p "$d"
    if [ "$fmt" = rpm ]; then
      cp "$top/howdah.spec" "$d/howdah.spec"
      cp "$top/SOURCES/howdah.ini" "$d/howdah.ini"
    else
      cp "$stage/DEBIAN/control" "$stage/DEBIAN/conffiles" "$d/"
      cp "$stage${ini_list[0]}" "$d/howdah.ini"
      ( cd "$stage" && find . -path ./DEBIAN -prune -o -type f -print | sort ) > "$d/files"
    fi
  fi
  built+=("$layout/$fmt:$pkg")
done < "$TABLE"

[ ${#built[@]} -gt 0 ] || { echo "== no layout rows for $ARCH${HOWDAH_LAYOUTS:+ ($HOWDAH_LAYOUTS)}"; exit 0; }
if [ -n "$RENDER" ]; then
  echo "== rendered ${#built[@]} row(s) into $RENDER: ${built[*]}"
  exit 0
fi

# ---- 3. build -----------------------------------------------------------------
mkdir -p "$OUT/layouts"
if ls -d "$WORK"/rpm/*/ >/dev/null 2>&1; then
  # Same EL7 rpmbuild image as packaging/rpm/build-rpm.sh (oldest rpm we
  # target => installs on EL7..EL10); prebuilt payload, so --target is enough.
  IMG=howdah-rpmbuild-el7
  docker image inspect "$IMG" >/dev/null 2>&1 \
    || docker build -q -t "$IMG" -f "$REPO_ROOT/packaging/rpm/builder.Dockerfile" "$REPO_ROOT/packaging/rpm"
  docker run --rm -e HU="$(id -u)" -e HG="$(id -g)" -e ARCH="$ARCH" -v "$WORK/rpm":/w "$IMG" bash -ec '
    for t in /w/*/; do
      rpmbuild -bb --target "$ARCH" --define "_topdir $t" --define "_rpmdir ${t}RPMS" \
        --define "_sourcedir ${t}SOURCES" "${t}howdah.spec" > "${t}log" 2>&1 || { cat "${t}log"; exit 1; }
    done
    chown -R "$HU:$HG" /w'
  for t in "$WORK"/rpm/*/; do
    dest="$OUT/layouts/$(cat "$t/dest")"; mkdir -p "$dest"
    cp "$t"RPMS/"$ARCH"/*.rpm "$dest/"
    echo "== built $(cd "$t"RPMS/"$ARCH" && ls *.rpm) -> layouts/$(cat "$t/dest")/"
  done
fi
for d in "$WORK"/deb/*/; do
  [ -d "$d/stage" ] || continue
  dest="$OUT/layouts/$(cat "$d/dest")"; mkdir -p "$dest"
  p="$(sed -n 's/^Package: //p' "$d/stage/DEBIAN/control")"
  v="$(sed -n 's/^Version: //p' "$d/stage/DEBIAN/control")"
  deb="$dest/${p}_${v}_${DEBARCH}.deb"
  # --root-owner-group: root:root regardless of builder uid; gzip members for old dpkg.
  dpkg-deb --root-owner-group -Zgzip --build "$d/stage" "$deb" >/dev/null
  echo "== built $(basename "$deb") -> layouts/$(cat "$d/dest")/"
done
echo "== layout packages for php$MINOR $ARCH:"
( cd "$OUT/layouts" && find . -type f \( -name "*.rpm" -o -name "*.deb" \) | sort )
