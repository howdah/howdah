#!/bin/sh
# Fail if a musl build of howdah.so needs a C library symbol that the oldest
# musl Howdah supports does not have: musl 1.1.24 (Alpine 3.11).
#
#   packaging/musl-floor-check.sh <howdah.so> <floor ld-musl> <current ld-musl>
#
# musl binds every symbol when a module is loaded, so a single missing one
# makes PHP refuse the whole extension at startup:
#   Error relocating .../howdah.so: posix_spawn_file_actions_addchdir_np: symbol not found
# (1.5.0 on php:7.1-fpm-alpine, Alpine 3.10 / musl 1.1.22: the [log] exec
# hook uses Rust's std::process::Command, which links posix_spawn and
# posix_spawn_file_actions_addchdir_np; musl added the latter in 1.1.24.)
#
# The libc symbols the module needs are its strong undefined dynamic symbols
# that the current musl defines (PHP's zend_* and libgcc's _Unwind_* are not
# libc and drop out). Every one must also be defined by the floor musl. Weak
# references (pidfd_spawnp, _environ, ...) are allowed to be missing: they
# resolve to NULL. Needs readelf (binutils). Run by packaging/build-one.sh in
# the musl release image; tested by packaging/musl-floor.test.sh.
set -eu

SO=${1:?usage: musl-floor-check.sh <howdah.so> <floor ld-musl> <current ld-musl>}
FLOOR=${2:?usage: musl-floor-check.sh <howdah.so> <floor ld-musl> <current ld-musl>}
NOW=${3:?usage: musl-floor-check.sh <howdah.so> <floor ld-musl> <current ld-musl>}
FLOOR_NAME=${HOWDAH_MUSL_FLOOR_NAME:-musl 1.1.24 (Alpine 3.11)}

for f in "$SO" "$FLOOR" "$NOW"; do
  [ -f "$f" ] || { echo "musl-floor-check: $f not found" >&2; exit 2; }
done

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
export LC_ALL=C
# readelf --dyn-syms -W: Num: Value Size Type Bind Vis Ndx Name
defined() { readelf --dyn-syms -W "$1" | awk '$7 != "UND" && $8 != "" { sub(/@.*/, "", $8); print $8 }' | sort -u; }
readelf --dyn-syms -W "$SO" | awk '$7 == "UND" && $5 == "GLOBAL" && $8 != "" { sub(/@.*/, "", $8); print $8 }' \
  | sort -u > "$T/needed"
defined "$NOW" > "$T/now"
defined "$FLOOR" > "$T/floor"
[ -s "$T/now" ] && [ -s "$T/floor" ] || { echo "musl-floor-check: no symbols read from the C libraries" >&2; exit 2; }

comm -12 "$T/needed" "$T/now" > "$T/libc"
comm -23 "$T/libc" "$T/floor" > "$T/missing"
n=$(wc -l < "$T/libc" | tr -d ' ')
if [ -s "$T/missing" ]; then
  echo "musl floor: $(basename "$SO") needs $(wc -l < "$T/missing" | tr -d ' ') C library symbol(s) that $FLOOR_NAME does not have:"
  sed 's/^/  /' "$T/missing"
  echo "PHP on that musl would refuse to load it (Error relocating ...: symbol not found)."
  exit 1
fi
echo "musl floor: all $n C library symbols $(basename "$SO") needs are in $FLOOR_NAME"
