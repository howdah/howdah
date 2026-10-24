# shellcheck shell=bash
# Shared helpers for reproducible release artefacts (docs/verify.md).
# Sourced by packaging/build-release.sh, packaging/deb/build-deb.sh and
# packaging/build-layouts.sh; tested by packaging/reproducible.test.sh.

# howdah_source_date_epoch REPO_ROOT
#   The timestamp every file in a release artefact carries, in seconds since
#   the epoch: $SOURCE_DATE_EPOCH if set, else the committer date of the
#   checked-out commit (in release.yml, the tag's commit), else 0 with a
#   warning. Never the current time.
howdah_source_date_epoch() {
  local t=""
  if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    t="$SOURCE_DATE_EPOCH"
  else
    t="$(git -C "$1" log -1 --format=%ct 2>/dev/null || true)"
    if [ -z "$t" ]; then
      echo "WARNING: SOURCE_DATE_EPOCH is unset and $1 is not a git checkout; using 0" >&2
      t=0
    fi
  fi
  case "$t" in
    ''|*[!0-9]*) echo "FATAL: SOURCE_DATE_EPOCH must be seconds since the epoch (got '$t')" >&2; return 1 ;;
  esac
  printf '%s\n' "$t"
}

# howdah_normalize_tree DIR EPOCH
#   Make a staging tree independent of the builder's umask and clock:
#   directories 0755, files with any execute bit 0755, other files 0644, and
#   every mtime set to EPOCH.
howdah_normalize_tree() {
  find "$1" -type d -exec chmod 0755 {} +
  find "$1" -type f -perm /111 -exec chmod 0755 {} +
  find "$1" -type f ! -perm /111 -exec chmod 0644 {} +
  find "$1" -exec touch -h -d "@$2" {} +
}

# howdah_installed_size_kib DIR
#   Debian Installed-Size of a staging tree, counted the way dpkg-gencontrol
#   does: each regular file's size rounded up to a KiB, plus 1 for every other
#   entry (directories, symlinks), DEBIAN/ excluded. `du -sk` is not used
#   because it depends on the builder's filesystem (tmpfs and ext4 count
#   directory blocks differently).
howdah_installed_size_kib() {
  ( cd "$1" && find . -path ./DEBIAN -prune -o \( -type f -printf 'f %s\n' -o -printf 'o 0\n' \) ) \
    | awk '$1 == "f" { k += int(($2 + 1023) / 1024); next } { k += 1 } END { print k + 0 }'
}

# HOWDAH_DET_TAR_GZ
#   A POSIX sh program that writes a deterministic .tar.gz of one directory to
#   stdout. Run it in the directory that holds TOP:
#       sh -c "$HOWDAH_DET_TAR_GZ" sh TOP EPOCH > out.tar.gz
#   Entries are sorted by name in the C locale, GNU tar format, owner and
#   group 0 (numeric, no names), every mtime EPOCH, and `gzip -n` keeps the
#   file name and time out of the gzip header. Modes are taken from the tree,
#   so normalize it first. It needs GNU tar >= 1.26 (no --sort) and is run in
#   the release image, so every rebuild uses the same tar and gzip.
# (SC2016: expanded by the inner sh, not here; SC2034: used by the sourcing scripts)
# shellcheck disable=SC2016,SC2034
HOWDAH_DET_TAR_GZ='set -e
t=$(mktemp -d)
find "$1" -print0 | LC_ALL=C sort -z > "$t/list"
tar --null --no-recursion -T "$t/list" --format=gnu --numeric-owner --owner=0 --group=0 --mtime="@$2" -cf "$t/a.tar"
gzip -n -c "$t/a.tar"
rm -rf "$t"'
