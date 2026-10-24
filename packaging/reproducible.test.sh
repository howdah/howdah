#!/bin/sh
# Tests for packaging/reproducible.sh (no docker): the SOURCE_DATE_EPOCH
# source, tree normalisation, Installed-Size, and the deterministic tar.gz.
# Run from anywhere:  sh packaging/reproducible.test.sh   (needs bash, GNU tar)
D=$(cd "$(dirname "$0")" && pwd)
L=$D/reproducible.sh
T=$(mktemp -d) || exit 2
trap 'rm -rf "$T"' EXIT
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }
check() { if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi; }
run() { bash -c '. "$1"; shift; "$@"' sh "$L" "$@"; }   # run a helper from the library

# ---- howdah_source_date_epoch ------------------------------------------------
[ "$(SOURCE_DATE_EPOCH=1700000000 run howdah_source_date_epoch "$T")" = 1700000000 ]
check "SOURCE_DATE_EPOCH from the environment wins" $?
SOURCE_DATE_EPOCH=yesterday run howdah_source_date_epoch "$T" >/dev/null 2>&1
[ $? -ne 0 ]; check "a non-numeric SOURCE_DATE_EPOCH is refused" $?
mkdir "$T/nogit"
out=$(unset SOURCE_DATE_EPOCH; run howdah_source_date_epoch "$T/nogit" 2>"$T/err")
[ "$out" = 0 ] && grep -q WARNING "$T/err"; check "outside git and unset: 0 with a warning" $?
if command -v git >/dev/null 2>&1; then
  mkdir "$T/repo"
  ( cd "$T/repo" && git init -q && echo x > f && git add f \
    && GIT_COMMITTER_DATE='@1650000000 +0000' GIT_AUTHOR_DATE='@1600000000 +0000' \
       git -c user.name=t -c user.email=t@example.invalid commit -q -m t ) >/dev/null 2>&1
  [ "$(unset SOURCE_DATE_EPOCH; run howdah_source_date_epoch "$T/repo")" = 1650000000 ]
  check "in git: the committer date of HEAD (not the author date, not now)" $?
fi

# ---- the same tree built twice, differently --------------------------------
mk_tree() { # <dir> <umask> <reverse:0|1>
  ( umask "$2"; mkdir -p "$1/top/sub"
    if [ "$3" = 1 ]; then
      printf 'b\n' > "$1/top/sub/b.txt"; printf '#!/bin/sh\n' > "$1/top/run"; printf 'a\n' > "$1/top/a.ini"
    else
      printf 'a\n' > "$1/top/a.ini"; printf '#!/bin/sh\n' > "$1/top/run"; printf 'b\n' > "$1/top/sub/b.txt"
    fi
    chmod +x "$1/top/run" )
}
mk_tree "$T/one" 022 0
sleep 1
mk_tree "$T/two" 002 1
touch -d '2001-02-03' "$T/two/top/a.ini"

run howdah_normalize_tree "$T/one/top" 1650000000
run howdah_normalize_tree "$T/two/top" 1650000000
[ "$(stat -c %a "$T/two/top/a.ini")" = 644 ] && [ "$(stat -c %a "$T/two/top/run")" = 755 ] \
  && [ "$(stat -c %a "$T/two/top/sub")" = 755 ]
check "normalize: 0644 files, 0755 executables and directories, whatever the umask" $?
[ "$(stat -c %Y "$T/two/top/a.ini")" = 1650000000 ] && [ "$(stat -c %Y "$T/two/top/sub")" = 1650000000 ]
check "normalize: every mtime is the epoch" $?

tgz() { ( cd "$1" && bash -c '. "$1"; sh -c "$HOWDAH_DET_TAR_GZ" sh top 1650000000' sh "$L" ) > "$2"; }
tgz "$T/one" "$T/one.tar.gz"; check "deterministic tar.gz exits 0" $?
tgz "$T/two" "$T/two.tar.gz"
cmp -s "$T/one.tar.gz" "$T/two.tar.gz"
check "two builds (other umask, order, clock) give byte-identical tar.gz" $?
tar -tzvf "$T/one.tar.gz" > "$T/list"
awk '{ print $2 }' "$T/list" | sort -u | grep -qx '0/0'; check "every entry is owned by 0/0" $?
[ "$(awk '{ print $2 }' "$T/list" | sort -u | wc -l | tr -d ' ')" = 1 ]; check "no other owner appears" $?
grep -q ' 2022-04-15 ' "$T/list"; check "entries carry the epoch's date (2022-04-15)" $?
[ "$(tar -tzf "$T/one.tar.gz" | tr '\n' ' ')" = "top/ top/a.ini top/run top/sub/ top/sub/b.txt " ]
check "entries are sorted by name" $?
# gzip header: byte 3 = flags (FNAME is 0x08), bytes 4-7 = MTIME
hdr=$(od -An -tx1 -N8 "$T/one.tar.gz" | tr -d ' \n')
[ "$hdr" = "1f8b080000000000" ]; check "gzip header carries no file name and no time" $?

# ---- Installed-Size ----------------------------------------------------------
mkdir -p "$T/deb/DEBIAN" "$T/deb/usr/lib"
head -c 2049 /dev/zero > "$T/deb/usr/lib/x.so"; printf 'y\n' > "$T/deb/usr/lib/y.ini"
head -c 99999 /dev/zero > "$T/deb/DEBIAN/control"
# x.so 3 KiB + y.ini 1 KiB + 3 directories (., usr, usr/lib) = 7; DEBIAN not counted
[ "$(run howdah_installed_size_kib "$T/deb")" = 7 ]
check "Installed-Size: per-file KiB rounded up, 1 per directory, DEBIAN excluded" $?

[ "$fail" = 0 ] && echo "all reproducible.sh tests passed"
exit "$fail"
