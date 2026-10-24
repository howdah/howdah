#!/bin/sh
# Tests for packaging/repo/attest-subjects.sh (no docker, no network).
# Run from anywhere:  sh packaging/repo/attest-subjects.test.sh
D=$(cd "$(dirname "$0")" && pwd)
S=$D/attest-subjects.sh
T=$(mktemp -d) || exit 2
trap 'rm -rf "$T"' EXIT
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }
check() { if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi; }
h() { sha256sum "$1" | cut -d' ' -f1; }

# new packages from this run, and the repo assembled from them plus a seed
mkdir -p "$T/out" "$T/repo/apt/pool/main/p/php7.4-howdah" "$T/repo/apt/pool/main/p/old" "$T/repo/yum"
echo deb-new > "$T/out/php7.4-howdah_9.9.9-1_amd64.deb"
echo rpm-unsigned > "$T/out/php74-howdah-9.9.9-1.x86_64.rpm"
cp "$T/out/php7.4-howdah_9.9.9-1_amd64.deb" "$T/repo/apt/pool/main/p/php7.4-howdah/"
echo rpm-signed > "$T/repo/yum/php74-howdah-9.9.9-1.x86_64.rpm"          # rpmsign rewrote it
echo seeded > "$T/repo/apt/pool/main/p/old/php7.4-howdah_1.0.0-1_amd64.deb"
echo seeded > "$T/repo/yum/php74-howdah-1.0.0-1.x86_64.rpm"

sh "$S" "$T/out" "$T/repo" > "$T/list"; check "exits 0 for a consistent run" $?
[ "$(wc -l < "$T/list" | tr -d ' ')" = 2 ]; check "lists exactly the two packages this run built" $?
grep -qxF "$(h "$T/repo/apt/pool/main/p/php7.4-howdah/php7.4-howdah_9.9.9-1_amd64.deb")  apt/pool/main/p/php7.4-howdah/php7.4-howdah_9.9.9-1_amd64.deb" "$T/list"
check "a .deb is named by its pool path" $?
grep -qxF "$(h "$T/repo/yum/php74-howdah-9.9.9-1.x86_64.rpm")  yum/php74-howdah-9.9.9-1.x86_64.rpm" "$T/list"
check "an .rpm is hashed after signing (the bytes users download)" $?
! grep -q "$(h "$T/out/php74-howdah-9.9.9-1.x86_64.rpm")" "$T/list"; check "the unsigned rpm digest is not used" $?
! grep -q '1\.0\.0' "$T/list"; check "seeded packages are not attested" $?

sh "$S" "$T/out" "$T/repo" plesk/ | grep -q '  plesk/yum/php74-howdah-9.9.9-1.x86_64.rpm$'
check "NAME_PREFIX is prepended (layout repositories)" $?

rm "$T/repo/yum/php74-howdah-9.9.9-1.x86_64.rpm"
sh "$S" "$T/out" "$T/repo" >/dev/null 2>&1; [ $? -ne 0 ]; check "a built rpm missing from yum/ is an error" $?
echo signed-again > "$T/repo/yum/php74-howdah-9.9.9-1.x86_64.rpm"
echo tampered > "$T/repo/apt/pool/main/p/php7.4-howdah/php7.4-howdah_9.9.9-1_amd64.deb"
sh "$S" "$T/out" "$T/repo" >/dev/null 2>&1; [ $? -ne 0 ]; check "a pool .deb that differs from the built one is an error" $?
mkdir "$T/empty"
sh "$S" "$T/empty" "$T/repo" >/dev/null 2>&1; [ $? -ne 0 ]; check "no packages at all is an error" $?

[ "$fail" = 0 ] && echo "all attest-subjects.sh tests passed"
exit "$fail"
