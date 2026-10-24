#!/bin/sh
# Tests for docker/matrix.sh and the docker/ scripts' syntax (no docker needed).
#   sh docker/matrix.test.sh
D=$(cd "$(dirname "$0")" && pwd)
M=$D/matrix.sh
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }
check() { if [ "$2" -eq 0 ]; then ok "$1"; else bad "$1"; fi; }
has() { printf '%s\n' "$1" | grep -qF -- "$2"; }

for f in matrix.sh fetch.sh smoke.sh fetch.test.sh; do
  sh -n "$D/$f"; check "syntax: docker/$f" $?
done

sums() { # one SHA256SUMS line per name given
  for n in "$@"; do printf '%064d  %s\n' 0 "$n"; done
}
V=1.4.0
full=$(
  for m in 5.4 5.5 5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5; do
    sums "howdah-$V-php$m-20990101-linux-x86_64.tar.gz" "howdah-$V-php$m-20990101-linux-aarch64.tar.gz"
  done
  sums howdah-check
)

out=$(printf '%s\n' "$full" | sh "$M" "$V"); rc=$?
check "full glibc release: exit 0" $rc
has "$out" '{"minor":"8.3","variant":"fpm","libc":"glibc","platforms":"linux/amd64,linux/arm64","tags":"ghcr.io/howdah/howdah:1.4.0-php8.3"}'
check "8.3: amd64+arm64, exact version tag only" $?
has "$out" '"minor":"5.6",'; check "5.6 gets an image" $?
has "$out" '"minor":"5.4",'; [ $? -ne 0 ]; check "5.4 gets no image (php:5.4-fpm cannot be pulled)" $?
has "$out" '"minor":"5.5",'; [ $? -ne 0 ]; check "5.5 gets no image (php:5.5-fpm is broken)" $?
n=$(printf '%s\n' "$out" | grep -o '"minor"' | wc -l | tr -d ' ')
[ "$n" = 12 ]; check "12 Debian images for a full glibc release (got $n)" $?
has "$out" 'alpine'; [ $? -ne 0 ]; check "no alpine image without musl tarballs" $?
printf '%s\n' "$out" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{JSON.parse(s)})' 2>/dev/null
check "output is valid JSON" $?

out=$(printf '%s\n' "$full" | sh "$M" "$V" 1)
has "$out" '"tags":"ghcr.io/howdah/howdah:1.4.0-php7.4,ghcr.io/howdah/howdah:php7.4"'
check "floating=1 adds php<minor>" $?

# a missing aarch64 cell drops only that platform
out=$(printf '%s\n' "$full" | grep -v 'php8.1-.*aarch64' | sh "$M" "$V")
has "$out" '{"minor":"8.1","variant":"fpm","libc":"glibc","platforms":"linux/amd64",'
check "8.1 without an aarch64 tarball: amd64 only" $?

# musl tarballs add -alpine images for the verified minors only
musl=$(printf '%s\n' "$full"; sums "howdah-$V-php8.3-20230831-linux-x86_64-musl.tar.gz" "howdah-$V-php5.4-20100525-linux-x86_64-musl.tar.gz")
out=$(printf '%s\n' "$musl" | sh "$M" "$V" 1)
has "$out" '{"minor":"8.3","variant":"fpm-alpine","libc":"musl","platforms":"linux/amd64","tags":"ghcr.io/howdah/howdah:1.4.0-php8.3-alpine,ghcr.io/howdah/howdah:php8.3-alpine"}'
check "musl tarball: 8.3-alpine image" $?
has "$out" '"minor":"5.4","variant":"fpm-alpine"'; [ $? -ne 0 ]
check "no alpine image for 5.4 (no php:5.4-fpm-alpine), musl tarball or not" $?
out=$(printf '%s\n' "$musl" | ALPINE_MINORS="8.3" sh "$M" "$V")
n=$(printf '%s\n' "$out" | grep -o '"variant":"fpm-alpine"' | wc -l | tr -d ' ')
[ "$n" = 1 ]; check "ALPINE_MINORS limits the alpine images (got $n)" $?
has "$out" '"minor":"8.3","variant":"fpm","libc":"glibc"'
check "the glibc image is still planned next to the alpine one" $?

# a full musl release (1.5.0 has 15 musl tarballs): -alpine images only where
# the base's musl is 1.1.24 or newer (php:7.2-fpm-alpine and later)
allmusl=$(printf '%s\n' "$full"; for m in 5.4 5.5 5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5; do sums "howdah-$V-php$m-20990101-linux-x86_64-musl.tar.gz"; done)
out=$(printf '%s\n' "$allmusl" | sh "$M" "$V")
for m in 5.6 7.0 7.1; do
  has "$out" "\"minor\":\"$m\",\"variant\":\"fpm-alpine\""; [ $? -ne 0 ]
  check "no $m-alpine image: php:$m-fpm-alpine's musl is older than 1.1.24" $?
  has "$out" "\"minor\":\"$m\",\"variant\":\"fpm\","; check "$m keeps its Debian image" $?
done
n=$(printf '%s\n' "$out" | grep -o '"variant":"fpm-alpine"' | wc -l | tr -d ' ')
[ "$n" = 9 ]; check "9 -alpine images (7.2 to 8.5) for a full musl release (got $n)" $?
has "$out" '"minor":"7.2","variant":"fpm-alpine"'; check "7.2 is the oldest -alpine image" $?

# smoke.sh's php-fpm refusal expectation follows the Howdah version in the image
fb() { sh "$D/smoke.sh" --fpm-block-for "$1" 2>/dev/null; }
[ "$(fb 1.4.0)" = bailout ]; check "smoke: howdah 1.4.0 -> FPM_BLOCK=bailout (worker exit 70)" $?
[ "$(fb 1.3.2)" = bailout ]; check "smoke: howdah 1.3.2 -> bailout" $?
[ "$(fb 1.5.0)" = clean ]; check "smoke: howdah 1.5.0 -> FPM_BLOCK=clean (#44)" $?
[ "$(fb 1.5.1)" = clean ]; check "smoke: howdah 1.5.1 -> clean" $?
[ "$(fb 1.10.0)" = clean ]; check "smoke: howdah 1.10.0 -> clean (versions compare numerically)" $?
[ "$(fb 2.0.0)" = clean ]; check "smoke: howdah 2.0.0 -> clean" $?
fb "" >/dev/null; rc=$?; [ "$rc" -eq 2 ]; check "smoke: an unreadable version is an error, not a guess (exit 2)" $?

# the musl tarball is never mistaken for the glibc one
only_musl=$(sums "howdah-$V-php8.3-20230831-linux-x86_64-musl.tar.gz")
out=$(printf '%s\n' "$only_musl" | sh "$M" "$V")
has "$out" '"variant":"fpm",'; [ $? -ne 0 ]
check "a musl-only release plans no Debian image" $?

printf '%s\n' "$full" | sh "$M" 1.5.0-rc1 >/dev/null 2>&1; rc=$?
[ "$rc" -eq 2 ]; check "pre-release version is refused (exit 2)" $?
sums howdah-check | sh "$M" "$V" >/dev/null 2>&1; rc=$?
[ "$rc" -eq 1 ]; check "a release with no tarballs fails (exit 1)" $?
out=$(printf '%s\n' "$full" | IMAGE=ghcr.io/example/howdah sh "$M" "$V")
has "$out" '"tags":"ghcr.io/example/howdah:1.4.0-php8.5"'; check "IMAGE overrides the repository" $?

[ $fail -eq 0 ] && echo "all passed"
exit $fail
