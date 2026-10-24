#!/bin/sh
# Test packaging/musl-floor-check.sh against the real 1.5.0 musl build (needs
# docker and network). The 1.5.0 PHP 7.2 musl .so loads on Alpine 3.11+ and
# fails on Alpine 3.10 (php:7.1-fpm-alpine) with
#   Error relocating howdah.so: posix_spawn_file_actions_addchdir_np: symbol not found
# so the check must pass against Alpine 3.11's musl 1.1.24 and fail, naming
# that symbol, against Alpine 3.10's musl 1.1.22.
#   sh packaging/musl-floor.test.sh
set -u
D=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fail=0
ok() { printf 'ok   %s\n' "$1"; }
bad() { printf 'FAIL %s\n' "$1"; fail=1; }

sh -n "$D/musl-floor-check.sh" && ok "syntax: musl-floor-check.sh" || bad "syntax: musl-floor-check.sh"

TB=howdah-1.5.0-php7.2-20170718-linux-x86_64-musl.tar.gz
curl -fsSL -o "$T/$TB" "https://github.com/howdah/howdah/releases/download/v1.5.0/$TB" || { echo "cannot download $TB"; exit 2; }
tar -xzf "$T/$TB" -C "$T"
cp "$T/howdah-1.5.0-php7.2/howdah.so" "$T/howdah.so"
# the loaders (musl's libc) of the two Alpine releases, by pinned digest
docker run --rm alpine:3.11@sha256:bcae378eacedab83da66079d9366c8f5df542d7ed9ab23bf487e3e1a8481375d \
  cat /lib/ld-musl-x86_64.so.1 > "$T/musl-1.1.24"
docker run --rm alpine:3.10@sha256:451eee8bedcb2f029756dc3e9d73bab0e7943c1ac55cff3a4861c52a0fdd3e98 cat /lib/ld-musl-x86_64.so.1 > "$T/musl-1.1.22"
cp "$D/musl-floor-check.sh" "$T/check.sh"
chmod -R a+rX "$T"

run() { # <floor libc file> <floor name> -> output, then rc=N
  docker run --rm -v "$T":/t:ro -e HOWDAH_MUSL_FLOOR_NAME="$2" alpine:3.21 sh -c \
    'apk add --no-cache binutils >/dev/null 2>&1; sh /t/check.sh /t/howdah.so "/t/$0" /lib/ld-musl-x86_64.so.1; echo "rc=$?"' "$1"
}

out=$(run musl-1.1.24 "musl 1.1.24 (Alpine 3.11)" 2>&1)
case "$out" in *"rc=0"*) ok "1.5.0 musl .so passes against musl 1.1.24 (Alpine 3.11)" ;; *) bad "1.5.0 musl .so passes against musl 1.1.24"; printf '%s\n' "$out" ;; esac
case "$out" in *"C library symbols howdah.so needs are in musl 1.1.24"*) ok "pass message names the floor" ;; *) bad "pass message names the floor" ;; esac

out=$(run musl-1.1.22 "musl 1.1.22 (Alpine 3.10)" 2>&1); printf "%s\n" "$out" | grep -v "^rc="
case "$out" in *"rc=1"*) ok "the same .so fails against musl 1.1.22 (Alpine 3.10)" ;; *) bad "the same .so fails against musl 1.1.22"; printf '%s\n' "$out" ;; esac
case "$out" in *"  posix_spawn_file_actions_addchdir_np"*) ok "the failure names posix_spawn_file_actions_addchdir_np" ;; *) bad "the failure names posix_spawn_file_actions_addchdir_np"; printf '%s\n' "$out" ;; esac
case "$out" in *"pidfd_"*) bad "weak references (pidfd_*) are not reported" ;; *) ok "weak references (pidfd_*) are not reported" ;; esac
case "$out" in *"zend_"*|*"_Unwind_"*) bad "PHP and libgcc symbols are not reported as libc" ;; *) ok "PHP and libgcc symbols are not reported as libc" ;; esac

[ $fail -eq 0 ] && echo "all passed"
exit $fail
