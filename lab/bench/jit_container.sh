#!/bin/sh
# In-container half of the OPcache JIT coexistence check (lab/bench/jit.sh).
# Runs inside a howdah-dev-php8.x image.
#
#  1. Measures whether the JIT is actually on (opcache_get_status()['jit']['on'])
#     under the CLI and under php-fpm in three cases: without Howdah; with
#     Howdah at the shipped defaults (no TOML; since #42 the default
#     `[sinks] hook = "auto"` is meant to keep the JIT on); and with Howdah
#     and `[sinks] hook = "opcode"` (the user opcode handler, which OPcache's
#     JIT refuses to run with). Keeps PHP's startup warning text if there is
#     one. On a tree without #42 the `hook` key is unknown, the TOML is
#     rejected and the core falls back to its defaults: the opcode case then
#     measures the same thing as the default case.
#  2. Runs the cross-version integration suite (lab/integration/
#     matrix_container.sh, cli + fpm) twice in this container: once with
#     OPcache on and the JIT off, once with opcache.jit=tracing and
#     opcache.jit_buffer_size=64M. Both runs' rows land in $OUT.
#
# Writes $OUT/jit-<minor>.json. jit_on is reported as measured, never assumed.
# Arg 1: output dir (default /out).
set -u
OUT="${1:-/out}"
W=/tmp/jit
mkdir -p "$W" "$OUT"
MINOR=$(php -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION;')
PHPVER=$(php -r 'echo PHP_VERSION;')
CONFD=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;')
[ -n "$CONFD" ] || CONFD=/usr/local/etc/php/conf.d

export CARGO_TARGET_DIR=/tmp/t
cd /src
if ! cargo build --locked -p howdah-ext --features php8 --release > "$W/build.log" 2>&1; then
  tail -20 "$W/build.log" >&2; exit 1
fi
cp /tmp/t/release/libhowdah_ext.so "$W/howdah.so"

LOADOP=""
php -m 2>/dev/null | grep -qx 'Zend OPcache' || LOADOP="zend_extension=opcache.so"
write_ini() { # jit on|off
  {
    [ -n "$LOADOP" ] && echo "$LOADOP"
    echo "opcache.enable=1"
    echo "opcache.enable_cli=1"
    if [ "$1" = on ]; then
      echo "opcache.jit=tracing"
      echo "opcache.jit_buffer_size=64M"
    else
      echo "opcache.jit_buffer_size=0"
    fi
  } > "$CONFD/zz-howdah-jit.ini"
}

# ---- 1. measured JIT state ---------------------------------------------------
write_ini on
printf '<?php $s = opcache_get_status(false); echo json_encode(isset($s["jit"]["on"]) ? (bool) $s["jit"]["on"] : null);\n' > "$W/probe.php"
printf '[sinks]\nhook = "opcode"\n' > "$W/opcode.toml"
CLI_NO=$(php "$W/probe.php" 2>/dev/null | tail -1)
# cli_case <tag> <extra args...>: the probe's answer; PHP's startup output kept
# in $W/cli-<tag>.out (the CLI prints startup warnings to stdout).
cli_case() {
  _t=$1; shift
  php -d extension="$W/howdah.so" "$@" "$W/probe.php" > "$W/cli-$_t.out" 2>&1
  tail -1 "$W/cli-$_t.out"
}
CLI_DEFAULT=$(cli_case default)
CLI_OPCODE=$(cli_case opcode -d howdah.config="$W/opcode.toml")
warning_of() { sed -n 's/^.*Warning: \(JIT [^.]*\.[^.]*\.\).*$/\1/p' "$1" | head -1; }
WARN_DEFAULT=$(warning_of "$W/cli-default.out")
WARN_OPCODE=$(warning_of "$W/cli-opcode.out")

fpm_state() { # extra -d args... -> prints the probe answer
  cat > "$W/fpm.conf" <<EOF
[global]
error_log = $W/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9010
pm = static
pm.max_children = 1
EOF
  : > "$W/fpm.err"
  php-fpm -R -F -y "$W/fpm.conf" "$@" > "$W/fpm.out" 2>&1 &
  _pid=$!
  _j=0; _r=""
  while [ "$_j" -lt 60 ]; do
    _r=$(env -i SCRIPT_FILENAME="$W/probe.php" SCRIPT_NAME=/probe.php REQUEST_METHOD=GET \
      REQUEST_URI=/probe.php SERVER_PROTOCOL=HTTP/1.1 GATEWAY_INTERFACE=CGI/1.1 \
      cgi-fcgi -bind -connect 127.0.0.1:9010 2>/dev/null | tail -1)
    [ -n "$_r" ] && break
    _j=$((_j + 1)); sleep 0.1
  done
  kill "$_pid" 2>/dev/null; wait "$_pid" 2>/dev/null
  echo "${_r:-null}"
}
FPM_NO=$(fpm_state)
FPM_DEFAULT=$(fpm_state -d extension="$W/howdah.so")
FPM_OPCODE=$(fpm_state -d extension="$W/howdah.so" -d howdah.config="$W/opcode.toml")

# ---- 2. integration suite without and with the JIT ----------------------------
count() { # tsv sapi result
  awk -F'\t' -v s="$2" -v r="$3" '$2==s && $4==r {n++} END {print n+0}' "$1"
}
for MODE in off on; do
  write_ini "$MODE"
  : > "$OUT/rows-$MINOR-jit-$MODE.tsv"
  sh /src/lab/integration/matrix_container.sh php8 "cli fpm" "$OUT/rows-$MINOR-jit-$MODE.tsv" > "$W/matrix-$MODE.log" 2>&1
done
rm -f "$CONFD/zz-howdah-jit.ini"

R0="$OUT/rows-$MINOR-jit-off.tsv"; R1="$OUT/rows-$MINOR-jit-on.tsv"
SAME=true
for S in cli fpm; do
  for R in PASS FAIL SKIP; do
    [ "$(count "$R0" $S $R)" = "$(count "$R1" $S $R)" ] || SAME=false
  done
done
cat > "$OUT/jit-$MINOR.json" <<EOF
{
  "php": "$PHPVER",
  "jit_settings": "opcache.enable=1 opcache.enable_cli=1 opcache.jit=tracing opcache.jit_buffer_size=64M",
  "jit_on": {
    "cli_without_howdah": $CLI_NO,
    "cli_default": $CLI_DEFAULT,
    "cli_opcode_hook": $CLI_OPCODE,
    "fpm_without_howdah": $FPM_NO,
    "fpm_default": $FPM_DEFAULT,
    "fpm_opcode_hook": $FPM_OPCODE
  },
  "startup_warning_default": "$WARN_DEFAULT",
  "startup_warning_opcode_hook": "$WARN_OPCODE",
  "suite": {
    "jit_off": {
      "cli": {"pass": $(count "$R0" cli PASS), "fail": $(count "$R0" cli FAIL), "skip": $(count "$R0" cli SKIP)},
      "fpm": {"pass": $(count "$R0" fpm PASS), "fail": $(count "$R0" fpm FAIL), "skip": $(count "$R0" fpm SKIP)}
    },
    "jit_on": {
      "cli": {"pass": $(count "$R1" cli PASS), "fail": $(count "$R1" cli FAIL), "skip": $(count "$R1" cli SKIP)},
      "fpm": {"pass": $(count "$R1" fpm PASS), "fail": $(count "$R1" fpm FAIL), "skip": $(count "$R1" fpm SKIP)}
    },
    "same_counts": $SAME
  }
}
EOF
cat "$OUT/jit-$MINOR.json"
