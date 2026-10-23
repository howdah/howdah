#!/bin/sh
# STEP 1b: the raised-cap scenario -- the REAL memory-exhaustion exposure.
# When an admin raises PHP's own caps (max_input_vars / max_file_uploads), the
# rfc1867 callback fires unbounded and the flood CAN climb toward memory_limit.
# This proves (a) undefended peak climbs with N toward 128M, and (b) Howdah at
# DEFAULT limits BLOCKS with peak pinned a few MB above baseline.
# Stock post_max_size stays 8M (the attacker's body budget); caps are raised.
set -eu
FEATURE="${1:-php7}"
WORK=/tmp/step1b; LOG=/tmp/step1b/events.log
rm -rf "$WORK"; mkdir -p "$WORK"; : > "$LOG"
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -1 >&2
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
PHPVER=$(php -r 'echo PHP_VERSION;')
printf '<?php $n=count($_FILES)+count($_POST); echo "OK n=$n\n";' > "$WORK/index.php"
gen() {
  php -r '
    $f=fopen($argv[1],"w"); $b=$argv[2]; $n=(int)$argv[3]; $k=$argv[4];
    for($i=0;$i<$n;$i++){ fwrite($f,"--$b\r\n");
      if($k=="file"){ fwrite($f,"Content-Disposition: form-data; name=\"f$i\"; filename=\"f$i.bin\"\r\n\r\n\r\n"); }
      else { fwrite($f,"Content-Disposition: form-data; name=\"f$i\"\r\n\r\n\r\n"); } }
    fwrite($f,"--$b--\r\n"); fclose($f);' "$1" "$2" "$3" "$4"
}
# RAISED caps; post_max_size 8M stays (attacker body budget). memory_limit 512M
# on baseline so we can watch the climb; 128M (stock) on the defended runs.
RAISED="-d max_input_vars=10000000 -d max_file_uploads=10000000 -d post_max_size=8M -d upload_max_filesize=8M"
start_server() { _port=$1; shift
  # shellcheck disable=SC2086
  php $RAISED "$@" -S "127.0.0.1:$_port" "$WORK/index.php" > "$WORK/srv.$_port.log" 2>&1 &
  SRVPID=$!; _j=0
  while ! curl -s -o /dev/null "http://127.0.0.1:$_port/" 2>/dev/null; do
    _j=$((_j+1)); [ "$_j" -gt 50 ] && { echo "down" >&2; cat "$WORK/srv.$_port.log" >&2; exit 1; }; sleep 0.1; done
}
vmhwm() { awk '/VmHWM/{print $2}' "/proc/$1/status"; }
stop_server() { kill "$SRVPID" 2>/dev/null || true; wait "$SRVPID" 2>/dev/null || true; }
measure() { _label=$1; _def=$2; _kind=$3; _n=$4; _bnd="StepB0"
  gen "$WORK/body.bin" "$_bnd" "$_n" "$_kind"; _sz=$(wc -c < "$WORK/body.bin"); : > "$LOG"
  if [ "$_def" = 1 ]; then printf 'mode="block"\n' > "$WORK/def.toml"
    start_server 8080 -d memory_limit=128M -d extension="$WORK/howdah.so" -d howdah.config="$WORK/def.toml" -d howdah.log="$LOG"
  else start_server 8080 -d memory_limit=512M; fi
  _hwm0=$(vmhwm "$SRVPID")
  _code=$(curl -s -o "$WORK/resp.txt" -w '%{http_code}' -X POST \
    -H "Content-Type: multipart/form-data; boundary=$_bnd" --data-binary @"$WORK/body.bin" "http://127.0.0.1:8080/" || echo 000)
  _hwm1=$(vmhwm "$SRVPID")
  _files=$(sed -n 's/.*OK n=\([0-9]*\).*/\1/p' "$WORK/resp.txt")
  _rule=$(sed -n 's/.*"rule":"\([a-z_]*\)".*/\1/p' "$LOG" | head -1)
  _action=$(sed -n 's/.*"action":"\([a-z]*\)".*/\1/p' "$LOG" | head -1)
  stop_server
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$_label" "$_def" "$_kind" "$_n" "$_sz" "$_code" "${_files:-NA}" "${_hwm0:-NA}" "${_hwm1:-NA}" "${_rule:-none}" "${_action:-none}"
}
printf 'phpver\tlabel\tdef\tkind\tcount\tbodybytes\thttp\tseen_n\thwm0kb\thwm1kb\trule\taction\n'
# Undefended, raised caps: watch peak climb with N (memory_limit 512M).
for n in 20000 50000 90000; do measure raised_base_field 0 field "$n"; done
for n in 20000 50000 90000; do measure raised_base_file 0 file "$n"; done
# Defended at DEFAULTS, raised caps, stock 128M memory_limit: must BLOCK, peak low.
measure raised_def_field 1 field 90000
measure raised_def_file  1 file  90000
echo "== done ==" >&2
