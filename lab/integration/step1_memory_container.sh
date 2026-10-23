#!/bin/sh
# STEP 1 decisive-gate measurement (runs INSIDE a howdah-dev-php<ver> image).
#
# Stock PHP config: memory_limit=128M, post_max_size=8M, max_input_vars=1000,
# max_file_uploads=20. Measures peak worker RSS (/proc/PID/status VmHWM, which
# survives the zend_bailout) for a PHP2Shell-SHAPED request (structure only:
# many empty parts), (a) undefended baseline and (b) Howdah at DEFAULT limits.
# Tests BOTH shapes: file parts (FILE_START / max_file_uploads) and form fields
# (FORMDATA / max_input_vars) to find whether PHP's own caps gate the callback.
#
# Arg1: cargo feature (php5|php7|php8). Output: TSV lines on stdout.
set -eu
FEATURE="${1:-php7}"
WORK=/tmp/step1; LOG=/tmp/step1/events.log
rm -rf "$WORK"; mkdir -p "$WORK"; : > "$LOG"

export CARGO_TARGET_DIR=/tmp/t
cd /src
echo "== building howdah-ext ($FEATURE) ==" >&2
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -2 >&2
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
PHPVER=$(php -r 'echo PHP_VERSION;')

printf '<?php $n=count($_FILES)+count($_POST); echo "OK n=$n\n";' > "$WORK/index.php"

# body generator: $1=outfile $2=boundary $3=count $4=kind(file|field)
gen() {
  php -r '
    $f=fopen($argv[1],"w"); $b=$argv[2]; $n=(int)$argv[3]; $k=$argv[4];
    for($i=0;$i<$n;$i++){
      fwrite($f,"--$b\r\n");
      if($k=="file"){ fwrite($f,"Content-Disposition: form-data; name=\"f$i\"; filename=\"f$i.bin\"\r\n\r\n\r\n"); }
      else { fwrite($f,"Content-Disposition: form-data; name=\"f$i\"\r\n\r\n\r\n"); }
    }
    fwrite($f,"--$b--\r\n"); fclose($f);
  ' "$1" "$2" "$3" "$4"
}

STOCK="-d memory_limit=128M -d post_max_size=8M -d upload_max_filesize=2M -d max_input_vars=1000 -d max_file_uploads=20"

# start_server <port> <extra-ini...>; sets SRVPID
start_server() {
  _port=$1; shift
  # shellcheck disable=SC2086
  php $STOCK "$@" -S "127.0.0.1:$_port" "$WORK/index.php" > "$WORK/srv.$_port.log" 2>&1 &
  SRVPID=$!
  _j=0
  while ! curl -s -o /dev/null "http://127.0.0.1:$_port/" 2>/dev/null; do
    _j=$((_j+1)); [ "$_j" -gt 50 ] && { echo "server $_port down" >&2; cat "$WORK/srv.$_port.log" >&2; exit 1; }
    sleep 0.1
  done
}
vmhwm() { awk '/VmHWM/{print $2}' "/proc/$1/status"; }  # KB
stop_server() { kill "$SRVPID" 2>/dev/null || true; wait "$SRVPID" 2>/dev/null || true; }

# measure <label> <defended 0|1> <kind> <count>
measure() {
  _label=$1; _def=$2; _kind=$3; _n=$4
  _bnd="StepB0"
  gen "$WORK/body.bin" "$_bnd" "$_n" "$_kind"
  _sz=$(wc -c < "$WORK/body.bin")
  : > "$LOG"
  if [ "$_def" = 1 ]; then
    # Howdah at DEFAULT limits (empty toml => defaults), block mode.
    printf 'mode="block"\n' > "$WORK/def.toml"
    start_server 8080 -d extension="$WORK/howdah.so" -d howdah.config="$WORK/def.toml" -d howdah.log="$LOG"
  else
    start_server 8080
  fi
  _hwm0=$(vmhwm "$SRVPID")
  _code=$(curl -s -o "$WORK/resp.txt" -w '%{http_code}' -X POST \
      -H "Content-Type: multipart/form-data; boundary=$_bnd" \
      --data-binary @"$WORK/body.bin" "http://127.0.0.1:8080/" || echo 000)
  _hwm1=$(vmhwm "$SRVPID")
  _files=$(sed -n 's/.*OK n=\([0-9]*\).*/\1/p' "$WORK/resp.txt")
  _rule=$(sed -n 's/.*"rule":"\([a-z_]*\)".*/\1/p' "$LOG" | head -1)
  _action=$(sed -n 's/.*"action":"\([a-z]*\)".*/\1/p' "$LOG" | head -1)
  stop_server
  # TSV: ver label defended kind count bodybytes http seen_n hwm0_kb hwm1_kb rule action
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$PHPVER" "$_label" "$_def" "$_kind" "$_n" "$_sz" "$_code" "${_files:-NA}" \
    "${_hwm0:-NA}" "${_hwm1:-NA}" "${_rule:-none}" "${_action:-none}"
}

printf 'phpver\tlabel\tdef\tkind\tcount\tbodybytes\thttp\tseen_n\thwm0kb\thwm1kb\trule\taction\n'
# Baseline attack curve (no ext) - how far can N drive memory within 8M post_max?
for n in 1000 5000 20000 50000; do measure base_file 0 file "$n"; done
for n in 1000 5000 20000 50000; do measure base_field 0 field "$n"; done
# Defended at DEFAULTS - must BLOCK and keep RSS well under 128M (131072 KB).
for n in 5000 50000; do measure def_file 1 file "$n"; done
for n in 5000 50000; do measure def_field 1 field "$n"; done
echo "== done ==" >&2
