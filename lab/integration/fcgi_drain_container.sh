#!/bin/sh
# In-container half of the fcgi_drain lab (see fcgi_drain.sh): php-fpm (ONE worker)
# behind the nginx sidecar on 127.0.0.1:8080 with a kept-alive FastCGI upstream.
#
# Mechanism claim validated, and no more: "Howdah drains the unread request body
# at teardown, removing the leftover-body precondition CVE-2026-129289 requires on
# reused FastCGI connections." Bodies are benign padding ('A' runs, random binary
# file bytes, form fields). No FastCGI framing is crafted and no directives are
# injected: the drain-off arm shows the connection DESYNC the leftover bytes cause,
# which is the precondition the drain removes.
#
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; APP=$WORK/app; LOG=$WORK/events.log; OUT=/out
URL=http://127.0.0.1:8080
ROUNDS=8
mkdir -p "$APP"; : > "$LOG"; : > "$RESULTS"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=fpm-nginx
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$1" "$2" "$3" "$4" >> "$RESULTS"; echo "  [$PHPVER $1] $2 $3: $4" >&2; }

echo "== [$PHPVER] building howdah-ext ($FEATURE) ==" >&2
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record $S build FAIL "cargo build failed"; exit 1
fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

# ---- app: scripts that handle (or ignore) the body in different ways ---------
cat > "$APP/next.php" <<'PHP'
<?php echo "NEXT-OK ", isset($_GET['id']) ? $_GET['id'] : '?', "\n";
PHP
# opens php://input but never reads it: the condition PHP's own drain skips.
cat > "$APP/unread.php" <<'PHP'
<?php $h = fopen('php://input', 'rb'); fread($h, 16); echo "UNREAD-DONE\n";
PHP
cat > "$APP/unread0.php" <<'PHP'
<?php $h = fopen('php://input', 'rb'); echo "UNREAD0-DONE\n";
PHP
cat > "$APP/full.php" <<'PHP'
<?php echo "FULL len=", strlen(file_get_contents('php://input')), "\n";
PHP
cat > "$APP/ignore.php" <<'PHP'
<?php echo "IGNORE-DONE\n";
PHP
cat > "$APP/finish.php" <<'PHP'
<?php $h = fopen('php://input', 'rb'); fread($h, 16); echo "FINISH-DONE\n";
if (function_exists('fastcgi_finish_request')) { fastcgi_finish_request(); }
usleep(50000);
PHP
cat > "$APP/upload.php" <<'PHP'
<?php
$o = array();
foreach ($_FILES as $k => $f) { $o[] = $k . ':' . $f['error'] . ':' . $f['size'] . ':' . md5_file($f['tmp_name']); }
echo "UPLOAD post=", count($_POST), " files=", implode(',', $o), "\n";
PHP
cat > "$APP/form.php" <<'PHP'
<?php echo "FORM post=", count($_POST), " bytes=", strlen(implode('', $_POST)), "\n";
PHP

# ---- benign fixtures (padding / random binary only) ---------------------------
head -c 700000 /dev/zero | tr '\0' 'A' > "$WORK/pad700k.bin"
head -c 300000 /dev/urandom > "$WORK/rand300k.bin"
head -c 3000000 /dev/urandom > "$WORK/rand3m.bin"
{ printf 'a='; head -c 600000 /dev/zero | tr '\0' 'x'; } > "$WORK/bigform.bin"
printf '{"k":"%s"}' "$(head -c 200000 /dev/zero | tr '\0' 'j')" > "$WORK/big.json"
# multipart: a binary file + a text field; and a big multi-field form.
{ printf -- '--BND\r\nContent-Disposition: form-data; name="f"; filename="r.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
  cat "$WORK/rand300k.bin"; printf '\r\n--BND\r\nContent-Disposition: form-data; name="t"\r\n\r\nhello\r\n--BND--\r\n'; } > "$WORK/mp_bin.bin"
{ printf -- '--BND\r\nContent-Disposition: form-data; name="f"; filename="r3.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'
  cat "$WORK/rand3m.bin"; printf '\r\n--BND--\r\n'; } > "$WORK/mp_3m.bin"
{ i=0; while [ $i -lt 400 ]; do printf -- '--BND\r\nContent-Disposition: form-data; name="f%s"\r\n\r\n' $i; head -c 1000 /dev/zero | tr '\0' 'v'; printf '\r\n'; i=$((i+1)); done; printf -- '--BND--\r\n'; } > "$WORK/mp_forms.bin"
# a MALFORMED but benign multipart (no Content-Disposition) holding random file bytes:
{ printf -- '--BND\r\nX-Junk: 1\r\n\r\n'; cat "$WORK/rand300k.bin"; printf '\r\n--BND--\r\n'; } > "$WORK/mp_malformed.bin"

RAISED="-d post_max_size=64M -d memory_limit=256M"
FPMPID=""
fpm_start() {
  cat > "$WORK/fpm.conf" <<EOT
[global]
error_log = $OUT/fpm.err
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 1
user = root
group = root
catch_workers_output = yes
EOT
  # shellcheck disable=SC2086
  php-fpm -R -F -y "$WORK/fpm.conf" $RAISED -d extension="$WORK/howdah.so" -d howdah.log="$LOG" "$@" > "$WORK/fpm.out" 2>&1 &
  FPMPID=$!; _j=0
  while [ "$(curl -s -m 2 -o /dev/null -w '%{http_code}' "$URL/next.php?id=ready" 2>/dev/null)" != 200 ]; do
    _j=$((_j+1)); [ "$_j" -gt 100 ] && { echo "php-fpm/nginx never answered 200" >&2; cat "$WORK/fpm.out" >&2; return 1; }; sleep 0.1
  done
}
fpm_stop() { [ -n "$FPMPID" ] && kill "$FPMPID" 2>/dev/null; wait "$FPMPID" 2>/dev/null; FPMPID=""; }
reset() { : > "$LOG"; }
cat > "$WORK/off.toml" <<'EOT'
drain_unread_body = false
EOT
cat > "$WORK/block.toml" <<'EOT'
[rules]
fastcgi_smuggle = "block"
EOT

B="$WORK/resp.txt"
# rounds <script> <content-type> <bodyfile>: POST the body, then ordinary GETs on
# the kept-alive upstream. Sets BAD (rounds whose POST or follow-up was wrong).
BAD=0; POSTBAD=0; NEXTBAD=0
rounds() {
  BAD=0; POSTBAD=0; NEXTBAD=0; r=1
  while [ $r -le $ROUNDS ]; do
    pc=$(curl -s -m 20 -o "$B" -w '%{http_code}' -X POST -H "Content-Type: $2" --data-binary @"$3" "$URL/$1" 2>/dev/null || echo 000)
    # Two ordinary follow-ups: the first rides the connection the POST left.
    nb=0
    for k in a b; do
      nc=$(curl -s -m 20 -o "$B" -w '%{http_code}' "$URL/next.php?id=$r$k" 2>/dev/null || echo 000)
      if [ "$nc" != 200 ] || [ "$(cat "$B")" != "NEXT-OK $r$k" ]; then nb=1; fi
    done
    [ "$pc" = 200 ] || POSTBAD=$((POSTBAD+1))
    [ $nb = 0 ] || NEXTBAD=$((NEXTBAD+1))
    r=$((r+1))
  done
  BAD=$((POSTBAD+NEXTBAD))
}
# benign <name> <script> <ct> <file>: drain ON, zero bad rounds, no smuggle/block line.
benign() {
  reset; rounds "$2" "$3" "$4"
  hits=$(grep -c '"action":"block"\|fastcgi_smuggle' "$LOG")
  if [ "$BAD" = 0 ] && [ "$hits" = 0 ]; then
    record $S "$1" PASS "$ROUNDS/$ROUNDS rounds: POST 200 + next request correct, worker alive, no block/fastcgi_smuggle line"
  else record $S "$1" FAIL "postbad=$POSTBAD nextbad=$NEXTBAD loglines=$hits $(tr -d '\n' < "$LOG" | head -c 160)"; fi
}

# ---- drain ON (default) -------------------------------------------------------
fpm_start || { record $S fpm_start FAIL down; exit 1; }
benign unread_php_input   unread.php  application/octet-stream "$WORK/pad700k.bin"
benign unread0_php_input  unread0.php application/octet-stream "$WORK/pad700k.bin"
benign unread_multipart_ct unread.php "multipart/form-data; boundary=BND" "$WORK/pad700k.bin"
benign unread_urlencoded  unread.php  application/x-www-form-urlencoded "$WORK/bigform.bin"
benign body_read_fully    full.php    application/octet-stream "$WORK/pad700k.bin"
benign body_ignored       ignore.php  application/octet-stream "$WORK/pad700k.bin"
# fastcgi_finish_request: some PHP/fpm builds (5.6) drop the kept-alive upstream
# connection after it REGARDLESS of the body (an empty-body control fails too), which
# nginx (no retry here) reports as 502. That is a quirk independent of the drain, so
# it is recorded INFO rather than blamed on the body.
reset; : > "$WORK/empty.bin"; rounds finish.php application/octet-stream "$WORK/empty.bin"
if [ "$BAD" -gt 0 ]; then
  record $S finish_request INFO "this fpm breaks the kept-alive connection after fastcgi_finish_request even with an EMPTY body ($NEXTBAD/$ROUNDS); body-independent quirk, not exercised"
else
  benign finish_request     finish.php  application/octet-stream "$WORK/pad700k.bin"
fi
benign upload_binary_300k upload.php  "multipart/form-data; boundary=BND" "$WORK/mp_bin.bin"
benign upload_binary_3m   upload.php  "multipart/form-data; boundary=BND" "$WORK/mp_3m.bin"
benign multipart_400_fields form.php  "multipart/form-data; boundary=BND" "$WORK/mp_forms.bin"
benign malformed_multipart_binary upload.php "multipart/form-data; boundary=BND" "$WORK/mp_malformed.bin"
benign urlencoded_600k    form.php    application/x-www-form-urlencoded "$WORK/bigform.bin"
benign json_200k          full.php    application/json "$WORK/big.json"
# upload integrity: the md5 PHP computed equals the file we sent.
reset; curl -s -m 30 -o "$B" -X POST -H "Content-Type: multipart/form-data; boundary=BND" --data-binary @"$WORK/mp_bin.bin" "$URL/upload.php"
want=$(md5sum < "$WORK/rand300k.bin" | cut -d' ' -f1)
if grep -q "f:0:300000:$want" "$B"; then record $S upload_integrity PASS "binary upload size+md5 intact through Howdah"; else record $S upload_integrity FAIL "$(head -c 120 "$B")"; fi
fpm_stop

# ---- the same benign corpus with fastcgi_smuggle = "block" (opt-in posture) ----
fpm_start -d howdah.config="$WORK/block.toml" || { record $S block_start FAIL down; exit 1; }
for spec in "upload.php|multipart/form-data; boundary=BND|$WORK/mp_bin.bin" "upload.php|multipart/form-data; boundary=BND|$WORK/mp_3m.bin" \
            "form.php|multipart/form-data; boundary=BND|$WORK/mp_forms.bin" "upload.php|multipart/form-data; boundary=BND|$WORK/mp_malformed.bin" \
            "full.php|application/json|$WORK/big.json" "form.php|application/x-www-form-urlencoded|$WORK/bigform.bin" "unread.php|application/octet-stream|$WORK/pad700k.bin"; do
  sc=${spec%%|*}; rest=${spec#*|}; ct=${rest%%|*}; fl=${rest#*|}
  benign "blockmode_$(basename "$fl" .bin)_$sc" "$sc" "$ct" "$fl"
done
fpm_stop

# ---- drain OFF: the leftover-bytes precondition remains ------------------------
fpm_start -d howdah.config="$WORK/off.toml" || { record $S off_start FAIL down; exit 1; }
reset; rounds unread.php application/octet-stream "$WORK/pad700k.bin"
if [ "$NEXTBAD" -gt 0 ]; then
  record $S drain_off_unread PASS "leftover body desynced the kept-alive connection: $NEXTBAD/$ROUNDS rounds got a bad next response (drain on: 0/$ROUNDS)"
else
  record $S drain_off_unread INFO "no desync observed with drain off ($ROUNDS rounds): this PHP drains the body itself, so the drain is a harmless no-op here"
fi
reset; rounds full.php application/octet-stream "$WORK/pad700k.bin"
if [ "$BAD" = 0 ]; then record $S drain_off_body_read PASS "control: script reads the body, no desync even with drain off"; else record $S drain_off_body_read FAIL "bad=$BAD"; fi
fpm_stop

# ---- drain OFF / ON probes of the other "PHP leaves the body unread" shapes -----
# PHP stops reading (and so skips its own drain) in other cases too: a body over
# post_max_size, and enable_post_data_reading=0 with a script that never opens
# php://input. Same benign padding; same next-request-correct oracle.
probe() { # <label> <toml-or-empty> <script> <ct> <file> <ini...>
  lbl=$1; tm=$2; sc=$3; ct=$4; fl=$5; shift 5
  if [ -n "$tm" ]; then fpm_start -d howdah.config="$tm" "$@" || { record $S "${lbl}_start" FAIL down; return; }
  else fpm_start "$@" || { record $S "${lbl}_start" FAIL down; return; }; fi
  reset; rounds "$sc" "$ct" "$fl"; fpm_stop
  echo "$lbl $POSTBAD $NEXTBAD"
}
for shape in "oversize_urlencoded|ignore.php|application/x-www-form-urlencoded|$WORK/bigform.bin|-d post_max_size=100K" \
             "oversize_multipart|upload.php|multipart/form-data; boundary=BND|$WORK/mp_3m.bin|-d post_max_size=100K" \
             "no_post_data_reading|ignore.php|application/octet-stream|$WORK/pad700k.bin|-d enable_post_data_reading=0"; do
  nm=${shape%%|*}; r1=${shape#*|}; sc=${r1%%|*}; r2=${r1#*|}; ct=${r2%%|*}; r3=${r2#*|}; fl=${r3%%|*}; ini=${r3#*|}
  # shellcheck disable=SC2086
  off=$(probe "off_$nm" "$WORK/off.toml" "$sc" "$ct" "$fl" $ini | tail -n 1)
  # shellcheck disable=SC2086
  on=$(probe "on_$nm" "" "$sc" "$ct" "$fl" $ini | tail -n 1)
  offbad=$(echo "$off" | awk '{print $3}'); onbad=$(echo "$on" | awk '{print $3}')
  if [ "$onbad" = 0 ] && [ "${offbad:-0}" -gt 0 ]; then
    record $S "drain_probe_$nm" PASS "drain OFF: $offbad/$ROUNDS rounds desynced (leftover bytes); drain ON: 0/$ROUNDS"
  elif [ "$onbad" != 0 ] && [ "$(php -r 'echo PHP_VERSION_ID < 50500 ? 1 : 0;')" = 1 ]; then
    record $S "drain_probe_$nm" INFO "PHP <5.5: no SG(post_read), the drain is a compiled-out no-op; native desync ($onbad/$ROUNDS) is NOT mitigated there (5.4 predates the CVE)"
  elif [ "$onbad" = 0 ]; then
    record $S "drain_probe_$nm" INFO "no desync even with drain off (PHP/fpm consumed the body itself); drain ON: 0/$ROUNDS"
  else record $S "drain_probe_$nm" FAIL "drain ON still desynced: $onbad/$ROUNDS (off=$offbad)"; fi
done
echo "== [$PHPVER] fcgi_drain rows done ==" >&2
