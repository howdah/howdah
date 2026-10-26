#!/bin/sh
# In-container half of the T5 file-guards integration test (see file_guard.sh).
# Builds the real extension, writes HARMLESS-SHAPE fixtures only (files whose
# only content is a comment marker), runs php with a [behavior] config and asserts
# on rule-id strings, file survival and HTTP status. Target paths and file
# content are never asserted into, and never logged.
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-t5
LOG="$WORK/events.log"
WWW="$WORK/www"
APP="$WWW/app"
UP="$WWW/uploads"
LEAK="$WWW/t5leakdir"
rm -rf "$WORK"; mkdir -p "$APP"

VER=$(php -r 'echo PHP_VERSION;')
echo "== php $VER / building howdah-ext ($FEATURE) =="
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -3
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
cd "$WORK"

SRV=""
stop_server() {
  if [ -n "$SRV" ]; then kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; fi
  SRV=""
}
cleanup() {
  stop_server
  rm -rf /etc/howdah-t5-fixture /etc/howdah-t5-dir
}
trap 'cleanup' EXIT

PASSN=0
N_DEL_BLOCK=0; N_DEL_OK=0; N_DEL_FP=0
N_UP_BLOCK=0;  N_UP_OK=0;  N_UP_FP=0
N_SC_BLOCK=0;  N_SC_OK=0;  N_SC_FP=0
N_RD_LOG=0;    N_RD_OK=0;  N_RD_FP=0

fail() {
  echo "FAIL: $1"
  echo "--- stdout ---"; cat "$WORK/out.txt" 2>/dev/null
  echo "--- stderr ---"; cat "$WORK/err.txt" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  echo "--- server log ---"; cat "$WORK/server.log" 2>/dev/null
  exit 1
}
ok() { PASSN=$((PASSN+1)); echo "  ok   - $1"; }

has_rule() { grep -q "\"rule\":\"$1\"" "$LOG"; }
no_rule() { ! grep -q "\"rule\":\"$1\"" "$LOG"; }
no_blocks() { ! grep -q '"action":"block"' "$LOG"; }
# "No T5 finding and no block" (other layers' log-only lines are ignored).
no_t5() { ! grep -qE '"rule":"(file_delete|secret_read|php_write)"|"action":"block"' "$LOG"; }
out_has() { grep -q "$1" "$WORK/out.txt"; }
lineof() { grep -n "$1" "$2" | head -1 | cut -d: -f1; }

# run_script <toml> <script> [extra -d args...]: CLI run; stdout -> out.txt.
run_script() {
  printf '%b' "$1" > "$WORK/t5.toml"
  _file="$2"; shift 2
  : > "$LOG"
  php -d extension="$WORK/howdah.so" \
      -d howdah.config="$WORK/t5.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      "$@" "$_file" > "$WORK/out.txt" 2>"$WORK/err.txt" || true
}

PORT=18200
start_server() {
  stop_server
  printf '%b' "$1" > "$WORK/t5.toml"
  : > "$LOG"
  PORT=$((PORT+1))
  php -d extension="$WORK/howdah.so" \
      -d howdah.config="$WORK/t5.toml" -d howdah.log="$LOG" \
      -d display_errors=1 -d error_reporting=-1 -d date.timezone=UTC \
      -S "127.0.0.1:$PORT" -t "$WWW" > "$WORK/server.log" 2>&1 &
  SRV=$!
  _j=0
  until curl -s -o /dev/null "http://127.0.0.1:$PORT/app/ping.php" 2>/dev/null; do
    _j=$((_j+1)); [ $_j -gt 80 ] && fail "built-in server did not start"
    sleep 0.1
  done
  : > "$LOG"
}

# ------------------------------------------------------------------ fixtures
HAVE_ETC=0
if [ -w /etc ]; then HAVE_ETC=1; fi

mkfix() {
  rm -rf "$UP" "$WWW/cache" "$WWW/benign" "$LEAK" "$WORK/sess" "$WWW/storage"
  mkdir -p "$UP/2026/10" "$WWW/cache/emptydir" "$WWW/benign" "$LEAK/keys" "$WORK/sess" "$WWW/storage/framework/views"
  for f in wp-config.php .env .env.production; do printf '<?php /* t5 */' > "$LEAK/$f"; done
  for f in id_rsa privkey.pem server.key; do printf 'KEY-PLACEHOLDER' > "$LEAK/keys/$f"; done
  # The ordinary things apps delete and read.
  for f in .env.example wp-config-sample.php .maintenance .htaccess cacert.pem deck.key id_rsa.pub .env.production; do
    printf 'x' > "$WWW/benign/$f"
  done
  printf 'x' > "$WWW/cache/page.html"
  printf 'x' > "$WWW/cache/a.tmp"; printf 'x' > "$WWW/cache/b.tmp"; printf 'x' > "$WWW/cache/x.tmp"
  printf 'x' > "$UP/2026/10/photo.jpg"; printf 'x' > "$UP/2026/10/photo-150x150.jpg"
  printf 'x' > "$UP/a.tmp"
  printf 'x' > "$WORK/sess/sess_abc123def"
  printf '<?php /* t5 */' > "$WWW/storage/framework/views/abc.php"
  printf '<?php return 1;' > "$WWW/config.php"
  printf '{"a":1}' > "$WWW/data.json"
  printf 'body{}' > "$WWW/style.css"
  printf 'x' > "$WORK/payload.txt"
  printf '<?php /* t5 */' > "$WORK/src.txt"
  if [ "$HAVE_ETC" = 1 ]; then
    printf 'x' > /etc/howdah-t5-fixture
    mkdir -p /etc/howdah-t5-dir
  fi
}
mkfix

# 9 `..` segments climb out of any depth here (extra ones at / are no-ops).
UPS='../../../../../../../../..'
TRAV_FILE="$UP/2026/$UPS/etc/howdah-t5-fixture"
TRAV_DIR="$UP/2026/$UPS/etc/howdah-t5-dir"

cat > "$APP/ping.php" <<'PHPEOF'
<?php
echo "PONG\n";
PHPEOF

# ====================================================== 1. DELETE GUARD (L4)
cat > "$APP/del.php" <<'PHPEOF'
<?php
$op = getenv('OP'); $t = getenv('T'); $t2 = getenv('T2');
if ($op === 'unlink') { $r = @unlink($t); }
elseif ($op === 'rmdir') { $r = @rmdir($t); }
elseif ($op === 'rename') { $r = @rename($t, $t2); }
elseif ($op === 'cuf') { $r = @call_user_func('unlink', $t); }
echo "RET[" . var_export($r, true) . "]\n";
echo "DONE\n";
PHPEOF
DELPHP="$APP/del.php"
# The shipped posture: global detect, [behavior] untouched. The guard is
# enforced by ITS OWN default (block), independent of every mode.
TOML_DEFAULT='mode = "detect"\n'

# blocked_del <label> <op> <target> [rename-target]
blocked_del() {
  _label=$1; _op=$2; _t=$3; _t2=${4:-}
  export OP="$_op" T="$_t" T2="$_t2"
  run_script "$TOML_DEFAULT" "$DELPHP"
  out_has 'RET\[false\]' || fail "delete $_label: the call was not refused"
  out_has DONE || fail "delete $_label: script did not continue after the refusal"
  [ -e "$_t" ] || fail "delete $_label: target is gone (sink was not neutralized)"
  if [ -n "$_t2" ] && [ -e "$_t2" ]; then fail "delete $_label: rename target was created"; fi
  has_rule file_delete || fail "delete $_label: no file_delete event"
  grep -q '"action":"block"' "$LOG" || fail "delete $_label: no action:block"
  grep -q '"layer":4' "$LOG" || fail "delete $_label: not a layer-4 line"
  case "$_op" in cuf) _ln=$(lineof "call_user_func('unlink'" "$DELPHP") ;; *) _ln=$(lineof "@$_op(" "$DELPHP") ;; esac
  grep -F '"rule":"file_delete"' "$LOG" | grep -qF "$DELPHP:$_ln" || fail "delete $_label: origin $DELPHP:$_ln not in the log line"
  _base=$(basename "$_t")
  if grep -qF "$_base" "$LOG"; then fail "delete $_label: the target name leaked into the log"; fi
  if grep -q 't5leakdir' "$LOG"; then fail "delete $_label: the target directory leaked into the log"; fi
  N_DEL_BLOCK=$((N_DEL_BLOCK+1))
  ok "delete $_label: refused ($_op returned false), target survived, script continued, file_delete/block @ del.php:$_ln"
}

blocked_del "unlink wp-config.php"            unlink "$LEAK/wp-config.php"
blocked_del "unlink .env"                     unlink "$LEAK/.env"
blocked_del "unlink .env.production"          unlink "$LEAK/.env.production"
blocked_del "unlink id_rsa (key material)"    unlink "$LEAK/keys/id_rsa"
blocked_del "unlink privkey.pem"              unlink "$LEAK/keys/privkey.pem"
blocked_del "unlink server.key"               unlink "$LEAK/keys/server.key"
blocked_del "unlink via uploads/../ traversal to wp-config.php" unlink "$UP/../t5leakdir/wp-config.php"
blocked_del "call_user_func('unlink') wp-config.php" cuf "$LEAK/wp-config.php"
blocked_del "rename wp-config.php away"       rename "$LEAK/wp-config.php" "$LEAK/wp-config.bak"
blocked_del "rename .env away"                rename "$LEAK/.env" "$LEAK/.env.bak"
if [ "$HAVE_ETC" = 1 ]; then
  blocked_del "unlink traversal into /etc"    unlink "$TRAV_FILE"
  blocked_del "rmdir traversal into /etc"     rmdir "$TRAV_DIR"
  grep -q 'system directory' "$LOG" || fail "delete traversal: category not named"
else
  echo "  note - /etc not writable: traversal fixtures skipped"
fi

# --- the category is named, but the file name is not
export OP=unlink T="$LEAK/wp-config.php" T2=""
run_script "$TOML_DEFAULT" "$DELPHP"
grep -q 'wp-config file' "$LOG" || fail "delete: wp-config category not named in the reason"
export T="$LEAK/.env"
run_script "$TOML_DEFAULT" "$DELPHP"
grep -q 'dotenv file' "$LOG" || fail "delete: dotenv category not named in the reason"
ok "delete reasons name only a category (wp-config / dotenv), never the file"

# --- modes: detect / observe / off / master switches / exception
mkfix
export OP=unlink T="$LEAK/wp-config.php" T2=""
run_script 'mode = "detect"\n[behavior]\ndelete_guard = "detect"\n' "$DELPHP"
out_has 'RET\[true\]' || fail "delete_guard=detect: the delete should proceed"
[ ! -e "$T" ] || fail "delete_guard=detect: file should be gone"
has_rule file_delete || fail "delete_guard=detect: no file_delete event"
grep -q '"action":"log"' "$LOG" || fail "delete_guard=detect: expected action:log"
no_blocks || fail "delete_guard=detect: produced a block"
ok "delete_guard=\"detect\": logged (action:log), delete proceeded, zero blocks"
mkfix
run_script 'mode = "detect"\n[behavior]\nobserve = true\n' "$DELPHP"
out_has 'RET\[true\]' || fail "observe: the delete should proceed"
grep -q 'proposed:' "$LOG" || fail "observe: no proposed line"
no_blocks || fail "observe: produced a block"
ok "[behavior] observe=true: file_delete is a PROPOSAL (delete proceeded, zero blocks)"
mkfix
run_script 'mode = "detect"\n[behavior]\ndelete_guard = "off"\n' "$DELPHP"
out_has 'RET\[true\]' || fail "delete_guard=off: the delete should proceed"
no_t5 || fail "delete_guard=off: an event was produced"
mkfix
run_script 'mode = "off"\n' "$DELPHP"
out_has 'RET\[true\]' || fail "global off: the delete should proceed"
no_t5 || fail "global off: an event was produced"
mkfix
run_script 'mode = "detect"\n[behavior]\nmode = "off"\n' "$DELPHP"
out_has 'RET\[true\]' || fail "[behavior] mode=off: the delete should proceed"
no_t5 || fail "[behavior] mode=off: an event was produced"
ok "delete_guard=\"off\", global mode=off and [behavior] mode=off each switch the guard off cleanly"
# Exception by executing script (a migration tool legitimately moves wp-config.php).
mkdir -p "$APP/migrate"; cp "$DELPHP" "$APP/migrate/del.php"
EXC='mode = "detect"\n[[exceptions]]\nrule = "behavior.file_delete"\nscript = "'"$APP"'/migrate/**"\nreason = "migration installer (lab)"\n'
mkfix
run_script "$EXC" "$APP/migrate/del.php"
out_has 'RET\[true\]' || fail "exception: excepted script should be allowed"
no_t5 || fail "exception: excepted script produced an event"
mkfix
run_script "$EXC" "$DELPHP"
out_has 'RET\[false\]' || fail "exception: a different script must still be blocked"
ok "[[exceptions]] rule=behavior.file_delete scoped to a script: that script passes, others are still refused"

# --- the BENIGN delete corpus: ZERO blocks, every delete really happens
cat > "$APP/benign_del.php" <<'PHPEOF'
<?php
$w = getenv('WWW'); $ok = 0; $n = 0;
function t($label, $r) { global $ok, $n; $n++; if ($r) { $ok++; } else { echo "FAILED[" . $label . "]\n"; } }
t('cache page',    @unlink($w . '/cache/page.html'));
$tmp = tempnam(sys_get_temp_dir(), 'php'); t('tempnam', @unlink($tmp));
t('session file',  @unlink(getenv('WORK') . '/sess/sess_abc123def'));
t('upload',        @unlink($w . '/uploads/2026/10/photo.jpg'));
t('thumbnail',     @unlink($w . '/uploads/2026/10/photo-150x150.jpg'));
t('.env.example',  @unlink($w . '/benign/.env.example'));
t('wp-config-sample.php', @unlink($w . '/benign/wp-config-sample.php'));
t('.maintenance',  @unlink($w . '/benign/.maintenance'));
t('root .htaccess', @unlink($w . '/benign/.htaccess'));
t('cacert.pem',    @unlink($w . '/benign/cacert.pem'));
t('keynote .key',  @unlink($w . '/benign/deck.key'));
t('id_rsa.pub',    @unlink($w . '/benign/id_rsa.pub'));
t('compiled view', @unlink($w . '/storage/framework/views/abc.php'));
t('internal ..',   @unlink($w . '/uploads/../cache/x.tmp'));
$g = glob($w . '/cache/[ab].tmp'); $m = array_map('unlink', $g); t('array_map glob', count($m) === 2 && $m[0] && $m[1]);
t('rmdir empty cache dir', @rmdir($w . '/cache/emptydir'));
t('rename upload tmp', @rename($w . '/uploads/a.tmp', $w . '/uploads/a.jpg'));
t('deploy .env.production -> .env', @rename($w . '/benign/.env.production', $w . '/benign/.env'));
echo "BENIGN_OK[" . $ok . "/" . $n . "]\n";
echo "DONE\n";
PHPEOF
mkfix
export WWW WORK
run_script "$TOML_DEFAULT" "$APP/benign_del.php"
out_has 'FAILED\[' && fail "benign delete corpus: a benign delete was refused"
_tot=$(sed -n 's/.*BENIGN_OK\[\([0-9]*\)\/\([0-9]*\)\].*/\1 \2/p' "$WORK/out.txt")
set -- $_tot
[ "${1:-x}" = "${2:-y}" ] && [ "${2:-0}" -ge 18 ] || fail "benign delete corpus: expected all deletes to succeed, got '$_tot'"
no_t5 || fail "benign delete corpus: a file_delete/php_write event or a block fired"
N_DEL_OK=$1
ok "BENIGN delete corpus ($1/$2: cache, tmp, session, upload, thumbnail, templates, .env.example, wp-config-sample, .htaccess, cacert.pem, Keynote .key, compiled view, internal '..', array_map(unlink), rmdir, ordinary rename, deploy .env.production->.env): all performed, ZERO blocks"

# ============================================== 2. WIDENED WRITE FACET (L4)
cat > "$APP/up.php" <<'PHPEOF'
<?php
$d = isset($_POST['d']) ? $_POST['d'] : 'none';
$dest = getenv('UP') . '/' . $d;
$ok = isset($_FILES['f']['tmp_name']) ? @move_uploaded_file($_FILES['f']['tmp_name'], $dest) : null;
echo "MOVE[" . var_export($ok, true) . "]\n";
echo "UP_DONE\n";
PHPEOF
export UP
UPLN=$(lineof 'move_uploaded_file' "$APP/up.php")

# upload <dest-basename>: a REAL multipart upload whose destination name is <name>.
upload() {
  set +e
  curl -s -o "$WORK/out.txt" -w '%{http_code}' -F "d=$1" -F "f=@$WORK/payload.txt;filename=payload.txt" \
    "http://127.0.0.1:$PORT/app/up.php" > "$WORK/code.txt"
  set -e
  CODE=$(cat "$WORK/code.txt")
}
alive() {
  set +e
  _p=$(curl -s "http://127.0.0.1:$PORT/app/ping.php")
  set -e
  [ "$_p" = "PONG" ] || fail "worker did not survive: ping returned '$_p'"
}

DANGEROUS="shell.php shell.phtml shell.pht shell.php3 shell.php4 shell.php5 shell.php7 shell.PHAR shell.Php .htaccess .user.ini web.config"
BENIGN_NAMES="photo.jpg note.txt data.json app.log archive.zip doc.pdf report.csv include.inc photo.png style.css"

# 2a. ALWAYS-ON upload tier: no config at all beyond the shipped global detect.
mkfix
start_server "$TOML_DEFAULT"
for N in $DANGEROUS; do
  upload "$N"
  [ "$CODE" = 200 ] || fail "upload $N: HTTP $CODE"
  out_has 'MOVE\[false\]' || fail "upload $N: move_uploaded_file was not refused"
  out_has UP_DONE || fail "upload $N: script did not continue"
  [ ! -e "$UP/$N" ] || fail "upload $N: the file was created despite the refusal"
  has_rule php_write || fail "upload $N: no php_write event"
  grep -q '"action":"block"' "$LOG" || fail "upload $N: no action:block"
  grep -q '"layer":4' "$LOG" || fail "upload $N: not a layer-4 line"
  grep -F '"rule":"php_write"' "$LOG" | grep -qF "$APP/up.php:$UPLN" || fail "upload $N: origin up.php:$UPLN not in the log"
  if grep -qF "$N" "$LOG"; then fail "upload $N: the file name leaked into the log"; fi
  if grep -q 'uploads' "$LOG"; then fail "upload $N: the target directory leaked into the log"; fi
  alive
  : > "$LOG"
  N_UP_BLOCK=$((N_UP_BLOCK+1))
done
ok "upload tier (default config): move_uploaded_file to $N_UP_BLOCK dangerous names (.php .phtml .pht .php3/4/5/7 .PHAR .Php .htaccess .user.ini web.config) refused, none created, php_write/block @ up.php:$UPLN, no name in the log, worker alive"
for N in $BENIGN_NAMES; do
  upload "$N"
  out_has 'MOVE\[true\]' || { N_UP_FP=$((N_UP_FP+1)); fail "benign upload $N: refused (false positive)"; }
  [ -e "$UP/$N" ] || fail "benign upload $N: file missing"
  N_UP_OK=$((N_UP_OK+1))
done
no_t5 || fail "benign uploads: a php_write event or a block fired"
ok "BENIGN uploads ($N_UP_OK: .jpg .txt .json .log .zip .pdf .csv .inc .png .css): all moved into place, ZERO events, ZERO blocks"
# The plain write sinks are NOT blocked by default (WordPress rewrites .htaccess, Blade/Twig compile .php).
cat > "$APP/write_set.php" <<'PHPEOF'
<?php
$how = getenv('HOW'); $dir = getenv('DIR'); $marker = '<?php /* howdah-t5-test */';
foreach (explode(',', getenv('NAMES')) as $n) {
    $t = $dir . '/' . $n;
    if ($how === 'fpc') { $r = @file_put_contents($t, $marker); }
    elseif ($how === 'fopen') { $h = @fopen($t, 'w'); $r = $h; if ($h) { fwrite($h, $marker); fclose($h); } }
    elseif ($how === 'copy') { $r = @copy(getenv('SRC'), $t); }
    else { $s = getenv('WORK') . '/mv-' . md5($n); file_put_contents($s, $marker); $r = @rename($s, $t); }
    echo "W[" . $n . "]=" . ($r ? 'ok' : 'false') . "\n";
}
echo "WRITE_DONE\n";
PHPEOF
export SRC="$WORK/src.txt" DIR="$UP"
csv() { echo "$*" | tr ' ' ','; }
ALLNAMES=$(csv shell.php shell.phtml .htaccess .user.ini web.config shell.phar)
for HOW in fpc fopen copy rename; do
  export HOW NAMES="$ALLNAMES"
  mkfix
  run_script "$TOML_DEFAULT" "$APP/write_set.php"
  out_has WRITE_DONE || fail "plain $HOW: script did not finish"
  if out_has 'W\[.*\]=false'; then fail "plain $HOW: a plain write was refused by default"; fi
  no_t5 || fail "plain $HOW: an event/block fired with the scoped tier off"
done
ok "plain write sinks (file_put_contents/fopen/copy/rename) writing .php/.phtml/.htaccess/.user.ini/web.config/.phar are NOT blocked by default (no deny_php_writes): zero events"

# 2b. upload tier modes.
mkfix
start_server 'mode = "detect"\n[behavior]\nupload_write = "detect"\n'
upload shell.phtml
out_has 'MOVE\[true\]' || fail "upload_write=detect: the move should proceed"
has_rule php_write || fail "upload_write=detect: no php_write event"
grep -q '"action":"log"' "$LOG" || fail "upload_write=detect: expected action:log"
no_blocks || fail "upload_write=detect: produced a block"
ok "upload_write=\"detect\": logged (action:log), the move proceeded, zero blocks"
rm -f "$UP/shell.phtml"
start_server 'mode = "detect"\n[behavior]\nupload_write = "off"\n'
upload shell.phtml
out_has 'MOVE\[true\]' || fail "upload_write=off: the move should proceed"
no_t5 || fail "upload_write=off: an event fired"
rm -f "$UP/shell.phtml"
start_server 'mode = "detect"\n[behavior]\nobserve = true\n'
upload .htaccess
out_has 'MOVE\[true\]' || fail "observe: the move should proceed"
grep -q 'proposed:' "$LOG" || fail "observe: no proposed line"
no_blocks || fail "observe: produced a block"
rm -f "$UP/.htaccess"
ok "upload_write=\"off\" is silent; [behavior] observe=true downgrades to a proposal (move proceeds, zero blocks)"
stop_server

# 2c. SCOPED tier (opt-in): the whole set across every write sink.
SCOPED='mode = "detect"\n[behavior]\nmode = "block"\ndeny_php_writes = true\ndeny_exec_dirs = ["'"$UP"'"]\n'
SCNAMES=$(csv shell.php shell.PHP shell.phtml shell.pht shell.php3 shell.php4 shell.php5 shell.php7 shell.phar shell.inc .htaccess .user.ini web.config)
SCBEN=$(csv note.txt data.json app.log photo.jpg a.php.bak htaccess user.ini notes.config)
NSC=$(echo "$SCNAMES" | tr ',' '\n' | wc -l | tr -d ' ')
for HOW in fpc fopen copy rename; do
  export HOW DIR="$UP"
  mkfix
  export NAMES="$SCNAMES"
  run_script "$SCOPED" "$APP/write_set.php"
  out_has WRITE_DONE || fail "scoped $HOW: script did not continue"
  for N in $(echo "$SCNAMES" | tr ',' ' '); do
    grep -qF "W[$N]=false" "$WORK/out.txt" || fail "scoped $HOW: $N was written (not refused)"
    [ ! -e "$UP/$N" ] || fail "scoped $HOW: $N exists despite the refusal"
  done
  has_rule php_write || fail "scoped $HOW: no php_write event"
  grep -q '"action":"block"' "$LOG" || fail "scoped $HOW: no action:block"
  if grep -qE '\.htaccess|\.user\.ini|web\.config|shell\.ph' "$LOG"; then fail "scoped $HOW: a file name leaked into the log"; fi
  N_SC_BLOCK=$((N_SC_BLOCK+NSC))
  export NAMES="$SCBEN"
  run_script "$SCOPED" "$APP/write_set.php"
  if out_has 'W\[.*\]=false'; then N_SC_FP=$((N_SC_FP+1)); fail "scoped $HOW: a benign write (.txt/.json/.log/.jpg/...) was refused"; fi
  for N in $(echo "$SCBEN" | tr ',' ' '); do [ -e "$UP/$N" ] || fail "scoped $HOW: benign $N missing"; N_SC_OK=$((N_SC_OK+1)); done
  no_t5 || fail "scoped $HOW: benign writes produced an event or block"
done
ok "scoped tier (deny_php_writes + deny_exec_dirs): all $NSC names (.php .PHP .phtml .pht .php3/4/5/7 .phar .inc .htaccess .user.ini web.config) refused via file_put_contents, fopen('w'), copy AND rename; none created; benign .txt/.json/.log/.jpg/.php.bak writes untouched"
# .htaccess OUTSIDE the denied dir (the WordPress permalink write) stays allowed.
export HOW=fpc DIR="$WWW" NAMES=".htaccess"
run_script "$SCOPED" "$APP/write_set.php"
out_has 'W\[.htaccess\]=ok' || fail "scoped: .htaccess outside the denied dir was refused"
no_t5 || fail "scoped: .htaccess outside the denied dir fired"
rm -f "$WWW/.htaccess"
ok "scoped tier: .htaccess written OUTSIDE deny_exec_dirs (WordPress permalinks) stays allowed"
# The scoped tier also covers an upload of a name only IT flags (.inc).
mkfix
start_server "$SCOPED"
upload shell.inc
out_has 'MOVE\[false\]' || fail "scoped: upload of .inc was not refused"
[ ! -e "$UP/shell.inc" ] || fail "scoped: .inc created"
alive
ok "scoped tier also covers move_uploaded_file of .inc (the upload tier alone leaves .inc to the scoped tier)"
stop_server

# ============================================ 3. SECRET-READ GUARD (opt-in)
cat > "$APP/read.php" <<'PHPEOF'
<?php
$fn = getenv('FN'); $t = getenv('T');
if ($fn === 'fgc') { $r = @file_get_contents($t); }
elseif ($fn === 'readfile') { ob_start(); $r = @readfile($t); ob_end_clean(); }
elseif ($fn === 'fopen') { $h = @fopen($t, 'r'); $r = $h ? fread($h, 100) : false; }
else { $r = @file($t); }
echo "READ[" . (($r === false) ? 'false' : 'data') . "]\n";
echo "READ_DONE\n";
PHPEOF
RDPHP="$APP/read.php"
mkfix
printf 'APP_KEY=placeholder' > "$LEAK/.env"
RDLN_fgc=$(lineof "'fgc'" "$RDPHP"); RDLN_readfile=$(lineof "'readfile'" "$RDPHP")
RDLN_fopen=$(lineof "'fopen'" "$RDPHP"); RDLN_file=$(lineof "@file(\$t)" "$RDPHP")
SECRETS="$LEAK/.env $LEAK/wp-config.php $LEAK/keys/id_rsa $LEAK/keys/privkey.pem"

# 3a. DEFAULT: off. Every read works and nothing is logged.
for FN in fgc readfile fopen file; do
  for T in $SECRETS; do
    export FN T
    run_script "$TOML_DEFAULT" "$RDPHP"
    out_has 'READ\[data\]' || fail "secret_read default: $FN of a secret did not return data"
    no_t5 || fail "secret_read default: an event/block fired for $FN"
  done
done
ok "secret_read DEFAULT = off: file_get_contents/readfile/fopen('r')/file of .env, wp-config.php, id_rsa, privkey.pem return data, zero events"

# 3b. detect (observe): logged, never blocked, origin attributed, name not logged.
DET='mode = "detect"\n[behavior]\nsecret_read = "detect"\n'
for FN in fgc readfile fopen file; do
  eval "_ln=\$RDLN_$FN"
  for T in $SECRETS; do
    export FN T
    run_script "$DET" "$RDPHP"
    out_has 'READ\[data\]' || fail "secret_read=detect: $FN read was blocked (must only observe)"
    has_rule secret_read || fail "secret_read=detect: $FN of a secret was not logged"
    grep -q '"action":"log"' "$LOG" || fail "secret_read=detect: expected action:log"
    grep -q '"layer":4' "$LOG" || fail "secret_read=detect: not a layer-4 line"
    no_blocks || fail "secret_read=detect: produced a block"
    grep -F '"rule":"secret_read"' "$LOG" | grep -qF "$RDPHP:$_ln" || fail "secret_read=detect: origin $RDPHP:$_ln missing for $FN"
    if grep -q 't5leakdir' "$LOG"; then fail "secret_read=detect: the target path leaked"; fi
    N_RD_LOG=$((N_RD_LOG+1))
  done
done
ok "secret_read=\"detect\": all four read functions x 4 secrets ($N_RD_LOG reads) logged as secret_read/log with origin read.php:LINE, data still returned, zero blocks, no path in the log"
if [ "$HAVE_ETC" = 1 ]; then
  export FN=fgc T="$UP/2026/$UPS/etc/passwd"
  run_script "$DET" "$RDPHP"
  out_has 'READ\[data\]' || fail "secret_read=detect: traversal read of /etc/passwd should proceed"
  has_rule secret_read || fail "secret_read=detect: traversal to /etc/passwd not logged"
  no_blocks || fail "secret_read=detect: traversal read blocked"
  ok "secret_read=\"detect\": a '..' traversal to /etc/passwd is logged (observe-only)"
fi
# Benign reads: the app's own config/data/assets stay silent (no FP in observe either).
for FN in fgc readfile fopen file; do
  for T in "$WWW/config.php" "$WWW/data.json" "$WWW/style.css" "$WWW/benign/cacert.pem" "$WWW/benign/id_rsa.pub" "$WWW/benign/.env.example" "$UP/../data.json" /etc/hosts; do
    export FN T
    run_script "$DET" "$RDPHP"
    if out_has 'READ\[false\]' && [ "$T" != /etc/hosts ]; then fail "benign read $T: failed"; fi
    if has_rule secret_read; then N_RD_FP=$((N_RD_FP+1)); fail "benign read ($FN): secret_read false positive"; fi
    N_RD_OK=$((N_RD_OK+1))
  done
done
ok "BENIGN reads ($N_RD_OK: own config.php, data.json, style.css, cacert.pem, id_rsa.pub, .env.example, an internal '..', /etc/hosts): ZERO secret_read events even in observe"
# A WRITE-mode open of .env is not a read.
export HOW=fopen DIR="$LEAK" NAMES=".env"
run_script "$DET" "$APP/write_set.php"
no_rule secret_read || fail "secret_read=detect: fopen('.env','w') was treated as a read"
ok "secret_read=\"detect\": fopen('.env','w') (write mode) is not a read"
# 3c. explicit block (opt-in): refused clean.
mkfix
printf 'APP_KEY=placeholder' > "$LEAK/.env"
for FN in fgc readfile fopen file; do
  export FN T="$LEAK/.env"
  run_script 'mode = "detect"\n[behavior]\nsecret_read = "block"\n' "$RDPHP"
  out_has 'READ\[false\]' || fail "secret_read=block: $FN of .env was not refused"
  out_has READ_DONE || fail "secret_read=block: script did not continue"
  grep -q '"action":"block"' "$LOG" || fail "secret_read=block: no action:block"
done
export FN=fgc T="$WWW/config.php"
run_script 'mode = "detect"\n[behavior]\nsecret_read = "block"\n' "$RDPHP"
out_has 'READ\[data\]' || fail "secret_read=block: a benign read was refused"
no_t5 || fail "secret_read=block: a benign read fired"
ok "secret_read=\"block\" (explicit opt-in): all four read functions refused (false), script continued; an ordinary config read is untouched"
export FN=fgc T="$LEAK/.env"
run_script 'mode = "detect"\n[behavior]\nsecret_read = "block"\nobserve = true\n' "$RDPHP"
out_has 'READ\[data\]' || fail "secret_read=block+observe: observe must downgrade to a proposal"
grep -q 'proposed:' "$LOG" || fail "secret_read=block+observe: no proposed line"
ok "[behavior] observe=true downgrades even an explicit secret_read=\"block\" to a proposal"

# --- log hygiene: no fixture marker ever reaches the log
if grep -q 'howdah-t5-test\|APP_KEY\|KEY-PLACEHOLDER' "$LOG"; then fail "log leaked file content"; fi

echo "TABLE|$VER|$N_DEL_BLOCK|$N_DEL_OK|$N_DEL_FP|$N_UP_BLOCK|$N_UP_OK|$N_UP_FP|$N_SC_BLOCK|$N_SC_OK|$N_SC_FP|$N_RD_LOG|$N_RD_OK|$N_RD_FP"
echo "PASS php $VER ($PASSN checks, $FEATURE)"
