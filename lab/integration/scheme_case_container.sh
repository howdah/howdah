#!/bin/sh
# In-container half of the scheme_case lab (see scheme_case.sh).
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
# A PHP listener (Howdah NOT loaded) serves plaintext :80 and TLS :443 and logs
# "<port> <path>" per request. The client runs with Howdah off / default / detect.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; LOG=$WORK/events.log; HITS=$WORK/hits.log
mkdir -p "$WORK"; : > "$LOG"; : > "$HITS"; : > "$RESULTS"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=scheme-case
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$S" "$1" "$2" "$3" >> "$RESULTS"; echo "  [$PHPVER] $1 $2: $3" >&2; }

echo "== [$PHPVER] building howdah-ext ($FEATURE) ==" >&2
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record build FAIL "cargo build failed"; exit 1
fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

# ---- self-signed cert (generated with PHP's openssl: no openssl CLI needed) ----
cat > "$WORK/mkcert.php" <<'PHP'
<?php
$cfg = array('private_key_bits' => 2048);
$k = openssl_pkey_new($cfg);
$csr = openssl_csr_new(array('commonName' => '127.0.0.1'), $k, $cfg);
$crt = openssl_csr_sign($csr, null, $k, 2);
openssl_x509_export($crt, $c); openssl_pkey_export($k, $p);
file_put_contents($argv[1], $c . $p);
PHP
php "$WORK/mkcert.php" "$WORK/srv.pem" >/dev/null 2>&1 || { record cert FAIL "could not generate cert"; exit 1; }

# ---- listener: :80 plaintext, :443 TLS. /redir on :80 answers 307 -> HTTPS:// ----
cat > "$WORK/listen.php" <<'PHP'
<?php
$hits = $argv[2];
$ctx = stream_context_create(array('ssl' => array('local_cert' => $argv[1], 'verify_peer' => false)));
$plain = stream_socket_server('tcp://0.0.0.0:80', $en, $es);
$tls = stream_socket_server('tcp://0.0.0.0:443', $en, $es, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if (!$plain || !$tls) { fwrite(STDERR, "listen failed\n"); exit(1); }
file_put_contents($argv[3], "ready");
function serve($c, $port, $hits) {
    stream_set_timeout($c, 3);
    $line = fgets($c, 4096);
    if ($line === false) { return; }
    $path = (preg_match('#^\S+ (\S+)#', $line, $m)) ? $m[1] : '?';
    while (($l = fgets($c, 4096)) !== false && trim($l) !== '') {}
    file_put_contents($hits, "$port $path\n", FILE_APPEND);
    if ($port == 80 && strpos($path, '/redir') === 0) {
        fwrite($c, "HTTP/1.0 307 Temporary Redirect\r\nLocation: HTTPS://127.0.0.1/landed\r\nContent-Length: 0\r\n\r\n");
    } else {
        fwrite($c, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    }
}
while (true) {
    $r = array($plain, $tls); $w = null; $e = null;
    if (!stream_select($r, $w, $e, 1)) { continue; }
    foreach ($r as $s) {
        if ($s === $plain) {
            $c = @stream_socket_accept($plain, 3);
            if ($c) { serve($c, 80, $hits); fclose($c); }
        } else {
            $c = @stream_socket_accept($tls, 3);
            if ($c && @stream_socket_enable_crypto($c, true, STREAM_CRYPTO_METHOD_SSLv23_SERVER)) { serve($c, 443, $hits); }
            if ($c) { fclose($c); }
        }
    }
}
PHP
php "$WORK/listen.php" "$WORK/srv.pem" "$HITS" "$WORK/ready" >"$WORK/listen.out" 2>&1 &
LPID=$!
i=0; while [ ! -f "$WORK/ready" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
[ -f "$WORK/ready" ] || { cat "$WORK/listen.out" >&2; record listener FAIL "two-listener oracle did not start"; exit 1; }

# ---- client: one call per API with the URL in $1; the tag rides the path ------
cat > "$WORK/client.php" <<'PHP'
<?php
stream_context_set_default(array(
    'ssl' => array('verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true),
    'http' => array('timeout' => 3),
));
$fn = $argv[1]; $url = $argv[2];
switch ($fn) {
case 'fgc':  @file_get_contents($url); break;
case 'fopen': $h = @fopen($url, 'r'); if ($h) { @fread($h, 10); fclose($h); } break;
case 'headers': @get_headers($url); break;
case 'copy': @copy($url, '/tmp/sc-copy.out'); break;
}
PHP
run_client() { # <ini-mode: off|default|detect> <fn> <url>
  mode=$1; : > "$LOG"
  case $mode in
    off) set -- "$2" "$3"; EXT="" ;;
    default) printf '' > "$WORK/c.toml"; EXT="-d extension=$WORK/howdah.so -d howdah.config=$WORK/c.toml -d howdah.log=$LOG" ;;
    detect) printf '[sinks.scheme_case]\nmode="detect"\n' > "$WORK/c.toml"; EXT="-d extension=$WORK/howdah.so -d howdah.config=$WORK/c.toml -d howdah.log=$LOG" ;;
    offcfg) printf '[sinks.scheme_case]\nmode="off"\n' > "$WORK/c.toml"; EXT="-d extension=$WORK/howdah.so -d howdah.config=$WORK/c.toml -d howdah.log=$LOG" ;;
  esac
  [ "$mode" = off ] || set -- "$2" "$3"
  # shellcheck disable=SC2086
  php $EXT -d default_socket_timeout=3 -d date.timezone=UTC "$WORK/client.php" "$@" >/dev/null 2>"$WORK/cerr.txt"
}
# hit_port <tag>: the port the request tagged <tag> landed on ("" if none).
hit_port() { grep " /$1\$" "$HITS" | tail -1 | cut -d' ' -f1; }

# Is this PHP vulnerable at all? Probe with Howdah OFF. A PHP that already
# connects HTTPS:// over TLS (fixed upstream) turns the "bug reproduced" arms
# into "still TLS" expectations; the fix arm is unchanged.
: > "$HITS"; run_client off fgc "HTTPS://127.0.0.1/probe"
PROBE=$(hit_port probe)
if [ "$PROBE" = "80" ]; then VULN=1; PLAINPORT=80; record probe PASS "stock PHP sends HTTPS:// in plaintext (CVE-2026-128064 reproduced)"
elif [ "$PROBE" = "443" ]; then VULN=0; PLAINPORT=443; record probe PASS "stock PHP already uses TLS for HTTPS:// (fixed upstream in this build); off/detect arms expect TLS"
else record probe FAIL "probe request not observed"; kill "$LPID" 2>/dev/null; exit 0; fi

fns="fgc fopen headers copy"
n=0
for fn in $fns; do
  for arm in off default detect offcfg; do
    for scheme in HTTPS https; do
      n=$((n+1)); tag="$fn-$arm-$scheme-$n"
      : > "$HITS"
      run_client "$arm" "$fn" "$scheme://127.0.0.1/$tag"
      port=$(hit_port "$tag"); logged=0; grep -q '"rule":"tls_scheme_case"' "$LOG" && logged=1
      case "$arm:$scheme" in
        off:HTTPS|detect:HTTPS|offcfg:HTTPS) want=$PLAINPORT; wlog=0; [ "$arm" = detect ] && wlog=1
          note="mixed-case goes plaintext (bug reproduced / not fixed)" ;;
        default:HTTPS) want=443; wlog=1; note="mixed-case fixed to TLS" ;;
        *:https) want=443; wlog=0; note="lowercase unaffected (TLS)" ;;
      esac
      if [ "$port" = "$want" ] && [ "$logged" = "$wlog" ]; then
        record "$fn/$arm/$scheme" PASS "port=$port logged=$logged: $note"
      else
        record "$fn/$arm/$scheme" FAIL "port=${port:-none} logged=$logged want port=$want logged=$wlog ($(head -c 200 "$WORK/cerr.txt"))"
      fi
    done
  done
done

# log content: rule + fixed reason only, never the URL / host / path / tag.
: > "$LOG"; run_client default fgc "HTTPS://user:pw@127.0.0.1/secret-path?token=abc123"
if grep -q '"rule":"tls_scheme_case"' "$LOG" && ! grep -Eq 'secret-path|token|abc123|user|pw@|127\.0\.0\.1' "$LOG"; then
  record log-no-url PASS "event logged without the URL"
else
  record log-no-url FAIL "$(head -c 300 "$LOG")"
fi

# redirect gap: lowercase http:// -> 307 -> HTTPS://127.0.0.1/landed. Under
# Howdah default the hop is followed by an internal direct call (not via the
# wrapper op), so it still goes plaintext to :80. Documents the gap.
for arm in off default; do
  : > "$HITS"; run_client "$arm" fgc "http://127.0.0.1/redir"
  p=$(grep ' /landed$' "$HITS" | tail -1 | cut -d' ' -f1)
  if [ "$p" = "80" ]; then
    record "redirect-gap/$arm" PASS "redirect hop to HTTPS:// went plaintext (:80): documented gap, not covered"
  elif [ "$p" = "443" ]; then
    record "redirect-gap/$arm" PASS "redirect hop to HTTPS:// went TLS (:443): gap NOT present on this PHP"
  else
    record "redirect-gap/$arm" FAIL "hop not observed: $(cat "$HITS" | tr '\n' ';')"
  fi
done

kill "$LPID" 2>/dev/null
exit 0
