#!/bin/sh
# In-container half of the Layer-3 SOAP request-guard test (CVE-2026-129506
# SoapServer DTD use-after-free, CVE-2026-15353 malformed arraySize heap
# over-read). Runs inside a howdah-dev-php<ver> image behind the built-in web
# server (cli-server SAPI) so SoapServer::handle() reads a real php://input
# body, exactly as a web request would.
#
# DEFENSIVE ONLY. Howdah refuses two malformed request shapes BEFORE ext/soap
# parses them; this test never attempts to trigger or observe the underlying
# use-after-free / heap over-read. It verifies the GUARD:
#   - a prolog <!DOCTYPE> request is refused (clean 403, soap_request logged,
#     reason dtd, SOAP never reached, worker survives);
#   - a malformed arraySize request is refused (403, reason array-dimensions);
#   - a benign corpus (valid SOAP 1.1 / 1.2, arraySize="*"/"2 3", a body/CDATA
#     carrying the literal <!DOCTYPE html>, a gzip Content-Encoding request)
#     produces ZERO blocks and reaches SOAP;
#   - with Howdah OFF the same dangerous shapes are NOT refused by Howdah (SOAP
#     is on the path), proving the guard is non-vacuous — without asserting any
#     crash.
#
# ext/soap is not baked into the dev images, so it is built here at runtime
# (libxml2-dev + docker-php-ext-install soap; the image carries php-src and
# phpize). A version where that fails is SKIPPED with the reason recorded, and
# the absent-class no-op path is still proven (howdah loads and serves cleanly).
#
# Arg 1: cargo feature for this image's PHP generation (php5|php7|php8).
set -eu

FEATURE="${1:-php8}"
WORK=/tmp/howdah-soap
LOG="$WORK/events.log"
PORT=8099
rm -rf "$WORK"; mkdir -p "$WORK"

PHPVER=$(php -r 'echo PHP_VERSION;')
PHPMAJ=$(php -r 'echo PHP_MAJOR_VERSION;')
echo "== php $PHPVER / SOAP request guard ($FEATURE) =="

fail() {
  echo "FAIL: $1"
  echo "--- server log ---"; tail -20 "$WORK/srv.log" 2>/dev/null
  echo "--- event log ---"; cat "$LOG" 2>/dev/null
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  exit 1
}

# ---- build howdah-ext ------------------------------------------------------
export CARGO_TARGET_DIR=/tmp/t
cd /src
cargo build -p howdah-ext --features "$FEATURE" --release 2>&1 | tail -2
cp /tmp/t/release/libhowdah_ext.so "$WORK/howdah.so"
cd "$WORK"

# ---- ensure ext/soap is present (build it if the image lacks it) -----------
have_soap() { php -r 'exit(class_exists("SoapServer") ? 0 : 1);' 2>/dev/null; }
if ! have_soap; then
  echo "  .. ext/soap absent; building it (libxml2-dev + docker-php-ext-install soap)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1 || true
  apt-get install -y -qq libxml2-dev >/dev/null 2>&1 || true
  docker-php-ext-install soap >/tmp/soapbuild.log 2>&1 || true
fi

if ! have_soap; then
  echo "  note - ext/soap could not be built on PHP $PHPVER (see /tmp/soapbuild.log tail below)"
  tail -5 /tmp/soapbuild.log 2>/dev/null || true
  # Prove the hook no-ops cleanly when the soapserver class is absent: howdah
  # loads (SOAP guard armed by default) and a script runs with no crash.
  OUT=$(php -d extension="$WORK/howdah.so" -d howdah.log="$LOG" -d display_errors=1 \
        -r 'echo class_exists("SoapServer") ? "HASSOAP" : "NOSOAP"; echo " LOADOK";' 2>&1 || true)
  echo "$OUT" | grep -q 'LOADOK' || fail "SKIP path: howdah did not load/run cleanly with soap absent ($OUT)"
  echo "  ok   - soap absent: howdah loads and serves cleanly, SoapServer::handle swap no-ops"
  echo "SOAP-ROW	$PHPVER	SKIP	ext-soap-unavailable	hook-noop-ok"
  echo "PASS"
  exit 0
fi

LV=$(php -r 'echo defined("LIBXML_VERSION") ? LIBXML_VERSION : 0;')
HASZLIB=$(php -r 'echo extension_loaded("zlib") ? 1 : 0;')
echo "  note - ext/soap present (libxml $LV, zlib=$HASZLIB)"

# ---- fixtures --------------------------------------------------------------
# A minimal non-WSDL SOAP endpoint. handle() with no argument reads php://input.
cat > "$WORK/soap_srv.php" <<'PHP'
<?php
class HowdahLab { public function ping($x) { return "pong:" . $x; } }
$server = new SoapServer(null, array('uri' => 'urn:howdah-lab'));
$server->setObject(new HowdahLab());
$server->handle();
PHP

# Generate byte-correct SOAP 1.1 and 1.2 ping requests via a capturing client.
# The trailing variadic keeps the override compatible across versions
# (SoapClient::__doRequest gained a $uriParserClass parameter in PHP 8.5).
php -r '
class Cap extends SoapClient { public $req="";
  public function __doRequest($r,$l,$a,$v,$o=0,...$rest){ $this->req=$r; return ""; } }
$c = new Cap(null, array("location"=>"http://127.0.0.1/","uri"=>"urn:howdah-lab"));
@$c->ping("hi"); file_put_contents("'"$WORK"'/valid11.xml", $c->req);
$c2 = new Cap(null, array("location"=>"http://127.0.0.1/","uri"=>"urn:howdah-lab","soap_version"=>SOAP_1_2));
@$c2->ping("hi"); file_put_contents("'"$WORK"'/valid12.xml", $c2->req);
' 2>/dev/null || true
[ -s "$WORK/valid11.xml" ] || fail "could not generate a valid SOAP 1.1 request"
[ -s "$WORK/valid12.xml" ] || fail "could not generate a valid SOAP 1.2 request"

# Dangerous shape 1: a DTD/DOCTYPE in the prolog (with an external entity ref).
cat > "$WORK/dtd.xml" <<'PHP'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE SOAP-ENV:Envelope [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:howdah-lab">
  <SOAP-ENV:Body><ns1:ping><p>&xxe;</p></ns1:ping></SOAP-ENV:Body>
</SOAP-ENV:Envelope>
PHP

# Dangerous shape 2: a malformed SOAP-ENC arraySize (non-numeric).
cat > "$WORK/badarray.xml" <<'PHP'
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:enc="http://www.w3.org/2003/05/soap-encoding" xmlns:ns1="urn:howdah-lab">
  <SOAP-ENV:Body><ns1:ping><arr enc:arraySize="abc"><i>1</i></arr></ns1:ping></SOAP-ENV:Body>
</SOAP-ENV:Envelope>
PHP

# Benign: a valid arraySize ("* 3"), and the literal <!DOCTYPE html> inside a
# CDATA section + as element text (must NOT trip: only a prolog DOCTYPE counts).
cat > "$WORK/okarray.xml" <<'PHP'
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:enc="http://www.w3.org/2003/05/soap-encoding" xmlns:ns1="urn:howdah-lab">
  <SOAP-ENV:Body><ns1:ping><arr enc:arraySize="* 3"><i>1</i></arr></ns1:ping></SOAP-ENV:Body>
</SOAP-ENV:Envelope>
PHP
cat > "$WORK/okarray2.xml" <<'PHP'
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:enc="http://www.w3.org/2003/05/soap-encoding" xmlns:ns1="urn:howdah-lab">
  <SOAP-ENV:Body><ns1:ping><arr enc:arraySize="2 3"><i>1</i></arr></ns1:ping></SOAP-ENV:Body>
</SOAP-ENV:Envelope>
PHP
cat > "$WORK/cdata.xml" <<'PHP'
<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:howdah-lab">
  <SOAP-ENV:Body><ns1:ping><p><![CDATA[<!DOCTYPE html>]]> and text mentioning <!DOCTYPE html></p></ns1:ping></SOAP-ENV:Body>
</SOAP-ENV:Envelope>
PHP

# gzip the valid SOAP 1.1 request for the Content-Encoding test.
gzip -c "$WORK/valid11.xml" > "$WORK/valid11.xml.gz" 2>/dev/null || true

# ---- server + request helpers ---------------------------------------------
SRV_PID=""
start_server() { # $1 = config toml file ("" for packaged defaults)
  : > "$LOG"
  CFG=""
  [ -n "$1" ] && CFG="-d howdah.config=$1"
  # shellcheck disable=SC2086
  php -d extension="$WORK/howdah.so" $CFG -d howdah.log="$LOG" \
      -d display_errors=0 -d error_reporting=0 -d date.timezone=UTC \
      -S 127.0.0.1:$PORT -t "$WORK" "$WORK/soap_srv.php" >"$WORK/srv.log" 2>&1 &
  SRV_PID=$!
  i=0
  while [ $i -lt 100 ]; do
    if curl -s -o /dev/null "http://127.0.0.1:$PORT/soap_srv.php" 2>/dev/null; then return 0; fi
    kill -0 "$SRV_PID" 2>/dev/null || { echo "server died on startup"; cat "$WORK/srv.log"; return 1; }
    i=$((i + 1)); sleep 0.1
  done
  return 1
}
stop_server() { [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null || true; SRV_PID=""; }

# post <body-file> [extra curl args...] -> http code on stdout, body in resp.txt
post() {
  bf="$1"; shift
  curl -s -o "$WORK/resp.txt" -w '%{http_code}' -X POST --data-binary @"$bf" \
       -H 'Content-Type: text/xml; charset=utf-8' "$@" "http://127.0.0.1:$PORT/soap_srv.php" 2>/dev/null || echo "000"
}
nsoap() { grep -c '"rule":"soap_request"' "$LOG" 2>/dev/null || true; }
nblock() { grep '"rule":"soap_request"' "$LOG" 2>/dev/null | grep -c '"action":"block"' || true; }

# ================================================================ Howdah ON
start_server "" || fail "could not start the server (Howdah default)"

# --- DTD prolog: refused with a clean 403, soap_request logged (dtd) --------
: > "$LOG"
code=$(post "$WORK/dtd.xml")
[ "$code" = "403" ] || fail "DTD request: expected HTTP 403, got $code"
grep -q 'Howdah blocked' "$WORK/resp.txt" || fail "DTD request: 403 body is not Howdah's refusal"
grep -q '"rule":"soap_request"' "$LOG" || fail "DTD request: no soap_request event"
grep -q '"action":"block"' "$LOG" || fail "DTD request: not action:block"
grep -q 'dtd' "$LOG" || fail "DTD request: reason does not say dtd"
grep -q '"layer":3' "$LOG" || fail "DTD request: not layer 3"
# Leak sentinels appear in the request body but never in the fixed reason string
# (which does legitimately contain the words DTD/DOCTYPE and the CVE id).
if grep -qi 'hostname\|Envelope\|ns1:ping\|&xxe' "$LOG"; then fail "DTD request: log leaked the request body"; fi
echo "  ok   - prolog <!DOCTYPE>: clean 403, soap_request logged (reason dtd, layer 3), body not logged, SOAP not reached"

# --- worker survives: the next benign request still works -------------------
code=$(post "$WORK/valid11.xml")
[ "$code" != "000" ] || fail "worker did not survive the DTD refusal (server gone)"
[ "$code" != "403" ] || fail "a valid request after a block was wrongly refused ($code)"
echo "  ok   - worker survived the refusal (next request served, HTTP $code)"

# --- malformed arraySize: refused with 403, reason array-dimensions ---------
: > "$LOG"
code=$(post "$WORK/badarray.xml")
[ "$code" = "403" ] || fail "arraySize request: expected HTTP 403, got $code"
grep -q '"rule":"soap_request"' "$LOG" || fail "arraySize request: no soap_request event"
grep -q 'array dimensions' "$LOG" || fail "arraySize request: reason does not say array dimensions"
if grep -qi 'Envelope\|ns1:ping\|"abc"' "$LOG"; then fail "arraySize request: log leaked the body"; fi
echo "  ok   - malformed arraySize: clean 403, soap_request logged (reason array dimensions), body not logged"

# --- BENIGN corpus: ZERO blocks, each reaches SOAP --------------------------
: > "$LOG"
BN=0
for b in valid11.xml valid12.xml okarray.xml okarray2.xml cdata.xml; do
  code=$(post "$WORK/$b")
  [ "$code" != "403" ] || fail "benign $b was refused with 403 (Howdah false positive)"
  if grep -q 'Howdah blocked' "$WORK/resp.txt"; then fail "benign $b got a Howdah refusal body"; fi
  BN=$((BN + 1))
done
# gzip Content-Encoding valid request (needs zlib for SOAP's own inflate).
if [ "$HASZLIB" = 1 ] && [ -s "$WORK/valid11.xml.gz" ]; then
  code=$(post "$WORK/valid11.xml.gz" -H 'Content-Encoding: gzip')
  [ "$code" != "403" ] || fail "benign gzip request was refused with 403 (Howdah false positive)"
  if grep -q 'Howdah blocked' "$WORK/resp.txt"; then fail "benign gzip request got a Howdah refusal body"; fi
  BN=$((BN + 1)); GZ=yes
else
  GZ="skipped(no zlib)"
fi
[ "$(nblock)" = 0 ] || fail "the benign corpus produced $(nblock) soap_request block event(s)"
[ "$(nsoap)" = 0 ] || fail "the benign corpus produced $(nsoap) soap_request event(s)"
echo "  ok   - benign corpus: $BN requests (valid SOAP 1.1/1.2, arraySize=\"* 3\"/\"2 3\", CDATA+text <!DOCTYPE html>, gzip=$GZ) -> 0 blocks, 0 soap_request events"
stop_server

# ================================================================ modes
# detect: logs but does not refuse (SOAP is reached).
printf '[sinks.soap]\nmode="detect"\n' > "$WORK/detect.toml"
start_server "$WORK/detect.toml" || fail "could not start server (detect)"
: > "$LOG"
code=$(post "$WORK/dtd.xml" || true)
grep -q '"rule":"soap_request"' "$LOG" || fail "detect: DTD not logged"
grep -q '"action":"log"' "$LOG" || fail "detect: DTD not action:log"
[ "$code" != "403" ] || fail "detect must not refuse (got 403)"
echo "  ok   - [sinks.soap] mode=detect: DTD logged (action:log), not refused (HTTP $code), SOAP reached"
stop_server

# ================================================================ Howdah OFF (non-vacuous)
# off: the SOAP guard is silent; the dangerous shapes reach ext/soap. We assert
# ONLY that Howdah did not intercept (no soap_request event, no 403 refusal) -
# never a crash. On a patched PHP SOAP returns its own fault; that is captured
# and noted, not asserted.
printf '[sinks.soap]\nmode="off"\n' > "$WORK/off.toml"
start_server "$WORK/off.toml" || fail "could not start server (soap off)"
: > "$LOG"
code=$(post "$WORK/dtd.xml" || true)
[ "$(nsoap)" = 0 ] || fail "off: Howdah still logged a soap_request event"
if grep -q 'Howdah blocked' "$WORK/resp.txt" 2>/dev/null; then fail "off: Howdah still refused the request"; fi
SOAPSAW="(no response / worker-level outcome, not asserted)"
if grep -qi 'DTD\|Fault\|faultstring' "$WORK/resp.txt" 2>/dev/null; then SOAPSAW="SOAP returned its own fault/DTD error"; fi
echo "  ok   - [sinks.soap] off: DTD request NOT intercepted by Howdah (HTTP $code); $SOAPSAW"
: > "$LOG"
post "$WORK/badarray.xml" >/dev/null 2>&1 || true
[ "$(nsoap)" = 0 ] || fail "off: Howdah still logged for the arraySize request"
echo "  ok   - [sinks.soap] off: arraySize request NOT intercepted by Howdah"
stop_server

echo "SOAP-ROW	$PHPVER	PASS	libxml=$LV	dtd=403+log	array=403+log	benign_blocks=0/$BN	gz=$GZ	worker=survived	off=not-intercepted"
echo "PASS"
