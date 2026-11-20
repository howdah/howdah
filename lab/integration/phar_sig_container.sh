#!/bin/sh
# In-container half of the phar_sig lab (see phar_sig.sh).
# Args: $1 cargo feature (php5|php7|php8); $2 results TSV.
# BENIGN fixtures only: every archive holds `<?php return "ok";`.
set -u
FEATURE="${1:-php8}"
RESULTS="${2:-/out/rows.tsv}"
WORK=/work; LOG=$WORK/events.log; FX=$WORK/fx
mkdir -p "$WORK" "$FX"; : > "$LOG"; : > "$RESULTS"
PHPVER=$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)
S=phar-sig
record() { printf '%s\t%s\t%s\t%s\t%s\n' "$PHPVER" "$S" "$1" "$2" "$3" >> "$RESULTS"; echo "  [$PHPVER] $1 $2: $3" >&2; }

echo "== [$PHPVER] building howdah-ext ($FEATURE) ==" >&2
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/t}"
cd /src
if ! cargo build -p howdah-ext --features "$FEATURE" --release 2>"$WORK/build.err"; then
  tail -8 "$WORK/build.err" >&2; record build FAIL "cargo build failed"; exit 1
fi
cp "$CARGO_TARGET_DIR/release/libhowdah_ext.so" "$WORK/howdah.so"

if ! php -m | grep -qi '^openssl$' || ! php -m | grep -qi '^phar$'; then
  # Hook must still no-op cleanly with nothing to guard: load Howdah and run.
  if php -d extension="$WORK/howdah.so" -r 'echo "loaded";' 2>/dev/null | grep -q loaded; then
    record all SKIP "no ext/openssl or ext/phar in this image: cannot sign fixtures; howdah still loads cleanly"
  else
    record all FAIL "no openssl/phar AND howdah failed to load"
  fi
  exit 0
fi

# ---- fixtures (Howdah NOT loaded). Native, tar and zip phar formats. ----------
cat > "$WORK/mk.php" <<'PHP'
<?php
// Benign fixtures: one file returning "ok", signed three ways.
$dir = $argv[1];
$k = openssl_pkey_new(array('private_key_bits' => 2048));
openssl_pkey_export($k, $priv);
$d = openssl_pkey_get_details($k); $pub = $d['key'];
function mk($file, $priv, $alg) {
    @unlink($file);
    $p = new Phar($file);
    $p->addFromString('index.php', '<?php return "ok";');
    if (substr($file, -5) === '.phar') { $p->setStub('<?php __HALT_COMPILER();'); }
    if ($priv !== null) { $p->setSignatureAlgorithm(Phar::OPENSSL, $priv); }
    else { $p->setSignatureAlgorithm($alg); }
    unset($p);
}
foreach (array('' => 'phar', 'tar' => 'phar.tar', 'zip' => 'phar.zip') as $f => $ext) {
    $f = $f === '' ? 'native' : $f;
    mk("$dir/g-$f.$ext", $priv, null);                 // genuine: OpenSSL
    mk("$dir/d-$f.$ext", null, Phar::SHA256);          // downgrade: keyless SHA-256
    mk("$dir/n-$f.$ext", null, Phar::SHA256);          // no .pubkey beside it
    file_put_contents("$dir/g-$f.$ext.pubkey", $pub);
    file_put_contents("$dir/d-$f.$ext.pubkey", $pub);  // same pinned key
}
echo "fixtures ok\n";
PHP
if ! php -d phar.readonly=0 "$WORK/mk.php" "$FX" >"$WORK/mk.out" 2>&1 || ! grep -q "fixtures ok" "$WORK/mk.out"; then
  head -c 600 "$WORK/mk.out" >&2; record fixtures FAIL "could not build signed/downgraded benign fixtures"; exit 1
fi
# Whole-archive compressed copy of the downgraded phar (indeterminate => detect only).
cat > "$WORK/mkz.php" <<'PHP'
<?php
$f = $argv[1];
try { $p = new Phar($f); $p->compress(Phar::GZ); unset($p); echo "gz ok\n"; } catch (Exception $e) { echo "gz no: ", $e->getMessage(), "\n"; }
PHP
cp "$FX/d-native.phar" "$FX/dz.phar"
php -d phar.readonly=0 "$WORK/mkz.php" "$FX/dz.phar" >"$WORK/mkz.out" 2>&1
HAVE_GZ=0
if grep -q "gz ok" "$WORK/mkz.out" && [ -f "$FX/dz.phar.gz" ]; then
  HAVE_GZ=1; cp "$FX/d-native.phar.pubkey" "$FX/dz.phar.gz.pubkey"
fi
rm -f "$FX/dz.phar.pubkey"

# ---- client: open the archive via the constructor / include of phar:// URL ---
cat > "$WORK/client.php" <<'PHP'
<?php
$f = $argv[2];
switch ($argv[1]) {
case 'ctor':
    try { $p = new Phar($f); echo "LOADED"; } catch (Exception $e) { echo "REFUSED"; }
    break;
case 'pdata':
    try { $p = new PharData($f); echo "LOADED"; } catch (Exception $e) { echo "REFUSED"; }
    break;
case 'load':
    try { echo Phar::loadPhar($f, "a.phar") ? "LOADED" : "REFUSED"; } catch (Exception $e) { echo "REFUSED"; }
    break;
case 'inc': // benign stub: returns "ok"
    $r = @include 'phar://' . $f . '/index.php';
    echo $r === 'ok' ? "LOADED" : "REFUSED";
    break;
}
echo "|alive\n";
PHP
run_client() { # <arm: off|default|detect|offcfg> <probe> <file>
  arm=$1; : > "$LOG"
  case $arm in
    off) EXT="" ;;
    default) printf '' > "$WORK/c.toml"; EXT="-d extension=$WORK/howdah.so -d howdah.config=$WORK/c.toml -d howdah.log=$LOG" ;;
    detect) printf '[sinks.phar]\nsignature="detect"\n' > "$WORK/c.toml"; EXT="-d extension=$WORK/howdah.so -d howdah.config=$WORK/c.toml -d howdah.log=$LOG" ;;
    offcfg) printf '[sinks.phar]\nsignature="off"\n' > "$WORK/c.toml"; EXT="-d extension=$WORK/howdah.so -d howdah.config=$WORK/c.toml -d howdah.log=$LOG" ;;
  esac
  # shellcheck disable=SC2086
  OUT=$(php $EXT -d date.timezone=UTC "$WORK/client.php" "$2" "$3" 2>"$WORK/cerr.txt"); RC=$?
}
logged() { grep -q '"rule":"phar_signature"' "$LOG" && echo 1 || echo 0; }

# ---- Is this PHP vulnerable? Probe the downgraded native phar with Howdah OFF.
run_client off ctor "$FX/d-native.phar"
case $OUT in
  LOADED*) VULN=1; record probe PASS "stock PHP accepts a keyless-signed phar beside a pinned .pubkey (CVE-2026-128090 reproduced)" ;;
  REFUSED*) VULN=0; record probe PASS "stock PHP already refuses the downgrade (fixed upstream in this build); off/detect arms expect REFUSED" ;;
  *) record probe FAIL "probe inconclusive: $OUT rc=$RC $(head -c 200 "$WORK/cerr.txt")"; exit 0 ;;
esac
[ "$VULN" = 1 ] && OFFWANT=LOADED || OFFWANT=REFUSED

chk() { # <name> <want-result> <want-logged>
  res=${OUT%%|*}
  if [ "$res" = "$2" ] && [ "$(logged)" = "$3" ] && [ "${OUT#*|}" = "alive" ]; then
    record "$1" PASS "$res logged=$3 (worker alive)"
  else
    record "$1" FAIL "got '$OUT' rc=$RC logged=$(logged), want $2 logged=$3 ($(head -c 150 "$WORK/cerr.txt"))"
  fi
}

for fmt in native tar zip; do
  case $fmt in native) ext=phar ;; tar) ext=phar.tar ;; zip) ext=phar.zip ;; esac
  if [ "$fmt" != native ]; then
    # PharData refuses names containing .phar: use plain .tar/.zip copies (+ pubkey).
    for k in g d n; do
      cp "$FX/$k-$fmt.$ext" "$FX/$k-pd.$fmt"
      [ -f "$FX/$k-$fmt.$ext.pubkey" ] && cp "$FX/$k-$fmt.$ext.pubkey" "$FX/$k-pd.$fmt.pubkey"
    done
  fi
  G="$FX/g-$fmt.$ext"; D="$FX/d-$fmt.$ext"; N="$FX/n-$fmt.$ext"
  probes="ctor inc"; [ "$fmt" != native ] && probes="ctor inc pdata"; [ "$fmt" = native ] && probes="ctor inc load"
  for pr in $probes; do
    G="$FX/g-$fmt.$ext"; D="$FX/d-$fmt.$ext"; N="$FX/n-$fmt.$ext"
    [ "$pr" = pdata ] && { G="$FX/g-pd.$fmt"; D="$FX/d-pd.$fmt"; N="$FX/n-pd.$fmt"; }
    # genuine OpenSSL phar: loads with Howdah on, never logged
    run_client default "$pr" "$G"; chk "$fmt/$pr/genuine/default" LOADED 0
    # no sibling .pubkey: unaffected under both
    run_client off "$pr" "$N";     chk "$fmt/$pr/nopubkey/off" LOADED 0
    run_client default "$pr" "$N"; chk "$fmt/$pr/nopubkey/default" LOADED 0
    # downgraded: bug with Howdah off / signature=off / detect; refused + logged by default
    run_client off "$pr" "$D";    chk "$fmt/$pr/downgrade/off" $OFFWANT 0
    run_client offcfg "$pr" "$D"; chk "$fmt/$pr/downgrade/sig-off" $OFFWANT 0
    run_client detect "$pr" "$D"; chk "$fmt/$pr/downgrade/detect" $OFFWANT 1
    run_client default "$pr" "$D"; chk "$fmt/$pr/downgrade/default-block" REFUSED 1
  done
done

# Logged line carries the rule + a fixed reason only: no path, no archive bytes.
run_client default ctor "$FX/d-native.phar"
if grep -q '"reason":"signature-downgrade' "$LOG" && ! grep -Eq 'd-native|/work|\.phar|/fx|\.zip|\.tar' "$LOG"; then
  record log-contract PASS "phar_signature / signature-downgrade logged without path or bytes"
else
  record log-contract FAIL "$(head -c 300 "$LOG")"
fi

# Whole-archive compressed phar: signature type not readable => detect only.
if [ "$HAVE_GZ" = 1 ]; then
  run_client default ctor "$FX/dz.phar.gz"
  if grep -q '"rule":"phar_signature"' "$LOG" && grep -q 'signature-indeterminate' "$LOG" && ! grep -q '"action":"block"' "$LOG"; then
    record compressed/detect-only PASS "indeterminate logged, not blocked (result: ${OUT%%|*})"
  else
    record compressed/detect-only FAIL "out='$OUT' log=$(head -c 300 "$LOG")"
  fi
else
  record compressed/detect-only SKIP "could not build a whole-archive .phar.gz in this image (no zlib?)"
fi
exit 0
