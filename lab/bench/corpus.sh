#!/bin/sh
# Howdah Layer 2 detection / false-positive run against the GoTestWAF corpus.
# One command, from the repo root:
#
#   sh lab/bench/corpus.sh
#
# What it does: starts PHP 8.3 php-fpm (one child) behind nginx with Howdah at
# the shipped defaults (howdah.mode = detect, no TOML, so Layer 2 is on in
# detect mode), copies GoTestWAF's test cases out of its image, splits each
# into one file per encoder, and runs GoTestWAF once per split file with one
# worker and no delay. The target app (lab/bench/corpus/app.php) writes a marker line into
# the Howdah event log for every request that reaches PHP, so each Howdah line
# is attributed to the request that caused it. bench.mjs then counts, per
# GoTestWAF test case, how many requests that reached PHP got a Layer 2 event
# (sql_injection, path_traversal or command_injection).
#
# Framing (keep it when quoting the numbers): Layer 2 is deliberately narrow
# (three classes, linear-time signatures, log-only by default). This measures
# what it flags of a standard corpus. It is not a WAF score: GoTestWAF's own
# score assumes a blocking WAF and would read 0% for any log-only tool.
#
# GoTestWAF runs from its published Docker image, pinned by digest (MIT
# licence, github.com/wallarm/gotestwaf); its payloads ship inside the image,
# so nothing is vendored here. --noEmailReport keeps the report local.
#
# Knobs: VERSION (8.3), GOTESTWAF_IMAGE, OUT (lab/bench/out/corpus-<stamp>),
# CASES ("set/case ..." to run a subset).
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BENCH="$ROOT/lab/bench"
: "${VERSION:=8.3}"
: "${GOTESTWAF_IMAGE:=wallarm/gotestwaf@sha256:ff7184da90029a98c87bfdbadcee544c979b999593175d17b2d38f642ee29977}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
: "${OUT:=$BENCH/out/corpus-$STAMP}"
TOOLS=howdah-bench-tools
IMG="howdah-dev-php$VERSION"
SRV="howdah-corpus-srv-$$"
FE="howdah-corpus-fe-$$"

command -v docker >/dev/null 2>&1 || { echo "corpus.sh: docker is required" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "corpus.sh: node is required" >&2; exit 1; }

cleanup() {
  docker rm -f "$FE" >/dev/null 2>&1 || true
  docker rm -f "$SRV" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

mkdir -p "$OUT/events" "$OUT/reports" "$OUT/logs"
chmod 777 "$OUT/reports"

docker build -q -f "$BENCH/tools.Dockerfile" -t "$TOOLS" "$BENCH" >/dev/null
if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  if ! docker image inspect "lab-php-$VERSION" >/dev/null 2>&1; then
    docker build -q -f "$ROOT/lab/images/php-$VERSION.Dockerfile" -t "lab-php-$VERSION" "$ROOT/lab/images" >/dev/null
  fi
  docker build -q -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=lab-php-$VERSION" -t "$IMG" "$ROOT" >/dev/null
fi
if ! docker image inspect "$GOTESTWAF_IMAGE" >/dev/null 2>&1; then
  docker pull "$GOTESTWAF_IMAGE" >/dev/null
fi

case "$VERSION" in 5.*) FEATURE=php5 ;; 7.*) FEATURE=php7 ;; *) FEATURE=php8 ;; esac

cleanup
docker run -d --init --name "$SRV" -e WORKERS=1 \
  -v "$ROOT":/src:ro -v "howdah-bench-target-$IMG":/tmp/t -v howdah-bench-cargo:/opt/cargo/registry \
  "$IMG" sleep infinity >/dev/null
echo "== $IMG: building the extension"
docker exec "$SRV" sh /src/lab/bench/server.sh build "$FEATURE" > "$OUT/logs/build.txt"
PHPVER=$(tail -1 "$OUT/logs/build.txt")
docker run -d --name "$FE" --network "container:$SRV" -v "$BENCH":/bench:ro \
  "$TOOLS" nginx -c /bench/corpus/nginx.conf >/dev/null
docker exec "$SRV" sh /src/lab/bench/server.sh start fpm default > "$OUT/logs/start.txt"

GTW_VERSION=$(docker run --rm "$GOTESTWAF_IMAGE" --version 2>&1 | sed -n 's/.*\(v[0-9][0-9.]*\).*/\1/p' | tail -1)
HVER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)

# Copy the test cases out of the image and split each into one file per
# encoder (Plain / URL / Base64Flat), so every run has a single known encoder.
rm -rf "$OUT/testcases-orig" "$OUT/testcases"
CID=$(docker create "$GOTESTWAF_IMAGE")
docker cp "$CID:/app/testcases" "$OUT/testcases-orig" >/dev/null
docker rm "$CID" >/dev/null
ALL=$(node "$BENCH/bench.mjs" split "$OUT/testcases-orig" "$OUT/testcases" "$OUT/cases-index.json")
chmod -R a+rX "$OUT/testcases"

# CASES narrows the run to some original test cases ("owasp/sql-injection ...").
if [ -n "${CASES:-}" ]; then
  SEL=""
  for SC in $ALL; do
    for W in $CASES; do
      case "$SC" in "$W~"*) SEL="$SEL $SC" ;; esac
    done
  done
  ALL=$SEL
fi

for SC in $ALL; do
  SET=${SC%%/*}; ID=${SC#*/}
  NAME="${SET}__${ID}"
  docker exec "$SRV" sh /src/lab/bench/server.sh reset
  echo "== $SET/$ID"
  docker run --rm --network "container:$SRV" -v "$OUT/reports":/reports -v "$OUT/testcases":/split:ro \
    "$GOTESTWAF_IMAGE" --url http://127.0.0.1:8080/ --testCasesPath /split \
    --workers 1 --sendDelay 0 --randomDelay 1 --addDebugHeader \
    --skipWAFBlockCheck --skipWAFIdentification --noEmailReport --quiet \
    --reportFormat json --reportPath /reports --reportName "$NAME" \
    --testSet "$SET" --testCase "$ID" > "$OUT/logs/$NAME.txt" 2>&1 || echo "   (gotestwaf exited non-zero; see logs/$NAME.txt)"
  docker exec "$SRV" cat /tmp/bench/events.log > "$OUT/events/$NAME.log"
done

cat > "$OUT/meta.json" <<EOF
{
  "date_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "php": "$PHPVER",
  "sapi": "php-fpm behind nginx",
  "howdah_version": "$HVER",
  "git_commit": "$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)",
  "howdah_config": "shipped defaults (howdah.mode = detect, no TOML; Layer 2 detect)",
  "gotestwaf_version": "$GTW_VERSION",
  "gotestwaf_image": "$GOTESTWAF_IMAGE"
}
EOF

node "$BENCH/bench.mjs" corpus "$OUT"
echo
echo "results: $OUT/corpus.json and $OUT/corpus.md"
