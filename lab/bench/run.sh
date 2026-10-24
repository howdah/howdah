#!/bin/sh
# Howdah latency benchmark -- host orchestrator. One command, from the repo root:
#
#   sh lab/bench/run.sh                 # full run: PHP 5.6 7.4 8.3, fpm + apache
#   MODE=ci sh lab/bench/run.sh         # CI short mode: PHP 8.3, fpm, 10 s cells
#
# For every PHP version and server type it starts one lab dev container
# (howdah-dev-php<ver> for php-fpm, howdah-dev-apache-php<ver> for Apache
# mod_php), builds the extension in it once, and then measures every
# workload x configuration cell with wrk from the tools image. nginx (php-fpm
# cells) and wrk both join the PHP container's network namespace, so all
# traffic is loopback. Workloads are the outer loop and configurations the
# inner loop (rotated each round), so a cell and its no-extension baseline
# are measured minutes apart at most.
#
# Knobs (environment):
#   VERSIONS   PHP minors              (full: "5.6 7.4 8.3"; ci: "8.3")
#   SAPIS      fpm and/or apache       (full: "fpm apache"; ci: "fpm")
#   CONFIGS    noext l1 l12 l123
#   WORKLOADS  get_nobody post_form_1k post_multipart_50k sink_exec_include
#   DURATION   seconds measured per round      (full: 6; ci: 10)
#   WARMUP     seconds discarded before it     (full: 2; ci: 2)
#   ROUNDS     rounds per cell, median taken   (full: 5; ci: 1)
#   CONNS      wrk connections (1: one request at a time, so a p50 is one
#              request's own time, with no queueing anywhere)
#   WORKERS    php-fpm children in the static pool (4)
#   PIN        auto | off   (auto pins PHP, nginx and wrk to separate CPUs
#              when the host has 8 or more: SRV_CPUS=2-5 FE_CPUS=6 CL_CPUS=1;
#              in MODE=ci all three share SHARED_CPUS=2-5 instead, the shape
#              of a 4-vCPU GitHub runner)
#   OUT        output directory (default lab/bench/out/<UTC timestamp>)
#
# Output: $OUT/raw.jsonl (one line per round), $OUT/machine.json (machine spec
# and parameters), $OUT/results.json and $OUT/results.md (per-cell medians,
# added microseconds versus no extension). Needs docker and node.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BENCH="$ROOT/lab/bench"
MODE="${MODE:-full}"
if [ "$MODE" = ci ]; then
  : "${VERSIONS:=8.3}" "${SAPIS:=fpm}" "${DURATION:=10}" "${WARMUP:=2}" "${ROUNDS:=1}"
else
  # Five short rounds rather than three long ones: on a shared machine a burst
  # of other work spoils a round or two, and the median of five drops them.
  : "${VERSIONS:=5.6 7.4 8.3}" "${SAPIS:=fpm apache}" "${DURATION:=6}" "${WARMUP:=2}" "${ROUNDS:=5}"
fi
: "${CONFIGS:=noext l1 l12 l123}"
: "${WORKLOADS:=get_nobody post_form_1k post_multipart_50k sink_exec_include}"
: "${CONNS:=1}" "${WORKERS:=4}" "${PIN:=auto}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
: "${OUT:=$BENCH/out/$STAMP}"
TOOLS=howdah-bench-tools
SRV="howdah-bench-srv-$$"
FE="howdah-bench-fe-$$"

command -v docker >/dev/null 2>&1 || { echo "run.sh: docker is required" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "run.sh: node is required" >&2; exit 1; }

NPROC=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN)
if [ "$MODE" = ci ]; then
  # CI shape: php, nginx and wrk share 4 CPUs, as on a GitHub-hosted runner.
  # On a bigger machine all three are pinned to the same 4 CPUs, so a local
  # run (and lab/bench/baseline-ci.json) is measured the way CI measures.
  if [ "$PIN" = auto ] && [ "$NPROC" -ge 8 ]; then
    : "${SHARED_CPUS:=2-5}"
    SRV_PIN="--cpuset-cpus=$SHARED_CPUS"; FE_PIN="$SRV_PIN"; CL_PIN="$SRV_PIN"
    PINNING="php, nginx and wrk share CPUs $SHARED_CPUS (CI shape)"
  else
    SRV_PIN=""; FE_PIN=""; CL_PIN=""
    PINNING="none ($NPROC CPUs shared by php, nginx and wrk)"
  fi
elif [ "$PIN" = auto ] && [ "$NPROC" -ge 8 ]; then
  : "${SRV_CPUS:=2-5}" "${FE_CPUS:=6}" "${CL_CPUS:=1}"
  SRV_PIN="--cpuset-cpus=$SRV_CPUS"; FE_PIN="--cpuset-cpus=$FE_CPUS"; CL_PIN="--cpuset-cpus=$CL_CPUS"
  PINNING="php $SRV_CPUS, nginx $FE_CPUS, wrk $CL_CPUS"
else
  SRV_PIN=""; FE_PIN=""; CL_PIN=""
  PINNING="none ($NPROC CPUs shared by php, nginx and wrk)"
fi
# wrk needs at least one connection per thread.
THREADS=1
[ "$CONNS" -ge 4 ] && THREADS=2

mkdir -p "$OUT/logs"
RAW="$OUT/raw.jsonl"; : > "$RAW"
LOAD_START=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown)

cleanup() {
  docker rm -f "$FE" >/dev/null 2>&1 || true
  docker rm -f "$SRV" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

feature_of() { case "$1" in 5.*) echo php5 ;; 7.*) echo php7 ;; *) echo php8 ;; esac; }

ensure_image() { # sapi minor -> prints image name (builds it when missing)
  if [ "$1" = apache ]; then
    _img="howdah-dev-apache-php$2"
    if ! docker image inspect "$_img" >/dev/null 2>&1; then
      echo "== building $_img (BASE=php:$2-apache)" >&2
      docker build -q -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=php:$2-apache" -t "$_img" "$ROOT" >&2
    fi
  else
    _img="howdah-dev-php$2"
    if ! docker image inspect "$_img" >/dev/null 2>&1; then
      if ! docker image inspect "lab-php-$2" >/dev/null 2>&1; then
        echo "== building lab-php-$2" >&2
        docker build -q -f "$ROOT/lab/images/php-$2.Dockerfile" -t "lab-php-$2" "$ROOT/lab/images" >&2
      fi
      echo "== building $_img (BASE=lab-php-$2)" >&2
      docker build -q -f "$ROOT/lab/images/dev.Dockerfile" --build-arg "BASE=lab-php-$2" -t "$_img" "$ROOT" >&2
    fi
  fi
  echo "$_img"
}

# workload -> METHOD RPATH BODY CTYPE (BODY is a path inside the client)
set_workload() {
  BODY=""; CTYPE=""
  case "$1" in
    get_nobody)         METHOD=GET;  RPATH=/index.php ;;
    post_form_1k)       METHOD=POST; RPATH=/index.php; BODY=/bodies/form-1k.txt; CTYPE="application/x-www-form-urlencoded" ;;
    post_multipart_50k) METHOD=POST; RPATH=/index.php; BODY=/bodies/multipart-50k.bin; CTYPE="multipart/form-data; boundary=----HowdahBench0" ;;
    sink_exec_include)  METHOD=GET;  RPATH=/sink.php ;;
    *) echo "run.sh: unknown workload $1" >&2; exit 1 ;;
  esac
}

client() { # seconds -> wrk output on stdout
  # shellcheck disable=SC2086
  docker run --rm --network "container:$SRV" $CL_PIN \
    -v "$BENCH":/bench:ro -v "$OUT/bodies":/bodies:ro \
    -e BENCH_METHOD="$METHOD" -e BENCH_BODY="$BODY" -e BENCH_CTYPE="$CTYPE" \
    "$TOOLS" wrk -t"$THREADS" -c"$CONNS" -d"${1}s" --timeout 5s -s /bench/wrk.lua "$URL$RPATH"
}

rotate() { # n item... -> items rotated left by n
  _n=$1; shift
  _i=0
  while [ "$_i" -lt "$_n" ]; do _x=$1; shift; set -- "$@" "$_x"; _i=$((_i + 1)); done
  echo "$@"
}

echo "== tools image"
docker build -q -f "$BENCH/tools.Dockerfile" -t "$TOOLS" "$BENCH" >/dev/null
node "$BENCH/bench.mjs" bodies "$OUT/bodies"

NCONF=$(echo "$CONFIGS" | wc -w | tr -d ' ')
TOTAL=$(( $(echo "$VERSIONS" | wc -w) * $(echo "$SAPIS" | wc -w) * $(echo "$WORKLOADS" | wc -w) * NCONF * ROUNDS ))
N=0
for V in $VERSIONS; do
  for S in $SAPIS; do
    IMG=$(ensure_image "$S" "$V")
    cleanup
    # shellcheck disable=SC2086
    docker run -d --init --name "$SRV" $SRV_PIN -e WORKERS="$WORKERS" \
      -v "$ROOT":/src:ro -v "howdah-bench-target-$IMG":/tmp/t -v howdah-bench-cargo:/opt/cargo/registry \
      "$IMG" sleep infinity >/dev/null
    echo "== $IMG: building the extension"
    docker exec "$SRV" sh /src/lab/bench/server.sh build "$(feature_of "$V")" > "$OUT/logs/build-$V-$S.txt"
    PHPVER=$(tail -1 "$OUT/logs/build-$V-$S.txt")
    if [ "$S" = fpm ]; then
      URL=http://127.0.0.1:8080
      # shellcheck disable=SC2086
      docker run -d --name "$FE" --network "container:$SRV" $FE_PIN -v "$BENCH":/bench:ro \
        "$TOOLS" nginx -c /bench/nginx.conf >/dev/null
    else
      URL=http://127.0.0.1:80
    fi
    for W in $WORKLOADS; do
      set_workload "$W"
      R=1
      while [ "$R" -le "$ROUNDS" ]; do
        # shellcheck disable=SC2086
        for C in $(rotate $(( (R - 1) % NCONF )) $CONFIGS); do
          N=$((N + 1))
          TAG="$V-$S-$W-$C-r$R"
          if ! PROBE=$(docker exec "$SRV" sh /src/lab/bench/server.sh start "$S" "$C" 2> "$OUT/logs/$TAG.start.err"); then
            echo "[$N/$TOTAL] $TAG: server did not start with this config (see logs/$TAG.start.err)" >&2
            exit 1
          fi
          PROBE=$(echo "$PROBE" | tail -1)
          client "$WARMUP" > "$OUT/logs/$TAG.warmup.txt" 2>&1 || true
          EVW=$(docker exec "$SRV" sh /src/lab/bench/server.sh events)
          docker exec "$SRV" sh /src/lab/bench/server.sh reset
          client "$DURATION" > "$OUT/logs/$TAG.txt" 2>&1 || true
          EV=$(docker exec "$SRV" sh /src/lab/bench/server.sh events)
          docker exec "$SRV" sh /src/lab/bench/server.sh stop "$S"
          WRK=$(sed -n 's/^BENCHJSON //p' "$OUT/logs/$TAG.txt" | tail -1)
          [ -n "$WRK" ] || WRK=null
          # 1-minute load average at the end of the round: shows when other
          # work on the machine overlapped a round.
          LOAD1=$(cut -d' ' -f1 /proc/loadavg 2>/dev/null || echo 0)
          printf '{"php":"%s","minor":"%s","sapi":"%s","workload":"%s","config":"%s","round":%d,"events":%d,"events_warmup":%d,"load1":%s,"probe":%s,"wrk":%s}\n' \
            "$PHPVER" "$V" "$S" "$W" "$C" "$R" "$EV" "$EVW" "${LOAD1:-0}" "$PROBE" "$WRK" >> "$RAW"
          P50=$(echo "$WRK" | sed -n 's/.*"p50":\([0-9]*\).*/\1/p')
          echo "[$N/$TOTAL] php $PHPVER $S $W $C round $R: p50 ${P50:-?} us, events $EV"
        done
        R=$((R + 1))
      done
    done
    cleanup
  done
done

# Machine spec, captured at the end so the load average covers the run.
jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
CPU=$(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo 2>/dev/null | head -1)
GOV=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)
OSN=$(sed -n 's/^PRETTY_NAME="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' /etc/os-release 2>/dev/null | head -1)
MEMKB=$(sed -n 's/^MemTotal:[[:space:]]*\([0-9]*\).*/\1/p' /proc/meminfo 2>/dev/null)
DOCKER_V=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)
WRK_V=$(docker run --rm "$TOOLS" wrk --version 2>&1 | head -1 | cut -d' ' -f1-2)
NGINX_V=$(docker run --rm "$TOOLS" nginx -v 2>&1 | sed 's/^nginx version: //')
COMMIT=$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
HVER=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
LOAD_END=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo unknown)
cat > "$OUT/machine.json" <<EOF
{
  "date_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "started_utc": "$STAMP",
  "cpu_model": "$(jstr "$CPU")",
  "nproc": $NPROC,
  "kernel": "$(jstr "$(uname -r)")",
  "os": "$(jstr "$OSN")",
  "mem_total_kb": ${MEMKB:-0},
  "cpu_governor": "$(jstr "$GOV")",
  "docker": "$(jstr "$DOCKER_V")",
  "wrk": "$(jstr "$WRK_V")",
  "nginx": "$(jstr "$NGINX_V")",
  "howdah_version": "$(jstr "$HVER")",
  "git_commit": "$(jstr "$COMMIT")",
  "pinning": "$(jstr "$PINNING")",
  "loadavg_start": "$(jstr "$LOAD_START")",
  "loadavg_end": "$(jstr "$LOAD_END")",
  "params": {
    "mode": "$MODE",
    "versions": "$(jstr "$VERSIONS")",
    "sapis": "$(jstr "$SAPIS")",
    "configs": "$(jstr "$CONFIGS")",
    "workloads": "$(jstr "$WORKLOADS")",
    "duration_s": $DURATION,
    "warmup_s": $WARMUP,
    "rounds": $ROUNDS,
    "conns": $CONNS,
    "fpm_workers": $WORKERS,
    "wrk_threads": $THREADS
  }
}
EOF

echo
node "$BENCH/bench.mjs" report "$RAW" "$OUT/machine.json" "$OUT"
echo
echo "results: $OUT/results.json and $OUT/results.md"
