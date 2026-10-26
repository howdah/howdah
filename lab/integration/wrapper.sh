#!/bin/sh
# Howdah T4 include/open wrapper-scheme firewall integration test (host driver).
#
# Builds the extension into each howdah-dev-php<ver> image and runs
# wrapper_container.sh: include/require and fopen/file_get_contents/readfile of a
# non-file stream wrapper (php://filter chains, php://input, data:, expect://,
# remote http(s)) and of a poisonable local target (/proc/self/environ, the
# session dir, error_log) must be refused clean (the sink returns false / the
# include is skipped and the SCRIPT CONTINUES — the worker survives, exactly like
# the command_exec / include sinks), logged as rule include_wrapper / file_open
# with only a scheme/category label (never the target). A benign include corpus
# (relative templates, autoloader paths, absolute config, vendor autoload) and
# the legitimate open targets (php://input, php://temp, remote fetch) must
# produce ZERO blocks. On PHP 7.0+ the opcode mechanism is exercised too; on 5.x
# only the compile-swap exists (an include served from a warm opcache is not
# re-inspected — an inherent, documented caveat, noted per run).
#
# Usage (repo root):
#   lab/integration/wrapper.sh                         # the full matrix
#   lab/integration/wrapper.sh 8.3                     # one minor
#   lab/integration/wrapper.sh 5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5
#
# Needs the howdah-dev-php<minor> images from lab/images/dev.Dockerfile.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSIONS="${*:-5.4 5.6 7.0 7.4 8.0 8.1 8.3 8.5}"

feature() {
  case "$1" in
    5.*) echo php5 ;;
    7.*) echo php7 ;;
    *)   echo php8 ;;
  esac
}

rc=0
for V in $VERSIONS; do
  IMG="howdah-dev-php$V"
  F=$(feature "$V")
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    echo "SKIP php$V (missing image $IMG; see lab/images/dev.Dockerfile)"
    continue
  fi
  echo "================ php $V ($F) ================"
  if docker run --rm -v "$ROOT":/src:ro "$IMG" sh /src/lab/integration/wrapper_container.sh "$F"; then
    :
  else
    echo "FAIL php$V"
    rc=1
  fi
done
exit $rc
