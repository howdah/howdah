# Milestone 0 findings: rfc1867 hook-point spike

**Gate verdict: PASS, with one precision the glue layer must respect.**

On every PHP version measured (5.4.16, 5.6, 7.3, 7.4, 8.1, 8.4; all NTS,
non-debug builds), chaining `php_rfc1867_callback` and returning `FAILURE`
from `MULTIPART_EVENT_FILE_START` once a hardcoded part count is exceeded:

- **stops per-part allocation.** Excess parts are dropped: `$_FILES` stays
  capped at the threshold and peak worker memory stays flat at the
  pre-request baseline, however large N grows. This is the security
  property the 0.1 defense needs.
- **does NOT abort the request.** Returning `FAILURE` only makes PHP stop
  materializing the offending part. PHP keeps scanning to the closing
  boundary (the callback is still invoked for every remaining part, and
  the last event seen is `MULTIPART_EVENT_END`), then runs the script
  normally with a truncated `$_FILES`. The callback alone does not refuse
  the request.

**Consequence for Task 9:** the allocation cap and the block response are
two separate mechanisms. The chained callback provides the cap (and the
counting); to actually refuse the request Task 9 must additionally produce
the block response (e.g. 413/403 and request termination) once the callback
has tripped, rather than assuming `FAILURE` ends the request. Task 9 must
also still chain to the previously installed callback (the spike probe does
not chain past the cap) so `session.upload_progress` keeps working.

Scope of the claim: only the six versions above were measured. The full
matrix (5.5, 7.0-7.2, 8.0, 8.2, 8.3, 8.5 as well) is Task 12's job. 5.5
could not be measured here (see below); 8.5 was never run.

## Environment

All PHP builds under test are **NTS** (non-ZTS), non-debug: the official
`php:<ver>-fpm` Docker images (5.6, 7.3, 7.4, 8.1, 8.4) and CentOS 7's stock
`php-5.4.16` RPM (`Zend Extension Build => ...NTS`). Linux x86_64.

## What was measured

- **Harness:** each version's own `php` CLI binary (present even in the
  `*-fpm` images) run as the built-in web server. The multipart parser and
  `php_rfc1867_callback` live in SAPI-independent core (`main/rfc1867.c`),
  so this exercises the same hook FPM/Apache/CGI use, without a FastCGI
  stack. `max_file_uploads` is raised to 100000 so PHP's own default cap
  (20) never masks the effect; only the probe's threshold (50) acts.
- **Shaped request:** N empty (0-byte) file parts with short names,
  structure only, no payload. N=40000 is ~5.3 MB, under the 8 MiB default
  `post_max_size`. The generator is kept out of the repo at the gitignored
  path `private/gen-shaped-request.js` (`node private/gen-shaped-request.js N`
  writes the body to stdout, boundary `howdahSpikeBoundary0123456789`).
  The response script `private/mem-probe.php` is also gitignored; it prints
  JSON with `count($_FILES)`, `memory_get_peak_usage(true)` and, if loaded,
  the probe extension's `probe_file_start_count()`, `probe_last_event()`,
  `probe_aborted()`.
- **Probe extension:** `lab/spike/probe.c` (+ `config.m4`), threshold 50,
  counting `MULTIPART_EVENT_FILE_START` (value 2). It saves the prior
  callback and chains to it below the cap, but returns `FAILURE`
  immediately above it. Version gates on `PHP_VERSION_ID`: callback return
  type (`int` through 7.x, `zend_result` from 8.0), local `TSRMLS_*` macros
  (removed from 8.x headers), and `zend_long` (absent before 7.0).

## Reproducible command sequence

Run from the repo root, per service `S` in `php-5.4 php-5.6 php-7.3 php-7.4
php-8.1 php-8.4` (images in `lab/images/`, services in `lab/compose.yaml`):

```sh
# 1. images + containers (long-running, /lab/spike mounted read-only)
docker compose -f lab/compose.yaml up -d --build S

# 2. build the probe inside the container
docker compose -f lab/compose.yaml exec S sh -c \
  'cp -r /lab/spike /tmp/spike && cd /tmp/spike && phpize && ./configure --enable-probe && make'
# -> /tmp/spike/modules/probe.so

# 3. shaped bodies (generator is gitignored) and the response script
for n in 50 500 5000 40000; do node private/gen-shaped-request.js $n > body_$n.bin; done
docker cp private/mem-probe.php <container>:/tmp/mem-probe.php
docker cp body_$n.bin <container>:/tmp/body_$n.bin      # for each n

# 4. baseline server (no extension), then defended server (extension loaded)
php -d memory_limit=512M -d post_max_size=16M -d upload_max_filesize=16M \
    -d max_file_uploads=100000 -S 127.0.0.1:8080 /tmp/mem-probe.php
php -d memory_limit=512M -d post_max_size=16M -d upload_max_filesize=16M \
    -d max_file_uploads=100000 -d extension=/tmp/spike/modules/probe.so \
    -S 127.0.0.1:8081 /tmp/mem-probe.php

# 5. send the shaped request (inside the container), once per N and port
curl -s -X POST \
  -H 'Content-Type: multipart/form-data; boundary=howdahSpikeBoundary0123456789' \
  --data-binary @/tmp/body_$n.bin http://127.0.0.1:PORT/
```

Lab-image notes: PHP 5.6 (Debian stretch) needs `archive.debian.org` and
`--allow-unauthenticated` (expired archive keys); 7.3/7.4 (bullseye) need
the image's own `snapshot.debian.org` pin and `Check-Valid-Until=false`;
5.4 uses `vault.centos.org` baseurls. All encoded in the Dockerfiles.

## Raw outputs

Each line is the script's JSON for one request (`files` = `count($_FILES)`,
`peak` = `memory_get_peak_usage(true)`, `probe_*` = -1 when the extension
is not loaded). Baseline = port 8080, defended = port 8081/8082.

### PHP 5.4.16 (CentOS 7)

```
baseline N=50    {"files":50,"peak":524288,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=500   {"files":500,"peak":1048576,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=5000  {"files":5000,"peak":8650752,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=40000 {"files":40000,"peak":67371008,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
defended N=50    {"files":50,"peak":524288,"probe_count":50,"probe_last_event":5,"probe_aborted":0}
defended N=500   {"files":50,"peak":524288,"probe_count":500,"probe_last_event":5,"probe_aborted":1}
defended N=5000  {"files":50,"peak":524288,"probe_count":5000,"probe_last_event":5,"probe_aborted":1}
defended N=40000 {"files":50,"peak":524288,"probe_count":40000,"probe_last_event":5,"probe_aborted":1}
```

### PHP 5.6

```
baseline N=50    {"files":50,"peak":524288,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=500   {"files":500,"peak":1048576,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=5000  {"files":5000,"peak":8650752,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=40000 {"files":40000,"peak":67371008,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
defended N=50    {"files":50,"peak":524288,"probe_count":50,"probe_last_event":5,"probe_aborted":0}
defended N=500   {"files":50,"peak":524288,"probe_count":500,"probe_last_event":5,"probe_aborted":1}
defended N=5000  {"files":50,"peak":524288,"probe_count":5000,"probe_last_event":5,"probe_aborted":1}
defended N=40000 {"files":50,"peak":524288,"probe_count":40000,"probe_last_event":5,"probe_aborted":1}
```

The 5.4.16 and 5.6 baselines are byte-identical at all four sizes. That is
expected, not a copy-paste: the PHP 5.x line (5.2 through 5.6) shares the
same Zend memory manager (`zend_alloc.c`, the pre-PHP 7 allocator) and the same rfc1867 per-file bookkeeping,
so the same request allocates the same heap. The two runs were separate
containers (CentOS RPM vs Docker image) captured independently above. PHP 7
replaced the allocator (2 MiB chunks), which is why 7.x/8.x start at 2 MiB.

### PHP 7.3

```
baseline N=50    {"files":50,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=500   {"files":500,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=5000  {"files":5000,"peak":6291456,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=40000 {"files":40000,"peak":34078720,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
defended N=50    {"files":50,"peak":2097152,"probe_count":50,"probe_last_event":5,"probe_aborted":0}
defended N=500   {"files":50,"peak":2097152,"probe_count":500,"probe_last_event":5,"probe_aborted":1}
defended N=5000  {"files":50,"peak":2097152,"probe_count":5000,"probe_last_event":5,"probe_aborted":1}
defended N=40000 {"files":50,"peak":2097152,"probe_count":40000,"probe_last_event":5,"probe_aborted":1}
```

### PHP 7.4

(Baseline ran at N=50/500/2000/5000/20000/40000 on 7.4; shown here with
the extra points.)

```
baseline N=50    {"files":50,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=500   {"files":500,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=2000  {"files":2000,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=5000  {"files":5000,"peak":6291456,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=20000 {"files":20000,"peak":17301504,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=40000 {"files":40000,"peak":27787264,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
defended N=50    {"files":50,"peak":2097152,"probe_count":50,"probe_last_event":5,"probe_aborted":0}
defended N=500   {"files":50,"peak":2097152,"probe_count":500,"probe_last_event":5,"probe_aborted":1}
defended N=5000  {"files":50,"peak":2097152,"probe_count":5000,"probe_last_event":5,"probe_aborted":1}
defended N=20000 {"files":50,"peak":2097152,"probe_count":20000,"probe_last_event":5,"probe_aborted":1}
defended N=40000 {"files":50,"peak":2097152,"probe_count":40000,"probe_last_event":5,"probe_aborted":1}
```

(The 7.4 N=40000 baseline varies run to run, 27.8 MB here and 34.1 MB in a
second baseline pass on a rebuilt container; the heap-growth pattern, not
the exact byte count above 2 MiB, is what matters.)

### PHP 8.1

```
baseline N=50    {"files":50,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=500   {"files":500,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=5000  {"files":5000,"peak":6291456,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=40000 {"files":40000,"peak":46137344,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
defended N=50    {"files":50,"peak":2097152,"probe_count":50,"probe_last_event":5,"probe_aborted":0}
defended N=500   {"files":50,"peak":2097152,"probe_count":500,"probe_last_event":5,"probe_aborted":1}
defended N=5000  {"files":50,"peak":2097152,"probe_count":5000,"probe_last_event":5,"probe_aborted":1}
defended N=40000 {"files":50,"peak":2097152,"probe_count":40000,"probe_last_event":5,"probe_aborted":1}
```

### PHP 8.4

```
baseline N=50    {"files":50,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=500   {"files":500,"peak":2097152,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=5000  {"files":5000,"peak":8388608,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
baseline N=40000 {"files":40000,"peak":50331648,"probe_count":-1,"probe_last_event":-1,"probe_aborted":-1}
defended N=50    {"files":50,"peak":2097152,"probe_count":50,"probe_last_event":5,"probe_aborted":0}
defended N=500   {"files":50,"peak":2097152,"probe_count":500,"probe_last_event":5,"probe_aborted":1}
defended N=5000  {"files":50,"peak":2097152,"probe_count":5000,"probe_last_event":5,"probe_aborted":1}
defended N=40000 {"files":50,"peak":2097152,"probe_count":40000,"probe_last_event":5,"probe_aborted":1}
```

## Summary table

| PHP (NTS) | Baseline peak N=50/500/5000/40000 | Defended peak (all N) | Event | `files` defended | FAILURE stops allocation? | Request aborted by callback? |
|---|---|---|---|---|---|---|
| 5.4.16 | 524288 / 1048576 / 8650752 / 67371008 | 524288 | `FILE_START` (2) | 50 | Yes | No |
| 5.6 | 524288 / 1048576 / 8650752 / 67371008 | 524288 | `FILE_START` (2) | 50 | Yes | No |
| 7.3 | 2097152 / 2097152 / 6291456 / 34078720 | 2097152 | `FILE_START` (2) | 50 | Yes | No |
| 7.4 | 2097152 / 2097152 / 6291456 / 27787264 | 2097152 | `FILE_START` (2) | 50 | Yes | No |
| 8.1 | 2097152 / 2097152 / 6291456 / 46137344 | 2097152 | `FILE_START` (2) | 50 | Yes | No |
| 8.4 | 2097152 / 2097152 / 8388608 / 50331648 | 2097152 | `FILE_START` (2) | 50 | Yes | No |

`MULTIPART_EVENT_FILE_START` fires once per file part before any content is
read and was reliable for counting on all six versions. In every defended
run `probe_file_start_count` equals the full N sent while `files` stays 50,
and `probe_last_event` is `MULTIPART_EVENT_END` (5): parsing ran to the end.

### PHP 5.5: not measured

`php:5.5-fpm` and `php:5.5.38-fpm` failed to pull (`failed to extract
layer ... content digest ... not found`, reproduced after re-pull and
`docker builder prune`), an environment/registry fault. 5.5 lies between
the measured 5.4 and 5.6, which share an identical `rfc1867.h` callback
shape, but that is an inference, not a measurement. `php-5.5.Dockerfile`
is written but untested. The full matrix is Task 12's job.

## Committed vs gitignored

Committed: `lab/images/php-{5.4,5.5,5.6,7.3,7.4,8.1,8.4}.Dockerfile`,
`lab/compose.yaml`, `lab/spike/probe.c`, `lab/spike/config.m4` (build
descriptor for probe.c), and this doc.

Gitignored (never staged): `private/gen-shaped-request.js` (generator) and
`private/mem-probe.php` (response script). `/private/` is ignored whole,
independent of filename. No `lab/spike/measure.sh` exists; the commands are
the sequence above.
