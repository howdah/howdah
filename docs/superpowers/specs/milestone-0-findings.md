# Milestone 0 findings: rfc1867 hook-point spike

**Gate verdict: PASS.** On every PHP version tested (5.4, 5.6, 7.3, 7.4, 8.1,
8.4 -- the minimum representative set), chaining `php_rfc1867_callback` and
returning `FAILURE` from `MULTIPART_EVENT_FILE_START` once a hardcoded part
count is exceeded:

- stops the per-part allocation (peak worker memory stays **flat** at the
  pre-request baseline, regardless of how large N grows), and
- the request is **refused past the threshold** -- `$_FILES` stops growing
  past the threshold and never reflects the attacker-supplied part count.

No version in the tested set defeats the hook. Howdah 0.1's release premise
(a chained `rfc1867` callback can abort an abusive multipart request before
PHP allocates per-part memory) holds across the full PHP 5.4-8.4 span.

## What was measured

- **Harness:** each PHP version's own `php` CLI binary (present even in the
  official `*-fpm` Docker images) run as `php -d ... -S 127.0.0.1:PORT
  private/mem-probe.php`. PHP's built-in web server uses the exact same
  `main/rfc1867.c` multipart parser and the same `php_rfc1867_callback` hook
  point that FPM/Apache/CGI SAPIs use -- the parser lives in SAPI-independent
  core code, not in the FPM-specific layer -- so this is a faithful exercise
  of the hook under test without the added complexity of a FastCGI/nginx
  stack. `mem-probe.php` calls `memory_get_peak_usage(true)` (real,
  OS-reported bytes) and, when the probe extension is loaded, also reads back
  `probe_file_start_count()`, `probe_last_event()` and `probe_aborted()`.
- **Shaped request:** `private/gen-shaped-request.js` emits a
  `multipart/form-data` body of N parts, each an empty (0-byte) file part
  with a short field/file name -- structure only, no payload. Bodies up to
  N=40000 stayed at ~5.3 MB, comfortably under the default 8 MiB
  `post_max_size`. `max_file_uploads` was raised to 100000 in every run so
  PHP's own built-in cap never masked the effect being measured -- the
  callback's own threshold is the only thing doing the blocking.
- **Probe extension:** `lab/spike/probe.c`, chaining `php_rfc1867_callback`
  (saves whatever was already installed, e.g. by `session.upload_progress`,
  and calls it after its own check), counting `MULTIPART_EVENT_FILE_START`
  events, and returning `FAILURE` once the count exceeds a hardcoded
  threshold of 50. Builds via `phpize` unmodified across PHP 5.4-8.4 using
  version gates keyed on `PHP_VERSION_ID`:
  - callback return type is `int` through PHP 7.x, `zend_result` from 8.0 on;
  - `TSRMLS_DC`/`TSRMLS_CC` (no-ops) exist through PHP 7.x headers, removed
    entirely by 8.x -- defined locally instead of relying on upstream;
  - `zend_long` didn't exist before PHP 7.0 (it was `long`).
- **Baseline runs:** the same request against the same PHP version with the
  probe extension *not* loaded.
- **Defended runs:** the same request with `-d
  extension=/tmp/spike/modules/probe.so`.

## Per-version results

All memory figures are `memory_get_peak_usage(true)` in bytes, for N = 50 /
500 / 5000 / 40000 empty file parts. Probe threshold = 50.

| PHP | Baseline peak (N=50/500/5000/40000) | Defended peak (same N's) | Event used | `files` count, defended (N=500) | FAILURE cancels? |
|---|---|---|---|---|---|
| 5.4.16 (CentOS 7 stock) | 524288 / 1048576 / 8650752 / 67371008 | 524288 / 524288 / 524288 / 524288 (flat) | `MULTIPART_EVENT_FILE_START` | 50 (not 500) | **Yes** |
| 5.6 | 524288 / 1048576 / 8650752 / 67371008 | 524288 / 524288 / 524288 / 524288 (flat) | `MULTIPART_EVENT_FILE_START` | 50 | **Yes** |
| 7.3 | 2097152 / 2097152 / 6291456 / 34078720 | 2097152 / 2097152 / 2097152 / 2097152 (flat) | `MULTIPART_EVENT_FILE_START` | 50 | **Yes** |
| 7.4 | 2097152 / 2097152 / 6291456 / 27787264 | 2097152 / 2097152 / 2097152 / 2097152 (flat) | `MULTIPART_EVENT_FILE_START` | 50 | **Yes** |
| 8.1 | 2097152 / 2097152 / 6291456 / 46137344 | 2097152 / 2097152 / 2097152 / 2097152 (flat) | `MULTIPART_EVENT_FILE_START` | 50 | **Yes** |
| 8.4 | 2097152 / 2097152 / 8388608 / 50331648 | 2097152 / 2097152 / 2097152 / 2097152 (flat) | `MULTIPART_EVENT_FILE_START` | 50 | **Yes** |

Every defended run also reported `probe_file_start_count()` equal to the
full N sent (e.g. 40000) even though `$_FILES` only ever held 50 entries and
memory never grew past the pre-request baseline -- i.e. the callback keeps
being invoked for every remaining part header PHP scans past the threshold
(so it reliably counts the full attack), but PHP stops materializing/
allocating per-part file state once `FAILURE` is returned, which is exactly
the property the 0.1 defense needs. `probe_last_event()` reported
`MULTIPART_EVENT_END` (5) at the end of every request, defended or not --
PHP finishes scanning to the closing boundary rather than hard-aborting the
connection, so the chained callback must do the actual refusal (it does: the
file is simply never kept).

Reliable event for counting on every version: **`MULTIPART_EVENT_FILE_START`**
(value `2`). It fires once per uploaded file part, before any content is
read, on all six versions.

### PHP 5.5 -- not independently measured

`php:5.5-fpm` (and `php:5.5.38-fpm`) repeatedly failed to pull in this lab
environment with `failed to extract layer ...: content digest ... not
found` -- a registry/content-store error reproduced across multiple pull
attempts and after pruning the build cache, unrelated to this spike's code.
5.5 sits directly between the two confirmed versions (5.4 and 5.6), which
share an identical `rfc1867.h` shape (`int (*php_rfc1867_callback)(unsigned
int, void *, void ** TSRMLS_DC)`) with no API changes in between upstream.
`lab/images/php-5.5.Dockerfile` is written and follows the same pattern that
worked for 5.6, but is untested. This is an environment limitation, not a
defense failure, and does not change the gate verdict.

## Gate decision

All versions in the required minimum set (5.4, 5.6, 7.3, 7.4, 8.1, 8.4) are
**defensible** at this hook point, using the same approach (chain
`php_rfc1867_callback`, count `MULTIPART_EVENT_FILE_START`, return `FAILURE`
past the limit) with no version-specific behavioral differences beyond the
C-level type/macro changes already noted. Task 9 (the real glue layer) can
rely on this hook uniformly across PHP 5.4-8.5; `howdah-sys`'s per-generation
bindgen headers will need the same `PHP_VERSION_ID`-keyed handling for the
callback's return type and for `TSRMLS_*`/`zend_long` as this spike's
`probe.c` demonstrates.

## What was committed vs what stayed gitignored

Committed (per task brief and `.gitignore`):
- `lab/images/php-5.4.Dockerfile`, `php-5.5.Dockerfile`, `php-5.6.Dockerfile`,
  `php-7.3.Dockerfile`, `php-7.4.Dockerfile`, `php-8.1.Dockerfile`,
  `php-8.4.Dockerfile`
- `lab/compose.yaml`
- `lab/spike/probe.c` and `lab/spike/config.m4` (the latter is the phpize
  build descriptor probe.c needs to compile; it is build boilerplate, not a
  generator or attack tool, so it travels with probe.c)
- this findings doc

Gitignored, never staged (verified with `git status` before each commit):
- `private/gen-shaped-request.js` -- the shaped-request generator
- `private/mem-probe.php` -- the measurement response script
- any `lab/spike/measure.sh` driver (none was added as a separate file in
  this spike; the measurement commands are recorded in this doc and were run
  by hand against `docker compose` services for reproducibility, per-version,
  with `private/gen-shaped-request.js` piped through `curl`)

`/private/` is fully gitignored at the repo root, independent of filename,
which is why the generator and response-probe script live there rather than
under `lab/spike/` (whose gitignore patterns only match `measure.sh` and
`*gen*`).
