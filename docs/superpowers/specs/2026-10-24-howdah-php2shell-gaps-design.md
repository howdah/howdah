# Howdah: closing the PHP2Shell request-parsing gaps (design)

**Status:** draft for owner review · 2026-10-24

Markers: **(owner)** = decided by the project owner. **(Claude's call)** = a
default proposed during design that the owner has not explicitly confirmed; the
builder may revisit these with a reason.

---

## 1. Why

PHP2Shell (CVE-2026-109618 / CVE-2026-109619) is what started Howdah. The owner
wants to put this sentence on howdah.org and have it be true, with lab evidence
behind it: **"Howdah blocks PHP2Shell on unpatched PHP."** **(owner)** It carries
a short qualifier underneath (approved by the owner; wording in §6).

Our current docs describe the CVE from secondary reports published before the
official advisories. The advisories and the upstream fix say something different:

- **GHSA-w8hw-w9fx-j79w (CVE-2026-109618).** When PHP hits `memory_limit` it
  longjmps out of the current operation. If that happens while request state is
  half-built, request shutdown later reads freed or uninitialized memory. The
  allocation that fails does not need to be related to the broken state. The
  advisory lists request-parsing paths that reach out-of-memory within PHP's
  apparent limits:
  1. multipart bodies with no usable declared length, which pass the
     `post_max_size` check and keep supplying data;
  2. unlimited headers per multipart part, whose in-memory form is much larger
     than their wire size;
  3. empty file controls, which don't count toward `max_file_uploads` but still
     build `$_FILES` arrays, multiplied by nested field names;
  4. application-specific large allocations.
- **GHSA-6wmf-4rv5-p3rp (CVE-2026-109619).** Worker-persistent globals keep
  pointers into the freed request heap when a fatal error (including
  out-of-memory) skips their reset. Session upload progress is one producer.
- **Upstream fix:** php-src `506e87fa7d` ("Avoid state corruption via bailout"),
  in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. It replaces the out-of-memory longjmp
  with a delayed "soft" limit and a hard `_exit()` limit across ~300 files. It
  also changes `main/rfc1867.c`: `fill_buffer` now enforces `post_max_size` on
  bytes actually read; `multipart_buffer_headers` keeps only
  `Content-Disposition`/`Content-Type` and drops duplicates;
  `multipart_buffer_read_body` uses a fallible realloc. Its request-parsing
  regression test is `Zend/tests/oom_request_parsing.phpt`.

PHP 5.4–8.1 will never get this fix. Howdah cannot fix the underlying bailout,
but it can stop a request from driving PHP to out-of-memory while PHP parses it.
That is what "blocks PHP2Shell" means here.

### 1.1 Where Howdah stands today (read from `origin/main` 16608c5)

| Advisory trigger | Today |
|---|---|
| (3) empty file controls with nested names | **Probably covered, untested.** On 8.4.26, `MULTIPART_EVENT_FILE_START` fires before PHP checks for an empty filename, and `howdah-core` counts the part as a file, so `max_files` should fire. Our 0.1 fixtures used named files, so this shape was never measured. |
| (2) header flood inside one part | **Gap A.** PHP parses all of a part's headers before it fires our callback, and the callback only exposes `Content-Disposition`. `max_part_headers` / `max_part_header_bytes` are documented as lower bounds; for this trigger they see nothing. |
| (1) body with no usable declared length | **Gap B.** PHP buffers a whole field value before `FORMDATA` fires. `max_parse_memory_bytes` defaults to 256 MiB, above the stock 128 MiB `memory_limit`, and is accounted after the fact. |
| nested field names (upstream's own regression test is urlencoded) | **Gap C.** `max_input_nesting_depth` (64) and `max_input_vars` (2000) are at or above PHP's own defaults, so they add nothing. Multipart field and file names bypass the nesting rule entirely (the input_filter skips multipart POST fields; file names never reach it). |
| (4) application-specific | Out of scope (§2). |

## 2. Goals, non-goals, anti-goals

**Goals**

- Close gaps A, B and C on every PHP version Howdah supports (5.4–8.5) that is
  unpatched, under Apache mod_php (prefork) and php-fpm, plus the SAPIs Layer 1
  already covers.
- The claim holds **at stock PHP settings and on servers that have raised
  them** (`post_max_size`, `upload_max_filesize`, `max_input_vars`,
  `max_file_uploads`, `max_input_nesting_level`, `memory_limit`). Upload-heavy
  sites often run `post_max_size` at or above `memory_limit`, and they are the
  most exposed. **(owner)** This is why §4.5 sizes the checks from the live
  `memory_limit`.
- Each new check **blocks out of the box**: it belongs to the Critical class
  that blocks even in `detect` mode, like `max_parts`/`max_files` today.
  **(Claude's call, raised with the owner during design and not objected to.)**
- Verify against **vulnerable** PHP builds in the lab (§5), and publish a
  per-trigger × version × SAPI evidence table on the coverage page.
- Also measure trigger (3), so the "probably" row becomes evidence.
- Add a backstop (§4.6): if PHP still runs out of memory on an unpatched
  version, end the worker before anything runs on the damaged state.
  **(owner)**
- Correct every page that describes the CVE from the early reports.

**Non-goals**

- Fixing or backporting PHP's out-of-memory handling.
- Preventing application-level out-of-memory (`json_decode`, `unserialize`,
  `str_repeat` and similar on attacker input). The upstream fix adds dozens of
  tests for these; a request filter cannot see them. The §4.6 backstop
  contains them instead: the worker ends before the damaged state is used, and
  that one request is lost.
- CVE-2026-109619 producers outside request parsing: PHP 8.5
  `fatal_error_backtraces`, execution timeouts, INI-diagnostic consumers.
  The session upload-progress producer runs *inside* request parsing (it is
  ext/session's rfc1867 callback, chained below Howdah's), so it **is** in
  scope: stopping the parse-time out-of-memory removes it. **(Claude's call:
  the owner's sentence says "PHP2Shell", which covers both CVEs.)**
- Building an exploit. Verification stops at the precondition (the worker
  reaches `memory_limit` during startup, or AddressSanitizer reports the memory
  error). No code-execution chain, heap grooming, or multi-worker race tooling.

**Anti-goals** (failure even if it technically works)

- Blocking legitimate traffic: large galleries, big forms, framework-style
  nested arrays, real chunked uploads. The benign corpus must stay at zero blocks
  at defaults.
- A new parser that client data can desynchronize into switching rules off, the
  bug class fixed in 1.2.1.
- Publishing the sentence for any version or SAPI the evidence table does not
  show as PASS.

## 3. Constraints

- PHP 5.4–8.5, Linux x86_64 and aarch64, NTS (the current support matrix).
- **No longjmp during request startup.** Refusals go through the RINIT delivery
  in `module::refuse` (see `2026-10-24-howdah-refusal-path-design.md`).
- Core logic is pure Rust in `howdah-core` with no PHP calls; `howdah-ext` stays
  thin glue; every FFI entry is `catch_unwind`-guarded.
- Logs record shapes and counts, never request content.
- Shared files (`ffi.rs`, `limits.rs`, `config.rs`, `howdah_core.h`) are also
  edited by a parallel session: coordinate via SendMessage before touching
  them, work in a worktree, never `git add -A`. Find the current peers with
  `ListAgents` at build time; names change between sessions.
- Any new config key needs a row in the web config editor, a `config.md` entry
  and a WASM rebuild. Another agent owns the editor; coordinate with it, and
  treat its row as a release dependency.

## 4. Mechanism

### 4.1 A raw-body hook: wrapping `sapi_module.read_post` (Claude's call)

Gaps A and B happen before PHP fires any rfc1867 event for the part involved,
so the callback cannot reach them. Every body reader PHP uses (the rfc1867
`fill_buffer`, the urlencoded reader) pulls bytes through
`sapi_module.read_post`.

- At MINIT, save the current `sapi_module.read_post` and install a wrapper,
  the same pattern `module.rs` already uses for `sapi_module.input_filter`.
  Restore it at MSHUTDOWN.
- The wrapper calls the prior reader, then hands the byte count (and, for
  multipart, the bytes) to a new streaming scanner in `howdah-core`, which
  returns continue or stop.
- **On stop**, the wrapper returns 0 (end of body) to PHP so it stops reading,
  and records the verdict for the existing RINIT refusal. No longjmp.
- The builder must confirm per PHP generation (5.x / 7.x / 8.x signatures
  differ) that a short read at that point does not itself produce a fatal
  error, and that `module::refuse` works when the verdict is recorded this
  early (urlencoded bodies are read in `sapi_activate`, before
  `php_hash_environment`).

### 4.2 Gap A: headers per multipart part

- The scanner follows multipart framing using the request's **real** boundary,
  extracted from `CONTENT_TYPE` the way PHP extracts it, and counts header lines
  and header bytes per part.
- Enforce the existing `max_part_headers` and `max_part_header_bytes` from the
  byte stream, making them exact, and move them to the Critical class.
  **(Claude's call: no new config keys; the editor already has these rows.)**
- **Fail closed.** The parsed-event counting (`max_parts`, `max_files`, name
  lengths) stays independent of the scanner, so a scanner that loses sync can
  never switch those off. If the scanner can't find the boundary or loses
  track, it must over-count, not under-count.
- The main risk is a differential between the scanner and PHP's parser (line
  endings, continuation lines, boundary edge cases). It must be differentially
  fuzzed against PHP's own parse, not only fuzzed for panics.

### 4.3 Gap B: bytes actually read

- The wrapper counts bytes actually read for a multipart request and stops once
  they exceed PHP's effective `post_max_size`. This backports upstream's
  `fill_buffer` check. New Critical rule (name to the builder), limit taken
  from PHP's own INI value. No new knob. If `post_max_size` is 0 (unlimited),
  this rule is off and §4.5 still bounds memory.
- `post_max_size` alone does not keep PHP under `memory_limit` on raised
  settings: PHP holds a whole non-file field value in memory, while file data
  goes to disk. So the scanner also counts the bytes of **non-file** part
  bodies (it knows from each part's `Content-Disposition` whether a filename
  is present) and feeds them into the §4.5 estimate.

### 4.4 Gap C: nested names

- Each nesting level keeps an array, so memory grows with the total number of
  levels across all variables in a request, not with any one depth.
- Add a per-request budget on total nesting levels, counted for urlencoded and
  cookie/GET names (input_filter path), multipart `FORMDATA` names and
  `FILE_START` names. A file name costs more than a field name because PHP builds
  several metadata arrays per file; weight it by that factor.
- These levels feed the §4.5 estimate. When it trips: drop the variable
  (input_filter returns 0, as today) or return `FAILURE` for the part, so PHP
  never builds the arrays, and refuse.

### 4.5 Following the live `memory_limit` (owner: cover raised settings)

Fixed defaults tuned to 128 MiB can't hold on servers that raised their
limits, so the memory-driven checks are sized per request:

- At request start, read PHP's effective `memory_limit` for this request (it
  can be set per directory, per pool or per vhost).
- Keep one per-request **estimate of the memory PHP's parser will hold**, made
  of: nesting levels (§4.4, file names weighted), buffered non-file part bytes
  (§4.3), and parsed header entries (§4.2). The cost constants are measured per
  PHP generation (5.x / 7.x / 8.x) on the lab builds.
- Critical block when the estimate passes a **ceiling of `memory_limit` / 4**,
  leaving the rest for the application. **(Claude's call on the fraction.)**
- One new `[limits]` key overrides the ceiling with a byte value; its default is
  automatic (derived as above). It needs an editor row (§3). The builder may
  fold this into `max_parse_memory_bytes` instead if its semantics fit without
  breaking existing configs. **(Claude's call.)**
- With `memory_limit = -1` (no limit), the ceiling falls back to a fixed default
  the builder measures. The advisory names `-1` as a partial mitigation;
  Howdah should keep working there.
- The existing fixed limits (`max_parts`, `max_files`, `max_part_headers`,
  `max_part_header_bytes`, name lengths) stay as independent hard caps.
- Zero blocks on the benign corpus at every ini profile in §5.1.

### 4.6 Backstop: end the worker on out-of-memory (owner)

The request limits stop requests that would run PHP out of memory while it
parses them. They can't see an application that runs itself out of memory, and
a scanner/parser disagreement could still let one through. The backstop makes
any out-of-memory that does happen harmless, by never letting code run on the
damaged state.

- **Why not repair or zero memory.** The danger is pointers that still lead
  into memory PHP freed or never finished setting up. Zeroing leaves those
  pointers in place, and PHP reuses the memory on the next allocation. Upstream
  had to fix each site separately (~300 files); an extension can't.
- **Mechanism.** At MINIT, save `zend_error_cb` and install Howdah's handler,
  chained like the input_filter. When the error is PHP's out-of-memory fatal
  (`E_ERROR` whose message starts "Allowed memory size of", or PHP's "Out of
  memory"), the handler writes Howdah's log line and ends the process with
  `_exit()`, before PHP longjmps. Request shutdown never runs, and no later
  request on that worker inherits stale pointers (CVE-2026-109619). Apache
  prefork and php-fpm start a fresh worker. Every other error chains to the
  prior callback unchanged. This matches what upstream's fix does at its hard
  limit.
- **Fatal errors during request startup** (before RINIT finishes) take the same
  exit. They are rare in normal traffic, and they are the CVE-2026-109619
  producer window. Fatal errors during the script do not: exiting on every
  uncaught exception would keep restarting workers on some apps.
  **(Claude's call.)**
- **The exit path allocates nothing.** It runs when memory is exhausted: a
  fixed stack buffer for the log line and a raw `write(2)`, no Zend or Rust heap
  allocation. If the configured log sink can't be written that way, fall back
  to stderr (the SAPI error log).
- **Scope.** Web SAPIs only (apache2handler, fpm-fcgi, cgi-fcgi, LSAPI); off on
  the CLI. Off on patched releases (8.2.35, 8.3.36, 8.4.27, 8.5.12 and later),
  where upstream's soft limit already handles out-of-memory safely. This check
  must use the **runtime** PHP version: a module built against 8.4.26 headers
  can run on 8.4.27.
- **Config.** On by default on unpatched versions; one boolean key turns it
  off (name to the builder; needs an editor row, §3). **(Claude's call.)**
- **Trade-offs to document:** the request that ran out of memory gets a
  dropped connection instead of an error page (nginx shows 502), and its
  worker restarts. Other extensions hooking `zend_error_cb` (Sentry, New
  Relic, Xdebug) won't see that error; Howdah's log line records it.
- `zend_error_cb`'s signature changes between 5.x, 7.x, 8.0 and 8.1+; use
  per-generation types as `input_filter.rs` does. The builder must confirm on
  each generation that the callback runs before the longjmp.

## 5. Verification

### 5.1 Lab targets

- **Vulnerable, with AddressSanitizer:** PHP 8.4.26 (last vulnerable 8.4),
  8.1.34 and 7.4.33 (never patched). Built from source; the current lab images
  are official Docker images, so these are new images.
- **Old generation:** PHP 5.6.40 without ASan if an ASan build isn't practical
  on its toolchain, using the out-of-memory signal only. **(Claude's call.)**
- **Patched control:** PHP 8.4.27 with ASan. Undefended trigger requests should
  produce no ASan report there, which shows the oracle measures this CVE.
- **SAPIs:** Apache mod_php prefork (the SAPI where RCE was demonstrated) and
  php-fpm.
- **Ini profiles** (owner: raised settings count): every trigger runs under
  (a) stock settings; (b) an upload-heavy profile with `post_max_size` and
  `upload_max_filesize` at 256M, `max_input_vars` and `max_file_uploads`
  raised, and `memory_limit` at 128M; and (c) the same with `memory_limit` at
  512M, which shows the ceiling scales. **(Claude's call on the exact
  profiles.)**
- **php-fpm evidence comes through a real front end** (nginx with stock body
  and buffering settings), not the lab's raw `cgi-fcgi` driver. Under
  `cgi-fcgi`, a `CONTENT_LENGTH` of -1 gets past PHP's up-front size check and
  lifts fpm's read cap, which no real front end allows; such runs don't count.
  `cgi-fcgi` stays fine for the existing matrix rows. **(Claude's call; the
  refusal-path design already found `cgi-fcgi` hiding real fpm behavior.)**

Note: the existing matrix runs 8.4.27 and Layer 2 ran 8.3.36, both patched
releases. Those rows say nothing about this CVE and must not be cited for it.

### 5.2 The oracle

For each trigger × version × SAPI: Howdah off, Howdah on at defaults, and the
patched control. Signals:

1. PHP's "Allowed memory size … exhausted" during request startup;
2. an AddressSanitizer report from the worker;
3. a benign follow-up request to the same worker answers 200 cleanly.

- **PASS (Howdah on):** refused by Howdah through the refusal path, no
  memory-exhausted line, no ASan report, clean follow-up.
- **The undefended run must show signal 1** (and signal 2 on ASan builds).
  Otherwise the fixture isn't reproducing the trigger, and the row is recorded
  NOT-RUN, never PASS.
- **N/A (unreachable on this SAPI)** is a separate status, recorded with its
  reason and a run showing the trigger can't get through. Example: php-fpm's
  `sapi_cgi_read_post` never reads past `CONTENT_LENGTH` (5.6, 7.4 and 8.3
  source), and nginx de-chunks bodies and sends a length, so trigger (1) and
  Gap B can't happen on fpm behind nginx. A SAPI can be named in the sentence
  when every trigger is PASS or N/A for it. **(Claude's call.)**
- **Each row records the PHP ini it ran under.** The undefended and defended
  runs of a row use the same ini. Reproducing a trigger may need a lowered
  `memory_limit` or raised caps, as upstream's phpt and
  `lab/integration/step1_raised_container.sh` do (PHP 8.x also caps parts via
  `max_multipart_body_parts`; 7.4 has no such cap).
- **Session upload progress is active in every trigger run**: the session
  extension loaded, `session.upload_progress.enabled=1` (the stock default),
  and the progress field sent before the parts. The same-worker follow-up
  request is the CVE-2026-109619 evidence. The builder must check that an
  early end of body from the read_post wrapper still lets ext/session's
  callback reach its cleanup, or record what state it leaves.
  **(Claude's call: progress on is the stock exposure; off is a subset.)**
- **Expected before the fix:** gaps A–C reproduce with Howdah on, and trigger
  (3) passes. Confirming that is the first milestone.

### 5.3 Trigger fixtures

- Derived from upstream's regression test (`oom_request_parsing.phpt`), the
  rfc1867 hunks of `506e87fa7d`, and the advisory's trigger list. No
  third-party proof-of-concept code.
- Generators live under the gitignored `private/` directory, following the
  milestone-0 precedent (`private/gen-shaped-request.js`). The committed harness
  calls them, and committed results name shapes, not bodies. **(Claude's call.)**

### 5.4 Regression and false positives

- `lab/integration/matrix.sh` stays green on every version it runs today.
- Extend the benign corpus: multi-file gallery uploads, parts with ordinary
  extra headers (`Content-Type`, `Content-Transfer-Encoding`), framework-style
  nested arrays, and a real chunked upload. Zero blocks at defaults.
- Fuzzing: cargo-fuzz on the scanner (no panics, bounded memory), plus a
  differential harness comparing the scanner's per-part header counts with what
  PHP parsed.

### 5.5 The backstop

Checked on the existing lab images with an ordinary test script that keeps
allocating past `memory_limit` (no attack request needed), under Apache mod_php
and php-fpm behind nginx:

- the worker exits, and Howdah's log line for the out-of-memory event is
  written;
- the next request is served by a fresh worker;
- with the key turned off, PHP's normal fatal-error behavior is unchanged;
- on a patched release (8.4.27) and on the CLI the handler stays off;
- any other error (a warning, an uncaught exception in the script) reaches the
  prior callback unchanged.

## 6. Release and claim

- Ships in the next minor release as Layer 1 work.
- Site sentence: **"Howdah blocks the PHP2Shell attack requests on unpatched
  PHP."** Qualifier line underneath, to this effect: *Howdah stops the
  request-parsing triggers named in the official advisories before PHP runs out
  of memory, and if PHP runs out of memory anyway, it ends that worker before
  the damaged state can be used. It does not fix the underlying PHP bug.
  Patching remains the fix.*
  **(Qualifier approved by the owner; exact wording to the copy pass.)**
- The sentence names only versions and SAPIs with PASS (or N/A) rows; the rest
  are listed as NOT-RUN. The coverage page lists the ini profiles tested.
- Correct the early-report descriptions in `README.md`,
  `site/src/pages/index.astro`, `docs/coverage.md`, `docs/coverage-data.md`,
  `site/scripts/gen-coverage.mjs`, and the `limits.rs` doc comment.

## 7. Left to the builder

- The scanner's state machine and data structures.
- Exact rule names and log fields.
- The §4.5 cost constants, the file-name weight, and the `memory_limit = -1`
  fallback ceiling.
- Whether `post_max_size` is read per request or cached.
- Lab image build details and the version list beyond §5.1.
- Milestone order. Suggested: vulnerable lab and oracle first, confirming the
  §5.2 "expected before the fix" result; then 4.6 (independent of the others,
  and the quickest protection to ship); then 4.1 → 4.3 → 4.2 → 4.4 → 4.5;
  then the full verification run, docs and site.
- The §4.6 out-of-memory message match per PHP version, the runtime version
  check, and the backstop config key's name.
