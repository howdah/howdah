# Howdah refusal path (design)

Status: implemented on branch `fix/refusal-path-fpm`. Fixes the php-fpm worker
exit on a Layer 1 refusal and moves Layer 2 `block` in front of the script
where the SAPI makes the input available before the script runs.

## 1. The problem

Two independent measurements on 1.3 and 1.4 under php-fpm behind nginx: when a
Layer 1 Critical rule refuses a multipart flood, the worker exits with code 70
and FPM respawns it; nginx logs `readv() failed (104: Connection reset by
peer)`, forwards a 403 with an empty body, and `howdah-check web` reports
"refused (HTTP 403) but not by Howdah". The lab did not see it because it
drives php-fpm with `cgi-fcgi` and only reads the `Status:` header.

### 1.1 Where the refusal ran

Both refusal sites in `crates/howdah-ext` ended in `rfc1867::emit_and_bail`:
`response::emit_block` (status header, `sapi_send_headers`, body through
`ub_write`) followed by `_zend_bailout` (a longjmp):

- the multipart `MULTIPART_EVENT_END` callback (Layer 1 part/file floods);
- the Layer 4 RINIT main-script `deny_exec_dirs` check.

Armed Layer 3 sinks never bail: `sink_hook.c` neutralises the call (returns
`false`) and the script continues. They were not part of the bug.

### 1.2 Why a bailout there is fatal under php-fpm (per PHP version)

`php_request_startup()` in `main/main.c` is the same shape on 5.4.45, 5.6.40,
7.4.33 and 8.3.36:

```c
zend_try {
    ...
    sapi_activate();            /* post reader: sets the rfc1867 post entry */
    ...
    php_hash_environment();     /* builds $_GET/$_POST/$_COOKIE: runs the
                                   multipart parser -> our rfc1867 callback,
                                   and the input_filter for every variable */
    zend_activate_modules();    /* every module's RINIT, ours included */
    PG(modules_activated) = 1;
} zend_catch {
    retval = FAILURE;
} zend_end_try();
```

`$_GET`, `$_POST` and `$_COOKIE` are registered with `jit = 0`
(`main/php_variables.c`, all four versions), so they are built here, before any
RINIT; only `$_SERVER`, `$_ENV` and `$_REQUEST` follow `auto_globals_jit`.
A `zend_bailout()` from the rfc1867 callback or from a RINIT therefore lands
in that `zend_catch` and `php_request_startup()` returns FAILURE. The SAPIs
handle that return like this:

| SAPI | on `php_request_startup() == FAILURE` | effect |
|---|---|---|
| php-fpm (`sapi/fpm/fpm/fpm_main.c`, 5.4 to 8.3) | `fcgi_finish_request(request, 1); SG(server_context) = NULL; php_module_shutdown(); return FPM_EXIT_SOFTWARE;` | force-close without flushing the output buffer (body lost, unread stdin records -> nginx `readv() failed (104)`), worker exits 70, master logs `child N exited with code 70` and respawns |
| php-cgi (`sapi/cgi/cgi_main.c`) | same shape, `return FAILURE` from `main` | the process exits; under FastCGI the manager respawns it |
| Apache mod_php (`sapi/apache2handler/sapi_apache2.c`) | `php_apache_request_ctor` returns the FAILURE, `php_handler` calls `zend_bailout()` into its own `zend_first_try` | the prefork child survives and the already-sent status reaches the client, which is why the matrix recorded 403 there |
| CLI built-in server | the request loop continues | survives, but RSHUTDOWN is skipped (the earlier stale-403 bug and the second `clear_request_state` call in `emit_and_bail`) |

Returning FAILURE from RINIT is no alternative: `zend_activate_modules()` calls
`exit(1)` on it (`Zend/zend_API.c`, all versions).

## 2. The mechanism

A refusal decided during request startup is recorded, not executed. It is
delivered at the end of Howdah's RINIT, which is the earliest point where a
response is legal, and the script is prevented from running without a longjmp.

### 2.1 Record

`crates/howdah-ext/src/refusal.rs` (pure Rust, host-tested) holds one
`Deferred` verdict per request: `(status, request_id)`. The first verdict wins.
`Deferred::refuse(verdict, during_startup)` returns `Delivery::Deferred` while
PHP is still inside `php_request_startup()` and `Delivery::Now` afterwards. The
phase is PHP's own `PG(during_request_startup)` flag, read through a C shim,
not a guess from our hook order.

- The multipart END callback now calls `module::refuse` instead of
  `emit_and_bail`. It still ends the core request and writes the log line at
  END, exactly as before, so the log and the request id are unchanged.
- The Layer 4 main-script check does the same.
- Both record while `during_request_startup` is set, which is always the case
  for them. The `Now` branch keeps the previous `emit + zend_bailout` behaviour
  for a verdict that arrives during execution, where a bailout is legal
  (`php_execute_script` runs inside its own `zend_try`), so nothing regresses
  if a future hook refuses mid-script.

### 2.2 Keep the multipart parser consistent

`main/rfc1867.c` has no whole-body abort that a callback can request once
parsing has started: `FAILURE` from `FORMDATA` or `FILE_START` skips that one
part (no allocation), `FAILURE` from `FILE_DATA`/`FILE_END` cancels that one
upload, and only `FAILURE` from `START` ends the parse before it begins. The
glue already returns `FAILURE` for every part after the core says Block, so no
over-limit part is materialised; the remaining bytes (bounded by
`post_max_size`) are scanned and discarded, as they were before this change,
because the refusal was always delivered at END after the body was consumed.
Forging `SG(read_post_bytes)` to make the parser see EOF early was rejected: it
would leave unread `FCGI_STDIN` records on the socket, which is the exact nginx
`readv()` failure this change removes.

### 2.3 Deliver at the end of RINIT

At the end of `rinit`, after the one-time hook installs:

1. If Layer 2 is armed (`howdah_inspect_armed`), materialise `$_SERVER` now
   (`zend_is_auto_global` for `_SERVER`), so the path (`REQUEST_URI`,
   `PATH_INFO`) and the `HTTP_*` headers go through the chained `input_filter`
   before the script instead of at first access. Cost: `$_SERVER` is built on
   every request even when the application never reads it (one
   `php_register_server_variables` pass, the same work every framework
   triggers on its first line). Not done when Layer 2 is not armed, so the
   default install does not pay it.
2. Take the stashed verdict, if any. Otherwise, if the input path latched a
   block before RINIT (`INPUT_BLOCKED`: Layer 1 input-shape or header rules,
   or an armed Layer 2 class) and the core request is still open, end it now,
   write the log line and derive the verdict from it.
3. Deliver: `response::emit_block` (status, headers, the same body text with
   the request id), then `howdah_refuse_arm()`: save `zend_compile_file` and
   point it at a function that returns `NULL`. `zend_execute_scripts`
   (`Zend/zend.c`, all versions) treats a `NULL` op_array for `ZEND_REQUIRE`
   as "nothing to run" and returns FAILURE without a message or a bailout;
   php-fpm, php-cgi, mod_php and the CLI server ignore that return and go
   straight to `php_request_shutdown`. `auto_prepend_file` and
   `auto_append_file` compile through the same pointer, so they do not run
   either. The swap is per request and sits on top of whatever is installed
   (opcache included, which would otherwise serve a cached script without
   calling the next compile function), and RSHUTDOWN restores the saved
   pointer. Returning `NULL` from a compile hook is the same neutralisation
   `sink_hook.c` already uses for a blocked `include` on PHP 5.x.
4. RSHUTDOWN sees the request as already ended and refused, skips the second
   response, restores `zend_compile_file`, and resets the per-request state.
   The worker continues to the next request.

Nothing in this path longjmps. If any step panics, `catch_unwind` turns it
into "no refusal delivered" and the request proceeds as if Howdah had
logged only (fail-open), which is the posture the brief requires.

### 2.4 The RSHUTDOWN path stays for what arrives late

A block latched after RINIT keeps today's behaviour: the response is emitted
at RSHUTDOWN, best-effort, after the script (named "post-hoc refuse" in the
docs). This still applies to a request-header flood whose `$_SERVER` is built
lazily during execution (Layer 2 not armed, `auto_globals_jit=On`).

## 3. SAPI matrix

"Pre-execution" means: HTTP 403/413 with the Howdah body and request id, the
script's side effect (a marker file) absent, no worker exit, no connection
reset. Verified by `lab/integration/refusal.sh` on 2026-10-24 (95 checks
passed, 0 failed, 1 skipped: no `cgi-fcgi` in the 5.6 image). Other minors of
the same generation are expected to match but are not claimed. The same lab
against the 1.4.0 tree on 8.3 reproduces the bug: five `child N exited with
code 70` lines, four nginx `readv() failed (104)` lines, an empty body on the
Layer 4 refusal, "refused (HTTP 403) but not by Howdah" from `howdah-check
web`, and every Layer 2 / input-shape block answered 200 with the script's
output followed by "Cannot modify header information".

| SAPI | Layer 1 multipart flood | Layer 1 input-shape rules | Layer 1 header rules | Layer 2 `block` (GET/POST/cookie) | Layer 2 `block` (path / headers) | Layer 4 `deny_exec_dirs` main script | armed Layer 3 sink |
|---|---|---|---|---|---|---|---|
| php-fpm behind nginx (5.6, 7.4, 8.3) | pre-execution, worker pid unchanged, twice on one worker | pre-execution (`max_input_vars`) | post-hoc when `$_SERVER` is built lazily (matrix: http=200, log line present); pre-execution when Layer 2 is armed | pre-execution (SQLi in GET, POST, cookie; traversal; command injection) | pre-execution (`$_SERVER` forced at RINIT when armed; not separately asserted by the lab) | pre-execution, worker pid unchanged | call returns false, script continues, worker alive |
| php-fpm via cgi-fcgi (7.4, 8.3) | pre-execution, worker alive | matrix 8.3/5.6: log line + 403 | post-hoc (matrix) | not run | not run | not run | not run |
| Apache mod_php prefork (5.6, 7.4, 8.3) | pre-execution, no child exit | pre-execution | post-hoc (matrix) | pre-execution | as fpm | pre-execution | not run |
| CLI built-in server (8.3, 5.6: the matrix, behavior and inspect labs re-run after the change) | pre-execution (403 + body) | 403 + log line | not asserted on this SAPI | detect-mode logging unchanged (inspect lab) | not run | pre-execution (behavior lab, 28 checks) | unchanged (behavior lab) |
| php-cgi (not run) | expected to match php-fpm (same startup code, same `FAILURE` handling), not claimed | | | | | | |

What stays post-hoc, honestly:

- A block that is first seen after our RINIT (today only: `HTTP_*` header
  counting when `$_SERVER` is built lazily by the script and Layer 2 is not
  armed). Response at RSHUTDOWN, best-effort.
- `variables_order` without `G`, `P` or `C`, or `enable_post_data_reading=0`:
  the corresponding superglobal is never built, so there is nothing to scan
  before or after the script. Not a regression; stated in `docs/config.md`.
- If a SAPI ever delivers a verdict while `PG(during_request_startup)` is
  clear, the `Now` branch is the old emit-and-bailout, which is legal during
  execution.

## 4. What did not change

- The log line, the request id, the body text and the status mapping
  (`status_for_rule`).
- Layer 3 sink blocks (neutralise, no response, script continues).
- The `FAILURE` returns that stop PHP allocating over-limit parts.
- No new php.ini directive, no new config key, no new rule id.
  `howdah_inspect_armed` is a new core FFI function (append-only in `ffi.rs`
  and `howdah_core.h`).

## 5. Sources read

`main/main.c`, `main/SAPI.c`, `main/rfc1867.c`, `main/php_variables.c`,
`Zend/zend.c`, `Zend/zend_API.c`, `sapi/fpm/fpm/fpm_main.c`,
`sapi/cgi/cgi_main.c`, `sapi/apache2handler/sapi_apache2.c` from the
`/usr/src/php.tar.xz` in the 5.6, 7.4 and 8.3 lab images, and the same files
at tag `php-5.4.45` from php-src for 5.4.
