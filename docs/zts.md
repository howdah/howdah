# ZTS (thread-safe PHP): why Howdah does not ship a build yet

Howdah is built for NTS PHP only. That rules out FrankenPHP, Apache's event
and worker MPMs with `mod_php`, and the ZTS builds some hosts offer (for
example CloudLinux `alt-php72-zts`). `howdah-check detect` says so for a ZTS
install, and the release build refuses ZTS headers (`packaging/build-one.sh`).

This page is the result of trying, on 24 October 2026, and the plan for the
item that will do it properly.

## What was tried

Against the official `php:8.3-zts` image (PHP 8.3.36, `Thread Safety =>
enabled`, Debian trixie, clang 19), `cargo build -p howdah-ext --features php8`
on the 1.4.0 source fails with three errors. Line numbers on this page are
for `main` after #39 (in 1.4.0 these three were lines 147, 295 and 75):

| Where | Error | Why |
|---|---|---|
| `crates/howdah-ext/src/module.rs:150` | cannot find value `sapi_globals` in crate `sys` | Under ZTS `SG()` is not a global variable; it is reached through `sapi_globals_offset` and the thread's TSRM cache. |
| `crates/howdah-ext/src/module.rs:298` | the same | the same |
| `crates/howdah-ext/src/module.rs:78` | struct `_zend_module_entry` has no field named `globals_ptr` | ZTS module entries have `globals_id_ptr` instead. |

The C hooks in `crates/howdah-sys/` compile unchanged: they use `EG()`,
`CG()` and `SG()` through the PHP macros, which handle TSRM.

A throwaway patch (not part of this change) made it compile: a C accessor
`howdah_sys_request_info()` returning `&SG(request_info)`, used at both call
sites, and `globals_id_ptr` in the module entry. The result loads (`php -m`
lists howdah) and passes the self-test one request at a time.

Then it ran in FrankenPHP 1.13.3 (`dunglas/frankenphp:1.13.3-php8.3-trixie`,
PHP 8.3.36 ZTS, classic mode, so PHP requests run on threads), with raised
part caps and `howdah.mode = detect`:

- `howdah-check web` one request at a time: the marker was flagged (200) and
  the over-limit request blocked (403). Each blocked request also made
  FrankenPHP log `Request startup failed, thread is unhealthy` and restart the
  thread, the threaded twin of php-fpm's exit 70 (see
  [install-docker.md](install-docker.md)).
- 8 clients sending 40 normal form posts each, at the same time as 8 clients
  sending 40 over-limit requests each: **1 normal request was refused with
  403, 16 over-limit requests were served with 200**, and FrankenPHP then
  aborted with `malloc(): unaligned tcache chunk detected` (heap corruption).
  573 of the 640 requests got no response.

So making it compile is a few lines; making it correct is not. A ZTS build is
not shipped, and the release matrix stays NTS-only.

## The blockers: process-global state touched per request

Under NTS each PHP process serves one request at a time, so per-request state
in process globals is safe (`module.rs` says so in its header comment). Under
ZTS every one of these is shared by all threads.

Rust, `crates/howdah-ext/src/`:

| Where | State | Per request? |
|---|---|---|
| `module.rs:25` `CTX` | the single core context (`howdah_ctx`): the request id, the multipart parser state, input counters, the worst action so far, the pending log line, inspection budgets | yes: every request on every thread writes the same one |
| `module.rs:36` `BEGUN`, `module.rs:37` `ENDED` | request begun / ended latches | yes |
| `module.rs:43` `MULTIPART` | this request took the multipart path | yes |
| `rfc1867.rs:36` `BLOCKED`, `rfc1867.rs:37` `SELFTEST_SEEN` | this request was refused / carried the self-test marker | yes: a plausible cause of the wrong 403 and the missed blocks above |
| `input_filter.rs:60` `INPUT_BLOCKED` | an input-shape limit fired in this request | yes |
| `module.rs:46` `LOG` | the log destination and the `[log] exec` hook (added by #39): the hook's rate-limit window and last-refusal note (`logsink.rs`, `Hook::recent`, `refused`, `noted`) | yes: written on every event that runs the hook |
| `module.rs:26` `PRIOR`, `module.rs:30` `PRIOR_INPUT_FILTER` | the chained rfc1867 callback and input filter | no: set at MINIT, read-only after |
| `module.rs:47` `MODULE_NUMBER`, `module.rs:49`-`53` `DISP_*`, `module.rs:89` `MODULE` | module number and the info table | no: MINIT only |

C, `crates/howdah-sys/`:

| Where | State | Per request? |
|---|---|---|
| `ssrf_hook.c:120` `g_cache[64]` | the per-request DNS resolution cache | yes: unsynchronised reads and writes from every thread |
| `ssrf_hook.c:358` `g_map[256]` | curl handle to URL map, keyed by resource id or object handle | yes: handle numbers are per thread under ZTS, so two threads' handles collide |
| `ssrf_hook.c:67` `g_ctx` | pointer to the core context | points at the shared `CTX` |
| `sink_hook.c:41`, `phar_hook.c:48`, `ssrf_hook.c:65`-`66`, `sink_hook.c:46`-`50` | decision callbacks | no: set at MINIT |
| `sink_hook.c:268`-`269`, `ssrf_hook.c:292`, `ssrf_hook.c:422` | saved original handlers (`zend_compile_file`, `zend_compile_string`, the swapped functions) | no: set at MINIT; whether the per-thread copies of the function table pick up the swapped handlers was not checked |
| `phar_hook.c:49`-`51` | the copied and replacement `phar://` wrapper ops | no: set at MINIT |

The core (`crates/howdah-core`) holds no process-global mutable state of its
own apart from the request-id counter (`log.rs:151`, an atomic). Its
`howdah_ctx` is safe to use from one thread at a time; the problem is that the
extension has only one.

## Plan for a ZTS build

1. **One context per thread.** Move `CTX` and the per-request latches
   (`BEGUN`, `ENDED`, `MULTIPART`, `BLOCKED`, `SELFTEST_SEEN`,
   `INPUT_BLOCKED`) into PHP module globals: `globals_size`, `globals_id_ptr`
   and a `globals_ctor` that creates a `howdah_ctx` per thread, with a
   `globals_dtor` that frees it. Read them through a C accessor
   (`ZEND_TSRMG_FAST` / `ZEND_MODULE_GLOBALS_BULK`), the same way under NTS
   so there is one code path. Thread-locals in Rust are not a substitute:
   PHP owns the threads, and TSRM is what it frees at thread exit.
2. **SAPI globals through TSRM.** Replace the two direct `sapi_globals` reads
   with the C accessor (the throwaway patch above).
3. **SSRF tables and the exec rate limiter per thread.** Move `g_cache` and
   `g_map` into the same module globals, and give the `[log] exec` hook one
   rate window per thread or a lock around the shared one
   (`exec_rate_limit` is documented as per PHP process, so its docs change
   with it).
4. **Check the swapped function handlers under ZTS**: whether
   `zend_set_user_opcode_handler`, the `zend_compile_*` pointers and the
   function-table swaps installed at MINIT are seen by every thread's copy.
5. **Build and test.** A ZTS row in the release matrix (`build-one.sh`
   currently refuses ZTS headers on purpose), the lab scenarios under ZTS,
   and a concurrency test: FrankenPHP (classic and worker mode) and Apache
   event MPM with ZTS `mod_php`, many clients mixing normal and refused
   requests, asserting no wrong verdict, one event per refused request, a
   unique request id per request, and no crash. The FrankenPHP run above is
   the failing test to start from.
6. **Packaging.** A ZTS tarball needs its own name (`...-zts-...`), and
   `howdah-check detect` should then offer it instead of "none".

Until then, a ZTS PHP has no Howdah build, and the threaded servers are not
covered.
