# Security audit brief

What we would hand an independent auditor. Howdah has had no third-party
audit yet; this is the scope we are asking for, not a report of one.

## The system

Howdah is a PHP extension (one `howdah.so` per PHP minor, 5.4 to 8.5, NTS
only) that runs inside every PHP worker. Layer 1 enforces request-shape limits
and its critical limits block by default; Layer 2 inspects decoded input
values and only logs; Layer 3 hooks dangerous sinks (command execution,
`unserialize`, `include`/`eval`, `phar://`, SSRF) and only logs unless an
operator arms one; Layer 4 watches after-breach behaviour and is inert until
configured. About 14,000 lines including unit tests: a pure-Rust core
(`crates/howdah-core`), Rust glue that talks to PHP (`crates/howdah-ext`),
and about 1,200 lines of C hooks and bindings (`crates/howdah-sys`).

## Scope, in priority order

1. **The C shim and the FFI boundary.** `crates/howdah-sys/*.c` and `*.h`
   (`shim.c`, `sink_hook.c`, `ssrf_hook.c`, `phar_hook.c`), the bindgen layer,
   and every `extern "C"` entry point in `crates/howdah-core/src/ffi.rs` and
   `crates/howdah-ext/src/*.rs`. Pointer and length handling across the
   boundary, lifetimes of strings handed to Rust, `catch_unwind` coverage, and
   the per-generation ABI differences (PHP 5 / 7 / 8 handler signatures,
   `zend_string` vs `char*`).
2. **Hook installation and displacement.** Everything that replaces a PHP or
   SAPI pointer and must keep calling what it displaced: the
   `php_rfc1867_callback` chain (`module.rs`, `rfc1867.rs`), the
   `sapi_module.input_filter` chain (`input_filter.rs`), the function-table
   handler swaps and the `ZEND_INCLUDE_OR_EVAL` user opcode handler
   (`sink_hook.c`), the `zend_compile_file` / `zend_compile_string` swap on
   PHP 5, the `phar://` stream-wrapper proxy (`phar_hook.c`), and the egress
   and file-write hooks (`ssrf_hook.c`, `behavior_filter.rs`). Order of
   installation against other extensions (opcache, debuggers, other security
   extensions), MSHUTDOWN restoration, and what happens if another extension
   swaps the same pointer after us.
3. **The multipart parser and reconstructor.** `crates/howdah-core/src/multipart.rs`
   and the event-to-bytes reconstruction in `howdah-ext`: the limits must be
   enforced before PHP allocates per-part memory, with bounded memory and time
   for any input.
4. **The log writer and the exec hook.** `crates/howdah-core/src/log.rs` and
   `crates/howdah-ext/src/logsink.rs`: file, syslog and the `[log]` exec hook
   (process spawn with `setsid`, `pipe2`, `fcntl`, rate limiting). Injection
   into log lines or into the hook's command, file descriptor leaks into the
   child, blocking or unbounded buffering on a slow consumer, and the privacy
   rule below.
5. **Config parsing.** The TOML config (`config.rs`, `limits.rs`,
   `exceptions/` including the glob matcher), the three `php.ini` directives
   (`ini_config.rs`), and the defaults applied when a file is missing,
   unreadable or malformed.
6. **The fail-open guarantees** stated in the threat model below.

Out of scope: the website, the config-fetch worker, the lab harness itself,
and bugs in PHP. The release pipeline is in scope only as far as
[verify.md](verify.md) makes claims about it.

## Threat model

- **Remote client (primary).** Controls the whole HTTP request: headers,
  query, cookies, body, multipart framing, and timing. Goals: crash or hang the
  worker, exhaust memory through Howdah, get a blocked request through, make
  Howdah block legitimate traffic, or make Howdah log data it must not.
- **Attacker code running in the PHP process (Layer 3 and 4).** After an
  application bug, it can call any PHP function. Howdah is not a sandbox and
  cannot stop in-process code from tampering with process memory; the
  question is whether the documented hooks see the documented calls, and
  whether a plain PHP-level call can switch them off.
- **Other local users (shared hosting).** Can they read the log, write the
  config, influence the exec hook's command or environment, or race the log
  file's creation?
- **Operators** are trusted but make mistakes: a malformed config must not
  take PHP down, and must not silently turn protection off.
- **Supply chain.** A tampered dependency, build image or release asset;
  [verify.md](verify.md) describes the signatures, provenance and
  reproducible rebuild that should catch it.

Properties the project claims and wants tested:

- No request can crash or hang PHP through Howdah. Panics are caught at every
  FFI entry (`panic = "unwind"`, enforced in CI and in the release build).
- When Howdah cannot decide (null context, panic, internal error), it allows
  the request or call and PHP continues.
- Nothing new blocks on install beyond the Layer 1 critical limits.
- Logs never contain request bodies, cookies, `Authorization` headers,
  matched values or sink arguments.
- A malformed config falls back to block mode with the built-in limits (or
  off, if the operator chose `on_invalid_config = "off"`), says so in the SAPI
  error log and `php --ri howdah`, and keeps serving.

## Artefacts for the auditor

- **Design specs:** `docs/superpowers/specs/` (the overall design, each layer,
  the input-hook spike findings, exceptions).
- **Coverage:** `docs/coverage.md` and the lab results it is generated from
  (`lab/integration/*-results.tsv`), per PHP minor and SAPI, including what is
  not covered.
- **Lab:** `lab/images/` (one container per PHP minor), `lab/integration/*.sh`
  (blocked shapes, self-test, sinks, behaviour, log contract, exceptions,
  mode matrix, Apache mod_php and LiteSpeed smokes), run in CI by `ci.yml`.
- **Fuzzing:** `fuzz/fuzz_targets/multipart.rs` and `events.rs` (the
  interface the PHP glue uses), with a seed corpus in `fuzz/corpus/multipart`; CI runs
  each for 60 seconds per PR. Longer campaigns are welcome.
- **Tests:** `cargo test --workspace` (core and glue), the site's tests that
  pin the config editor to the core's schema, `tools/howdah-check.test.sh`.
- **Log contract:** `docs/log-schema.md` and `docs/howdah-event.schema.json`.
- **Build and release:** `packaging/` (release images, reproducible build,
  SBOM), `.github/workflows/release.yml` and `publish-repos.yml`.

## Assumptions we want challenged

1. Every path from PHP into Rust goes through a `catch_unwind`, and no Rust
   panic or C `longjmp` (`zend_bailout`) can cross a frame of the other
   language.
2. Displaced handlers are always called on the allow path, with the arguments
   unchanged, in every PHP generation; a hook installed by another extension
   after ours is not broken by us, and ours is not silently lost.
3. The NTS-only assumption holds: the global context is never touched from a
   second thread (for example by an extension that runs PHP callbacks off the
   main thread).
4. One binary per minor, built against one patch release's headers, is
   ABI-correct for every patch release of that minor, on every distribution
   build of it (struct layouts, function signatures, opcode numbers).
5. The multipart limits are enforced before PHP allocates for the part, under
   every SAPI we claim (FPM, CGI, Apache mod_php, LiteSpeed), and chunked or
   slow bodies cannot get around them.
6. The Layer 3 sink list is complete for each PHP version: no other built-in
   function, callback or wrapper reaches the same operation unhooked.
7. Falling back to block mode on a malformed config is the right default for
   our users, and cannot be triggered by a remote client.
8. The exec hook cannot be made to run anything but the operator's command,
   and a slow or hostile hook process cannot stall PHP workers.
9. Log lines cannot be forged or split by request data (newlines, control
   bytes, invalid UTF-8), and the privacy rule holds for every rule and layer.
10. The signing, provenance and reproducible-build chain in
    [verify.md](verify.md) catches a tampered release asset, and its listed
    residual causes are the only ones.
