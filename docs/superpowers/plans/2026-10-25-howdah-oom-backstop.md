# Howdah out-of-memory backstop (§4.6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When PHP hits out-of-memory (or any fatal during request startup) on an
unpatched engine, end the worker before any code runs on the half-built request
state — the PHP2Shell backstop.

**Architecture:** A C shim in `howdah-sys` saves and chains `zend_error_cb` and is
installed from MINIT on web SAPIs only, on unpatched PHP only. On a matching
error it calls a Rust callback that writes one Howdah event line through the
normal log path and then `_exit()`s the worker before PHP longjmps. The
error-to-rule decision is a pure, host-tested function in `howdah-core`; the glue
is thin. A top-level `oom_exit` boolean (default true) turns it off.

**Tech Stack:** Rust (`howdah-core` pure, `howdah-ext` cdylib glue), C shim
compiled by `cc` in `howdah-sys` against the per-generation PHP headers, TOML
config, a Docker lab, a JS config editor + Astro site.

**Spec:** `docs/superpowers/specs/2026-10-24-howdah-php2shell-gaps-design.md` (§4.6,
plus §5.5 for verification). This plan implements §4.6 ONLY; §4.1–4.5 (the
read_post wrapper and request limits) are a separate plan and PR. The site claim
and the CVE-description corrections in §6 belong with the request-limits work, not
here.

## Global Constraints

Every task's requirements implicitly include this section.

- **Support matrix:** PHP 5.4–8.5, Linux x86_64 and aarch64, NTS. The C shim must
  compile and behave correctly on PHP 5.x, 7.x, 8.0 and 8.1+ (four `zend_error_cb`
  signatures).
- **Core stays pure Rust:** no PHP calls in `howdah-core`; `howdah-ext` is thin
  glue; every `extern "C"` entry point runs its body inside `catch_unwind` and
  fails open (the established FFI contract).
- **Logs record shapes and counts, never request content** (no body, cookie,
  Authorization header, matched value, or path).
- **Shared, append-only files, edited by a parallel session:** `config.rs`,
  `limits.rs`, `ffi.rs`, `howdah_core.h`. Before editing any of them run
  `ListAgents`; if a peer session is up, `SendMessage` it that you are adding the
  `oom_exit` key / `out_of_memory`+`startup_fatal` rules / `howdah_oom_exit`
  getter, and coordinate. Add at the END of enums/structs/catalogs; never modify
  or reorder existing entries. Never `git add -A`; stage named paths.
- **New config key needs three surfaces:** a `site/config-editor/schema.js` row, a
  `docs/config.md` entry, and a WASM rebuild (the demo wasm is built at
  test/deploy time, not committed).
- **Backstop decisions already made (follow unless the code proves one wrong):**
  - C shim in `crates/howdah-sys` (pattern: `refuse_hook.c`), installed from MINIT
    in `crates/howdah-ext/src/module.rs`; it saves and chains `zend_error_cb`.
  - Detection: `E_ERROR` (any bailout-fatal type) whose message/format starts
    `"Allowed memory size of"` or `"Out of memory"` → `out_of_memory`. Any fatal
    type while `PG(during_request_startup)` is set → `startup_fatal`. 5.x/7.x pass
    a `format` + `va_list`, so detection reads the **format** prefix and never
    consumes `args`; 8.0/8.1+ pass a pre-rendered `zend_string *message`.
  - Classification is a pure function in `howdah-core` (host-testable).
  - On a match: a Rust callback emits the event via `response::write_log_line`
    (hitting `memory_limit` exhausts only the Zend heap, so Rust's system-malloc
    log path still works; a real malloc failure makes Rust abort, still a
    fail-stop), then the shim `_exit()`s. No HTTP response is attempted.
  - Enabled only on SAPIs `apache2handler`, `fpm-fcgi`, `cgi-fcgi`, `litespeed`.
    Off on `cli` and `cli-server`. Off when the `memory_hard_limit_percent` INI
    directive exists at runtime (upstream's fix adds it; a runtime probe catches
    distro backports). Confirm the directive is present on 8.2.35 / 8.3.36 /
    8.4.27 / 8.5.12.
  - Config: top-level boolean `oom_exit`, default true, plumbed like
    `exceptions_log` plus an FFI getter.
  - Two new Critical, Layer 1 `RuleId`s: `out_of_memory` and `startup_fatal`.
- **Verification gates:** `cargo test --workspace`; `cargo clippy --all-targets -- -D
  warnings` for `howdah-core`/`howdah-ext` on the host AND once with a `phpN`
  feature (`cargo clippy -p howdah-ext --features php8 --all-targets -- -D
  warnings`, since CI's clippy does not see the php-gated glue); `cd site && npm
  test` (after building the wasm: `sh packaging/build-wasm.sh` or `npm run wasm`);
  the backstop lab (§5.5) where dev images exist, else NOT-RUN. Get an independent
  Fable review of everything touching core, ext or C and fix what it finds.
- **Attribution:** end commit messages with the `Co-Authored-By: Claude Opus 4.8`
  line; end the PR body with the Claude Code footer.
- **Stopping point:** push the branch and open a PR to `main` with CI green and the
  review addressed, then stop and report the PR link. Do not merge, bump versions,
  tag, or publish.

## Review Focus

Inputs/failure modes the spec implies that the happy path does not exercise;
most-likely-to-bite first. Each has its test added to the owning task.

- **A false "patched" probe disables the backstop on a vulnerable build** (the
  dangerous direction). `memory_hard_limit_percent` must never read as present on
  an unpatched supported version. → Task 3 lab asserts the phpinfo row is
  "armed" on an unpatched image; builder confirms the directive's absence on
  unpatched and presence on the four patched versions.
- **A non-matching error must reach the prior `zend_error_cb` unchanged**, with the
  `va_list` intact on 5.x/7.x, or every other error handler (PHP's own logging,
  Sentry/New Relic/Xdebug) goes silent. → Task 3 lab: an ordinary warning is still
  logged by PHP and the worker survives.
- **A fatal during the SCRIPT that is not OOM must NOT exit** — only OOM (any
  phase) and fatals during request startup exit; exiting on every uncaught fatal
  would crash-loop workers on buggy apps. → Task 1 classifier test (script-phase
  fatal, non-OOM → `None`); Task 3 lab (uncaught exception/`trigger_error` does
  not exit).
- **The log line must be written before `_exit` under real exhaustion** (Zend heap
  full): Rust/system-malloc builds it, the sink flushes, and the `[log] exec` fork
  must not wedge the dying worker. → Task 3 lab asserts the `out_of_memory` line is
  present in the log after the worker exits.
- **`oom_exit = false`, `off`, CLI, and patched builds must leave PHP's behavior
  exactly as today** (no hook installed, normal fatal page/behavior, worker
  survives). → Task 2 getter test; Task 3 lab asserts the `oom_exit = false` and
  CLI paths.

---

### Task 1: Core classifier + the two Layer-1 rules

Adds the pure error-to-rule classifier and the `RuleId`s it returns. Bundled
because the classifier cannot compile without the variants, and `rule_layer` /
`rule_name` are exhaustive matches that stop the whole workspace compiling until
the variants are given arms. Entirely host-testable.

**Files:**
- Create: `crates/howdah-core/src/oom.rs`
- Modify: `crates/howdah-core/src/lib.rs` (add `pub mod oom;`)
- Modify (shared, append-only): `crates/howdah-core/src/limits.rs`
- Modify: `crates/howdah-core/src/log.rs`
- Modify (shared, append-only): `crates/howdah-core/src/ffi.rs` (`describe` arms only)
- Modify: `crates/howdah-core/src/exceptions/mod.rs` (`Layer::of` arms)

**The four exhaustive `RuleId` matches** that stop the workspace compiling until the
new variants are placed (verified by grep — there are exactly four; `RuleId::severity`
has a `_ => Critical` arm so it needs no change):
1. `log.rs::rule_layer` → add to the `=> 1` group.
2. `log.rs::rule_name` → `"out_of_memory"`, `"startup_fatal"`.
3. `ffi.rs::describe` → short human strings.
4. `exceptions/mod.rs::Layer::of` → add to the `=> Layer::Limits` group.
Plus the catalog machinery in `limits.rs` and the two test tables.

**Interfaces:**
- Produces:
  - `howdah_core::oom::classify_fatal(error_type: i32, message: &[u8], during_startup: bool) -> Option<RuleId>`
  - `RuleId::OutOfMemory` (serde `"out_of_memory"`), `RuleId::StartupFatal` (serde
    `"startup_fatal"`) — both `Severity::Critical`, both `rule_layer` == 1,
    both `Layer::of` == `Layer::Limits`.
- Consumes: `crate::limits::{RuleId, Severity}`.

- [ ] **Step 1: Coordinate on the shared files.** Run `ListAgents`; if a peer is
  up, `SendMessage` that this task appends `out_of_memory` and `startup_fatal` to
  `RuleId`/`rule_catalog`/`rule_layer`/`rule_name`/`describe`/`Layer::of`. Proceed
  when clear.

- [ ] **Step 2: Write the failing classifier tests** in `crates/howdah-core/src/oom.rs`:

```rust
#[test] fn oom_format_prefix_5x_7x_is_out_of_memory() {
    // 5.x/7.x hand the FORMAT string (with %zu still in it).
    let f = b"Allowed memory size of %zu bytes exhausted (tried to allocate %zu bytes)";
    assert_eq!(classify_fatal(E_ERROR, f, false), Some(RuleId::OutOfMemory));
}
#[test] fn oom_rendered_message_8x_is_out_of_memory() {
    let m = b"Allowed memory size of 2097152 bytes exhausted (tried to allocate 40 bytes)";
    assert_eq!(classify_fatal(E_ERROR, m, false), Some(RuleId::OutOfMemory));
}
#[test] fn out_of_memory_literal_is_out_of_memory() {
    assert_eq!(classify_fatal(E_ERROR, b"Out of memory", false), Some(RuleId::OutOfMemory));
}
#[test] fn oom_wins_even_during_startup() {
    assert_eq!(classify_fatal(E_ERROR, b"Out of memory", true), Some(RuleId::OutOfMemory));
}
#[test] fn any_fatal_during_startup_is_startup_fatal() {
    for t in [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE, E_USER_ERROR] {
        assert_eq!(classify_fatal(t, b"Uncaught Error: boom", true), Some(RuleId::StartupFatal), "type {t}");
    }
}
#[test] fn script_phase_non_oom_fatal_does_not_match() {
    assert_eq!(classify_fatal(E_ERROR, b"Uncaught Error: boom", false), None);
}
#[test] fn warning_never_matches_even_during_startup() {
    assert_eq!(classify_fatal(E_WARNING, b"Allowed memory size of ...", true), None); // not a bailout type -> no match; but OOM prefix on a non-fatal type: see note
    assert_eq!(classify_fatal(E_WARNING, b"undefined index", true), None);
    assert_eq!(classify_fatal(E_NOTICE, b"undefined var", false), None);
    assert_eq!(classify_fatal(E_RECOVERABLE_ERROR, b"boom", true), None); // catchable, not a bailout
}
#[test] fn empty_or_unrelated_message_is_none() {
    assert_eq!(classify_fatal(E_ERROR, b"", false), None);
    assert_eq!(classify_fatal(E_ERROR, b"Division by zero", false), None);
}
```

  Note on the first `warning` assertion: OOM is always raised as a bailout fatal
  (`E_ERROR`), so requiring a fatal type for the OOM branch is correct and the
  assertion documents that a non-fatal type with an OOM-looking message is not
  treated as OOM. Keep the comment.

- [ ] **Step 3: Run the tests to verify they fail**

  Run: `cargo test -p howdah-core oom::`
  Expected: FAIL — `classify_fatal`, the `E_*` consts, and `RuleId::OutOfMemory`/`StartupFatal` are undefined.

- [ ] **Step 4: Add the two variants to `RuleId`** in `limits.rs`, appended after
  `TlsVerify`: `OutOfMemory`, `StartupFatal`. They are NOT added to the Standard
  list in `RuleId::severity` (the `_ => Severity::Critical` arm already makes them
  Critical). Append both to the `rule_catalog()` `ALL` array, change its length
  `[RuleId; 35]` → `[RuleId; 37]`, and update the two `assert_eq!(rule_catalog().len(), 35)`
  occurrences (in `rule_catalog_covers_every_variant` and anywhere else) to `37`.
  Add both to the exhaustive match in `rule_catalog_covers_every_variant`.

- [ ] **Step 5: Place the variants in every exhaustive match** so the workspace
  compiles:
  - `log.rs::rule_layer`: add `| RuleId::OutOfMemory | RuleId::StartupFatal` to the
    `=> 1` group; add both rows (layer 1) to the `every_rule_has_a_layer` `want`
    table and bump its two `rule_catalog().len()` asserts `35` → `37`.
  - `log.rs::rule_name`: `RuleId::OutOfMemory => "out_of_memory"`,
    `RuleId::StartupFatal => "startup_fatal"`.
  - `ffi.rs::describe`: `RuleId::OutOfMemory => "worker ended on out-of-memory"`,
    `RuleId::StartupFatal => "fatal error during request startup"`. (The backstop
    builds its own log line, so `describe` is never reached for these at runtime,
    but the match is exhaustive and must compile.)
  - `exceptions/mod.rs::Layer::of`: add `| RuleId::OutOfMemory | RuleId::StartupFatal`
    to the `=> Layer::Limits` group.

- [ ] **Step 6: Implement `classify_fatal` and the `E_*` consts** in `oom.rs`.
  The `E_*` values are PHP's stable error-type bit flags (`Zend/zend_errors.h`,
  unchanged across 5.x–8.5): `E_ERROR=1`, `E_WARNING=2`, `E_PARSE=4`, `E_NOTICE=8`,
  `E_CORE_ERROR=16`, `E_COMPILE_ERROR=64`, `E_USER_ERROR=256`,
  `E_RECOVERABLE_ERROR=4096`. Define a `FATAL_MASK = E_ERROR | E_CORE_ERROR |
  E_COMPILE_ERROR | E_USER_ERROR | E_PARSE` (the bailout set; `E_RECOVERABLE_ERROR`
  is catchable and excluded). Logic: a bailout-fatal type whose `message` starts
  with `b"Allowed memory size of"` or `b"Out of memory"` → `OutOfMemory`; else a
  bailout-fatal type with `during_startup` → `StartupFatal`; else `None`. Use
  `message.starts_with(prefix)` (case-sensitive, exact bytes). `pub use` the `E_*`
  consts from the module so the glue and tests can name them.

- [ ] **Step 7: Run the classifier tests and the touched suites**

  Run: `cargo test -p howdah-core`
  Expected: PASS (including `oom::*`, `limits::rule_catalog_covers_every_variant`,
  `log::every_rule_has_a_layer`, and `tests/event_schema.rs` — the new rules
  validate against the pattern-based `rule` field at layer 1 with no schema edit).

- [ ] **Step 8: Add a severity/layer guard test** in `oom.rs`:

```rust
#[test] fn new_rules_are_critical_layer1() {
    use crate::limits::Severity;
    use crate::log::rule_layer;
    for r in [RuleId::OutOfMemory, RuleId::StartupFatal] {
        assert_eq!(r.severity(), Severity::Critical);
        assert_eq!(rule_layer(r), 1);
    }
}
```

  Run: `cargo test -p howdah-core oom::new_rules_are_critical_layer1` → PASS.

- [ ] **Step 9: Commit**

```bash
git add crates/howdah-core/src/oom.rs crates/howdah-core/src/lib.rs \
        crates/howdah-core/src/limits.rs crates/howdah-core/src/log.rs \
        crates/howdah-core/src/ffi.rs crates/howdah-core/src/exceptions/mod.rs
git commit -m "core: OOM/startup-fatal classifier and two Layer-1 rules"
```

---

### Task 2: `oom_exit` config key + FFI getter + regenerated header

Adds the top-level `oom_exit` boolean (default true) and the `howdah_oom_exit`
getter the glue reads at MINIT to decide whether to install the hook. Host-tested.

**Files:**
- Modify (shared, append-only): `crates/howdah-core/src/config.rs`
- Modify (shared, append-only): `crates/howdah-core/src/ffi.rs`
- Modify (regenerated, shared): `crates/howdah-core/howdah_core.h`

**Interfaces:**
- Produces:
  - `Config.oom_exit: bool` (serialized top-level key `oom_exit`), default `true`.
  - `howdah_oom_exit(ctx: *mut howdah_ctx) -> i32` — `1` iff the context's config
    has `oom_exit == true`; `0` for a NULL ctx or on panic (fail toward not
    installing, i.e. no behavior change — CTX is always set at the MINIT call
    site).
- Consumes: Task 1 is independent of this task.

- [ ] **Step 1: Coordinate on the shared files** (`ListAgents`; `SendMessage` a peer
  that this task appends `oom_exit` to `Config`/`RawConfig` and a `howdah_oom_exit`
  getter to `ffi.rs`).

- [ ] **Step 2: Write the failing config tests** in `config.rs` `mod tests`:

```rust
#[test] fn oom_exit_defaults_on_and_serializes() {
    let c = Config::safe_defaults();
    assert!(c.oom_exit);
    let j: serde_json::Value = serde_json::to_value(&c).unwrap();
    assert_eq!(j["oom_exit"], true);
    // absent in the file -> default true
    assert!(Config::from_toml("mode = \"block\"\n").unwrap().oom_exit);
}
#[test] fn oom_exit_parses_and_rejects_non_bool() {
    assert!(!Config::from_toml("oom_exit = false\n").unwrap().oom_exit);
    assert!(Config::from_toml("oom_exit = true\n").unwrap().oom_exit);
    assert!(Config::from_toml("oom_exit = \"no\"").is_err());
}
```

- [ ] **Step 3: Write the failing getter test** in `ffi.rs` `mod tests` (follow the
  nearby `howdah_exceptions_log` tests for ctx construction):

```rust
#[test] fn oom_exit_getter() {
    let on = unsafe { howdah_init(b"".as_ptr() as *const c_char, 0) };      // defaults -> true
    assert_eq!(unsafe { howdah_oom_exit(on) }, 1);
    let off_toml = b"oom_exit = false\n";
    let off = unsafe { howdah_init(off_toml.as_ptr() as *const c_char, off_toml.len()) };
    assert_eq!(unsafe { howdah_oom_exit(off) }, 0);
    assert_eq!(unsafe { howdah_oom_exit(std::ptr::null_mut()) }, 0);
    unsafe { howdah_free(on); howdah_free(off); }
}
```

- [ ] **Step 4: Run the tests to verify they fail**

  Run: `cargo test -p howdah-core oom_exit`
  Expected: FAIL — `oom_exit` field and `howdah_oom_exit` do not exist.

- [ ] **Step 5: Add the field** in `config.rs`: append `pub oom_exit: bool` to
  `Config` (after `exceptions_log`) and `oom_exit: bool` to `RawConfig` (after
  `exceptions_log`); add `oom_exit: c.oom_exit` to `impl Default for RawConfig`;
  add `oom_exit: raw.oom_exit` to the `Config { .. }` built in `from_toml`; add
  `oom_exit: true` to `safe_defaults()`. (`RawConfig`'s struct-level
  `#[serde(default)]` makes an absent key take `safe_defaults()`'s `true`;
  `deny_unknown_fields` is why the field must be declared for `oom_exit = false` to
  be accepted.)

- [ ] **Step 6: Add the getter** in `ffi.rs`, mirroring `howdah_exceptions_log`
  exactly:

```rust
/// 1 iff the context's config has `oom_exit = true` (the default); 0 otherwise,
/// for NULL and on panic. Read by the glue at MINIT to decide whether to install
/// the out-of-memory backstop (`zend_error_cb` hook).
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_oom_exit(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() { return 0; }
    catch_unwind(AssertUnwindSafe(|| i32::from((*ctx).config.oom_exit))).unwrap_or(0)
}
```

- [ ] **Step 7: Run the tests to verify they pass**

  Run: `cargo test -p howdah-core` → PASS.

- [ ] **Step 8: Regenerate the C header.** From the repo root:
  `cbindgen --config crates/howdah-core/cbindgen.toml --crate howdah-core --output
  crates/howdah-core/howdah_core.h` (install cbindgen with `cargo install cbindgen`
  if absent). Confirm the diff adds only the `howdah_oom_exit` declaration and its
  doc comment, with nothing else reordered. If cbindgen is unavailable, hand-append
  the declaration in the same style next to `howdah_exceptions_log`; the header is
  not diff-checked in CI, but it must stay an accurate record of the ABI.

- [ ] **Step 9: Commit**

```bash
git add crates/howdah-core/src/config.rs crates/howdah-core/src/ffi.rs \
        crates/howdah-core/howdah_core.h
git commit -m "core: oom_exit config key (default on) and howdah_oom_exit getter"
```

---

### Task 3: Wire the backstop — C shim, bindings, decide callback, MINIT gate

The PHP-side glue. Compiled only under a `phpN` feature, so it is not exercised by
the host `cargo test`; its deliverable is that `cargo build -p howdah-ext --features
phpN` succeeds on 5/7/8 and `php --ri howdah` shows the backstop row reflecting the
gate. Its behavior is proven by the lab (Task 4). One task because the shim does
nothing without the install and the install needs the shim.

**Files:**
- Create: `crates/howdah-sys/oom_hook.c`
- Modify: `crates/howdah-sys/build.rs` (compile `oom_hook.c`; add its
  `rerun-if-changed`)
- Modify: `crates/howdah-sys/src/lib.rs` (extern decls + `HowdahOomDecide` type)
- Create: `crates/howdah-ext/src/oom_filter.rs`
- Modify: `crates/howdah-ext/src/lib.rs` (`#[cfg(phpN)] mod oom_filter;`)
- Modify: `crates/howdah-ext/src/module.rs` (MINIT gated install, MSHUTDOWN
  uninstall, phpinfo row, SAPI helper)

**Interfaces:**
- Consumes: `howdah_core::oom::classify_fatal` and the `E_*` consts (Task 1);
  `core::howdah_oom_exit` (Task 2); `response::write_log_line`,
  `howdah_core::log::{log_line, new_request_id, EventRecord}`,
  `howdah_core::rules::Action`, `howdah_core::RuleId`.
- Produces (C ABI, `howdah-sys`):
  - `void howdah_install_oom_hook(HowdahOomDecide cb)` — save `zend_error_cb`,
    install Howdah's.
  - `void howdah_uninstall_oom_hook(void)` — restore the saved callback.
  - `int howdah_memory_hard_limit_percent_exists(void)` — 1 iff the INI directive
    is registered (patched engine).
  - `HowdahOomDecide = unsafe extern "C" fn(error_type: c_int, msg: *const c_char,
    msg_len: usize, during_startup: c_int) -> c_int` (1 = end the worker, 0 =
    chain to the prior handler).
- Produces (`howdah-ext`): `crate::oom_filter::decide` (the `HowdahOomDecide`).

- [ ] **Step 1: Write the C shim** `crates/howdah-sys/oom_hook.c`, modeled on
  `refuse_hook.c`. `zend_error_cb` is a global function pointer whose signature
  differs by generation; save the prior with its real type and forward
  non-matching errors to it unchanged (do NOT consume the 5.x/7.x `va_list` — our
  check reads only the `format` string, then forwards `args` untouched). `_exit` on
  a match, before PHP longjmps.

```c
#include "main/php.h"
#include <unistd.h>   /* _exit */
#include <string.h>   /* strlen */
#include <stdarg.h>

#define HOWDAH_OOM_EXIT_CODE 0  /* a clean recycle: nginx 502s, fpm forks a fresh
                                 * worker, and does NOT count it against
                                 * emergency_restart_threshold under a flood. The
                                 * event is recorded in Howdah's log. */

typedef int (*howdah_oom_decide_t)(int type, const char *msg, size_t msg_len, int during_startup);
static howdah_oom_decide_t howdah_oom_decide = NULL;

#if PHP_VERSION_ID >= 80100
#  define HOWDAH_ERR_FILE_T zend_string *
typedef void (*howdah_zend_error_cb_t)(int, zend_string *, const uint32_t, zend_string *);
#elif PHP_VERSION_ID >= 80000
#  define HOWDAH_ERR_FILE_T const char *
typedef void (*howdah_zend_error_cb_t)(int, const char *, const uint32_t, zend_string *);
#else
typedef void (*howdah_zend_error_cb_t)(int, const char *, const uint, const char *, va_list);
#endif
static howdah_zend_error_cb_t howdah_oom_prev_error_cb = NULL;

static int howdah_oom_during_startup(void) { return PG(during_request_startup) ? 1 : 0; }

#if PHP_VERSION_ID >= 80000
static void howdah_oom_error_cb(int type, HOWDAH_ERR_FILE_T file, const uint32_t line, zend_string *message) {
    if (howdah_oom_decide && message &&
        howdah_oom_decide(type, ZSTR_VAL(message), ZSTR_LEN(message), howdah_oom_during_startup()))
        _exit(HOWDAH_OOM_EXIT_CODE);
    if (howdah_oom_prev_error_cb) howdah_oom_prev_error_cb(type, file, line, message);
}
#else
static void howdah_oom_error_cb(int type, const char *file, const uint line, const char *format, va_list args) {
    if (howdah_oom_decide &&
        howdah_oom_decide(type, format, format ? strlen(format) : 0, howdah_oom_during_startup()))
        _exit(HOWDAH_OOM_EXIT_CODE);
    if (howdah_oom_prev_error_cb) howdah_oom_prev_error_cb(type, file, line, format, args);
}
#endif

void howdah_install_oom_hook(howdah_oom_decide_t cb) {
    howdah_oom_decide = cb;
    howdah_oom_prev_error_cb = (howdah_zend_error_cb_t) zend_error_cb;
    zend_error_cb = howdah_oom_error_cb;
}
void howdah_uninstall_oom_hook(void) {
    if (howdah_oom_prev_error_cb) { zend_error_cb = (void *) howdah_oom_prev_error_cb; howdah_oom_prev_error_cb = NULL; }
    howdah_oom_decide = NULL;
}

/* The upstream OOM fix (8.2.35/8.3.36/8.4.27/8.5.12) registers this ini
 * directive; its presence means the engine already handles OOM safely, so the
 * backstop stays off. Runtime check -> distro backports count. */
int howdah_memory_hard_limit_percent_exists(void) {
    return zend_hash_str_exists(EG(ini_directives),
        "memory_hard_limit_percent", sizeof("memory_hard_limit_percent") - 1) ? 1 : 0;
}
```

  The builder must confirm on each generation that `zend_error_cb` runs before the
  OOM longjmp (it does: PHP calls `zend_error_cb` from `zend_error`/
  `zend_error_noreturn` before `zend_bailout`), and that the 5.x/7.x `format`
  prefix for OOM is exactly `"Allowed memory size of"` / `"Out of memory"` (the
  §4.6 "message match per PHP version" item). Confirm `memory_hard_limit_percent`
  is visible in `EG(ini_directives)` at MINIT on a patched build; if it is
  registered after module MINIT, move both the probe and the install to the
  process-once block at first RINIT instead (note it in the phpinfo row logic).

- [ ] **Step 2: Declare the shim in `howdah-sys/src/lib.rs`** (inside the existing
  `extern "C"` block / alongside the callback typedefs), with doc comments in the
  house style:

```rust
pub type HowdahOomDecide = unsafe extern "C" fn(
    error_type: ::std::ffi::c_int,
    msg: *const ::std::ffi::c_char,
    msg_len: usize,
    during_startup: ::std::ffi::c_int,
) -> ::std::ffi::c_int;

extern "C" {
    pub fn howdah_install_oom_hook(cb: HowdahOomDecide);
    pub fn howdah_uninstall_oom_hook();
    pub fn howdah_memory_hard_limit_percent_exists() -> ::std::ffi::c_int;
}
```

- [ ] **Step 3: Compile the shim** — in `howdah-sys/build.rs`, add
  `.file("oom_hook.c")` to the `cc::Build` and a
  `println!("cargo:rerun-if-changed=oom_hook.c");` beside the others.

- [ ] **Step 4: Write the Rust decide callback** `crates/howdah-ext/src/oom_filter.rs`.
  Context-free (the gate is applied at install time), fully panic-guarded, and
  fails open (return 0) on any panic — consistent with the FFI contract; the
  classifier is a trivial prefix match that cannot realistically panic. It logs a
  shape-only line with EMPTY request metadata (reading half-built SAPI request
  state on the OOM path is avoided by design; the fresh `request_id` plus the
  timestamp and worker identify the event).

```rust
//! The out-of-memory backstop's Rust side: classify the fatal, log one event,
//! tell the C shim to end the worker. Installed from MINIT only on web SAPIs,
//! only on unpatched PHP, only when `oom_exit` is on (see `module::minit`).
use std::ffi::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

use howdah_core::log::{log_line, new_request_id, EventRecord};
use howdah_core::oom::classify_fatal;
use howdah_core::rules::Action;
use howdah_core::RuleId;

use crate::response;

/// `HowdahOomDecide`: 1 = end the worker (after logging), 0 = chain to the prior
/// `zend_error_cb`. NULL/empty `msg` and any panic return 0 (fail-open).
///
/// # Safety
/// `msg` is NULL or valid for `msg_len` bytes, for the duration of the call.
pub unsafe extern "C" fn decide(
    error_type: c_int,
    msg: *const c_char,
    msg_len: usize,
    during_startup: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if msg.is_null() || msg_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(msg as *const u8, msg_len)
        };
        let Some(rule) = classify_fatal(error_type, bytes, during_startup != 0) else {
            return 0;
        };
        let reason = match rule {
            RuleId::OutOfMemory => "worker ended on PHP out-of-memory before the half-built request state could be used",
            _ => "worker ended on a fatal error during request startup before the half-built request state could be used",
        };
        let line = log_line(&EventRecord {
            ts: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0).to_string(),
            request_id: new_request_id(),
            rule,
            action: Action::Block,
            client_ip: String::new(),
            method: String::new(),
            uri: String::new(),
            reason: reason.to_string(),
        });
        response::write_log_line(&line);
        1
    }))
    .unwrap_or(0)
}
```

- [ ] **Step 5: Register the module** — in `crates/howdah-ext/src/lib.rs`, add
  `#[cfg(any(feature = "php5", feature = "php7", feature = "php8"))] mod oom_filter;`
  with the other php-gated modules.

- [ ] **Step 6: Install from MINIT, gated** — in `module.rs`. Add a helper that
  reads the SAPI name and the gate, and install near the other MINIT installs
  (after the sink/include hooks). Add a phpinfo row so operators and the lab can
  see the decision. Uninstall in `mshutdown` before `core::howdah_free(CTX)`.

  - SAPI helper:

```rust
/// Web SAPIs the out-of-memory backstop runs on. Off on cli / cli-server.
fn is_backstop_sapi(name: &str) -> bool {
    matches!(name, "apache2handler" | "fpm-fcgi" | "cgi-fcgi" | "litespeed")
}
```

  - In `minit`, after the include/eval hook block, before `SUCCESS`:

```rust
// Out-of-memory backstop (§4.6): save+chain zend_error_cb so an OOM (or a
// fatal during request startup) ends the worker before code runs on the
// half-built request state. Web SAPIs only, unpatched PHP only, oom_exit on.
let sapi = { let p = (*ptr::addr_of!(sys::sapi_module)).name;
    if p.is_null() { String::new() } else { CStr::from_ptr(p).to_string_lossy().into_owned() } };
let patched = sys::howdah_memory_hard_limit_percent_exists() != 0;
let oom_on = !CTX.is_null() && core::howdah_oom_exit(CTX) != 0;
let backstop = oom_on && is_backstop_sapi(&sapi) && !patched;
if backstop {
    sys::howdah_install_oom_hook(crate::oom_filter::decide);
}
DISP_OOM = Some(cstring(&oom_backstop_label(oom_on, &sapi, patched)));
```

  with a new `static mut DISP_OOM: Option<CString> = None;` and a label helper:

```rust
fn oom_backstop_label(oom_on: bool, sapi: &str, patched: bool) -> String {
    if !oom_on { return "off (oom_exit = false)".into(); }
    if patched { return "off (patched PHP: memory_hard_limit_percent present)".into(); }
    if !is_backstop_sapi(sapi) { return format!("off (SAPI {sapi})"); }
    format!("armed (oom_exit; ends the worker on out-of-memory, SAPI {sapi})")
}
```

  - In `minfo`, add a row after the Layer-1 limits row:
    `if let Some(o) = (*ptr::addr_of!(DISP_OOM)).as_ref() { row(b"OOM backstop (oom_exit)\0", o.as_bytes_with_nul()); }`
  - In `mshutdown`, before `core::howdah_free(CTX)`: `sys::howdah_uninstall_oom_hook();`

- [ ] **Step 7: Build the glue on every generation and inspect the row**

  Run (each where a PHP dev image/toolchain exists; else record NOT-RUN):
  `PHP_CONFIG=php-config cargo build -p howdah-ext --features php8`
  then `php -d extension=target/debug/libhowdah_ext.so --ri howdah | grep "OOM backstop"`.
  Repeat with `--features php7` / `--features php5` against those php-configs.
  Expected: builds succeed; the row reads `armed (...)` on an unpatched CLI build?
  No — CLI is off, so under `php --ri` (cli SAPI) the row reads `off (SAPI cli)`.
  That itself verifies the SAPI gate. (The armed path is exercised in Task 4's
  fpm/apache lab.)

- [ ] **Step 8: Clippy with a php feature**

  Run: `cargo clippy -p howdah-ext --features php8 --all-targets -- -D warnings`
  Expected: clean (CI's clippy does not cover the php-gated glue, so this is the
  only gate on it).

- [ ] **Step 9: Commit**

```bash
git add crates/howdah-sys/oom_hook.c crates/howdah-sys/build.rs crates/howdah-sys/src/lib.rs \
        crates/howdah-ext/src/oom_filter.rs crates/howdah-ext/src/lib.rs crates/howdah-ext/src/module.rs
git commit -m "ext: install the OOM backstop (zend_error_cb shim) from MINIT, web SAPIs + unpatched only"
```

---

### Task 4: The backstop lab

A lab that drives a worker to allocate past `memory_limit` and checks the backstop,
modeled on `lab/integration/refusal.sh` (php-fpm behind nginx + Apache mod_php).
No attack request is needed — an ordinary script that keeps allocating. Testing
against *vulnerable* PHP versions is out of scope (the owner supplies those); this
lab runs on the ordinary dev images.

**Files:**
- Create: `lab/integration/oom_backstop.sh` (host driver)
- Create: `lab/integration/oom_backstop_container.sh` (fpm-behind-nginx half)
- Create: `lab/integration/oom_backstop_apache_container.sh` (Apache mod_php half)
- Reuse: `lab/integration/refusal_nginx.conf`

**Interfaces:**
- Consumes: the built `libhowdah_ext.so` (the container builds it, as
  `refusal_container.sh` does); the phpinfo `OOM backstop` row from Task 3.

- [ ] **Step 1: Write the host driver** `oom_backstop.sh` by adapting
  `refusal.sh`: same image discovery, same fpm+nginx sidecar and Apache arms, same
  per-row TSV output and non-zero exit on any `FAIL`. Default versions
  `5.6 7.4 8.3` (and `8.0`/`8.1` where images exist); a missing dev image is
  `SKIP`/NOT-RUN, never FAIL.

- [ ] **Step 2: Write the container half** `oom_backstop_container.sh` by adapting
  `refusal_container.sh`. Build `libhowdah_ext.so`; write an app whose OOM script
  allocates past a low `memory_limit`:

```php
// oom.php
<?php @file_put_contents('/work/marker/ran', (string) getmypid());
$a = []; while (true) { $a[] = str_repeat('x', 1024 * 1024); }
```

  and a `warn.php` (emits an `E_WARNING` / `trigger_error(..., E_USER_WARNING)`,
  then prints `OK pid=`) and an `ex.php` (`throw new RuntimeException('x');`).
  Run php-fpm with one static worker behind nginx, `-d memory_limit=32M`, the
  extension loaded, `howdah.log` set. Assertions (TSV rows, PASS/FAIL/SKIP):
  - **oom_exits:** request `/oom.php` → connection dropped / HTTP 502; the log has
    a line with `"rule":"out_of_memory"` and `"action":"block"`; the worker pid
    CHANGES (a fresh worker answers the next `/`); a benign follow-up `/` answers
    200. (Inverse of `refusal.sh`, where the pid must NOT change.)
  - **oom_off_survives:** restart fpm with `-d howdah... ` and a config carrying
    `oom_exit = false` → `/oom.php` returns PHP's normal fatal (HTTP 500 with
    "Allowed memory size" in the body or fpm log), the worker pid is UNCHANGED, and
    the log has NO `out_of_memory` block line.
  - **warning_survives:** `/warn.php` → 200, pid unchanged, no backstop line.
  - **exception_survives:** `/ex.php` → PHP's normal 500 (uncaught exception), pid
    unchanged, no backstop line.
  - **cli_off:** run `php -d extension=... -d memory_limit=32M /work/app/oom.php`
    directly → PHP prints its normal "Allowed memory size ... exhausted" fatal and
    the log has NO `out_of_memory` line (the hook is not installed on the cli
    SAPI); the phpinfo row reads `off (SAPI cli)`.
  - **patched_off:** if a patched image (e.g. 8.4.27) is available, the phpinfo row
    reads `off (patched ...)` and `/oom.php` returns PHP's own behavior with no
    backstop line; else record NOT-RUN.

- [ ] **Step 3: Write the Apache half** `oom_backstop_apache_container.sh` by
  adapting `refusal_apache_container.sh`: mod_php prefork, one worker, the
  `oom_exits` and `warning_survives` checks (pid change via a `getmypid()` marker
  across two requests).

- [ ] **Step 4: Run the lab where images exist; record NOT-RUN otherwise**

  Run: `lab/integration/oom_backstop.sh` (or `SAPIS=fpm lab/integration/oom_backstop.sh 8.3`
  for one). Expected: every runnable row PASS; results in
  `lab/integration/.oom-backstop-out/results.tsv`. If Docker or the dev images are
  unavailable in this environment, record the run as NOT-RUN in the PR description
  (the owner can run it), and rely on Task 1's host tests + Task 3's build for the
  mechanism.

- [ ] **Step 5: Commit**

```bash
git add lab/integration/oom_backstop.sh lab/integration/oom_backstop_container.sh \
        lab/integration/oom_backstop_apache_container.sh
git commit -m "lab: the out-of-memory backstop (worker exits, oom_exit=false survives, CLI/patched off)"
```

---

### Task 5: Config editor, docs, and schema surfaces

The three surfaces a new config key needs, plus the doc touch-ups for the two new
rules. Separate task because its test cycle is `npm test` and its reviewer concern
is user-facing copy.

**Files:**
- Modify: `site/config-editor/schema.js` (add `oom_exit` to `TOP`; add the two new
  catalog rules to `RULE_LAYER`; mark them `noop` in `rulesKeys`)
- Modify: `site/test/editor.test.mjs` (round-trip test for `oom_exit`)
- Modify: `site/test/schema.test.mjs` (the noop test must expect the two backstop
  rules to be noop)
- Modify: `docs/config.md` (a `### oom_exit` subsection)
- Modify: `docs/log-schema.md` (list `out_of_memory` and `startup_fatal`)
- Modify: `docs/howdah-event.schema.json` (mention the backstop in the `layer`
  description — the `rule` field is pattern-based, so no enum change)

**Interfaces:**
- Consumes: the core's canonical config JSON now carries `oom_exit` (Task 2) and
  the rule catalog now carries `out_of_memory`/`startup_fatal` (Task 1), both read
  through the WASM validator — so the wasm MUST be rebuilt from this branch before
  the site tests (Step 3).

**Why the catalog rules need editor handling:** `rule_catalog()` holds every
`RuleId` (enforced by a core test), so the two backstop rules flow into the
editor's `[rules]` section and `schema.test.mjs` checks `RULE_LAYER[name]` for each
catalog rule directly. But the backstop is governed solely by `oom_exit`, not by a
per-rule `[rules]` mode — a `[rules].out_of_memory` override is inert. So, exactly
as the editor already does for inspect/sinks/behavior names, these are shown but
marked `noop` with a note pointing at `oom_exit` (not left as apparently-live
Critical knobs, which the site truth-audit would rightly flag). Making the backstop
honor a per-rule override is out of scope: the owner's design is a single
`oom_exit` boolean.

- [ ] **Step 1: Add the editor row** — append to the `TOP` array in `schema.js`
  (after `exceptions_log`, so existing `SCHEMA.top[0]`/`[1]` indices are unchanged):

```js
{ key: 'oom_exit', type: 'bool', default: true,
  note: 'End the PHP worker if it runs out of memory (or hits a fatal during request startup) before any code runs on the half-built request state — the PHP2Shell backstop. On by default. Web SAPIs only, and automatically off on PHP versions that carry upstream’s fix. The dropped request becomes a 502; the worker is replaced.' }
```

  The emitter (`editor.js`) and `defaultState` consume `TOP` generically, so the
  key round-trips with no editor.js change: `true` (the default) is emitted
  commented-out / omitted; `false` is written as `oom_exit = false`.

- [ ] **Step 1b: Place the two backstop rules in the `[rules]` section as noop.**
  In `schema.js`: add `out_of_memory: 'other', startup_fatal: 'other'` to the
  `RULE_LAYER` map. In `rulesKeys`, mark these two as `noop` with a dedicated note
  (they are not inspect/sinks/behavior, so the existing `noop` condition misses
  them):

```js
var BACKSTOP_RULES = { out_of_memory: 1, startup_fatal: 1 };
var OOM_NOOP_NOTE = 'Accepted by the core but has no effect here: the out-of-memory backstop is turned on and off by the top-level oom_exit key, not by a per-rule mode.';
// inside rulesKeys(...).map:
var layer = RULE_LAYER[r.name] || 'other';
var noop = layer === 'inspect' || layer === 'sinks' || layer === 'behavior' || !!BACKSTOP_RULES[r.name];
return { key: r.name, type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
         severity: r.severity, layer: layer, noop: noop,
         note: BACKSTOP_RULES[r.name] ? OOM_NOOP_NOTE : (noop ? NOOP_NOTE : (RULE_NOTES[r.severity] || '')) };
```

  Then update the noop test in `site/test/schema.test.mjs` ("Layer 2/3 rule names
  under [rules] are marked as having no effect") so its expected-noop condition
  also treats `out_of_memory`/`startup_fatal` as noop:
  `const noop = k.layer === 'inspect' || k.layer === 'sinks' || k.layer === 'behavior' || k.key === 'out_of_memory' || k.key === 'startup_fatal';`
  and allow their note to match `/no effect/` (the `OOM_NOOP_NOTE` contains "no
  effect"). The "a layer each" test then passes because `RULE_LAYER['out_of_memory']`
  is now truthy (`'other'`).

- [ ] **Step 2: Write the failing editor test** in `site/test/editor.test.mjs`,
  modeled on the `on_invalid_config` test:

```js
test('oom_exit: default true omitted, false emitted top-level, round-trips', () => {
  assert.equal(SCHEMA.top.find((t) => t.key === 'oom_exit').default, true);
  assert.equal(validate('').config.oom_exit, true);
  const s = fresh();
  s.oom_exit = false;
  const toml = E.emitToml(s);
  assert.ok(toml.indexOf('oom_exit = false') < toml.indexOf('[limits]'), toml);
  const v = validate(toml);
  assert.equal(v.config.oom_exit, false);
  assert.equal(E.loadFromCanonical(v.config, catalog).state.oom_exit, false);
  assert.ok(E.emitToml(fresh(), { includeDefaults: true }).includes('# oom_exit = true'));
});
```

  (Match the helper names already used in that file — `fresh()`, `validate()`,
  `E`, `catalog`, `SCHEMA`.)

- [ ] **Step 3: Build the wasm and run the site tests to verify the test fails for
  the right reason**

  Run: `sh packaging/build-wasm.sh` (produces `site/demo/howdah_wasm.wasm` from the
  branch's core, which now includes `oom_exit`), then `cd site && npm ci && npm
  test`.
  Expected: the new `oom_exit` test FAILS first only if the row is missing; with
  Step 1 done it should PASS. If the wasm is stale (built before Task 2), the
  round-trip FAILS with `deny_unknown_fields` rejecting `oom_exit = false` — the
  signal to rebuild the wasm.

- [ ] **Step 4: Document the key** — add to `docs/config.md`, right after the
  `### on_invalid_config` subsection (both are top-level TOML keys):

```markdown
### `oom_exit`

```toml
oom_exit = true   # true (default) | false
```

On by default. If PHP runs out of memory — or hits a fatal error during request
startup — on an engine without upstream's fix, Howdah ends the worker before any
code runs on the half-built request state (the PHP2Shell backstop,
CVE-2026-109618/109619). The worker is replaced; the one request that ran out of
memory gets a dropped connection (nginx answers 502). The event is logged with
rule `out_of_memory` (or `startup_fatal`) and action `block`. The backstop runs
only on web SAPIs (apache2handler, php-fpm, cgi-fcgi, LiteSpeed), never on the
command line, and turns itself off on PHP versions that ship the upstream fix
(detected at runtime). Set `oom_exit = false` to keep PHP's default behavior (a
fatal error page, the worker surviving) — on an unpatched engine that reopens the
PHP2Shell window. It does not fix the underlying PHP bug; patching remains the fix.
```

- [ ] **Step 5: List the two rules** in `docs/log-schema.md` wherever the rule
  names/layers are enumerated (the Layer-1 group): add `out_of_memory` and
  `startup_fatal` with a one-line description each. Keep the existing ≥3 sample
  JSON lines; optionally add one `out_of_memory` sample (it is validated by
  `tests/event_schema.rs::docs_sample_lines_validate`).

- [ ] **Step 6: Touch the schema description** — in `docs/howdah-event.schema.json`,
  extend the `layer` property's `description` so layer 1 reads "...multipart, input
  shape, request headers, self-test, and the out-of-memory backstop". No structural
  change (the `rule` field is a pattern, not an enum, so the new names already
  validate — confirmed by `cargo test -p howdah-core` running
  `tests/event_schema.rs`).

- [ ] **Step 7: Run the full gate**

  Run: `cargo test --workspace`; `cargo clippy --all-targets -- -D warnings`
  (host); `cargo clippy -p howdah-ext --features php8 --all-targets -- -D warnings`;
  `sh packaging/build-wasm.sh && cd site && npm test`.
  Expected: all PASS.

- [ ] **Step 8: Commit**

```bash
git add site/config-editor/schema.js site/test/editor.test.mjs site/test/schema.test.mjs \
        docs/config.md docs/log-schema.md docs/howdah-event.schema.json
git commit -m "config editor + docs: oom_exit, out_of_memory/startup_fatal rules"
```

---

### Task 6: Independent review, finish, PR

- [ ] **Step 1: Whole-branch verification.** Re-run the full gate (Task 5 Step 7)
  on the final branch; capture the output for the PR.

- [ ] **Step 2: Independent Fable review** of everything touching core, ext or C
  (the whole diff, with emphasis on: the per-generation `zend_error_cb` signatures
  and the untouched `va_list` forwarding; the `memory_hard_limit_percent` probe not
  reading present on unpatched builds; the classifier's fatal-mask and prefix
  match; fail-open on panic; the MINIT gate and MSHUTDOWN restore; append-only
  discipline on the shared files). Apply the superpowers:receiving-code-review
  skill to each finding; fix what is real, push back on what is not, commit the
  fixes.

- [ ] **Step 3: Push and open the PR** to `main`. The PR carries the approved
  design spec (already on the branch), this plan, and the implementation. Body:
  what the backstop does and its trade-offs (dropped connection → 502, other
  `zend_error_cb` consumers won't see the error, worker recycles); the lab results
  (PASS rows, and any NOT-RUN with the reason); the versions/SAPIs exercised; and
  the Claude Code footer. CI must be green. Stop and report the PR link; do not
  merge, tag, bump versions, or publish.

---

## Self-review

**1. Spec coverage (§4.6 + §5.5):**
- "save `zend_error_cb` and install Howdah's handler, chained" → Task 3 shim +
  MINIT install.
- OOM/`"Out of memory"` match + startup-fatal → Task 1 classifier.
- "writes Howdah's log line then `_exit()` before the longjmp" → Task 3 decide +
  shim `_exit`.
- "exit path allocates nothing [relaxed to system-malloc log path]" → Task 3 decide
  uses `write_log_line`; fail-stop preserved (a real malloc failure aborts).
- "fatal errors during request startup take the same exit; during the script do
  not" → Task 1 `during_startup` branch; Review Focus + lab.
- "Web SAPIs only; off on CLI; off on patched (runtime version check)" → Task 3
  SAPI helper + `memory_hard_limit_percent` probe; lab `cli_off`/`patched_off`.
- "one boolean key turns it off" → Task 2 `oom_exit` + Task 5 surfaces.
- "two new Critical Layer-1 RuleIds; every exhaustive `RuleId` match updated;
  schema/log-schema/event_schema/header updated" → Task 1 places the variants in
  all four exhaustive matches (`rule_layer`, `rule_name`, `describe`, `Layer::of`)
  plus the catalog; Task 2 regenerates the header; Task 5 updates log-schema and
  the schema `layer` description. `event_schema.rs` needs no edit: the `rule` field
  is a pattern and layer 1 is already in the enum, so the new rules validate (and
  `cargo test -p howdah-core` exercises them). `RuleId::severity` needs no arm (its
  `_ => Critical` arm covers them).
- lab (§5.5): worker exits + line logged; next request fresh worker; `oom_exit`
  off unchanged; patched + CLI off; warning/exception don't exit → Task 4.

**2. Step scan:** code blocks appear only for the genuinely underdetermined pieces
(the per-generation C handler, the classifier's constants/logic, the decide
skeleton, the exact test assertions and config wiring). No "handle edge cases"
placeholders.

**3. Type consistency:** `classify_fatal(i32, &[u8], bool) -> Option<RuleId>` is used
identically in Task 1 (tests) and Task 3 (decide). `HowdahOomDecide` /
`howdah_oom_decide_t` signatures match between `lib.rs`, `oom_hook.c` and
`oom_filter::decide`. `howdah_oom_exit`/`howdah_install_oom_hook`/
`howdah_uninstall_oom_hook`/`howdah_memory_hard_limit_percent_exists` names match
across their declaration and call sites.

**4. Review Focus:** the five entries each have a test named in their owning task
(classifier cases in Task 1; lab rows in Task 3/4; getter in Task 2).

**5. Proportion:** the plan is long because the backstop crosses the core, the C
shim, the ext glue, the lab, the config editor and the docs; the code blocks are
the exact C/Rust the implementer cannot derive (per-generation ABI signatures, PHP
error constants, the config wiring) and the precise test assertions, not a
transcript of derivable bodies.
