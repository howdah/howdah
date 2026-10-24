# Howdah Layer 4 "After a Breach" Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Howdah 1.4.0 Layer 4 — an application-behaviour policy, anchored on execution origin, that detects (and, opt-in, blocks) PHP run from directories that should not hold executable PHP, unexpected `exec`/egress/`.php`-writes, with a propose-only discovery mode — log-first and off-safe by default.

**Architecture:** A new `[behavior]` config section mirroring `[inspect]`. A pure-Rust `behavior` module in `howdah-core` does all classification (no arg values logged). FFI `howdah_behavior_*` entrypoints mirror `howdah_sink_*`. Hooks reuse Layer 3's mechanisms: the compile-file pointer swap + a new RINIT main-script check for execution origin; the command-exec fn-table trampolines (additive second decision) for binaries; the SSRF egress trampolines (origin threaded in, `armed` widened) for egress; a shared `fopen` trampoline plus new fn-table swaps for `.php`-writes. Origin at a sink is `zend_get_executed_filename()` (spike-proven 5.4–8.4).

**Tech Stack:** Rust (howdah-core pure, howdah-ext glue), C shims (howdah-sys, ABI-variant hooking), TOML config, cbindgen-generated `howdah_core.h`, Astro site, Docker lab across PHP 5.4–8.5.

**Spec:** `docs/superpowers/specs/2026-10-24-howdah-layer4-after-breach-design.md`

## Global Constraints

- **Defensive tool only.** No capability that aids attack. Reproducers recreate only harmless request/behaviour *shape*, never a runnable exploit (no real miner, no working webshell payload — a script that calls `system('true')` from an uploads dir is the shape).
- **No overclaiming.** Every claim on the site/coverage is backed by a passing test. State the §7 limitations verbatim in spirit; never claim Howdah stops miners in general.
- **Log-first, never blocks by default.** `[behavior]` ships `mode = "detect"`, all facet lists empty, `deny_php_writes = false`, `observe = false`. A fresh install must block nothing.
- **Independent mode.** `behavior.effective_mode(global) = Off if global==Off || !enabled else self.mode`. `howdah.mode = block` must NOT force Layer 4 to block.
- **No new php.ini directives** (stays at 3).
- **Argument/target values are never logged.** Log a classification + the directory/host/binary basename, never the serialized payload or file contents. (Consistent with Layer 3: detail strings carry rule + category, not the arg.)
- **Observe only ever proposes.** It emits `proposed` log lines and never blocks and never writes config, so a first install on an already-breached box cannot bless malicious behaviour.
- **Commit trailer:** `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **cbindgen:** `crates/howdah-core/howdah_core.h` is generated — regenerate, never hand-edit.
- **ABI check:** for any new/changed C shim, compile it once per PHP image with `-Werror=incompatible-pointer-types` (caught a real 5.6 bug in 1.3).

## Review Focus

- **Default install blocks nothing.** A config with no `[behavior]` section, and one with `[behavior]` present but all facets empty + `mode="detect"`, must produce zero BLOCK actions on any input. (Task 1 + Task 8 assert this.)
- **Legit framework `.php` writes are not flagged.** A `file_put_contents("/var/www/app/storage/framework/views/x.php", …)` from an app script, with `deny_exec_dirs` NOT covering that path, must be ALLOW even when `deny_php_writes=true`. Blade/Twig must keep working. (Task 3 + Task 8.)
- **`fopen` in read mode on a `.php` is ignored.** `fopen("/var/www/app/config.php","r")` must never be flagged by the write facet. (Task 3/5 + Task 8.)
- **Origin attribution is to the actual caller.** When an app `require`s an uploaded shell that calls `system`, the finding names the uploaded shell's directory, not the entry script. (Task 8, direct + require cases.)
- **Opcache does not silently void the headline control.** A direct request to `/uploads/x.php` is caught at RINIT every request regardless of opcache; only the `require`d-file case is first-compile best-effort. (Task 6 + Task 8, and stated honestly on the site in Task 9.)

---

### Task 1: `[behavior]` config section

**Files:**
- Modify: `crates/howdah-core/src/config.rs`
- Test: inline `#[cfg(test)]` in `config.rs`

**Interfaces:**
- Produces: `pub struct BehaviorConfig { pub enabled: bool, pub mode: Mode, pub observe: bool, pub deny_exec_dirs: Vec<String>, pub allow_exec_binaries: Vec<String>, pub allow_egress_hosts: Vec<String>, pub deny_php_writes: bool }` with `#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)] #[serde(deny_unknown_fields, default)]`; `impl Default` = `{ enabled: true, mode: Mode::Detect, observe: false, deny_exec_dirs: vec![], allow_exec_binaries: vec![], allow_egress_hosts: vec![], deny_php_writes: false }`; `pub fn effective_mode(&self, global: Mode) -> Mode` (Off if `global==Off || !enabled`, else `self.mode`).
- Consumes: `Mode` (existing).
- `Config` gains `pub behavior: BehaviorConfig`; `RawConfig` gains `behavior: BehaviorConfig`; `safe_defaults()` sets `behavior: BehaviorConfig::default()`; `from_toml` maps `behavior: raw.behavior` and validates (below).

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn behavior_defaults_off_safe() {
    let c = Config::from_toml("mode=\"detect\"").unwrap();
    assert!(c.behavior.enabled);
    assert_eq!(c.behavior.mode, Mode::Detect);
    assert!(!c.behavior.observe);
    assert!(c.behavior.deny_exec_dirs.is_empty());
    assert!(!c.behavior.deny_php_writes);
}
#[test] fn behavior_effective_mode_independent_of_global_block() {
    let c = Config::from_toml("mode=\"detect\"\n[behavior]\nmode=\"detect\"").unwrap();
    assert_eq!(c.behavior.effective_mode(Mode::Block), Mode::Detect); // global block does NOT escalate
    assert_eq!(c.behavior.effective_mode(Mode::Off), Mode::Off);
}
#[test] fn behavior_disabled_is_off() {
    let c = Config::from_toml("[behavior]\nenabled=false\nmode=\"block\"").unwrap();
    assert_eq!(c.behavior.effective_mode(Mode::Block), Mode::Off);
}
#[test] fn behavior_rejects_relative_exec_dir() {
    assert!(Config::from_toml("[behavior]\ndeny_exec_dirs=[\"relative/path\"]").is_err());
}
#[test] fn behavior_rejects_blank_binary() {
    assert!(Config::from_toml("[behavior]\nallow_exec_binaries=[\"  \"]").is_err());
}
```

- [ ] **Step 2: Run tests, verify they fail** — `cargo test -p howdah-core behavior_` → FAIL (BehaviorConfig undefined).
- [ ] **Step 3: Implement `BehaviorConfig`** in `config.rs`: the struct, `Default`, `effective_mode`; add the field to `Config`/`RawConfig`/`safe_defaults`/`from_toml`. In `from_toml`, validate each `deny_exec_dirs` entry is absolute (`starts_with('/')`) and non-blank, and each `allow_exec_binaries`/`allow_egress_hosts` entry is non-blank/no inner whitespace; reuse `crate::sinks::ssrf::valid_allow_entry` for `allow_egress_hosts`. Return `ConfigError` with a message naming the bad field/entry.
- [ ] **Step 4: Run tests, verify pass** — `cargo test -p howdah-core behavior_` → PASS.
- [ ] **Step 5: Commit** — `feat(core): [behavior] Layer-4 config section`.

### Task 2: Four new RuleIds

**Files:**
- Modify: `crates/howdah-core/src/limits.rs`
- Test: inline (extend `rule_catalog_covers_every_variant`).

**Interfaces:**
- Produces: `RuleId::{UploadExec, UnexpectedBinary, UnexpectedEgress, PhpWrite}`, all `Severity::Standard`, all present in `rule_catalog()`.

- [ ] **Step 1: Extend the exhaustive-catalog test** (the one at limits.rs ~537) to include the four new variants in its match; add an assertion `assert_eq!(rule_catalog().len(), 28);`.
- [ ] **Step 2: Run** `cargo test -p howdah-core rule_catalog` → FAIL to compile (non-exhaustive match / wrong len).
- [ ] **Step 3: Implement** — add the four variants to `enum RuleId` (after `Ssrf`), add them to the default-`Standard` arm of `severity()` (they fall through to `_ => Critical` today, so they MUST be named in the `Standard` list), and add them to `rule_catalog()`'s `ALL` array (bump `[RuleId; 24]` → `[RuleId; 28]`).
- [ ] **Step 4: Run** `cargo test -p howdah-core` → PASS (catalog + severity tests green).
- [ ] **Step 5: Commit** — `feat(core): Layer-4 RuleIds (UploadExec/UnexpectedBinary/UnexpectedEgress/PhpWrite)`.

### Task 3: `behavior` core module (pure Rust classification)

**Files:**
- Create: `crates/howdah-core/src/behavior/mod.rs`
- Modify: `crates/howdah-core/src/lib.rs` (add `pub mod behavior;`)
- Test: inline in `behavior/mod.rs`

**Interfaces:**
- Consumes: `BehaviorConfig` (Task 1), `RuleId` (Task 2), `Mode`.
- Produces (pure functions, borrow `&BehaviorConfig`, return `Option<BehaviorHit>` where `BehaviorHit { rule: RuleId, detail: String }` — `detail` names the dir/host/basename, NEVER the arg/payload):
  - `pub fn exec_dir_hit(script_realpath: &str, cfg: &BehaviorConfig) -> Option<BehaviorHit>` — `UploadExec` iff `script_realpath` is under a canonicalised `deny_exec_dirs` entry (prefix match on path boundary, so `/var/www/uploadsX` does not match `/var/www/uploads`).
  - `pub fn binary_hit(caller_realpath: &str, program: &str, cfg: &BehaviorConfig) -> Option<BehaviorHit>` — `UnexpectedBinary` iff the exec facet is active (observe, or non-empty `allow_exec_binaries`, or caller under `deny_exec_dirs`) and `program`'s basename/path is NOT in `allow_exec_binaries`.
  - `pub fn egress_hit(caller_realpath: &str, host: &str, cfg: &BehaviorConfig) -> Option<BehaviorHit>` — `UnexpectedEgress` iff egress facet active and `host` not matched by `allow_egress_hosts` (reuse ssrf host/CIDR matching for the allow test).
  - `pub fn php_write_hit(caller_realpath: &str, target_path: &str, is_write_mode: bool, cfg: &BehaviorConfig) -> Option<BehaviorHit>` — `PhpWrite` iff `deny_php_writes` && `is_write_mode` && `target_path` has a PHP extension (`.php`/`.php5`/`.phtml`/`.phar`) && **origin-scoped**: target is under a `deny_exec_dirs` entry OR caller is under a `deny_exec_dirs` entry. When `deny_exec_dirs` is empty, `deny_php_writes` scopes to nothing and returns `None` (documented: operator must name the writable dirs).
  - `pub fn has_php_ext(path: &str) -> bool`, `pub fn path_under(path: &str, dir: &str) -> bool` (boundary-correct prefix) — helpers, `pub(crate)` ok.

- [ ] **Step 1: Write failing tests** — cover: shell under `/var/www/uploads` → `UploadExec`; `/var/www/uploadsX/a.php` NOT flagged; binary `xmrig` not in allowlist → `UnexpectedBinary`, `gs` in allowlist → None; egress `evil.test` → `UnexpectedEgress`, allowed host → None; **`php_write_hit("/var/www/app/index.php", "/var/www/app/storage/framework/views/x.php", true, cfg)` with `deny_exec_dirs=[]` → None** (Blade false-positive guard); same with `deny_exec_dirs=["/var/www/uploads"]` and target under uploads → `PhpWrite`; **`php_write_hit(.., "/var/www/app/config.php", /*is_write_mode*/ false, ..)` → None** (read ignored).
- [ ] **Step 2: Run** `cargo test -p howdah-core behavior::` → FAIL.
- [ ] **Step 3: Implement** the module and helpers. No `std::fs::canonicalize` in core (core is sandbox-pure and gets realpaths from the ext); treat inputs as already-resolved absolute paths and do lexical boundary matching.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): behavior module — origin/binary/egress/php-write classifiers`.

### Task 4: FFI `howdah_behavior_*` + cbindgen

**Files:**
- Modify: `crates/howdah-core/src/ffi.rs`
- Regenerate: `crates/howdah-core/howdah_core.h`
- Test: inline FFI smoke tests in `ffi.rs`

**Interfaces:**
- Consumes: Task 3 classifiers, `module`/ctx config access as the existing `howdah_sink_*` fns do; the per-hit log slot (`howdah_take_sink_log_line`, reused — behavior hits write the same slot).
- Produces (all `#[no_mangle] pub unsafe extern "C"`, null-ctx-safe, returning `HOWDAH_ALLOW/LOG/BLOCK` and writing the log slot on a hit; in `observe` mode they NEVER return BLOCK and the slot line is prefixed `proposed`):
  - `pub const HOWDAH_BEHAVIOR_EXEC_DIR: i32 = 0; _BINARY = 1; _EGRESS = 2; _PHP_WRITE = 3;`
  - `howdah_behavior_armed(ctx, facet: i32) -> i32` — 1 iff `behavior.effective_mode != Off` AND that facet is active (observe, or the relevant list non-empty / `deny_php_writes` / `deny_exec_dirs` non-empty).
  - `howdah_behavior_egress_active(ctx) -> i32` — convenience for the widened SSRF `armed` (Task 5): 1 iff behavior egress facet armed.
  - `howdah_behavior_check_exec_dir(ctx, path: *const c_char, path_len: usize) -> i32`
  - `howdah_behavior_check_binary(ctx, caller, caller_len, prog, prog_len) -> i32`
  - `howdah_behavior_check_egress(ctx, caller, caller_len, host, host_len) -> i32`
  - `howdah_behavior_check_php_write(ctx, caller, caller_len, target, target_len, is_write_mode: i32) -> i32`
- The action from `effective_mode`: `Detect`→max(LOG), `Block`→BLOCK on a hit; observe forces ≤LOG.

- [ ] **Step 1: Write failing FFI tests** — build a ctx with a `[behavior]` config (detect, `deny_exec_dirs=["/u"]`), call `howdah_behavior_check_exec_dir(ctx,"/u/x.php")` → `HOWDAH_LOG`; with `mode=block` → `HOWDAH_BLOCK`; observe=true + block → `HOWDAH_LOG` and slot line starts `proposed`.
- [ ] **Step 2: Run** `cargo test -p howdah-core ffi` → FAIL.
- [ ] **Step 3: Implement** the entrypoints (mirror `howdah_sink_check`'s structure: null-guards, `effective_mode`, call classifier, format the log line via the shared slot, map to action, observe clamps to LOG).
- [ ] **Step 4: Regenerate header** — `cargo build -p howdah-core` (or the repo's cbindgen step); confirm `howdah_core.h` now declares the new fns + consts. Run `cargo test -p howdah-core` → PASS.
- [ ] **Step 5: Commit** — `feat(core): howdah_behavior_* FFI + regenerate header`.

### Task 5: C shims — origin capture, binary/egress/php-write hooks

**Files:**
- Modify: `crates/howdah-sys/sink_hook.c` (command-exec trampolines: capture origin, additive behavior binary check; compile-file hook: additive exec-dir check)
- Modify: `crates/howdah-sys/ssrf_hook.c` (widen `armed`; thread origin into egress `decide`; shared `fopen` trampoline also runs php-write; new php-write swaps)
- Modify: `crates/howdah-sys/howdah_sink.h` (declare new install fn + extended typedefs)
- Test: covered by Task 8 (lab); add a compile-time ABI check step here.

**Interfaces:**
- Consumes: Task 4 FFI.
- Produces: `void howdah_install_behavior_hooks(...)` that swaps `file_put_contents`, `move_uploaded_file`, `rename` (and shares the existing `fopen` swap). A helper `static const char* howdah_current_script(void)` = `zend_get_executed_filename()` (5.x: `TSRMLS_FETCH()` + `zend_get_executed_filename(TSRMLS_C)`; 7/8: `zend_get_executed_filename()`), spike-proven.
- **Arg positions:** `file_put_contents` arg 1; `move_uploaded_file`/`rename` arg 2; `fopen` arg 1 = path, arg 2 = mode-string → `is_write_mode` iff it contains any of `waxc+`. Use the `ssrf_hook.c` `HOWDAH_ARG(n,var)` n-th-arg accessor, not `sink_hook.c`'s arg-1-only macro.
- **Shared `fopen`:** do NOT add a second swap. In the existing `fopen` trampoline (ssrf_hook.c), after the SSRF check, if behavior php-write armed, capture origin + mode and call `howdah_behavior_check_php_write`; final action = max(ssrf_action, behavior_action).
- **Command-exec:** in each command-exec trampoline (sink_hook.c), after the existing sink decide, if `howdah_behavior_armed(ctx, BINARY)`, capture origin + program (arg 1) and call `howdah_behavior_check_binary`; action = max(sink_action, behavior_action); BLOCK still neutralizes via `RETVAL_FALSE`.
- **Egress origin:** extend `howdah_ssrf_decide_t` with `const char *origin, size_t origin_len` (captured in each URL-sink trampoline); `ssrf_filter::decide` passes it to `howdah_behavior_check_egress` when egress armed (Task 4). Widen `howdah_ssrf_armed` glue (Task 7 wiring) so the trampoline's `if (!g_armed) return 0;` does not short-circuit when only behavior-egress is on.
- **Compile-file exec-dir:** in `howdah_compile_file` (sink_hook.c), in addition to the existing include/eval path, if `howdah_behavior_armed(ctx, EXEC_DIR)` and `fh->filename` set, call `howdah_behavior_check_exec_dir`; on BLOCK, bail (reuse the include neutralize path).

- [ ] **Step 1:** Add `howdah_current_script()` helper + extend typedefs/headers.
- [ ] **Step 2:** Implement the php-write swaps + shared `fopen` branch + arg accessors + write-mode gate.
- [ ] **Step 3:** Implement the additive command-exec binary check + compile-file exec-dir check.
- [ ] **Step 4:** Thread origin into the egress decide typedef + trampolines.
- [ ] **Step 5: ABI check** — compile `sink_hook.c` + `ssrf_hook.c` with `-Werror=incompatible-pointer-types` against PHP 5.4, 5.6, 7.4, 8.3, 8.5 headers (lab images). Fix any `const char*` vs `char*` splits (PHP_VERSION_ID gated). Expected: clean.
- [ ] **Step 6: Commit** — `feat(sys): Layer-4 C shims — origin, binary/egress/php-write hooks`.

### Task 6: Ext glue + module wiring (RINIT main-script, install gating)

**Files:**
- Create: `crates/howdah-ext/src/behavior_filter.rs` (the behavior glue callbacks, mirroring `sink_filter.rs`/`ssrf_filter.rs`)
- Modify: `crates/howdah-ext/src/module.rs` (RINIT main-script exec-dir check; install gating; request reset), `crates/howdah-ext/src/lib.rs` (`mod behavior_filter;`), `crates/howdah-ext/src/ssrf_filter.rs` (widen `armed`; pass origin to egress)
- Test: Task 8 (lab).

**Interfaces:**
- Consumes: Task 4 FFI, Task 5 install fns.
- `ssrf_filter::armed` returns 1 iff `howdah_sink_ssrf_armed(CTX) || howdah_behavior_egress_active(CTX)`.
- `ssrf_filter::decide` gains the origin params and forwards to `howdah_behavior_check_egress` when egress armed, combining actions.
- `module.rs`:
  - At first-RINIT once-guard (where phar/ssrf install today), also: `if howdah_behavior_armed(CTX, EXEC_DIR) || behavior php-write armed || behavior egress armed { install the needed hooks }`. The compile-file hook must install if **include/eval OR behavior exec-dir** is armed (today it installs with the MINIT sink hooks — confirm the compile-file swap fires for behavior even when include/eval are off; if it is MINIT-unconditional, no change needed beyond the in-hook armed check). `howdah_install_behavior_hooks` installs the php-write swaps; ssrf hooks install if ssrf OR behavior-egress armed.
  - **RINIT main-script check:** in `maybe_begin` (or the RINIT path), read the main script path from the SAPI (`SG(request_info).path_translated`, via a small accessor in the C shim or an existing one) and call `howdah_behavior_check_exec_dir`; on BLOCK, emit the log line + `emit_and_bail` (reuse Layer 1's 403 bailout). This is the opcache-independent headline control.
  - `clear_request_state`: reset any behavior per-request state (if added). No new state expected (checks are stateless), so likely a no-op — confirm.

- [ ] **Step 1:** `behavior_filter.rs` glue (read log slot + `response::write_log_line`, fail-open, mirroring `sink_filter::decide`).
- [ ] **Step 2:** Widen `ssrf_filter::armed`; thread origin through `ssrf_filter::decide`.
- [ ] **Step 3:** Module install gating + `howdah_install_behavior_hooks` call + compile-file/ssrf install conditions.
- [ ] **Step 4:** RINIT main-script exec-dir check + bail on block.
- [ ] **Step 5: Build the whole extension** for one modern (8.3) and one legacy (5.6) image; `cargo build` + load `php -m | grep howdah`. Expected: loads.
- [ ] **Step 6: Commit** — `feat(ext): Layer-4 wiring — RINIT main-script check, install gating, egress origin`.

### Task 7: Observe (propose-only) mode end to end

**Files:**
- Modify: `crates/howdah-core/src/ffi.rs` + `behavior/mod.rs` as needed
- Test: inline + Task 8.

**Interfaces:** When `behavior.observe == true`, every facet's check that *would* produce a hit (or that observes a not-yet-allowlisted binary/host/exec-dir) emits a `proposed` log line and returns at most `HOWDAH_LOG` (never BLOCK), regardless of `mode`. Observe does not require the allow-list to be non-empty — its purpose is discovery, so it logs the observed binary/host/dir so the operator can build the list.

- [ ] **Step 1: Write failing tests** (core FFI) — observe=true + mode=block + `deny_exec_dirs=["/u"]`: `check_exec_dir("/u/x.php")` → `HOWDAH_LOG`, slot line begins `proposed`. observe=true, `allow_exec_binaries=[]`, `check_binary(..,"/usr/bin/gs")` → `HOWDAH_LOG` proposed (even though nothing is denied yet).
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** the observe clamp + `proposed` prefix in the FFI entrypoints (single place: after computing a candidate hit).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** — `feat(core): Layer-4 observe (propose-only) mode`.

### Task 8: Lab integration script across PHP versions

**Files:**
- Create: `lab/integration/behavior.sh`, `lab/integration/behavior_container.sh` (mirror `sinks_fastfollow*.sh`)
- Test: the script itself is the test; run on 5.4, 5.6, 7.4, 8.3, 8.5.

**Interfaces:** Build the real extension with a `[behavior]` config and assert, per version:
- A `shell.php` under `/var/www/uploads` calling `system('true')`: **direct request** → `UploadExec` logged (detect) / 403 (block); **`require`d from an app script** → finding names the uploads dir (origin), not the entry script.
- `exec`/`system` of a binary not in `allow_exec_binaries` → `UnexpectedBinary`; a binary in the list → no finding.
- An outbound `fopen("http://evil.test/", "r")` / `file_get_contents` to a host not in `allow_egress_hosts` → `UnexpectedEgress`; allowed host → none. (Egress works even with L3 `ssrf` mode off — proves the widened `armed`.)
- `file_put_contents("/var/www/uploads/x.php", "<?php …harmless… ?>")` with `deny_php_writes=true` + `deny_exec_dirs=["/var/www/uploads"]` → `PhpWrite` / block; **`file_put_contents("/var/www/app/storage/framework/views/x.php", …)` with uploads-only deny_exec_dirs → NO finding** (Blade guard); `fopen("/var/www/app/config.php","r")` → NO finding (read).
- Default config (no `[behavior]` or empty detect) → zero blocks.
- `observe=true` → `proposed` lines, zero blocks.

- [ ] **Step 1:** Write `behavior_container.sh` (build ext, write the fixtures as harmless shapes, run php, grep the log for rule ids / 403s).
- [ ] **Step 2:** Write `behavior.sh` driver iterating the compose services.
- [ ] **Step 3: Run** on 5.4, 5.6, 7.4, 8.3, 8.5. Expected: PASS all. Record any version that can't (e.g. a facet dormant on 5.x) as an explicit asserted-dormant line, never a silent skip.
- [ ] **Step 4: Commit** — `test(lab): Layer-4 behaviour integration across PHP 5.4–8.5`.

### Task 9: Version bump, docs, site, README, config-editor labels

**Files:**
- Modify: `Cargo.toml`(s) / version source → `1.4.0`; `docs/config.md` (+ `[behavior]`); `site/src/pages/index.astro` (Layer 4 row → released/log-only; new Layer-4 section + coverage rows + "how it works" copy); coverage page + `docs/coverage*.md`; `README` banner; the config-editor no-op label set (the four new rule ids).
- Test: `npm run build` (site) if present; coverage generated from the matrix, never hand-typed.

**Interfaces:** Site copy states the §7 honest limitations verbatim in spirit (PHP-only visibility; opcache scope on the included-file case; allowlist bypasses; `.php`-write false positives; observe propose-only). The Layer-4 coverage rows are generated from Task 8's results, not hand-written. The config editor marks `upload_exec`/`unexpected_binary`/`unexpected_egress`/`php_write` as no-op labels (extend the set added in commit bdc5329).

- [ ] **Step 1: Bump version to 1.4.0** everywhere 1.3.0 appears as the package version; `cargo build` to confirm.
- [ ] **Step 2: Docs** — add the `[behavior]` section to `docs/config.md` with the example from the design §4 and the honest caveats.
- [ ] **Step 3: Site** — flip the Layer 4 row to `released`/log-only; add a Layer-4 `<section>` modelled on the Layer-3 one (what it watches, the hybrid operator+observe policy, the coverage matrix, the honest-caveat block); regenerate/extend the coverage matrix from Task 8.
- [ ] **Step 4: Config editor** — add the four ids to the no-op label set so the editor shows them as labels, not effective modes. Coordinate note: peer session `howdah-94` owns the config editor/wasm; the wasm `rule_catalog` picks up new RuleIds automatically, so only the no-op labelling needs touching.
- [ ] **Step 5: README** — update the layer summary + banner to "1.4.0 released / Layer 4".
- [ ] **Step 6: Build the site** (`npm run build` in `site/` if that's the flow) → clean. **Commit** — `feat: Howdah 1.4.0 — Layer 4 docs, site, README`.

---

## Self-Review

- **Spec coverage:** design §3 facets → Tasks 1/3/5/6; §4 config → Task 1; §5 RuleIds → Task 2; origin primitive → Tasks 4/5; observe → Task 7; §6 spike already done; §7 limitations → Task 9 copy + Task 8 asserts (Blade guard, read-ignore, origin, opcache headline). Covered.
- **Type consistency:** `BehaviorConfig` field names are used identically in Task 1/3/4; FFI const names (`HOWDAH_BEHAVIOR_*`) and fn names identical in Tasks 4/5/6; `BehaviorHit{rule,detail}` in Task 3 consumed by Task 4.
- **Review Focus:** each of the five lines has an owning test (Task 1 defaults; Task 3+8 Blade + read; Task 8 origin; Task 6+8 opcache headline).
- **Proportion:** plan pins signatures + test names, not bodies — appropriate for a layer reusing proven mechanisms.
