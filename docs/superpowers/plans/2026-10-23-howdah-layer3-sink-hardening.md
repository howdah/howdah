# Howdah Layer 3 — Sink Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Guard a small set of dangerous PHP sinks (command/code exec, include/require, eval, unserialize) with flat per-sink policy that **logs and never blocks by default**, as Howdah 1.2 (Layer 3).

**Architecture:** A new pure-Rust `sinks` module in `howdah-core` decides a flat policy per sink (`command_exec` anchored-regex allowlist, `include` `allow_paths`, `eval`, `unserialize` object/class scan). A new C-ABI entry point `howdah_sink_check` resolves a hit against an **independent** `sinks.mode` (never the global `howdah.mode`), formats a privacy-preserving line into a **dedicated per-hit sink slot** (sink + function/construct name — never the argument), and returns an action. A small C shim in `howdah-sys` (`sink_hook.c`, the productized form of the throwaway spike) installs two hook mechanisms at MINIT — a function-table handler swap for the exec family + `unserialize`, and a `ZEND_INCLUDE_OR_EVAL` user opcode handler for include/require/eval — each trampoline extracting the argument as `(ptr,len)` and calling into a Rust callback that runs `howdah_sink_check`, writes the per-hit line, and on **block** neutralizes the call the `disable_functions` way (return false/NULL + warning, no mid-VM bailout). Docs, site, README, CHANGELOG, `howdah-check` and the lab all state, loudly, that Layer 3 guards sinks, detects-and-logs, and does not block by default.

**Tech Stack:** Rust (workspace crates `howdah-core`, `howdah-ext`, `howdah-sys`), a C shim compiled by `cc` against the PHP headers (like the existing `shim.c`), bindgen allowlist additions, Astro site, bash lab integration + `gen-coverage.mjs`.

**Spec:** `docs/superpowers/specs/2026-10-23-howdah-layer3-sink-hardening-design.md` (read it, including §10 "Resolutions from the builder check"; this plan argues from it).

## Global Constraints

- **Log-first, never block by default — and a global `howdah.mode = block` must NOT arm Layer 3.** Layer-3 rules are `Severity::Standard`, resolved against `sinks.mode` (default `detect` = log) via a `SinkConfig::effective_mode` that ignores the global `block`, exactly like `InspectConfig`. Only an explicit `sinks.mode = block` (or a per-sink mode) blocks. Global `off` disables everything. (spec §2.3, §5.3, §10.2)
- **Block = neutralize-and-continue, NOT bailout.** A blocked sink suppresses the call, returns false/NULL, emits a PHP warning + a log line, and lets execution continue. No `zend_bailout` mid-VM. (spec §5.4, §10.4). **Proven (Task 0) for the function-swap sinks only: `command_exec` and `unserialize` support `block`; `include` and `eval` ship DETECT-ONLY in 1.2** — their block (opcode-neutralize) is deferred to the fast-follow. Setting `[sinks.include]`/`[sinks.eval]` `mode = "block"` therefore behaves as `detect` in 1.2 and the config docs say so.
- **Per-hit logging, emitted at the call site.** Each sink hit writes its own line immediately (dedicated sink slot), outside the Layer-1/2 sticky `worst`/single-slot verdict, so nothing is dropped and the RSHUTDOWN 403 path never double-fires. (spec §5.5, §10.1)
- **Never log the sink argument.** A Layer-3 event carries sink + function/construct name (+ class name for `unserialize`, a type not user data) only. The `log::EventRecord` privacy test must still pass unchanged. (spec §5.5)
- **`command_exec` `allow` patterns are full-string anchored** (`^…$`); a substring match is a security hole. (spec §10.5)
- **Quiet-by-default sink defaults:** `command_exec` detect/on (logs exec-family calls), `include` detect-but-inert-until-`allow_paths`, `eval` detect/on, `unserialize` **off** by default. (spec §10.2)
- **Defensive only; no overclaiming; no payload generator.** Test fixtures are static representative strings (a serialized object, a traversal path), never a runnable exploit. No per-sink public bypass cookbook. Every knob has a test. (spec §3, §4, §5.6)
- **No new php.ini directives** — `[sinks]` lives in the existing TOML `howdah.config`; the extension still registers exactly 3 ini entries. (spec §2.2)
- **All glue work inside `catch_unwind` fail-open.** A sink-hook bug must never unwind into PHP and must never break a working call (fail open = chain to original). (spec §5.2)
- **phar:// and SSRF are OUT of 1.2** (documented fast-follow). (spec §8)
- Pure-Rust core stays host-unit-testable through the C ABI; builds on PHP 5.4–8.5, NTS, FPM/Apache-prefork/CGI, like Layers 1–2.

## Review Focus

- **Global-block arming:** a request under `howdah.mode = block` with `sinks.mode` unset (default detect) must **log, not block/neutralize** a guarded `system()` call. Covered in Task 4 (`sink_logs_under_global_block_when_sinks_detect`).
- **Allow-pattern anchoring:** `allow = ["ls"]` must NOT permit `ls; rm -rf /` in block mode. Covered in Task 1 (`command_allow_is_anchored_whole_string`).
- **Argument privacy:** a flagged call's argument bytes never appear in the log line; only sink/function (+ class) do. Covered in Task 4 (`sink_log_omits_argument`).
- **Per-hit emit:** three `system()` calls in one request produce three log lines, none dropped, and none disturbs a pending Layer-1/2 line. Covered in Task 4 (`multiple_sink_hits_each_emit`) and Task 8 (lab).
- **unserialize benign quiet:** a plain-data unserialize (`a:1:{...}`, no object) and framework object unserialize when the sink is default-off produce **zero** events. Covered in Task 1 (`unserialize_plain_data_is_allow`) and Task 3 (`unserialize_sink_defaults_off`).
- **Fail-open:** a panic in the sink callback chains the original call unchanged (the guarded function still runs). Covered in Task 4 (`sink_check_panic_fails_open`) and Task 5 (live).

---

### Task 0: Refuse-path spike (throwaway — settles the block idiom)

**Goal:** Before building the C shim, prove on PHP **5.6, 7.4, 8.3** exactly how a blocked sink *neutralizes* without a mid-VM bailout, and record the idiom for Task 5. The hook install+chain is already proven (spec §9); this proves only the **block** branch.

**Files:**
- Create (throwaway, NOT merged): a spike `sink_hook` C shim + a lab runner under the session scratchpad, on the model of the hook spike in spec §9.
- Record the outcome in this plan file (edit Task 5's "Refuse idiom (proven in Task 0)" line) and, if a fallback is chosen, in the design §10.4.

**What to prove, per version:**
- **Function neutralize:** from inside a swapped `system` handler, on a block decision, set the return value false and return WITHOUT calling the original — assert `system()` returned `false`, the command did **not** run, and the script continued to the next statement. (Standard `disable_functions` idiom; expected trivial.)
- **Opcode neutralize (the uncertain one):** from the `ZEND_INCLUDE_OR_EVAL` user opcode handler, on a block decision, prevent the include/eval from running while keeping VM invariants and letting the script continue. Try, in order, and record which is safe on all three: (a) set the opcode result var to NULL and return `ZEND_USER_OPCODE_CONTINUE`; (b) rewrite op1 to an empty stub file and `DISPATCH`; (c) if neither is clean on 5.6, record that **include/eval block falls back to detect-only for 1.2** (a ruling — log-only for those two; command_exec/unserialize still block) and open the opcode-block as fast-follow.

- [ ] **Step 1:** Build the throwaway spike shim (function neutralize + opcode neutralize candidates), driven from MINIT, into `howdah-ext`, as in spec §9.
- [ ] **Step 2:** Run it under the `howdah-dev-php5.6 / 7.4 / 8.3` images with a script that calls `system('…')` and `include '…'` against a block decision; capture stdout+stderr.
- [ ] **Step 3:** Confirm per version: blocked `system()` returns false + command did not run + script continued; blocked include did not load + script continued. Pick the opcode idiom (a/b) or record the detect-only fallback (c).
- [ ] **Step 4:** Record the chosen idiom in Task 5 below. **Revert all spike changes** (`git checkout -- …`, delete the spike shim) — nothing from Task 0 is committed except the recorded decision.

### Task 1: `sinks` policy module (`howdah-core`)

**Files:**
- Create: `crates/howdah-core/src/sinks.rs`
- Modify: `crates/howdah-core/src/lib.rs` (add `pub mod sinks;`)
- Test: in-module `#[cfg(test)]` in `sinks.rs`

**Interfaces:**
- Produces:
  - `pub enum SinkId { CommandExec, Include, Eval, Unserialize }`
  - `pub enum SinkOutcome { Allow, Log, Block }` (policy outcome before mode resolution: `Allow` = on allowlist / benign; `Log`/`Block` = matched, caller resolves against mode).
  - Per-sink policy fns, all **linear-time, no backtracking**, operating on `&[u8]`:
    - `pub fn command_allowed(cmd: &[u8], allow: &[String]) -> bool` — true iff `cmd` matches one pattern. A pattern is an **anchored literal** matched against the WHOLE command, UNLESS it ends in a single `*`, which matches any suffix: `"id"` matches only `id`; `"/usr/bin/convert *"` matches any command beginning `/usr/bin/convert `. **No regex, no mid-pattern wildcards** — a trailing `*` is the only metacharacter (a literal `*` is not needed in a command allowlist). Hand-rolled, trivially linear. (spec §10.5)
    - `pub fn include_allowed(path: &[u8], allow_paths: &[String]) -> bool` — true iff the normalized `path` lies under one of `allow_paths` (prefix on a normalized absolute path). Empty `allow_paths` ⇒ the include sink is inert (caller treats as Allow; see Task 3/4).
    - `pub fn unserialize_classes(payload: &[u8]) -> UnserializeScan` — a bounded forward pass returning whether the payload names any class (`O:`/`C:` tokens) and, if so, the class names found (capped count/length); plain data ⇒ no classes.
- Consumes: **nothing new** — no `regex`/`aho-corasick`. `howdah-core` stays dependency-light (serde, toml, serde_json) and keeps Layer 2's deliberate no-regex, hand-rolled-linear-time stance. The command matcher and unserialize scan are hand-rolled.

- [ ] **Step 1: Write failing tests** in `sinks.rs`:
  - `command_allow_is_anchored_whole_string` — with `allow = ["id", "/usr/bin/convert *"]`: `command_allowed(b"id", …) == true`, `command_allowed(b"id; rm -rf /", …) == false`, `command_allowed(b"/usr/bin/convert a b", …) == true`, `command_allowed(b"x/usr/bin/convert a", …) == false`, `command_allowed(b"/usr/bin/convert", …) == false` (the space after `convert` is required by the pattern).
  - `include_under_allow_paths` — `include_allowed(b"/var/www/app/tpl/x.php", &["/var/www/app".into()]) == true`; `include_allowed(b"/var/www/app/../../etc/passwd", …) == false` (normalized); `include_allowed(b"/tmp/x.php", …) == false`.
  - `unserialize_plain_data_is_allow` — `unserialize_classes(b"a:1:{i:0;s:3:\"abc\";}")` reports **no classes**; `unserialize_classes(b"O:8:\"stdClass\":0:{}")` reports class `stdClass`; `unserialize_classes(b"C:3:\"Foo\":0:{}")` reports class `Foo`.
  - `unserialize_scan_is_bounded` — a multi-megabyte payload returns within a generous time budget (prefix/'count-capped').
- [ ] **Step 2: Run tests, verify they fail** (`cargo test -p howdah-core sinks` → module missing).
- [ ] **Step 3: Implement `sinks.rs`** — enums, the anchored-pattern wrapper, the three policy fns, the bounded unserialize scan, a bounded path-normalizer for `include_allowed` (lexical `..`/`.` resolution on bytes, no filesystem access).
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** (`feat(core): add flat sink policy module (Layer 3)`).

### Task 2: Layer-3 `RuleId`s, severity and names

**Files:**
- Modify: `crates/howdah-core/src/limits.rs` (`enum RuleId`, `RuleId::severity()`)
- Modify: `crates/howdah-core/src/log.rs` (`rule_name`)
- Modify: `crates/howdah-core/src/ffi.rs` (`describe`)
- Test: in-module tests in `limits.rs`

**Interfaces:**
- Produces: `RuleId::CommandExec`, `RuleId::Include`, `RuleId::Eval`, `RuleId::Unserialize`, each `severity() == Severity::Standard`. `#[serde(rename_all = "snake_case")]` makes them parse/serialize as `command_exec`, `include`, `eval`, `unserialize` (the log `rule` values and the `[sinks.*]` override keys). `rule_name` and `describe` return those names and a short human description.

- [ ] **Step 1: Write failing tests** — extend the `severity()` test with the four new variants asserting `Severity::Standard`; add a `log::tests` assertion `rule_name(RuleId::CommandExec) == "command_exec"` (+ three).
- [ ] **Step 2: Run, verify fail** (variants don't exist).
- [ ] **Step 3: Implement** — add the four variants; add them to the `Standard` arm of `severity()` (they otherwise fall into `_ => Critical`); add arms to `rule_name` and `describe`. The compiler's non-exhaustive-match errors enumerate every site — fix each.
- [ ] **Step 4: Run, verify pass** (`cargo test -p howdah-core`).
- [ ] **Step 5: Commit** (`feat(core): add Layer-3 sink rule ids (standard severity)`).

### Task 3: `[sinks]` config section with independent mode

**Files:**
- Modify: `crates/howdah-core/src/config.rs` (`Config`, `RawConfig`, new `SinkConfig` + per-sink structs)
- Test: in-module tests in `config.rs`

**Interfaces:**
- Produces:
  - `pub struct SinkConfig { pub enabled: bool, pub mode: Mode, pub command_exec: CommandExecConfig, pub include: IncludeConfig, pub eval: EvalConfig, pub unserialize: UnserializeConfig }` — `#[serde(deny_unknown_fields, default)]`.
  - Per-sink structs, each with its own `mode: Mode` (defaulting so the per-sink default in §10.2 holds) plus its allowlist:
    - `CommandExecConfig { mode: Mode (default Detect), allow: Vec<String> (default empty) }`
    - `IncludeConfig { mode: Mode (default Detect), allow_paths: Vec<String> (default empty) }`
    - `EvalConfig { mode: Mode (default Detect) }`
    - `UnserializeConfig { mode: Mode (default **Off**), allow_classes: Vec<String> (default empty) }`
  - `SinkConfig` default: `enabled = true`, `mode = Mode::Detect`.
  - `pub fn SinkConfig::effective_mode(&self, sink: SinkId, global: Mode) -> Mode` — `Off` if `global == Off` or `!enabled`; else the per-sink mode if set, else `self.mode`. (Mirrors `InspectConfig::effective_mode`; the global `block` never arms a sink.)
  - `Config` gains `pub sinks: SinkConfig`; `safe_defaults()` sets it to default.
  - Config load **validates** the `command_exec.allow` patterns (a `*` anywhere but the final character is a `ConfigError`, like a zero limit) and rejects unknown keys. No regex compilation.

- [ ] **Step 1: Write failing tests:**
  - `sinks_defaults_detect_enabled_unserialize_off` — empty TOML → `sinks.enabled`, `sinks.mode == Detect`, `command_exec`/`include`/`eval` effective `Detect`, **`unserialize` effective `Off`**.
  - `global_block_does_not_arm_sinks` — `mode = "block"` with no `[sinks]` → `effective_mode(CommandExec, Block) == Detect` (NOT Block). **Load-bearing.**
  - `global_off_disables_sinks` — `effective_mode(CommandExec, Off) == Off`.
  - `per_sink_mode_overrides_section_mode` — `[sinks]\nmode="off"\n[sinks.command_exec]\nmode="block"` → `effective_mode(CommandExec, Block) == Block`, `effective_mode(Include, Block) == Off`.
  - `mid_wildcard_command_pattern_rejected` — `[sinks.command_exec]\nallow=["a*b"]` → `ConfigError` (a `*` is only permitted as the final character; this catches an operator expecting regex/mid-glob semantics). `allow=["ok *"]` and `allow=["exact"]` are accepted.
  - `sinks_unknown_key_rejected` — `[sinks]\nnope = 1` is an error.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `SinkConfig` + sub-structs, add to `Config`/`RawConfig`/`safe_defaults`, `effective_mode`, allow-pattern compilation in `from_toml`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): [sinks] config with independent, log-first per-sink modes`).

### Task 4: `howdah_sink_check` C-ABI entry point + per-hit sink log

**Files:**
- Modify: `crates/howdah-core/src/ffi.rs` (new export, dedicated sink log slot, sink apply)
- Test: `#[cfg(test)]` in `ffi.rs` (drives the C ABI like the existing tests)

**Interfaces:**
- Consumes: Task 1 `sinks::*`, Task 3 `SinkConfig`, Task 2 `RuleId`s.
- Produces:
  - `pub const HOWDAH_SINK_COMMAND_EXEC: i32 = 0; … INCLUDE = 1; EVAL = 2; UNSERIALIZE = 3;`
  - `pub unsafe extern "C" fn howdah_sink_check(ctx, sink: i32, name: *const c_char, name_len: usize, arg: *const c_char, arg_len: usize) -> i32` — `name` is the function/construct the trampoline stands in for (`"system"`, `"include"`, …); `arg` is the sink argument (command / path / payload), scanned **but never logged**. NULL ctx or unknown sink → `HOWDAH_ALLOW`.
  - Behavior: resolve `mode = sinks.effective_mode(sink, config.mode)`; if `Off` → Allow. Run the sink's policy (Task 1) over `arg`; `Allow` → return `HOWDAH_ALLOW` (no log). On `Log`/`Block`, resolve the action with the sink's effective mode (detect ⇒ Log, block ⇒ Block), **format the line into a dedicated `sink_log: Option<String>` slot** (rule = sink's `RuleId`, action, function/construct `name`, and for `unserialize` the offending class name; **never the argument**), and return the action code. A sink hit does NOT touch `self.worst`/`self.log` (the Layer-1/2 slot).
  - `pub unsafe extern "C" fn howdah_take_sink_log_line(ctx) -> *mut c_char` — drains the dedicated sink slot (same ownership contract as `howdah_take_log_line`; free with `howdah_free_str`). The glue calls it immediately after each `howdah_sink_check`.
  - Runs inside `catch_unwind`; on panic returns `HOWDAH_ALLOW` (fail-open: the guarded call proceeds). A sink-check panic must never neutralize a legitimate call.

- [ ] **Step 1: Write failing tests** (helper `sink(c, id, name, arg) -> i32` over the ABI, plus a `take_sink` for the dedicated slot):
  - `sink_logs_under_global_block_when_sinks_detect` — `mode="block"`, default sinks; `sink(c, COMMAND_EXEC, "system", b"id")` returns `HOWDAH_LOG`; the sink line has `"rule":"command_exec"`, `"action":"log"`, function `system`.
  - `sink_blocks_only_when_sink_mode_block` — `[sinks.command_exec]\nmode="block"`; a non-allowlisted command → `HOWDAH_BLOCK`; line `"action":"block"`.
  - `command_allow_silences` — `[sinks.command_exec]\nmode="block"\nallow=["id"]`; `sink(c, COMMAND_EXEC, "system", b"id")` → `HOWDAH_ALLOW`, no sink line.
  - `sink_log_omits_argument` — `sink(c, COMMAND_EXEC, "system", b"cat /etc/shadow")`; line contains `system` and `command_exec`, and does **not** contain `shadow` or `/etc/`.
  - `multiple_sink_hits_each_emit` — three `sink(...)` calls each produce a drainable line (take between calls); and a sink hit does not clobber a pending Layer-1/2 `log` line (stash a Layer-1 line via an input-var flood first, then a sink hit, assert both are retrievable from their own slots).
  - `unserialize_sink_off_by_default_is_allow` — default config; `sink(c, UNSERIALIZE, "unserialize", b"O:8:\"stdClass\":0:{}")` → `HOWDAH_ALLOW`, no line.
  - `global_off_silences_sinks` and `sink_check_panic_fails_open` (reuse the `FORCE_PANIC` thread-local pattern) and `sink_unknown_id_and_null_are_allow`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the new exports, the `sink_log` ctx field (reset in `request_begin`), the apply path (independent of `worst`), the class-name extraction for `unserialize`.
- [ ] **Step 4: Run, verify pass** (`cargo test -p howdah-core`).
- [ ] **Step 5: Commit** (`feat(core): howdah_sink_check + per-hit sink log slot`).

### Task 5: Sink-hook C shim + bindgen + MINIT install + neutralize glue

**Refuse idiom (PROVEN in Task 0, 2026-10-23 on 5.6/7.4/8.3):** function neutralize = `RETVAL_FALSE` + return without calling the original (no bailout) — confirmed: blocked `system()` returns false, the command does not run, the script continues, an unmarked call still runs.

**SCOPE (final): this task installs ONLY the function-table-swap hooks** for the six `command_exec` functions (`system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open`) and `unserialize` — both detect AND block (via the proven neutralize). **It installs NO `ZEND_INCLUDE_OR_EVAL` opcode handler in 1.2** — `include`/`eval` are reserved/dormant (spec §10.4, §8): reading the include path operand across the PHP 5/7/8 ABI is unproven. The `[sinks.include]`/`[sinks.eval]` config + FFI stay in place (dormant; never fire because nothing is hooked). So there is NO C opcode-handler code in `sink_hook.c` for 1.2 — only the function-table trampolines.

**Files:**
- Create: `crates/howdah-sys/sink_hook.c` (the productized hook: function-table swap for the exec family + `unserialize`; `ZEND_INCLUDE_OR_EVAL` opcode handler for include/require/eval; a `howdah_install_sink_hooks(decide_cb, emit_cb)` installer; neutralize on block per the Task-0 idiom). `#if PHP_VERSION_ID` splits the PHP 5 vs 7/8 ABIs (proven in spec §9).
- Modify: `crates/howdah-sys/build.rs` (compile `sink_hook.c` alongside `shim.c`), `crates/howdah-sys/src/lib.rs` (declare `howdah_install_sink_hooks` + the callback typedefs; add any needed bindgen allowlist entries only if the installer needs Rust-visible symbols — prefer keeping ABI detail in the C shim).
- Create: `crates/howdah-ext/src/sink_filter.rs` (the Rust callback: for each intercepted call, `maybe_begin`, call `core::howdah_sink_check`, take+write the sink line via `response::write_log_line`, and return to the trampoline whether to CHAIN or NEUTRALIZE; all inside `catch_unwind`, fail-open = CHAIN).
- Modify: `crates/howdah-ext/src/module.rs` (install the hooks at MINIT after the other chains; nothing to restore if the handler swap is process-global and PHP tears down per process — match `shim`/spike behavior), `crates/howdah-ext/src/lib.rs` (`mod sink_filter;`).
- Test: Rust unit tests for `sink_filter`'s pure helpers (name→`SinkId` mapping, the CHAIN/NEUTRALIZE decision from an action code); the live hook is proven in Task 8.

**Interfaces:**
- The C installer takes two `extern "C"` callbacks from `howdah-ext`:
  - `decide(sink: c_int, name: *const c_char, name_len: usize, arg: *const c_char, arg_len: usize) -> c_int` returning `HOWDAH_ALLOW`/`HOWDAH_LOG`/`HOWDAH_BLOCK`. The trampoline calls it, then: `ALLOW`/`LOG` ⇒ chain the original (opcode ⇒ `DISPATCH`); `BLOCK` ⇒ neutralize (Task-0 idiom).
  - The callback itself writes the per-hit log line (it owns `module::CTX` and the log destination); the C side does no logging.
- Argument extraction per sink (the piece spec §7 leaves to the builder): command-exec functions ⇒ first string arg; `unserialize` ⇒ first string arg; the opcode ⇒ op1 (the include path / eval code), read per generation in C.

- [ ] **Step 1:** Port the proven spike into `sink_hook.c`: install the full exec-family + `unserialize` function swaps and the opcode handler; wire the `decide` callback; implement neutralize per Task 0. Add `sink_hook.c` to `build.rs`’s `cc` build and declare the installer in `lib.rs`.
- [ ] **Step 2:** Write `sink_filter.rs`: the `extern "C"` `decide` callback (map `name`→`SinkId` by the function/construct, call `howdah_sink_check`, take+write the line, return the action), its `catch_unwind` fail-open wrapper, and unit tests for the pure mapping/decision helpers.
- [ ] **Step 3:** Install from MINIT (`module.rs`). Build the extension for one php8 image (`cargo build -p howdah-ext --features php8`) to confirm it compiles and links.
- [ ] **Step 4:** Run `cargo test -p howdah-core -p howdah-ext` (host) — pure parts green.
- [ ] **Step 5: Commit** (`feat(ext): install sink hooks and route them through howdah-core`).

### Task 6: Docs — config reference, generated ini, howdah-check

**Files:**
- Modify: `docs/config.md` (new `[sinks]` section), `packaging/howdah.ini` (commented `[sinks]` block — loud "log-first, does not block; unserialize off by default; set allow_paths before arming include"), `tools/howdah-check` (surface Layer-3 sinks as log-only where it lists active rules).
- Test: none (docs); verify by reading. If `tools/howdah-check` has a self-check, keep it green.

- [ ] **Step 1:** Document every `[sinks]` key, its default (per §10.2), and the "does not block by default / global block does not arm it" rule. Mirror the Layer-2 `[inspect]` docs' tone.
- [ ] **Step 2:** Add the commented `[sinks]` block to `packaging/howdah.ini` with the loud log-first comment.
- [ ] **Step 3:** Update `tools/howdah-check` to list the sinks as log-only; run any existing `howdah-check` self-test.
- [ ] **Step 4: Commit** (`docs: document [sinks] (Layer 3), log-first`).

### Task 7: Lab integration test (`lab/integration/sinks.sh`)

**Files:**
- Create: `lab/integration/sinks.sh` (host driver, on the model of `inspect.sh`) and `lab/integration/sinks_container.sh` (in-container half).
- Test: the script itself is the test; it must PASS on at least `howdah-dev-php8.3` and one of `7.4`/`5.6`.

**Asserts (detect mode default, then an armed block):**
- A request/script that calls `system('id')` logs one event `"rule":"command_exec"`, `"action":"log"`, function `system`, and the log **never contains** `id`'s output or the command string.
- An `include` of a path outside `allow_paths` (with `allow_paths` set) logs `"rule":"include"`; a path inside is silent.
- `unserialize` is **silent by default** (sink off); with `[sinks.unserialize] mode="detect"`, an `O:`-payload logs `"rule":"unserialize"` with the class name, never the payload.
- With `howdah.mode = block` but `sinks.mode` unset, a guarded `system()` still **runs and only logs** (global block does not arm).
- With `[sinks.command_exec] mode="block"`, a non-allowlisted `system('id')` is **neutralized**: returns false, `id` does not run, and the script **continues** to print a following marker; an `allow=["id"]` call runs normally.

- [ ] **Step 1:** Write `sinks_container.sh`: build `howdah-ext`, load it, run PHP CLI/built-in-server snippets for each assertion, grepping the event log.
- [ ] **Step 2:** Write `sinks.sh` host driver (image check + `docker run -v …:ro`), mirroring `inspect.sh`.
- [ ] **Step 3:** Run on `howdah-dev-php8.3` and `howdah-dev-php7.4` (and `5.6` for the php5 ABI); confirm PASS.
- [ ] **Step 4: Commit** (`test(lab): Layer-3 sink integration (detect + armed block, multi-version)`).

### Task 8: Site, README, CHANGELOG, coverage

**Files:**
- Modify: `README.md` ("What Layer 3 does" / the Layer summary), `CHANGELOG.md` (`[1.2.0]`), `site/src/lib/site.ts` (`VERSION = '1.2.0'`), the site home Layer status + a "Layer 3 — sinks Howdah guards" section, `site/src/pages/docs/configuration.astro` (`[sinks]`), `site/src/pages/coverage.astro` + coverage data, and a launch blog entry **only if** the owner approves a 1.2 release (leave the release/versioning to the owner — see handoff).
- Test: `npm run build` in `site/` succeeds. **Do NOT commit a regenerated `docs/coverage.md`** (it is generated; `git restore docs/coverage.md` after any build — the Layer-2 prose there is fragile).

- [ ] **Step 1:** README + CHANGELOG: Layer 3 guards sinks, detects-and-logs, does not block by default; phar/SSRF are roadmap.
- [ ] **Step 2:** Site: `VERSION`, layer status → Layer 3 "Active in 1.2 · log-only", a Layer-3 showcase section (4 sinks, log-first, value-never-logged, best-effort/bypassable, phar+SSRF explicitly roadmap), `[sinks]` config docs, coverage table/data.
- [ ] **Step 3:** `npm run build`; `git restore docs/coverage.md` if the build regenerated it.
- [ ] **Step 4: Commit** (`docs(site): Layer 3 shown as available in 1.2 (log-first)`).

---

## Self-review

- **Spec coverage:** §2 goals 1–9 → Tasks 1 (policy), 2 (rules), 3 (config incl. no-new-ini), 4 (FFI + per-hit log + independent mode), 5 (hooks + neutralize), 7 (bounded/multi-version), 8 (messaging); §5.1 mechanisms → Task 5 (proven Task 0/spike §9); §5.4 neutralize → Task 0 + 5; §5.5 per-hit log → Task 4; §6 messaging → Tasks 6+8; §8 phar/SSRF deferral → stated in Tasks 6/8 copy; §10 resolutions → Tasks 0/1/3/4. No gap.
- **Type consistency:** `SinkId`/`SinkOutcome`/`SinkConfig`/`effective_mode(sink, global)`/`howdah_sink_check`/`howdah_take_sink_log_line`/`HOWDAH_SINK_*` used consistently across Tasks 1→5; `RuleId::{CommandExec,Include,Eval,Unserialize}` consistent across Tasks 2→4.
- **Review Focus:** each of the five lines has an owning task + named test. Empty-allowlist noise, anchoring, privacy, per-hit emit, fail-open all pinned.
- **Proportion:** interfaces + test names, no code bodies the signatures determine. The one genuine unknown (opcode neutralize) is a spike (Task 0), not prose.

## Execution handoff

Subagent-driven-development. After Task 8, open a PR against `main` from `feat/layer3-sink-hardening` and **stop**: the owner makes the merge-to-main and 1.2-release/publish calls (tag, `publish-repos.yml`, the launch blog), exactly as they did for 1.1. Do not merge, tag, or publish without the owner.
