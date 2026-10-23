# Howdah Layer 2 — Input Inspection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add content inspection of decoded request values (SQLi, path traversal, command/code injection) that **logs and never blocks by default**, as the first post-1.0 layer.

**Architecture:** A new pure-Rust `inspect` module in `howdah-core` runs guaranteed-linear-time, non-backtracking scanners over each decoded value. A new C-ABI entry point `howdah_inspect_value` resolves a hit against an **independent** `inspect.mode` (never the global `howdah.mode`), stashes a privacy-preserving log event (class + source + variable name — never the value), and returns an action. The chained `input_filter` glue reads the value binary-safe and calls it for GET / POST (incl. multipart fields) / COOKIE values and the `REQUEST_URI`/`PATH_INFO` path, on its own path independent of Layer 1's count/drop branch, inside the existing fail-open `catch_unwind`. Docs, site, README, CHANGELOG, `howdah-check` and the lab matrix all state, loudly, that Layer 2 detects-and-logs and does not block by default.

**Tech Stack:** Rust (workspace crates `howdah-core`, `howdah-ext`), `regex`/`aho-corasick` for linear-time matching, Astro site, bash lab integration + `gen-coverage.mjs`.

**Spec:** `docs/superpowers/specs/2026-10-23-howdah-layer2-input-inspection-design.md` (read it; this plan argues from it).

## Global Constraints

- **Log-first, never block by default — and a global `howdah.mode = block` must NOT arm Layer 2.** Layer-2 rules are `Severity::Standard` and are resolved against `inspect.mode` (default `detect` = log), not the global mode. Only an explicit `inspect.mode = block` (or per-class override) blocks. Global `off` disables everything. (spec §2.3, §5.3)
- **Never log the raw value.** A Layer-2 event carries class + source (`get`/`post`/`cookie`/`path`) + variable name only. The `log::EventRecord` privacy test (`privacy_cookie_body_auth_never_logged`) must still pass unchanged. (spec §5.4)
- **No backtracking / linear-time matching only.** No ReDoS surface. Bounded per-value bytes AND a per-request aggregate scan budget; scanning stops once Layer 1 latches `INPUT_BLOCKED` / passes `max_input_vars`. (spec §5.2)
- **Defensive only; no overclaiming; no payload generator.** Test fixtures are static representative strings, never a runnable generator. No per-signature public bypass cookbook. Every signature has a test. (spec §3, §4, §5.5)
- **Reads value binary-safe** (`*val`, `val_len`), never as a C string (NUL-safe). All glue work inside the existing `catch_unwind` fail-open path; a scanner bug never unwinds into PHP and never drops a var. (spec §5.1)
- **Never drops the variable on an inspect hit** (unlike Layer 1's shape block): in `block` mode it latches the request-end 403 but passes the value through; in `detect` it only logs.
- Pure-Rust core stays host-unit-testable through the C ABI; builds on PHP 5.4–8.5, NTS, FPM/Apache-prefork/CGI, like Layer 1.

## Review Focus

- **Global-block arming:** a request under `howdah.mode = block` with `inspect.mode` unset (default detect) must **log, not block** a SQLi value. Covered in Task 4 (`inspect_logs_under_global_block_when_inspect_detect`).
- **Value privacy:** a flagged value's bytes never appear in the log line; only name/class/source do. Covered in Task 4 (`inspect_log_omits_value`).
- **ReDoS / huge value:** a multi-megabyte value, and thousands of array values, complete within the per-value cap and per-request budget. Covered in Task 1 (`huge_value_is_prefix_bounded`) and Task 4 (`aggregate_budget_caps_total_scan`).
- **Encoded traversal on the path:** `%2e%2e%2f` in `REQUEST_URI` is flagged after bounded percent-decode. Covered in Task 1 (`encoded_traversal_caught`).
- **False-positive realism:** a benign corpus (prose containing "or", a real relative path, "rock & roll", "union of two sets") produces **zero** flags. Covered in Task 1 (`benign_corpus_is_clean`) and Task 8 (lab).

---

### Task 1: `inspect` scanner module (`howdah-core`)

**Files:**
- Create: `crates/howdah-core/src/inspect.rs`
- Modify: `crates/howdah-core/src/lib.rs` (add `pub mod inspect;`)
- Test: in-module `#[cfg(test)]` in `inspect.rs`

**Interfaces:**
- Produces:
  - `pub enum InspectClass { SqlInjection, PathTraversal, CommandInjection }`
  - `pub struct InspectLimits { pub max_value_bytes: usize, pub max_total_bytes: usize, pub max_values: usize }` with `pub fn defaults() -> InspectLimits` (`max_value_bytes = 16 * 1024`, `max_total_bytes = 2 * 1024 * 1024`, `max_values = 2000`).
  - `pub enum Source { Get, Post, Cookie, Path }`
  - `pub fn scan(value: &[u8], source: Source, limits: &InspectLimits) -> Option<InspectClass>` — scans at most `limits.max_value_bytes` of `value` (prefix beyond that); for `Source::Path`, scans a bounded percent-decoded copy as well as the raw bytes; returns the first class that matches, in priority order SQLi, PathTraversal, CommandInjection.
  - `pub fn class_rule(c: InspectClass) -> RuleId` mapping to the Task-2 `RuleId`s.

**Signatures to implement (high-confidence, low false-positive; pinned here):**
- **SQLi** (case-insensitive, word-bounded): (a) `union` + whitespace + `select`; (b) a quote (`'` or `"`) followed by optional ws and `or`/`and` + optional ws + a comparison `X=X` (e.g. `' or 1=1`, `" OR 'a'='a`); (c) a quote immediately followed by a SQL comment introducer (`--`, `#`, `/*`); (d) `;` + optional ws + one of `drop|delete|update|insert|select` + ws.
- **PathTraversal:** a `..` immediately followed by `/` or `\` (raw or after percent-decode); OR a well-known target substring: `/etc/passwd`, `/proc/self/`, `php://`, `file://`, `boot.ini`.
- **CommandInjection:** (a) `$(`; (b) a backtick pair `` `…` ``; (c) a shell metachar (`;`, `|`, `&&`, `||`) + optional ws + a word-bounded known binary from a fixed small list (`cat ls id whoami uname wget curl nc ncat bash sh ping python perl`); (d) a word-bounded PHP exec sink name followed by `(`: `system exec shell_exec passthru proc_open popen eval assert` .

Use `regex` (linear-time, no backtracking) or `aho-corasick`; compile the pattern set **once** (e.g. `once_cell`/`std::sync::OnceLock`), never per call.

- [ ] **Step 1: Write failing tests** in `inspect.rs`:
  - `sqli_tautology_and_union_and_comment_caught` — `scan(b"' OR 1=1 --", Get, &d)`, `scan(b"1 UNION SELECT pw FROM users", Get, &d)`, `scan(b"admin'--", Post, &d)` all `== Some(SqlInjection)`.
  - `traversal_caught` — `../../etc/passwd`, `/proc/self/environ`, `php://filter/convert.base64-encode/resource=x` → `Some(PathTraversal)`.
  - `encoded_traversal_caught` — `scan(b"%2e%2e%2fetc%2fpasswd", Path, &d) == Some(PathTraversal)`.
  - `cmdi_caught` — `; cat /etc/passwd`, `$(id)`, `` `whoami` ``, `system('ls')` → `Some(CommandInjection)`.
  - `benign_corpus_is_clean` — each of: `b"I think 1 or 2 will do"`, `b"union of two sets"`, `b"rock & roll"`, `b"reports/2024/q1.pdf"`, `b"./theme/style.css"`, `b"it's a test"`, `b"name=O'Brien"` → `None`.
  - `huge_value_is_prefix_bounded` — a 4 MiB value with the attack token only AFTER `max_value_bytes` returns `None` (prefix-bounded) and completes well under a generous time budget.
  - `path_source_also_scans_decoded` — raw `..%2f..%2f` on `Source::Path` → `Some(PathTraversal)`; same bytes on `Source::Get` (no decode) still caught via the raw `..%2f`? (decide: Get does not percent-decode; assert `None` to document the source difference.)
- [ ] **Step 2: Run tests, verify they fail** (`cargo test -p howdah-core inspect` → fail: module missing).
- [ ] **Step 3: Implement `inspect.rs`** — the enums, `InspectLimits`, the compiled pattern set, `scan`, `class_rule`. Percent-decode helper bounded to `max_value_bytes`.
- [ ] **Step 4: Run tests, verify they pass.**
- [ ] **Step 5: Commit** (`feat(core): add linear-time input-inspection scanners (Layer 2)`).

### Task 2: Layer-2 `RuleId`s, severity and names

**Files:**
- Modify: `crates/howdah-core/src/limits.rs` (`enum RuleId`, `RuleId::severity()`)
- Modify: `crates/howdah-core/src/log.rs` (`rule_name`)
- Modify: `crates/howdah-core/src/ffi.rs` (`describe`)
- Test: in-module tests in `limits.rs`

**Interfaces:**
- Produces: `RuleId::SqlInjection`, `RuleId::PathTraversal`, `RuleId::CommandInjection`, each `severity() == Severity::Standard`. Wire the `#[serde(rename_all)]`/`Deserialize` so they parse in `[rules]`/`[inspect]` overrides as `sql_injection`, `path_traversal`, `command_injection`. `rule_name` and `describe` return those snake_case names and a short human description.

- [ ] **Step 1: Write failing tests** — extend the existing `severity()` test: `assert_eq!(RuleId::SqlInjection.severity(), Severity::Standard)` (and the other two). Add a `log::tests` assertion that `rule_name(RuleId::SqlInjection) == "sql_injection"` (+ two).
- [ ] **Step 2: Run, verify fail** (variants don't exist).
- [ ] **Step 3: Implement** — add the three variants; they fall into the existing `_ => Severity::Critical` arm, so **add them to the `Standard` arm** of `severity()`. Add arms to `rule_name` and `describe`. (The compiler's non-exhaustive-match errors enumerate every site to update — fix each.)
- [ ] **Step 4: Run, verify pass** (`cargo test -p howdah-core`).
- [ ] **Step 5: Commit** (`feat(core): add Layer-2 rule ids (standard severity)`).

### Task 3: `[inspect]` config section with independent mode

**Files:**
- Modify: `crates/howdah-core/src/config.rs` (`Config`, `RawConfig`, new `InspectConfig`)
- Test: in-module tests in `config.rs`

**Interfaces:**
- Produces:
  - `pub struct InspectConfig { pub enabled: bool, pub mode: Mode, pub sqli: bool, pub traversal: bool, pub cmdi: bool, pub limits: InspectLimits, pub rule_modes: BTreeMap<RuleId, Mode> }` — `#[serde(deny_unknown_fields, default)]`; default `enabled = true`, `mode = Mode::Detect`, three classes `true`, `limits = InspectLimits::defaults()`.
  - `Config` gains `pub inspect: InspectConfig`; `safe_defaults()` sets it to default.
  - `pub fn InspectConfig::effective_mode(&self, global: Mode) -> Mode` — returns `Mode::Off` if `global == Off` or `!self.enabled`, else `self.mode`. (This is the independent-mode rule; the global block never arms it.)
  - A per-class effective check: `pub fn class_enabled(&self, c: InspectClass) -> bool`.

- [ ] **Step 1: Write failing tests:**
  - `inspect_defaults_detect_and_enabled` — empty TOML → `inspect.enabled`, `inspect.mode == Detect`, all three classes on.
  - `inspect_section_parses` — `[inspect]\nmode = "block"\ncmdi = false` parses; `effective_mode(Mode::Block) == Block`, `class_enabled(CommandInjection) == false`.
  - `global_block_does_not_arm_inspect` — `mode = "block"` with no `[inspect]` → `inspect.effective_mode(Mode::Block) == Detect` (NOT Block). **This is the load-bearing test.**
  - `global_off_disables_inspect` — `inspect.effective_mode(Mode::Off) == Off`.
  - `inspect_unknown_key_rejected` — `[inspect]\nnope = 1` is an error.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `InspectConfig`, add to `Config`/`RawConfig`/`safe_defaults`, `effective_mode`, `class_enabled`.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): [inspect] config with an independent, log-first mode`).

### Task 4: `howdah_inspect_value` C-ABI entry point + logging

**Files:**
- Modify: `crates/howdah-core/src/ffi.rs` (new export, ctx counters, inspect apply)
- Test: `#[cfg(test)]` in `ffi.rs` (drives the C ABI like the existing tests)

**Interfaces:**
- Consumes: Task 1 `inspect::{scan, Source, InspectClass, class_rule}`, Task 3 `InspectConfig`, Task 2 `RuleId`s.
- Produces:
  - `pub unsafe extern "C" fn howdah_inspect_value(ctx, source: i32, name: *const c_char, name_len: usize, val: *const c_char, val_len: usize) -> i32` — `source` is `0=get,1=post,2=cookie,3=path` (define `pub const HOWDAH_SRC_GET/POST/COOKIE/PATH`). NULL ctx → `HOWDAH_ALLOW`.
  - Behavior: if `!inspect.enabled` or per-class disabled → Allow. Enforce the **per-request aggregate budget** (new `howdah_ctx` fields `inspect_bytes: usize`, `inspect_values: usize`): once `inspect_values >= limits.max_values` or `inspect_bytes >= limits.max_total_bytes`, return Allow without scanning. Otherwise `scan` the value; on `Some(class)`, resolve the action with `decide(Some(&hit), inspect.effective_mode(config.mode), &inspect.rule_modes)` where `hit.rule = class_rule(class)`, fold via a new `apply_with_mode`, and stash a reason string `"<class> pattern in <source> variable '<name>'"` (name truncated to a bound; **value never included**). Return the action code.
  - Never drops the variable (caller decides latch); this fn only logs + returns the action.

- [ ] **Step 1: Write failing tests** (C-ABI style, like `howdah_input_var` tests):
  - `inspect_logs_under_global_block_when_inspect_detect` — init with `mode = "block"` (no `[inspect]`); `howdah_inspect_value(c, SRC_GET, "q", "' OR 1=1 --")` returns `HOWDAH_LOG`; the stashed line has `rule == "sql_injection"`, `action == "log"`.
  - `inspect_blocks_only_when_inspect_mode_block` — init `[inspect]\nmode = "block"`; same call returns `HOWDAH_BLOCK`, line `action == "block"`.
  - `inspect_log_omits_value` — the stashed JSON line contains `q` and `sql_injection` but NOT `OR 1=1` nor `1=1`.
  - `inspect_disabled_is_allow` — `[inspect]\nenabled = false` → `HOWDAH_ALLOW`, no log.
  - `aggregate_budget_caps_total_scan` — after `max_values` benign calls, a subsequent attack value returns `HOWDAH_ALLOW` (budget exhausted) and stashes nothing new.
  - `global_off_silences_inspect` — `mode = "off"` → `HOWDAH_ALLOW`, no log even on an attack value.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the export, the two `howdah_ctx` counters (reset in `request_begin`), `apply_with_mode`, and the reason formatter. Reuse `stash`.
- [ ] **Step 4: Run, verify pass** (`cargo test -p howdah-core ffi`).
- [ ] **Step 5: Commit** (`feat(core): howdah_inspect_value — log-first, value never logged`).

### Task 5: `input_filter` glue — scan values on an independent path

**Files:**
- Modify: `crates/howdah-ext/src/input_filter.rs`
- Modify: `crates/howdah-ext/src/module.rs` if a new latch is needed (reuse `INPUT_BLOCKED` for the response; add `INSPECT_BLOCKED` only if a distinct response reason is wanted — default: reuse).
- Test: host unit tests for the pure helper (below); end-to-end across versions is Task 8.

**Interfaces:**
- Consumes: `core::howdah_inspect_value` + the `HOWDAH_SRC_*` constants.
- Produces: in `filter()`, after computing `drop_var` from `process()` and **regardless of it**, call a new `inspect_value(arg, var, val, val_len)` inside the SAME `catch_unwind`. It:
  - maps `arg` → `Source`: `PARSE_GET→Get`, `PARSE_COOKIE→Cookie`, `PARSE_POST→Post` (**including** multipart — unlike Layer 1's count path, inspect does scan multipart fields), `PARSE_SERVER` → `Path` **only** when the name is `REQUEST_URI` or `PATH_INFO` (never `HTTP_*`, never other `$_SERVER` keys);
  - reads the value binary-safe from `*val`/`val_len`;
  - calls `howdah_inspect_value`; if it returns `HOWDAH_BLOCK`, set `INPUT_BLOCKED = true` (drives the RSHUTDOWN 403) but **do not** set `drop_var` (the value is chained through);
  - a pure, host-testable helper `fn source_for(arg, name: &[u8]) -> Option<Source>` holds the arg/name→Source mapping.

- [ ] **Step 1: Write failing host tests** for `source_for`: GET/POST/COOKIE map to their source; `PARSE_SERVER` + `REQUEST_URI`/`PATH_INFO` → `Some(Path)`; `PARSE_SERVER` + `HTTP_HOST` → `None`; `PARSE_SERVER` + `SCRIPT_NAME` → `None`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `source_for` and `inspect_value`; wire into `filter()` inside the existing `catch_unwind`; keep the fail-open contract (panic → no scan, chain prior).
- [ ] **Step 4: Run, verify pass** (`cargo test -p howdah-ext`) and `cargo build` for a representative PHP feature set (php8).
- [ ] **Step 5: Commit** (`feat(ext): scan decoded values for Layer-2 patterns (never drops the var)`).

### Task 6: Config docs, `howdah.ini` note, `howdah-check` output

**Files:**
- Modify: `docs/config.md` (new `[inspect]` section)
- Modify: `packaging/howdah.ini` (one comment pointing at inspect = log-only)
- Modify: `tools/howdah-check` + `tools/howdah-check.test.sh` (show Layer-2 rules as log-only where it lists rules)

- [ ] **Step 1: Write/adjust the failing check** — add a case to `tools/howdah-check.test.sh` asserting the rules listing marks inspect rules `log-only` (and that a plain run never prints "block" for them by default).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** — `docs/config.md` `[inspect]` block opening with the plain-language guarantee (*these rules only log; they do not block any request; a global `howdah.mode = block` does NOT arm them; set `inspect.mode` or a class to `block` to block*); the keys (`enabled`, `mode`, `sqli`/`traversal`/`cmdi`, limits); a short note in `howdah.ini`; the `howdah-check` listing.
- [ ] **Step 4: Run, verify pass** (`bash tools/howdah-check.test.sh`).
- [ ] **Step 5: Commit** (`docs: document [inspect]; howdah-check shows Layer 2 as log-only`).

### Task 7: Site, README, CHANGELOG — "detects and logs; does not block by default"

**Files:**
- Modify: `site/src/pages/index.astro` (Layer-2 entry → make explicit it is log-only; keep "Planned"/"Active" honest — see note)
- Modify: `site/src/pages/coverage.astro` (a Layer-2 line in "Honest limits": detects-and-logs, bypassable, no block by default)
- Modify: `README.md` (feature/release summary line)
- Create: `CHANGELOG.md` entry (or modify if present) for the Layer-2 release

**Interfaces / copy rules:** every mention says Layer 2 **detects and logs; does not block by default**; the general honesty line ("signature inspection is best-effort and bypassable — that is why it logs") appears once on the site; **no per-signature bypass recipes**. The comparison table/altitude stays accurate (Howdah now also does content inspection, log-only).

- [ ] **Step 1:** Draft the copy; decide the Layer-2 status pill wording (it is shipping but log-only — label it clearly, e.g. "Active (log-only)" rather than implying blocking).
- [ ] **Step 2:** `cd site && npm run build` — expect current site builds (baseline green).
- [ ] **Step 3:** Apply the edits across the four files.
- [ ] **Step 4:** `cd site && npm run build` — expect PASS; grep the built output to confirm "does not block by default" appears on the Layer-2 and coverage pages.
- [ ] **Step 5: Commit** (`docs(site): Layer 2 — detects and logs, does not block by default; README + CHANGELOG`).

### Task 8: Lab integration + honest coverage

**Files:**
- Modify: `lab/integration/matrix.sh` (add inspect detection scenarios + a benign-corpus no-flag scenario)
- Modify/regen: `lab/integration/matrix-results.tsv`, `site/src/data/coverage.json`, `docs/coverage.md`, `docs/coverage-data.md`
- Modify: `site/scripts/gen-coverage.mjs` only if a new result dimension is needed

**Interfaces:** scenarios that POST/GET a known SQLi / traversal / cmdi value and assert the JSON event log shows `action: "log"` with the right `rule`, on representative PHP minors across SAPIs (reuse the Task-15 matrix harness); and a benign-corpus scenario asserting **zero** inspect flags. Fixtures are static strings (no generator). Coverage data states Layer-2 detection is log-only and best-effort.

- [ ] **Step 1:** Add the failing scenarios to `matrix.sh` (detection asserts log line; benign asserts none).
- [ ] **Step 2:** Run the lab for a representative subset (e.g. 7.4, 8.1, 8.4) — expect the new scenarios fail until Tasks 1–5 are built (they are, by now) then pass; record results.
- [ ] **Step 3:** Regenerate `matrix-results.tsv` → `coverage.json`/`coverage.md`; add a Layer-2 subsection to `docs/coverage-data.md` (what each signature catches, that it is log-only and bypassable, no per-signature evasion recipes).
- [ ] **Step 4:** `cd site && npm run build`; confirm the coverage page renders the Layer-2 facts and still shows no stale claims.
- [ ] **Step 5: Commit** (`test(lab): Layer-2 detection + benign-corpus coverage, regenerated`).

---

## Self-review notes

- **Spec coverage:** §5.1 hook → Task 5; §5.2 engine/bounds → Task 1 + Task 4 budget; §5.3 independent mode → Task 3 (`global_block_does_not_arm_inspect`) + Task 4; §5.4 logging → Task 4 (`inspect_log_omits_value`); §5.5 rules/honesty → Task 1 + Task 8; §6 five surfaces → Tasks 6 (config/howdah-check) + 7 (README/CHANGELOG/site) + 4 (`action: log` in events). README is covered (Task 7).
- **Review Focus → tests:** each of the five lines maps to a named test above.
- **Type consistency:** `InspectClass`/`Source`/`InspectLimits` defined in Task 1 and consumed unchanged in Tasks 3–5; `class_rule` is the single mapping to the Task-2 `RuleId`s; `effective_mode` is the single independent-mode rule, defined in Task 3 and used in Task 4.
- **Open owner item (non-blocking):** exact signature set in Task 1 is a starting high-confidence set; the lab benign corpus (Task 8) is the tuning gate. If the corpus shows a noisy signature, tighten or drop it — log-only means no safety regression, only signal quality.
