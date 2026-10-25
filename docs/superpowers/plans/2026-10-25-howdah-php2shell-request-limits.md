# Howdah PHP2Shell request limits (§4.1–4.5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop a request from driving PHP to out-of-memory *while PHP parses it* —
closing the three request-parsing gaps the PHP2Shell advisories name (header flood
within one multipart part; a body with no usable declared length; deeply nested
field/file names) — by scanning the raw body as PHP reads it and sizing the checks
from the request's live `memory_limit`.

**Architecture:** A C shim wraps `sapi_module.read_post` (the raw body reader every
PHP body path pulls through), like `module.rs` already wraps `input_filter`. The
wrapper chains the prior reader and feeds the bytes to a **second, independent**
`MultipartState` byte-scanner in `howdah-core` (the existing parsed-event counter
stays, so a scanner desync can never switch the structural limits off). The scanner
makes the per-part header limits exact (gap A), counts bytes actually read against
the effective `post_max_size` (gap B), and feeds a per-request estimate of the
memory PHP's parser will hold; a new summed nesting-levels budget covers gap C; and
the memory-driven checks are sized from the live `memory_limit` (§4.5). On a stop
the wrapper returns 0 (end of body) and records a refusal delivered at the end of
RINIT — no longjmp.

**Tech Stack:** Rust (`howdah-core` pure, `howdah-ext` glue), a C shim in
`howdah-sys` compiled by `cc` per PHP generation, TOML config, the Docker lab, the
JS config editor + Astro site.

**Spec:** `docs/superpowers/specs/2026-10-24-howdah-php2shell-gaps-design.md`
(§4.1–4.5; §5 verification; §7 builder notes). §4.6 (the backstop) shipped in #60
and is on `main`. This plan is §4.1–4.5 ONLY.

**Scope of this PR (owner decision):** build and verify the **trigger-independent**
parts — the scanner, the limits, the §4.5 estimate, the config, the glue — proven
on the **benign corpus** (zero blocks) and a **differential fuzz** against PHP's own
parse. The **"PASS on vulnerable PHP" evidence table (§5.2) and its trigger
fixtures are owner-supplied** (§5.3: generators live in gitignored `private/`); those
rows are recorded **NOT-RUN** here. The site claim (§6) and the CVE-description
corrections ship when that evidence exists, NOT in this PR.

## Global Constraints

Every task's requirements implicitly include this section.

- **Support matrix:** PHP 5.4–8.5, Linux x86_64 and aarch64, NTS. The C shim must
  compile and behave on 5.x (`int read_post(char*, uint TSRMLS_DC)`) and 7.x/8.x
  (`size_t read_post(char*, size_t)`). Build-verify on 5.4 too (not only 5.6 — its
  older headers differ; the backstop's `<stdint.h>`/`zend_hash_str_exists` traps
  were 5.4/5.x-only and CI's aarch64 5.4 smoke is the gate).
- **Core stays pure Rust**; `howdah-ext` is thin glue; every `extern "C"` entry is
  `catch_unwind`-guarded and fails open (Allow). No PHP calls in the core.
- **No longjmp during request startup.** A read_post-time verdict is recorded and
  delivered through the existing RINIT refusal (`module::refuse` /
  `deliver_startup_refusal`), exactly as the multipart END path does.
- **Fail closed on scanner desync (§4.2).** The parsed-event counter
  (`note_part`/`note_data` → `max_parts`/`max_files`/name lengths) stays wired and
  independent; the byte-scanner only ever ADDS blocks. If the byte scanner cannot
  find the boundary or loses track it must over-count, never under-count, and must
  never be able to clear a structural hit.
- **No parser desync off-switch (the 1.2.1 bug class).** Client data fed to the
  byte scanner must never be able to turn a rule off; limits read high-water marks,
  never live state (the existing `MultipartState` already does this).
- **Logs record shapes and counts, never request content.**
- **Shared, append-only, parallel-session files:** `config.rs`, `limits.rs`,
  `ffi.rs`, `howdah_core.h`. `ListAgents` before editing; `SendMessage` a peer that
  you are appending rule(s)/limit key(s)/FFI. Append at the END; never reorder.
  `log.rs` `rule_layer`/`rule_name`, `ffi.rs` `describe`, `exceptions/mod.rs`
  `Layer::of`, `limits.rs` `rule_catalog` + its exhaustiveness tests, and the wasm
  + `site/` catalog-count tests are all exhaustive/pinned: every new `RuleId` needs
  each updated (the backstop touched all of them — grep `OutOfMemory` to find the
  sites). Never `git add -A`; stage named paths.
- **New config key → three surfaces:** a `site/config-editor/schema.js` row, a
  `docs/config.md` entry, and a wasm rebuild (`sh packaging/build-wasm.sh` before
  `cd site && npm test`; the demo wasm is built at test/deploy time, not committed).
- **Decisions already fixed by the design (revisit only with a code reason):** the
  read_post wrapper is a `howdah-sys` C shim installed from MINIT and restored at
  MSHUTDOWN; it extracts the boundary from `CONTENT_TYPE` the way PHP does; the
  byte scanner is independent of the parsed-event counter; the memory-driven
  ceiling is `memory_limit / 4` (§4.5, Claude's-call fraction — keep unless a lab
  cost measurement says otherwise); `memory_limit = -1` falls back to a fixed
  measured ceiling; `post_max_size = 0` (unlimited) turns gap B off and §4.5 still
  bounds memory.
- **Verification gates:** `cargo test --workspace`; host `cargo clippy
  -p howdah-core -p howdah-ext --all-targets -- -D warnings` AND a `phpN`-feature
  clippy of the glue (new code clean; pre-existing php-gated lints out of scope);
  `sh packaging/build-wasm.sh && cd site && npm test`; `cargo fuzz` smoke on the
  scanner (existing `fuzz/` targets stay green; add a differential target); the
  benign-corpus lab (zero blocks) on the dev images; build-verify the glue on
  5.4/5.6/7.4/8.0/8.3. Independent Fable review of everything touching core, ext or
  C; apply superpowers:receiving-code-review to its findings.
- **Attribution:** `Co-Authored-By: Claude Opus 4.8` on commits; Claude Code footer
  on the PR body.
- **Stopping point:** push the branch and open a PR to `main` with CI green and the
  review addressed, then stop and report the PR link. Do not merge, tag, bump
  versions, or publish. Do not author attack/trigger-request generators (owner
  supplies §5 trigger fixtures).

## Review Focus

Inputs/failure modes the spec implies that the happy path misses; most-likely-first.
Each gets its test in the owning task.

- **A benign upload must never block** at defaults on any ini profile: multi-file
  galleries, parts with ordinary extra headers (`Content-Type`,
  `Content-Transfer-Encoding`), framework-style nested arrays
  (`a[b][c][d]`), a real chunked upload. The byte scanner adds new block
  surfaces (exact header counts, byte totals, nesting sum, the §4.5 estimate); any
  of them firing on benign traffic is an anti-goal. → Task 8 benign corpus, zero
  blocks at every §5.1 ini profile.
- **A scanner/PHP-parser differential** (line endings, continuation lines, boundary
  edge cases, the final `--`): the byte scanner must not count differently from
  PHP's `rfc1867.c` in a way that either misses a flood or blocks a legal body. →
  Task 7 differential fuzz harness comparing per-part header counts with PHP's
  parse; the scanner over-counts (never under-counts) on any ambiguity.
- **A short read returned to PHP must not itself crash or mis-signal.** Returning 0
  from the wrapper mid-body must read to PHP as a clean end of body on every
  generation and SAPI, and `module::refuse` must work when the verdict is recorded
  this early (urlencoded bodies are read in `sapi_activate`, before
  `php_hash_environment`). → Task 6 builder confirmation + lab.
- **`memory_limit = -1` and a raised `post_max_size`.** With no limit the §4.5
  ceiling must fall back to a fixed measured value and keep working; with
  `post_max_size` ≥ `memory_limit` (the upload-heavy exposure) the checks must size
  from `memory_limit`, not from fixed 128 MiB constants. → Task 5 tests + Task 8
  ini profiles (b) and (c).
- **`cgi-fcgi` hides real fpm behavior** (a `CONTENT_LENGTH` of -1 gets past PHP's
  size check and lifts fpm's read cap; no real front end allows it). fpm evidence
  must come through nginx; `cgi-fcgi` rows for gap B / trigger (1) don't count. →
  Task 8 runs fpm behind nginx; documented.

---

### Task 1: Extract the real multipart boundary (core, pure)

The scanner must follow framing using the request's **real** boundary, taken from
`CONTENT_TYPE` the way PHP's `php_mt_rand`-free `rfc1867.c` does (the `boundary=`
parameter, optionally quoted; everything after it on the header is ignored).

**Files:** Create `crates/howdah-core/src/boundary.rs`; modify `lib.rs`
(`pub mod boundary;`).

**Interfaces — Produces:** `howdah_core::boundary::extract(content_type: &[u8]) ->
Option<Vec<u8>>` (the boundary bytes, or `None` when absent/empty/not multipart).

- [ ] **Step 1: Failing tests** — `multipart/form-data; boundary=abc` → `abc`;
  quoted `boundary="a b"` → `a b`; case-insensitive `BOUNDARY`; `boundary=` with
  trailing `; charset=…`; not-multipart or missing → `None`; empty boundary →
  `None`; a boundary at PHP's 70-char max; CRLF/garbage rejected. Mirror PHP's
  extraction (first `boundary=` token; quoted value ends at the closing quote;
  unquoted ends at `;` or end).
- [ ] **Step 2: Run → FAIL** (`cargo test -p howdah-core boundary::`).
- [ ] **Step 3: Implement `extract`.** One line on approach: find `boundary=`
  case-insensitively after the media type, handle a quoted or bare value. Match
  `rfc1867.c`'s `php_ap_getword_conf` semantics; the builder confirms edge cases in
  the Task 7 differential harness.
- [ ] **Step 4: Run → PASS. Step 5: Commit.**

---

### Task 2: The independent post-byte scanner + its FFI (core) — gap A exact

Add a second `MultipartState` (in `feed` byte mode) to the ctx, fed the raw body by
the read_post wrapper, **independent** of the existing structured counter. It makes
`max_part_headers` / `max_part_header_bytes` exact (the structured path sees only
PHP's one exposed `Content-Disposition`; the byte scanner sees every header line).

**Files:** Modify (shared) `ffi.rs` (ctx field + 2 FFI fns + `describe` if a new
rule); modify `limits.rs` (if a new RuleId — see below); `howdah_core.h`
(regenerate). Reuse `multipart.rs` (`MultipartState::feed`, unchanged) and
`limits.rs` `check`.

**Interfaces — Produces:**
- ctx gains `post_scan: Option<MultipartState>` and a `post_scan_worst` fold that
  never touches the structured `state`.
- `howdah_scan_post_begin(ctx, content_type, ct_len)` — extract the boundary
  (Task 1) and init `post_scan`; no-op (and the scanner stays `None`, fail-open)
  when not multipart or the boundary is absent.
- `howdah_scan_post(ctx, buf, len) -> i32` (0 Allow / 2 Block) — feed `len` bytes
  to `post_scan.feed`, run `limits.check` on its state, fold into the ctx worst;
  returns Block once any limit trips so the wrapper can stop. Panic/NULL/`None`
  scanner → 0. Never logs bytes; a desync (feed error) counts as `MalformedMultipart`
  and, per §4.2, must only ever add a block.
- Reuses the existing `max_part_headers`/`max_part_header_bytes` rules (already
  Critical; confirm in a test). No new RuleId for gap A.

- [ ] **Step 1: Coordinate** (`ListAgents`/`SendMessage`) — this appends an FFI fn
  pair and a ctx field; no new RuleId.
- [ ] **Step 2: Failing tests** (in `ffi.rs` tests, using `howdah_init` + the new
  FFI): a body with 50 header lines in one part trips `max_part_headers` through
  `howdah_scan_post` even though a structured `howdah_part` for the same request
  reports only 1 header; an oversized single header trips `max_part_header_bytes`;
  a benign 2-header part does not; feeding in arbitrary chunk splits gives the same
  verdict (resumability); a non-multipart `begin` leaves the scanner off (Allow).
- [ ] **Step 3: Run → FAIL.**
- [ ] **Step 4: Implement** the ctx field, `howdah_scan_post_begin`,
  `howdah_scan_post`. Fold hits with the existing `apply`/`fold` so the log line and
  worst action match the other layers; the byte scanner writes to the SAME per-request
  worst/log as the structured path (one verdict per request) but its COUNTERS are a
  separate `MultipartState`.
- [ ] **Step 5: Run → PASS. Step 6: Regenerate `howdah_core.h`. Step 7: Commit.**

---

### Task 3: Gap B — bytes actually read vs effective `post_max_size` (core)

Count bytes actually read for a multipart request and stop once they exceed PHP's
effective `post_max_size` (backports upstream's `fill_buffer` check). Also count the
bytes of **non-file** part bodies (from each part's `Content-Disposition`) for the
§4.5 estimate — PHP holds a whole non-file field value in memory; file data goes to
disk.

**Files:** Modify (shared) `limits.rs` (new Critical RuleId `PostTooLarge`, serde
`post_too_large`), `log.rs` (layer 1, name), `ffi.rs` (`describe` arm; the scanner
passes `post_max_size` in via `howdah_scan_post_begin`), `exceptions/mod.rs`
(`Layer::of`), the catalog + exhaustiveness/count tests (35+backstop → +1). Reuse
`MultipartState` (needs a non-file-byte accumulator: add `max_nonfile_bytes` /
`total_nonfile_bytes` high-water in `multipart.rs`, fed when a `FieldStart` part's
data is scanned).

**Interfaces — Produces:** `RuleId::PostTooLarge` (Critical, layer 1);
`howdah_scan_post_begin(ctx, content_type, ct_len, post_max_size: i64)` gains the
limit (0 or negative = unlimited → gap B off); `MultipartState::total_nonfile_bytes()`.

- [ ] **Step 1: Coordinate.** Appends a RuleId + a scanner accumulator.
- [ ] **Step 2: Failing tests:** a multipart body whose read bytes exceed
  `post_max_size` → `PostTooLarge` (Critical); exactly at the limit → none;
  `post_max_size <= 0` → never fires; non-file bytes are accumulated and file bytes
  are not (feed a field part and a file part, check `total_nonfile_bytes`). Add the
  new rule to the exhaustive catalog/layer/name tests.
- [ ] **Step 3: Run → FAIL. Step 4: Implement** the accumulator + the check (a
  `check_post_bytes(total_read, post_max_size)` on `Limits`, called from
  `howdah_scan_post`). Status map: `post_too_large` → 413 (add to
  `response::status_for_rule` in ext — it is a string match, not exhaustive).
- [ ] **Step 5: Run → PASS. Step 6: Regenerate header. Step 7: Commit.**

---

### Task 4: Gap C — summed nesting-levels budget (core)

Memory grows with the TOTAL number of array levels across all variables, not any one
depth. Add a per-request budget on summed nesting levels, counted for urlencoded /
cookie / GET names (input_filter path), multipart `FORMDATA` names and `FILE_START`
names. A file name costs more (PHP builds several metadata arrays per file): weight
it. These levels feed the §4.5 estimate.

**Files:** Modify `input.rs` (add `total_levels: u64` summed accumulator + a
`note_name(name, is_file)` that adds `nesting_depth(name) + 1`, file-weighted by a
measured factor `FILE_NAME_WEIGHT`); modify (shared) `limits.rs` (new Critical
RuleId `NestingBudget`, serde `nesting_budget`, + a `max_nesting_levels` `[limits]`
key) and the exhaustive sites; `log.rs`/`ffi.rs`/`exceptions/mod.rs`; glue wires the
multipart names (see Task 7). Reuse the input_filter path (`howdah_input_var`
already feeds names).

**Interfaces — Produces:** `RuleId::NestingBudget` (Critical, layer 1);
`InputState::total_levels()`; `Limits.max_nesting_levels` (default measured in
Task 8, generous enough for the benign corpus); the multipart names feed the same
accumulator via a new `howdah_note_name_levels(ctx, name, len, is_file)` or by
extending `howdah_part` (choose the append-only path).

- [ ] **Step 1: Coordinate.** Appends a RuleId + a `[limits]` key.
- [ ] **Step 2: Failing tests:** many shallow vars vs few deep vars that sum to the
  same level count both trip `NestingBudget` at the same total; a file name counts
  `FILE_NAME_WEIGHT`× a field name; the benign corpus's deepest legit nesting does
  NOT trip the default; `max_nesting_levels` of 0 rejected by `validate`.
- [ ] **Step 3: Run → FAIL. Step 4: Implement.** `note_name` sums
  `(nesting_depth + 1) * weight`; `check_input` gains the budget check (field
  order: after the existing input checks). `FILE_NAME_WEIGHT` and the default
  `max_nesting_levels` are provisional; Task 8 measures and pins them.
- [ ] **Step 5: Run → PASS. Step 6: Regenerate header. Step 7: Commit.**

---

### Task 5: §4.5 — size the memory checks from the live `memory_limit` (core)

Keep one per-request **estimate of the memory PHP's parser will hold** — summed
nesting levels (Task 4, file-weighted), buffered non-file part bytes (Task 3),
parsed header entries (Task 2) — and Critical-block when it passes a ceiling of
`memory_limit / 4`. The glue reads the request's effective `memory_limit` and passes
it in; `-1` falls back to a fixed measured ceiling.

**Files:** Modify (shared) `limits.rs` (new Critical RuleId `ParseMemoryEstimate`,
serde `parse_memory_estimate`; a `memory_ceiling_bytes` `[limits]` key whose default
is **automatic** — `memory_limit / 4`, or a fixed fallback when `memory_limit = -1`;
the builder MAY fold this into the existing `max_parse_memory_bytes` if the
semantics fit without breaking configs — **decide in Step 4 with the code in front
of you**), the exhaustive sites; `ffi.rs` (the estimate accumulator on the ctx; a
`memory_limit` parameter threaded through `howdah_scan_post_begin`); cost constants
module.

**Interfaces — Produces:** `RuleId::ParseMemoryEstimate` (Critical, layer 1); a
per-request `estimate_bytes` on the ctx combining the three inputs with
per-generation cost constants (`COST_PER_LEVEL`, `COST_PER_HEADER`,
`COST_PER_NONFILE_BYTE` ≈ 1); `howdah_scan_post_begin(..., memory_limit: i64)`; the
ceiling = `memory_limit/4` or the `memory_ceiling_bytes` override or the `-1`
fallback.

- [ ] **Step 1: Coordinate.** Appends a RuleId + a `[limits]` key.
- [ ] **Step 2: Failing tests:** with `memory_limit = 128 MiB`, an estimate passing
  32 MiB → `ParseMemoryEstimate`; the same request under `memory_limit = 512 MiB`
  does NOT trip (ceiling scales); `memory_limit = -1` uses the fixed fallback
  ceiling; the estimate combines all three inputs (unit-test the accumulator with
  known levels/headers/bytes). The benign corpus's heaviest legit request stays
  under the ceiling at every profile.
- [ ] **Step 3: Run → FAIL. Step 4: Implement**; decide the fold-vs-new-key question
  and record it in the doc-comment. Cost constants are provisional; Task 8 measures
  per generation and pins them.
- [ ] **Step 5: Run → PASS. Step 6: Regenerate header. Step 7: Commit.**

---

### Task 6: The `read_post` C wrapper + bindings (howdah-sys)

Wrap `sapi_module.read_post` like `oom_hook.c`/`refuse_hook.c` wrap their targets.
Per-generation signature: 5.x `int (char*, uint)`, 7.x/8.x `size_t (char*, size_t)`
(TSRMLS is empty in NTS). The wrapper calls the prior reader, feeds the bytes just
read to the core scanner via a Rust callback, and on Block returns 0 (end of body)
so PHP stops reading; it records the verdict for the RINIT refusal. Restore at
MSHUTDOWN.

**Files:** Create `crates/howdah-sys/read_post_hook.c`; modify `build.rs` (compile
it + `rerun-if-changed`), `src/lib.rs` (install/uninstall fns + a
`HowdahReadPostDecide` callback type: `(buf: *const c_char, len: usize) -> c_int`).

**Interfaces — Produces:** `howdah_install_read_post_hook(cb)` /
`howdah_uninstall_read_post_hook()`; the wrapper holds the prior `read_post` and the
Rust `cb`; on `cb` returning Block it latches a static flag and returns 0 thereafter.

- [ ] **Step 1: Write the shim** with the per-generation `#if PHP_VERSION_ID`
  signatures (include `<stdint.h>` — 5.4's headers do not pull it in; the backstop
  learned this). The wrapper: `n = prior(buf, count); if (n>0 && cb(buf, n)==BLOCK)
  { g_stop=1; } return g_stop ? 0 : n;`. A returned 0 is a clean EOF to PHP.
- [ ] **Step 2: Bindings** in `src/lib.rs` (type + extern fns, house-style docs).
- [ ] **Step 3: Compile** — add to `build.rs`.
- [ ] **Step 4: Build-verify** on 5.4/5.6/7.4/8.0/8.3 dev images
  (`cargo build -p howdah-ext --features phpN`); each compiles and links. Confirm per
  generation that a 0 return mid-body does not itself raise a PHP fatal (read the
  SAPI's `read_post` callers). Commit.

---

### Task 7: Wire the wrapper to the scanner + feed multipart names (howdah-ext)

Install the wrapper at MINIT (gated: a multipart request with Layer-1 limits active;
cheap to always install and no-op on non-multipart). At request begin, read the
effective `memory_limit` and `post_max_size` (per request — settable per
dir/pool/vhost) and the `CONTENT_TYPE`, call `howdah_scan_post_begin`. The Rust
`read_post` callback calls `howdah_scan_post`; on Block, record the refusal (RINIT
path). Feed multipart `FORMDATA`/`FILE_START` names to the nesting accumulator
(Task 4) from `rfc1867.rs`.

**Files:** Create `crates/howdah-ext/src/post_scan.rs` (the Rust `read_post` decide
callback); modify `module.rs` (MINIT install + MSHUTDOWN restore; read the two INI
values + content_type at begin; pass to `howdah_scan_post_begin`), `rfc1867.rs`
(feed names to the nesting accumulator), `lib.rs` (`mod post_scan`).

**Interfaces — Consumes:** Tasks 2/3/4/5 FFI; Task 6 install. The INI reads use the
existing `ini_string` pattern for `memory_limit`/`post_max_size` (parse the shorthand
`128M`/`-1`).

- [ ] **Step 1: Confirm the delivery seam** — a verdict recorded during read_post
  (which runs in `sapi_activate` for urlencoded, before `php_hash_environment`)
  reaches `deliver_startup_refusal`. Write a lab check (Task 8) that the refusal body
  + 403/413 arrive and the worker survives, like the refusal-path lab.
- [ ] **Step 2: Implement** the callback + install + name feeding. Fail-open
  throughout (`catch_unwind`; a panic → no suppression).
- [ ] **Step 3: Differential fuzz harness** in `fuzz/`: a target that feeds the same
  random multipart body to the byte scanner and to a minimal PHP parse (or to
  recorded PHP parse counts) and asserts the scanner's per-part header count ≥ PHP's
  (over-count, never under-count) and never panics / is bounded in memory. Keep the
  existing `multipart`/`events` fuzz targets green.
- [ ] **Step 4: Build-verify** the glue on 5.4/5.6/7.4/8.0/8.3; php-feature clippy
  clean for the new code. Commit.

---

### Task 8: Config surfaces, benign corpus, cost calibration, docs

**Files:** `site/config-editor/schema.js` (+`max_nesting_levels`,
`memory_ceiling_bytes` or the folded key); `site/test/*` + wasm + `crates/howdah-wasm`
catalog counts (+3 or +4 new rules); `docs/config.md`; `docs/log-schema.md` (new
rule names); `docs/howdah-event.schema.json` (layer-1 description — rule field is a
pattern, no enum change); `lab/integration/` (extend the benign corpus +
`matrix.sh` stays green; a byte-limits lab modeled on `refusal.sh`/the backstop lab,
fpm-behind-nginx + Apache); `crates/howdah-core/src/limits.rs` default values
(measured).

- [ ] **Step 1: Calibrate** the cost constants, `FILE_NAME_WEIGHT`, the default
  `max_nesting_levels`, and the `memory_limit = -1` fallback ceiling by measuring
  peak worker RSS on the lab dev images (as `limits.rs::defaults` doc-comment and
  `step1_*` already do). Pin the defaults; the full false-positive corpus must be
  zero-block at them.
- [ ] **Step 2: Benign corpus** — add multi-file gallery uploads, parts with
  ordinary extra headers, framework-style nested arrays, a real chunked upload;
  assert ZERO blocks at the stock, upload-heavy (128M), and raised (512M) ini
  profiles (§5.1). This is the Review-Focus #1 gate.
- [ ] **Step 3: Config editor + docs** rows for the new keys/rules; run
  `sh packaging/build-wasm.sh && cd site && npm test` green (bump the hardcoded
  catalog counts in `glue.test.mjs`, `schema.test.mjs` if present, and
  `crates/howdah-wasm` — grep the backstop's `37`).
- [ ] **Step 4: Vulnerable-version rows = NOT-RUN.** Record in the lab/docs that the
  §5.2 "PASS on vulnerable PHP" table and its trigger fixtures are owner-supplied
  (§5.3, gitignored `private/`); do not author them.
- [ ] **Step 5: Full gate + commit** (`cargo test --workspace`, clippy host +
  feature, `npm test`, `cargo fuzz` smoke, benign-corpus lab).

---

### Task 9: Independent review, finish, PR

- [ ] **Step 1: Whole-branch gate** re-run; capture output.
- [ ] **Step 2: Independent Fable review** of all core/ext/C (emphasis: the
  scanner/PHP differential and fail-closed-on-desync; the read_post per-generation
  signatures and the 0-return EOF safety; the §4.5 ceiling math and `-1`/raised
  profiles; fail-open on panic; append-only discipline; no request content logged).
  Apply superpowers:receiving-code-review; fix what is real, commit.
- [ ] **Step 3: Push, open the PR** to `main` (CI green). Body: what the three gaps
  are and how the scanner closes each; the trade-offs; the benign-corpus + fuzz
  evidence; the explicit NOT-RUN for vulnerable-version PASS rows (owner triggers);
  the Claude Code footer. Stop and report the PR link; do not merge/tag/bump.

---

## Self-review

**1. Spec coverage (§4.1–4.5 + §5):** §4.1 read_post wrapper → Task 6/7. §4.2 gap A
exact headers + independent scanner + fail-closed → Task 2 (+ constraint). §4.3 gap B
bytes vs post_max_size + non-file byte counting → Task 3. §4.4 gap C summed nesting,
file-weighted, both paths → Task 4 (+ Task 7 name feeding). §4.5 live memory_limit,
estimate, memory_limit/4 ceiling, override key, -1 fallback → Task 5. §5.1 ini
profiles + §5.4 benign corpus + fuzz → Task 8 + Task 7 differential. §5.2/§5.3
vulnerable-version evidence + triggers → explicitly NOT-RUN/owner-supplied. §6
site claim + CVE-description corrections → out of scope here (gated on the evidence).

**2. Step scan:** code appears only as signatures/decisions the implementer can't
derive (FFI shapes, the per-generation read_post signature, the ceiling math);
bodies are left to the implementer. The two genuinely open design calls
(fold-vs-new-key in §4.5; whether a new RuleId or a reused one for gap A) are called
out as "decide in Step 4 with the code in front of you", not left vague elsewhere.

**3. Type consistency:** `howdah_scan_post_begin` grows parameters across Tasks 2→3→5
(content_type, post_max_size, memory_limit); the plan states the final shape in
Task 5. The new RuleIds (`PostTooLarge`, `NestingBudget`, `ParseMemoryEstimate`) and
`[limits]` keys (`max_nesting_levels`, `memory_ceiling_bytes`) are named once and
reused.

**4. Review Focus:** each of the five has a test named in its task (benign corpus →
Task 8; differential → Task 7; short-read → Task 6/7 lab; -1/raised → Task 5/8;
cgi-fcgi → Task 8).

**5. Proportion:** the plan is long because §4.1–4.5 spans a C wrapper, a second
core scanner, three new rules, two new config keys, the memory estimate, and the
corpus/fuzz verification across four crates + lab + editor + docs. It stays shorter
than the code it describes: no full function bodies, just interfaces, the exact new
rule/key names, and the test assertions.

**Known unknowns pinned to a task, not left floating:** cost constants /
`FILE_NAME_WEIGHT` / default `max_nesting_levels` / `-1` fallback ceiling (Task 8
measures); the fold-vs-new-key §4.5 decision (Task 5 Step 4); the read_post 0-return
EOF safety per generation (Task 6 Step 4). The vulnerable-version PASS table is the
owner's to complete.
