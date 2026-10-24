# Howdah policy pack (1.6.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Howdah 1.6.0 with signed, versioned, opt-in policy packs: a pack file format and validator in the core, evaluation at the Layer 2 position, at RINIT and at the Layer 3 sinks, `[packs]` configuration, loading at MINIT with the loud failure path, `howdah-check pack install|verify|list|show|remove`, a pack release pipeline, and the two initial packs (`noise`, `virtual-patch`) with test vectors run in CI, in the browser and in the lab.

**Architecture:** A pure-Rust `packs` module in `howdah-core` (parser and validator, compiled matcher, vector runner; filesystem-free, regex-free, dependency-free). Append-only FFI entry points hand pack bytes in from the glue and hand per-hit lines and messages out. Rules ride inside the existing positions: value rules latch in the input filter, request rules decide at RINIT using the Layer 4 `emit_and_bail` path, sink rules run after the built-in policy in the existing trampolines via the PR #43 `_at` entry points. Delivery is static files on `pkg.howdah.org/packs/`, signed with a new pack signing subkey of the project key, installed by POSIX sh in `tools/howdah-check`.

**Tech Stack:** Rust (howdah-core, howdah-ext, howdah-wasm), C shims untouched except for one armed-predicate call, TOML, cbindgen-generated `howdah_core.h`, POSIX sh + curl + gpg, GitHub Actions + rclone to R2, Docker lab across PHP 5.6/7.4/8.3 with php-fpm and Apache.

**Spec:** `docs/superpowers/specs/2026-10-24-howdah-policy-pack-design.md` (read §5.2 for the grammar, §5.3 for the three evaluation points, §10 for the builder-check rulings; the tasks below are authoritative where they refine it).

## Global Constraints

- **Dependency:** PR #43 (`feat/scoped-exceptions`) must be on `main` before Task 1 starts. This plan uses `crate::exceptions::glob::Glob`, `crate::exceptions::RuleSelector`, `Layer`, and the `_at` sink/behavior entry points. If `crates/howdah-core/src/exceptions/glob.rs` is absent, stop and report; do not fork a glob.
- Defensive only. Vectors are static shapes (`O:4:"Test":0:{}`, a path, a route string); never a runnable exploit or a real gadget chain. No class name is written into `classes_any` unless it was verified against the advisory; otherwise the key is omitted.
- Log-first. `[packs] mode` defaults to `detect`; no pack, version or update arms a block. A global `howdah.mode = block` never arms a pack rule. `RuleId::PackRequest` and `RuleId::PackSink` are `Severity::Standard`.
- A pack can only add findings: no pack key may change a limit, a mode, an allowlist or any built-in rule. The validator enforces the closed grammar (`deny_unknown_fields` everywhere).
- No new php.ini directives (three). All new keys live under `[packs]` in the TOML.
- Privacy: no value, no sink argument, no header value crosses into the log or into `reason`. Only names.
- `howdah-core`: no new runtime dependencies, no regex, no filesystem, no network, no `std::net`; every match is linear-time with the bounds in spec §5.2 (256 rules/pack, 8 packs, 32 needles × 128 bytes, 8 tokens, 64 tests/rule, 16 entries per list facet, 256-byte globs, 1 MiB per pack file).
- Fail-open: every new core entry point is wrapped in `catch_unwind`; NULL ctx returns `HOWDAH_ALLOW` / 0 / NULL.
- Append-only in `ffi.rs`, `limits.rs`, `config.rs`, `howdah_core.h`: new items go at the end; existing signatures, fields and variant order are untouched. `howdah_core.h` is regenerated with cbindgen, never hand-edited.
- Rule names: `^[a-z][a-z0-9_]{0,63}$`, never equal to a `rule_catalog()` name; pack ids `^[a-z][a-z0-9-]{0,31}$`, never `enabled`, `mode` or `dir`.
- The event line stays schema 2. `rule` keeps `^[a-z0-9_]+$`; `pack` and `pack_version` are added as optional fields.
- No workflow among `pages.yml`, `worker.yml`, `publish-repos.yml`, `release.yml` is edited. The pack pipeline is a new `pack-release.yml`.
- Commit trailer: `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Report real test output; never claim a pass that was not seen.

## Review Focus

- **A config without `[packs]` changes nothing.** No pack event, no extra hook installed, `howdah_sink_armed` answers exactly as in 1.5, `howdah_inspect_value` is called exactly when it was before. *(Task 4 `packs_absent_is_default`, Task 6 `no_packs_sink_armed_unchanged`, Task 13 check (j).)*
- **A pack that fails to load never makes the main config INVALID.** Missing file for an enabled id, `min_howdah` above the build, wrong `format`, a duplicate rule name across packs: each is skipped with a message, `Config status => ok`, built-ins unchanged. *(Task 6 `load_failure_keeps_config`, Task 8, Task 13 check (e).)*
- **A value hit latched before a Layer 1 bailout leaves nothing behind.** Multipart POST that Layer 1 refuses while a pack value rule had latched: no second response, no pack line, state cleared for the next request in the same worker. *(Task 6 `latched_hits_cleared_on_request_begin`, Task 13 check (c).)*
- **Worst-case value matching stays inside the budget.** A 16 KiB value against a rule with 32 needles of 128 bytes, 2000 values in one request: bounded by `inspect.limits`, well under a second in the unit test, no quadratic blow-up. *(Task 2 `needles_worst_case_bounded`.)*
- **Nothing from the value or the argument reaches the line.** `reason` for a value hit names source and variable; for a sink hit the sink and function; the lab greps the payload bytes absent. *(Task 6 `pack_lines_carry_no_value_or_arg`, Task 13 check (h).)*
- **The decoded URI view does not create a benign false positive.** `/vendor/phpunit-bridge/`, `/wp-json/bricks/v1/render_elements_list`, `/.environment`, `/api/index.php/v1/config/application-help` are negative vectors in the packs. *(Task 9 vectors, enforced by `tests/packs.rs`.)*

---

### Task 1: Pack schema, parser and validator

**Files:**
- Create: `crates/howdah-core/src/packs/mod.rs` (module root: constants, `pub mod schema; pub mod matcher; pub mod vectors;`, re-exports)
- Create: `crates/howdah-core/src/packs/schema.rs`
- Modify: `crates/howdah-core/src/lib.rs` (add `pub mod packs;`)
- Test: inline `#[cfg(test)]` in `schema.rs`

**Interfaces:**
- Consumes: `crate::limits::rule_catalog`, `crate::exceptions::glob::Glob::parse(&str) -> Result<Glob, String>` (PR #43), `crate::sinks::SinkId`, `crate::inspect::Source`.
- Produces (all `serde::Deserialize` with `deny_unknown_fields`, `Clone`, `Debug`, `PartialEq`):
  - `pub const PACK_FORMAT: u32 = 1; MAX_PACKS = 8; MAX_RULES_PER_PACK = 256; MAX_NEEDLES = 32; MAX_NEEDLE_BYTES = 128; MAX_TOKENS = 8; MAX_TESTS_PER_RULE = 64; MAX_LIST_FACET = 16; MAX_GLOB_BYTES = 256; MAX_PACK_BYTES = 1 << 20;`
  - `pub enum PackSeverity { Info, Low, Medium, High, Critical }` (serde lowercase), `pub enum PackAction { Log, Block }`, `pub enum Position { Request, Sink }`, `pub enum View { Raw, Lower, Decoded }` (default `Lower`), `pub enum PackSink { Eval, Include, CommandExec, Unserialize, Phar }` with `pub fn sink_id(self) -> SinkId`.
  - `pub struct Manifest { id, version, name, created, min_howdah, max_howdah: Option<String>, rule_count: usize, retired: Vec<String>, homepage: Option<String>, signing_key: Option<String> }`
  - `pub struct OneOrMany(pub Vec<String>)` deserializing from a string or an array (used by `uri_prefix`, `uri_suffix`, `uri_glob`, `main_script_glob`).
  - `pub struct RequestFacets { method: Vec<String>, uri_prefix: OneOrMany, uri_suffix: OneOrMany, uri_glob: OneOrMany, main_script_glob: OneOrMany, param: Option<String>, param_prefix: Option<String>, source: Vec<Source>, param_present: Vec<String>, header_present: Vec<String> }` with `pub fn is_empty(&self) -> bool`.
  - `pub struct ValueTest { view: View, equals, prefix: Option<String>, contains_any: Vec<String>, tokens_in_order: Vec<String>, max_gap: Option<usize>, serialized_object: bool, classes_any: Vec<String>, length_min: Option<usize> }`
  - `pub struct SinkTest { sink: PackSink, script_glob: OneOrMany, arg_contains_traversal: bool, arg_scheme: Vec<String>, arg_prefix: Option<String>, arg_contains_any: Vec<String>, classes_any: Vec<String>, binary_in: Vec<String> }`
  - `pub struct TestParam { source: Source, name: String, value: String }`, `pub struct TestRequest { method: Option<String>, uri: Option<String>, main_script: Option<String>, params: Vec<TestParam>, headers: Vec<String> }`, `pub struct TestSink { sink: PackSink, arg: String, script: Option<String> }`, `pub enum Expect { Match, NoMatch }`, `pub struct RuleTest { request: Option<TestRequest>, sink: Option<TestSink>, expect: Expect }`
  - `pub struct PackRule { name, severity, action, enabled: bool (default true), refs: Vec<String>, summary, review_by, position, request: RequestFacets, value: Option<ValueTest>, sink: Option<SinkTest>, tests: Vec<RuleTest> }`
  - `pub struct Pack { format: u32, pack: Manifest, rules: Vec<PackRule> }`
  - `pub struct PackError { pub rule: Option<usize>, pub key: Option<&'static str>, pub message: String }` with `Display` = `rules[<i>].<key>: <message>` / `pack.<key>: <message>` / `<message>`.
  - `impl Pack { pub fn from_toml(s: &str) -> Result<Pack, PackError>; pub fn compatible_with(&self, howdah_version: &str) -> Result<(), String>; }`
  - `pub fn parse_version(s: &str) -> Option<(u32, u32, u32)>` (three numeric components; a `-suffix` on the input is ignored).
  - `pub fn valid_pack_id(s: &str) -> bool`, `pub fn valid_rule_name(s: &str) -> bool`.

Validation rules `from_toml` enforces, each with the `rules[i].key` error named: `format == 1`; manifest id/version/min_howdah parse; `rule_count == rules.len()`; bounds from the constants; name charset and uniqueness in the pack; name not in `rule_catalog()` and not in `retired`; `refs` non-empty; `summary` non-empty; `review_by` a date `YYYY-MM-DD`; `position = request` ⇒ `request` non-empty, `sink` absent, `value` ⇒ `param` or `param_prefix` set; `position = sink` ⇒ `sink` present, `value` absent, `request.param`/`param_prefix`/`source` absent; `classes_any` only with `unserialize` (sink) or `serialized_object = true` (value); `binary_in` only with `command_exec`; `arg_scheme` only with `include`, `phar`, `command_exec`; every glob parses; `tests` has at least one `Match` and one `NoMatch`; a sink rule's vectors each have a `sink` table whose `sink` equals the rule's, a request rule's vectors have none; `max_gap` only with `tokens_in_order`.

- [ ] **Step 1: Write the failing tests** in `schema.rs`: `minimal_request_rule_parses`, `minimal_sink_rule_parses`, `string_or_list_facets`, `format_2_rejected`, `rule_count_mismatch_rejected`, `builtin_name_rejected` (`name = "eval"` → error mentions `rules[0].name`), `retired_name_rejected`, `duplicate_name_rejected`, `missing_negative_vector_rejected`, `value_without_param_rejected`, `sink_rule_with_value_rejected`, `classes_any_on_eval_rejected`, `binary_in_on_include_rejected`, `too_many_needles_rejected` (33), `needle_too_long_rejected` (129 bytes), `bad_glob_rejected`, `unknown_key_rejected` (`[rules.request] uri = "/x"`), `review_by_not_a_date_rejected`, `compatible_with_range` (`min 1.6.0 max 1.99.99` accepts `1.6.0`, `1.6.0-rc1`, `1.12.3`; rejects `1.5.9`, `2.0.0`), `parse_version_forms`, `pack_id_charset` (`enabled`, `Mode`, `a_b`, 33 chars rejected).
- [ ] **Step 2: Run, verify fail** — `cargo test -p howdah-core packs::schema`.
- [ ] **Step 3: Implement** the types and `from_toml` (serde then a second validation pass that produces `PackError`). `OneOrMany` via `#[serde(untagged)]` over `String | Vec<String>`.
- [ ] **Step 4: Run, verify pass**; `cargo clippy -p howdah-core --all-targets -- -D warnings` clean.
- [ ] **Step 5: Commit** — `feat(core): pack schema, parser and validator (format 1)`.

### Task 2: Compiled matcher and the three evaluation functions

**Files:**
- Create: `crates/howdah-core/src/packs/matcher.rs`
- Test: inline tests

**Interfaces:**
- Consumes: Task 1 types; `crate::inspect::{Source, InspectLimits}`; `crate::sinks::unserialize_classes`; `crate::exceptions::glob::Glob`; the percent-decoder from `inspect.rs` (make `inspect::percent_decode` `pub(crate)`).
- Produces:
  - `pub struct PackHit { pub pack: usize, pub rule: usize }`
  - `pub struct PackRef<'a> { pub pack: &'a str, pub version: &'a str, pub rule: &'a str, pub position: Position, pub summary: &'a str, pub action: PackAction, pub enabled: bool, pub sink: Option<SinkId> }`
  - `pub struct RequestFacts<'a> { pub method: &'a [u8], pub uri: &'a [u8], pub main_script: Option<&'a [u8]> }`
  - `pub struct RequestState { /* names_seen: BTreeSet<Vec<u8>> (only names some rule lists), headers_seen: BTreeSet<Vec<u8>>, latched: Vec<PackHit>, fired: Vec<u64> bitset */ }` with `pub fn new() -> Self`, `pub fn reset(&mut self)`.
  - `pub struct Packs { /* packs: Vec<Pack>, request_rules: Vec<(usize,usize)>, by_param: BTreeMap<Vec<u8>, Vec<(usize,usize)>>, prefix_rules: Vec<(usize,usize)>, by_sink: [Vec<(usize,usize)>; 6], wanted_names, wanted_headers, needle tables */ }`
  - `impl Packs { pub fn compile(packs: Vec<Pack>) -> Result<Packs, String>` (error = duplicate rule name across packs, names both); `pub fn is_empty(&self) -> bool; pub fn len(&self) -> usize; pub fn wants_values(&self) -> bool; pub fn wants_sink(&self, s: SinkId) -> bool; pub fn wants_header_names(&self) -> bool; pub fn rule_ref(&self, h: PackHit) -> PackRef<'_>; pub fn find(&self, pack: &str, rule: &str) -> Option<PackHit>; pub fn pack_index(&self, id: &str) -> Option<usize>; pub fn note_var(&self, st: &mut RequestState, name: &[u8]); pub fn note_header(&self, st: &mut RequestState, http_key: &[u8])` (converts `HTTP_X_Y` → `x-y`); `pub fn eval_value(&self, st: &mut RequestState, src: Source, name: &[u8], value: &[u8], lim: &InspectLimits) -> Vec<PackHit>` (latches and returns the new hits; a rule already in `fired` is skipped); `pub fn eval_request(&self, st: &mut RequestState, f: &RequestFacts) -> Vec<PackHit>` (request rules now true, plus every latched value hit whose request facets also hold; marks fired); `pub fn eval_sink(&self, st: &mut RequestState, f: &RequestFacts, sink: SinkId, arg: &[u8], script: Option<&[u8]>) -> Vec<PackHit>`; `pub fn report(&self, loaded: &[(String, Result<usize, String>)]) -> String`.
  - `pub fn uri_matches(prefix: &[&str], suffix: &[&str], globs: &[Glob], uri: &[u8]) -> bool` (raw view or decoded-lowercased view).
  - `pub fn first_token_basename(cmd: &[u8]) -> &[u8]`, `pub fn arg_scheme(arg: &[u8]) -> Option<Vec<u8>>` (lowercased scheme before `://`, letters/digits/`+-.` only).
  - `pub fn contains_any(hay: &[u8], needles: &NeedleSet) -> bool`, `pub struct NeedleSet` built once per rule (first-byte buckets; the builder may substitute a hand-written Aho–Corasick if measured faster, same signature).
  - `pub fn tokens_in_order(hay: &[u8], tokens: &[Vec<u8>], max_gap: Option<usize>) -> bool`.

- [ ] **Step 1: Failing tests**: `uri_prefix_raw_and_decoded_views` (`/VENDOR/%70hpunit/` matches `/vendor/phpunit/`), `uri_glob_double_star`, `main_script_glob_is_raw_case_sensitive`, `method_case_insensitive`, `value_rule_latches_then_fires_at_request` (eval_value returns the hit; eval_request returns it once; second eval_request returns nothing), `value_rule_request_facets_must_also_hold` (uri mismatch → latched hit dropped at eval_request), `param_prefix_matches_argv_style` (`--templatesPath`), `source_filter_respected`, `contains_any_hits_and_misses`, `tokens_in_order_with_gap`, `serialized_object_and_classes_any` (`O:4:"Test":0:{}` matches; `a:1:{i:0;i:1;}` does not), `length_min`, `decoded_view_percent`, `sink_rule_requires_request_facets_in_same_request` (param_present satisfied only after `note_var`), `sink_script_glob`, `arg_contains_traversal`, `arg_scheme_list` (`PHAR://x` → `phar`), `binary_in_basename` (`/usr/bin/curl -s x` → `curl`), `header_present_from_http_key` (`HTTP_X_FORWARDED_HOST`), `names_seen_is_bounded_to_wanted` (an unlisted name is not stored), `fired_once_per_rule_per_request`, `reset_clears_everything`, `duplicate_name_across_packs_rejected_names_both`, `needles_worst_case_bounded` (16 KiB value, 32 × 128-byte needles, 2000 values: `< 1 s` on the host, mirroring `huge_value_is_prefix_bounded`).
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement.** Value cut to `lim.max_value_bytes` before any view. `eval_request` evaluates request rules whose facets hold, then the latched list; both mark `fired`. `eval_sink` checks the sink's rule list only; `script_glob` against `script`; request facets against `f` and `st`.
- [ ] **Step 4: Run, verify pass**; clippy clean.
- [ ] **Step 5: Commit** — `feat(core): pack matcher — request, value and sink evaluation`.

### Task 3: Vector runner

**Files:**
- Create: `crates/howdah-core/src/packs/vectors.rs`
- Test: inline tests

**Interfaces:**
- Consumes: Tasks 1–2.
- Produces: `pub struct VectorFailure { pub pack: String, pub rule: String, pub index: usize, pub expected: Expect, pub got: bool }` with `Display`; `pub fn run_pack_tests(p: &Pack) -> Vec<VectorFailure>` (compiles the single pack, and for each vector: `RequestState::new()`, `note_var` + `eval_value` per `params` entry in order, `note_header` per header, `eval_request` with `method`/`uri`/`main_script` (defaults `GET`, `/`, `None`), then `eval_sink` if a `sink` table is present; "matched" = this rule's `PackHit` appears in any returned list); `pub fn lint_release(p: &Pack, today: &str) -> Vec<String>` (warnings: `review_by` more than 12 months after `created`, `review_by` already past `today`, a rule with fewer than 2 negative vectors).

- [ ] **Step 1: Failing tests**: `vector_match_and_no_match_pass`, `vector_mismatch_reported_with_index`, `sink_vector_runs_params_first` (a sink rule with `param_present` passes only when the vector lists the param), `lint_review_by_window`.
- [ ] **Step 2: Run, verify fail.** **Step 3: Implement.** **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(core): pack vector runner and release lint`.

### Task 4: `[packs]` configuration and mode resolution

**Files:**
- Modify: `crates/howdah-core/src/config.rs` (append only: new types after the `[log]` tests' siblings; new `packs: PacksConfig` field appended to `Config` and `RawConfig`; validation appended at the end of `from_toml`)
- Test: inline tests appended

**Interfaces:**
- Produces:
  - `pub enum PackMode { Off, Detect, Block, Recommended }` (serde lowercase)
  - `pub struct PackOverride { pub mode: Option<PackMode>, pub rules: BTreeMap<String, Mode> }` (`deny_unknown_fields, default`)
  - `pub struct PacksConfig { pub enabled: Vec<String>, pub mode: PackMode, pub dir: String, #[serde(flatten)] pub overrides: BTreeMap<String, PackOverride> }`; `Default`: `enabled = []`, `mode = Detect`, `dir = "/etc/howdah/packs"`.
  - `impl PacksConfig { pub fn resolve(&self, pack: &str, rule: &str, rule_action: PackAction, rule_enabled: bool, global: Mode) -> Mode` (spec §5.4 order; a rule shipped `enabled = false` is `Off` unless a per-rule override says `detect`/`block`); `pub fn warnings(&self, loaded: &[(&str, &[&str])]) -> Vec<String>` (override table for a pack not in `enabled`; rule key not in that pack's rule list). }`
  - `Config.packs: PacksConfig` (serialized as `packs`, so the wasm validator shows it).
- Validation in `from_toml` (errors): `dir` absolute and non-blank; each `enabled` id passes `valid_pack_id`, no duplicates; `enabled.len() <= MAX_PACKS`; every override key passes `valid_pack_id`.

- [ ] **Step 1: Failing tests**: `packs_absent_is_default` (no `[packs]` → `enabled` empty, `Detect`, default dir; `Config::from_toml("")` still equals `safe_defaults()`), `packs_table_parses`, `packs_per_pack_and_per_rule_tables`, `packs_typo_key_rejected` (`[packs] enabeld = []` is an error), `packs_relative_dir_rejected`, `packs_duplicate_enabled_rejected`, `packs_bad_id_rejected` (`"mode"`, `"A"`), `resolve_order` (per-rule > per-pack > section; `Recommended` → rule action; global `Off` wins), `resolve_global_block_does_not_arm`, `resolve_shipped_off_needs_override`, `warnings_for_stale_override_and_unenabled_table`, `config_serializes_packs`.
- [ ] **Step 2: Run, verify fail.** **Step 3: Implement.** **Step 4: Run, verify pass**; the whole `-p howdah-core` suite green.
- [ ] **Step 5: Commit** — `feat(core): [packs] config section and mode resolution`.

### Task 5: Rule ids and the event line

**Files:**
- Modify: `crates/howdah-core/src/limits.rs` (append `PackRequest`, `PackSink` to `RuleId`, to the `Standard` arm of `severity()`, to `rule_catalog()` (28 → 30) and to `rule_catalog_covers_every_variant`)
- Modify: `crates/howdah-core/src/log.rs` (`rule_layer`: `PackRequest => 2`, `PackSink => 3`; `rule_name`: `"pack_request"`, `"pack_sink"`; `EventRecord` gains `pub pack: Option<PackLine>` where `pub struct PackLine { pub pack: String, pub version: String, pub rule: String }`; `log_line` writes `rule` = `pack.rule` and adds `pack`, `pack_version` when present)
- Modify: `crates/howdah-core/src/exceptions/mod.rs` (`Layer::of`: `PackRequest => Inspect`, `PackSink => Sinks`, so the exhaustive match compiles; selector semantics come in Task 7)
- Modify: `docs/howdah-event.schema.json` (optional `pack`, `pack_version` string properties; `rule` pattern unchanged), `docs/log-schema.md` (two rows; the "at most one line per request" sentence amended for pack lines), `crates/howdah-core/tests/event_schema.rs` (a pack sample validates; `rule` of a pack line matches the pattern)
- Modify: `site/src/pages/config.astro` or its schema table (label `pack_request`/`pack_sink` as inert under `[rules]`, extending the no-op set from commit bdc5329)

- [ ] **Step 1: Failing tests**: `limits::pack_rule_ids_standard_and_serde` (`"pack_request"`, `"pack_sink"`), `log::pack_line_uses_rule_name_and_adds_fields` (`rule == "phpunit_eval_stdin"`, `pack == "noise"`, `pack_version == "2026.11.0"`, `layer == 2`), `log::builtin_line_has_no_pack_fields`, `event_schema::pack_line_validates`, the existing privacy test extended with a pack record.
- [ ] **Step 2: Run, verify fail.** **Step 3: Implement.** **Step 4: Run, verify pass** (`cargo test -p howdah-core`, `cd site && npm test`).
- [ ] **Step 5: Commit** — `feat(core,log): pack_request/pack_sink rule ids; pack and pack_version on the event line`.

### Task 6: FFI — load, evaluate, report (append-only) and the cbindgen header

**Files:**
- Modify: `crates/howdah-core/src/ffi.rs` (append after the last existing entry point; `howdah_ctx` gains fields `packs: Option<Packs>`, `pack_state: RequestState`, `pack_loaded: Vec<(String, Result<usize, String>)>`, `pack_staged: Vec<Pack>`, `pack_messages: VecDeque<String>`, `pack_lines: VecDeque<String>`; `request_begin` resets `pack_state`)
- Regenerate: `crates/howdah-core/howdah_core.h` (cbindgen)
- Test: inline FFI tests through the C ABI

**Interfaces (C ABI, all `#[no_mangle] pub unsafe extern "C"`):**
- `howdah_pack_load(ctx, id: *const c_char, id_len: usize, toml: *const c_char, toml_len: usize) -> i32` — 0 staged, 1 rejected (reason queued). Checks `toml_len <= MAX_PACK_BYTES`, parses, `pack.id == id`, `compatible_with(env!("CARGO_PKG_VERSION"))`, staged count `< MAX_PACKS`.
- `howdah_pack_finish(ctx) -> i32` — compiles staged packs (a cross-pack duplicate drops the later pack, message queued), stores `Packs`, queues `PacksConfig::warnings`, returns the number loaded.
- `howdah_packs_enabled_count(ctx) -> usize`, `howdah_packs_enabled_id(ctx, i: usize) -> *mut c_char`, `howdah_packs_dir(ctx) -> *mut c_char` (both freed with `howdah_free_str`).
- `howdah_take_pack_message(ctx) -> *mut c_char` (NULL when empty), `howdah_packs_report(ctx) -> *mut c_char` (the `--ri` row text), `howdah_packs_stale_report(ctx, today: *const c_char, len: usize) -> *mut c_char`.
- `howdah_packs_want_values(ctx) -> i32`, `howdah_packs_want_header_names(ctx) -> i32`, `howdah_pack_header_name(ctx, name, len)` (an `HTTP_*` key; names only).
- `howdah_pack_request_check(ctx, main_script: *const c_char, len: usize) -> i32` — RINIT: `eval_request`, resolves each hit with `PacksConfig::resolve` and the exceptions matcher (Task 7), queues one line per hit, returns the most severe action (`HOWDAH_BLOCK` if any hit resolved to block).
- `howdah_take_pack_log_line(ctx) -> *mut c_char` — NULL when the queue is empty.
- Internal behaviour changes to existing entry points (bodies only, signatures unchanged): `howdah_input_var` also calls `Packs::note_var`; `howdah_inspect_value` also calls `eval_value` (latching only; no line yet) and returns the max of the Layer 2 action and `HOWDAH_LOG` when a pack hit latched; `howdah_sink_check` and `howdah_sink_check_at` run `eval_sink` after the built-in policy, resolve, queue lines, return the max action; `howdah_sink_armed(ctx, sink)` returns 1 also when `packs.wants_sink(sink)`.
- Pack event lines use `EventRecord { rule: PackRequest | PackSink, pack: Some(PackLine{..}), reason: "pack rule <summary ≤160 bytes>; <get|post|cookie|path> variable '<name ≤64>'" | "; <sink> via <function>" | "; request" }`.

- [ ] **Step 1: Failing tests**: `pack_load_stages_and_finish_compiles`, `pack_load_wrong_id_rejected_with_message`, `pack_load_incompatible_version_rejected`, `load_failure_keeps_config` (ctx config `mode` and limits unchanged, `howdah_packs_report` names the failure), `request_check_blocks_when_rule_block` (config `[packs] mode = "block"`; line queued; return `HOWDAH_BLOCK`), `request_check_detect_logs_and_allows`, `value_rule_latch_then_request_check`, `sink_check_runs_pack_rules_after_builtin` (`[sinks.eval] mode = "off"` and a pack eval rule → `HOWDAH_LOG` with a pack line, no built-in line), `sink_armed_true_for_pack_sink` and `no_packs_sink_armed_unchanged`, `pack_lines_carry_no_value_or_arg`, `latched_hits_cleared_on_request_begin`, `recommended_mode_follows_rule_action`, `per_rule_override_off_silences`, `panic_in_pack_eval_fails_open`, `null_ctx_guarded`.
- [ ] **Step 2: Run, verify fail.** **Step 3: Implement**; regenerate the header with cbindgen (`cbindgen --config crates/howdah-core/cbindgen.toml --crate howdah-core --output crates/howdah-core/howdah_core.h`). **Step 4: Run, verify pass**; `cargo test --workspace`, clippy clean.
- [ ] **Step 5: Commit** — `feat(core): pack FFI — load, request/value/sink evaluation, lines and report`.

### Task 7: `[[exceptions]]` selectors for packs

**Files:**
- Modify: `crates/howdah-core/src/exceptions/mod.rs` (`RuleSelector` gains `pack: Option<(String, Option<String>)>`; `parse` accepts `packs`, `packs.<id>`, `packs.<id>.<rule>`, and a bare pack rule name when `Packs::find` resolves it uniquely — `parse` therefore takes `Option<&Packs>`; `covers_pack(&self, pack: &str, rule: &str) -> bool`; whole-layer `inspect`/`sinks` selectors return false for pack hits; facet applicability: request/value rules as Layer 2 (value rules additionally accept `param`/`param_prefix`), sink rules as Layer 3)
- Modify: `crates/howdah-core/src/ffi.rs` — the Task 6 resolution path consults `Exceptions::matches_pack(&EventFacts, pack, rule)`; with `exceptions_log` on, an excepted pack hit writes an `excepted` pack line.
- Test: inline tests

- [ ] **Step 1: Failing tests**: `selector_packs_all`, `selector_packs_one_pack`, `selector_packs_one_rule`, `selector_bare_pack_rule_name`, `selector_unknown_pack_rule_rejected`, `whole_layer_inspect_does_not_cover_pack_rule`, `value_rule_accepts_param_facet`, `sink_rule_rejects_param_facet`, `request_rule_rejects_script_facet`, FFI `excepted_pack_hit_silent_unless_exceptions_log`.
- [ ] **Step 2: Run, verify fail.** **Step 3: Implement.** Config validation of `[[exceptions]]` entries that name a pack happens at `howdah_pack_finish` (the pack must be loaded to know its rules); an entry naming an unloaded pack is a queued warning, not an error (same leniency as stale overrides, same reason). **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** — `feat(core): packs.* exception selectors`.

### Task 8: Extension glue — MINIT loading, RINIT refusal, input filter, `--ri`

**Files:**
- Create: `crates/howdah-ext/src/packs.rs` (file reading, message draining, line draining helpers)
- Modify: `crates/howdah-ext/src/module.rs` (MINIT: after `howdah_init`, for each enabled id read `<dir>/<id>.toml` (≤ 1 MiB, else a message) and `howdah_pack_load`; `howdah_pack_finish`; drain messages to the SAPI error log once per process as `Howdah: pack "<id>" ...`. RINIT: after `main_script_exec_dir_check`, `pack_request_check()` with the same `path_translated` read; drain and write lines; on `HOWDAH_BLOCK` → `rfc1867::emit_and_bail(status, request_id)` outside the panic guard, exactly as the exec-dir check does. `--ri`: rows `Packs` and `Pack rules past review_by`.)
- Modify: `crates/howdah-ext/src/input_filter.rs` (call `howdah_inspect_value` when Layer 2 is active **or** `howdah_packs_want_values` is 1; pass `HTTP_*` keys to `howdah_pack_header_name` when `howdah_packs_want_header_names` is 1)
- Modify: `crates/howdah-ext/src/sink_filter.rs`, `ssrf_filter.rs` (unchanged calls; after each `howdah_sink_check*` drain `howdah_take_pack_log_line` and write each line)
- Modify: `crates/howdah-ext/src/rfc1867.rs` (`emit_and_bail` already clears request state; confirm the pack queue is drained before the bail so the pack line is written)

- [ ] **Step 1: Build** for `php5`, `php7`, `php8` features: `cargo build -p howdah-ext --features phpN --release` compiles clean; `cargo test -p howdah-ext` green (unit tests for the file-size guard and the message formatting).
- [ ] **Step 2: Smoke in one lab image** (`howdah-dev-php8.3`): a hand-written pack with one request rule, `[packs] enabled`, `php -d extension=... --ri howdah` shows the `Packs` row; a `php -S` request to the matching path under `block` returns 403 before the script's output.
- [ ] **Step 3: Commit** — `feat(ext): load packs at MINIT, refuse at RINIT, drain pack lines, --ri rows`.

### Task 9: The two packs and the CI vector test

**Files:**
- Create: `packs/noise/pack.toml`, `packs/virtual-patch/pack.toml` (spec §6, every rule with ≥ 1 positive and ≥ 2 negative vectors including the near misses in Review Focus), `packs/README.md` (what a pack is, the 404 caveat verbatim from spec §6.1, how to install, how to write one), `packs/CHANGELOG.md` (`## [2026.11.0]` unreleased)
- Create: `crates/howdah-core/tests/packs.rs`
- Create: `fuzz/fuzz_targets/pack_toml.rs` (`Pack::from_toml` on arbitrary bytes never panics); register in `fuzz/Cargo.toml`

**Interfaces:**
- `tests/packs.rs` reads `../../packs/*/pack.toml` relative to `CARGO_MANIFEST_DIR`, and asserts: parses; `run_pack_tests` empty; `lint_release` empty for `today = created`; rule names unique across packs and disjoint from `rule_catalog()` names and from every pack's `retired`; `Packs::compile` of all packs together succeeds; every `inspect.rs` benign string and every request shape in `lab/integration/corpus/` (method + path + field names) produces zero hits; no rule has `classes_any` unless a `# verified:` comment with an advisory URL precedes it.

- [ ] **Step 1: Write `tests/packs.rs` first**; run `cargo test -p howdah-core --test packs` → fails (no packs).
- [ ] **Step 2: Write the two pack files.** Rules and facets per spec §6.1 and §6.2; `created = 2026-11-03`, `review_by` ≤ 12 months out; `min_howdah = "1.6.0"`; `signing_key` left for Task 12.
- [ ] **Step 3: Run** `cargo test -p howdah-core --test packs` → pass; `cargo fuzz run pack_toml -- -runs=20000 -max_total_time=60` clean; add the target to the `fuzz-smoke` job in `ci.yml` (one new `run:` line; `ci.yml` is not on the do-not-edit list).
- [ ] **Step 4: Commit** — `feat(packs): noise and virtual-patch packs with vectors; CI vector test; pack_toml fuzz target`.

### Task 10: wasm export for the browser

**Files:**
- Modify: `crates/howdah-wasm/src/lib.rs` (`howdah_wasm_pack_validate(toml_ptr, toml_len) -> result_ptr`, JSON `{"ok":true,"pack":{"id","version","rules":[{"name","severity","action","enabled","position","refs","summary","review_by"}]},"failures":[]}` or `{"ok":false,"error":"<PackError>"}`; failures from `run_pack_tests` as `{"rule","index","expected"}`)
- Modify: `site/demo/howdah-wasm.js` (`validatePack(toml)` wrapper), `site/demo/verify.js` (round-trip test with a two-rule fixture)
- Test: `cargo test -p howdah-wasm`; `cd site && npm test`

- [ ] **Step 1: Failing tests** — `wasm::pack_validate_ok_and_failures`, `wasm::pack_validate_bad_toml_error`; the JS test.
- [ ] **Step 2: Run, verify fail. Step 3: Implement. Step 4: Run, verify pass** (`cargo build -p howdah-wasm --target wasm32-unknown-unknown --release` still builds with no imports).
- [ ] **Step 5: Commit** — `feat(wasm): howdah_wasm_pack_validate`.

### Task 11: `howdah-check pack`

**Files:**
- Modify: `tools/howdah-check` (`cmd_pack` with `list|install|verify|show|remove`; usage text; constants `PACK_BASE_URL=${HOWDAH_PACK_BASE_URL:-https://pkg.howdah.org/packs}`, `KEY_URL=${HOWDAH_KEY_URL:-https://howdah.org/key.asc}`, `PRIMARY_FPR=11521035C600F63831F825512087B8720997807B` (overridable by `HOWDAH_CHECK_PRIMARY_FPR` for tests only, printed as "TEST KEY" when overridden))
- Modify: `tools/howdah-check.test.sh` (fixtures under a temp dir served by `file://` URLs; a throwaway key from `packaging/repo/gen-throwaway-key.sh`)

**Behaviour to pin (spec §5.7):** verification requires a `VALIDSIG` status line whose fingerprint is `PRIMARY_FPR` (any subkey of it); manifest fields read with `sed` from the `[pack]` table only; `id` must equal the requested id; version range compared against every install from `discover` that loads Howdah (`php --ri howdah` → `Version`), `--php BIN` narrows to one, `--force` installs anyway with a warning naming the installs that will skip it; atomic write (`.tmp` then `mv`), `.prev` kept, `.asc` installed beside, mode 0644; diff against `.prev`: rules added, retired, recommended `action` changed; restart reminder; exit codes 0 installed, 3 unchanged, 1 failure, 2 usage; default channel `lts`, `--latest`, `--version V`; `list` reads `[packs] enabled`/`dir` from the first install's `howdah.config` by a lenient line scan, labelled best effort; `verify <file>` on a third-party file reports "not signed by the Howdah key"; nothing downloaded is ever executed.

- [ ] **Step 1: Write the failing shell tests**: `pack_install_verifies_and_installs`, `pack_install_rejects_tampered_byte`, `pack_install_rejects_wrong_id`, `pack_install_rejects_min_howdah_above_installed` (fake `php` stub reporting `Version => 1.5.0`), `pack_install_unchanged_exit_3`, `pack_install_prints_recommendation_diff`, `pack_verify_file_unsigned_by_howdah_key`, `pack_list_shows_installed_enabled_loaded`, `pack_remove`, `pack_usage_exit_2`.
- [ ] **Step 2: Run** `sh tools/howdah-check.test.sh` → the new tests fail.
- [ ] **Step 3: Implement** in POSIX sh (dash-clean; no arrays, no `[[`, no `local` beyond what the file already uses).
- [ ] **Step 4: Run, verify pass** (`sh tools/howdah-check.test.sh`; also `dash tools/howdah-check.test.sh` where dash exists).
- [ ] **Step 5: Commit** — `feat(howdah-check): pack install|verify|list|show|remove`.

### Task 12: Signing and publishing pipeline

**Files:**
- Create: `packaging/pack-sign.sh` (signs `packs/<id>/pack.toml` → `pack.toml.asc` with `HOWDAH_PACK_SIGNING_KEY` (subkey id, `!`-pinned), writes `latest`/`lts` pointer files and signs them, writes and signs `packs/index.toml`; verifies everything against `packaging/howdah-release-signing.asc` in a throwaway `GNUPGHOME` as `release.yml` does)
- Create: `packaging/repo/publish-packs-r2.sh` (rclone `copy`, never `sync`; `<id>/<version>/` first, then `index.toml`, then the pointers; `Cache-Control` long for versioned paths, `max-age=60` for pointers and index)
- Create: `.github/workflows/pack-release.yml` (on `pack-v*` tags; job `test`: `cargo test -p howdah-core --test packs`, `sh tools/howdah-check.test.sh`, the lab pack subset on 8.3; job `publish`: environment `pack-publish` (required reviewer), import `HOWDAH_GPG_PACK_SIGNING_KEY`, `pack-sign.sh`, clean-keyring verify, `publish-packs-r2.sh` with the existing R2 secrets, GitHub Release with the files attached)
- Modify: `packaging/repo/GO-LIVE.md` (new section: create the pack signing subkey offline under the primary (RSA 4096, sign-only, 2-year expiry), export only the subkey to the `pack-publish` Environment secret, refresh `howdah.org/key.asc` and `packaging/howdah-release-signing.asc` so they carry the new subkey, the R2 cache rule for `packs/`, the `lts` pointer policy)
- Modify: `packaging/howdah-release-signing.asc` (owner action: the refreshed public key; the plan task stops and asks the owner for it, then verifies the fingerprint)

- [ ] **Step 1: Dry run locally** with a throwaway key (`gen-throwaway-key.sh`): `HOWDAH_PACK_SIGNING_KEY=<throwaway> packaging/pack-sign.sh` produces the files; `gpg --verify` passes; `publish-packs-r2.sh --dry-run` prints the upload order.
- [ ] **Step 2: Owner step** (blocking, documented in GO-LIVE): the subkey and the Environment exist; the refreshed public key is committed; `curl -fsSL https://howdah.org/key.asc | gpg --show-keys --with-fingerprint` lists the new subkey.
- [ ] **Step 3: Commit** — `ci(packs): pack signing and R2 publish pipeline on pack-v* tags`.

### Task 13: Lab integration

**Files:**
- Create: `lab/integration/packs.sh` (host driver, same shape as `behavior.sh`), `lab/integration/packs_container.sh` (built-in server), `lab/integration/packs_fpm_container.sh` (real php-fpm via cgi-fcgi, as `exceptions.sh` does), `lab/integration/packs_apache_container.sh` (mod_php prefork, as `log_contract_apache_container.sh` does)

Checks, each printed `ok - ...` and failing loudly, run on PHP 5.6, 7.4 and 8.3 (fpm and Apache phases on 7.4 and 8.3): (a) both repo packs load, `--ri` shows `Packs => noise ... virtual-patch ...`; (b) default `detect`: a `POST` to a script placed at `vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (a harmless file that echoes a marker) returns 200 with the marker and one line `rule=phpunit_eval_stdin_script`, `layer=2`, `pack=noise`, `pack_version` set; (c) `[packs.noise.rules] phpunit_eval_stdin_script = "block"`: 403 before the script (marker absent), request id in body and line; under fpm and Apache too; a multipart POST to the same path with a Layer 1 field flood is refused by Layer 1 and writes no pack line, and the next request in the same worker behaves as (b); (d) the Bricks-shaped sink rule: an `eval` from a file under `wp-content/themes/bricks/` during a request to `/wp-json/bricks/v1/render_element` writes `cve_2024_25600_bricks_eval`, `layer=3`; the same `eval` during `/index.php` writes nothing; under `block` the `eval` returns NULL and the script continues; (e) a copy of `noise` with `min_howdah = "9.0.0"` enabled: not loaded, the SAPI error-log line, `--ri` says `NOT LOADED`, `Config status => ok`, Layer 1 still blocks a flood; (f) a per-rule `off` override and a `[[exceptions]] rule = "packs.noise.dotenv_probe"` with `uri_prefix` each silence that rule only; (g) `recommended` mode blocks a `block`-recommended rule and logs a `log`-recommended one; (h) privacy: the route string, the serialized payload and the eval code never appear in the log; (i) `howdah-check pack verify|install|list` against a `file://` tree signed with a throwaway key, `HOWDAH_CHECK_PRIMARY_FPR` set; (j) a config without `[packs]` writes no pack line for any of the above requests and `php --ri howdah` shows `Packs => none`.

- [ ] **Step 1: Write the scripts; run on 8.3** → iterate until green. **Step 2: Run on 5.6 and 7.4**; fpm and Apache phases on 7.4 and 8.3. Record the per-version results in the commit message.
- [ ] **Step 3: Commit** — `lab(packs): request/value/sink rules, RINIT refusal under fpm and Apache, load-failure path, howdah-check pack`.

### Task 14: Version, docs, site, changelog

**Files:**
- Modify: `Cargo.toml` (workspace version `1.6.0`), `CHANGELOG.md` (`## [1.6.0]` from `[Unreleased]`: packs, `[packs]`, `pack`/`pack_version` fields, `howdah-check pack`, the two rule ids, the two packs; the "does not block by default" sentence)
- Create: `docs/packs.md` (what a pack is; install, verify, enable, reload; the `[packs]` reference; the log line; writing a pack: the full grammar from spec §5.2; the 404 caveat; limitations from spec §7; the cron example with its paragraph; the release cadence and LTS policy; the claim the project makes and does not make)
- Modify: `docs/config.md` (`[packs]` section linking `packs.md`; `[rules]` paragraph lists `pack_request`/`pack_sink` as inert), `docs/log-schema.md` (done in Task 5; cross-link), `docs/exceptions.md` (`packs.*` selectors), `README.md` (one paragraph under the layers), `packaging/howdah.ini` (no change: no new directive; add a comment pointing at `[packs]`)
- Modify: `site/src/pages/docs/configuration.astro` (the `[packs]` section), `site/src/pages/docs/index.astro` (nav), create `site/src/pages/packs.astro` (the pack page: fetches `packs/index.toml` and the pack from `pkg.howdah.org` in the browser, validates with `howdah_wasm_pack_validate`, shows the rule table with severities, refs, review dates and the vector pass count; the claim text from spec §8 verbatim; works without JS as a static description with the install commands), `site/src/pages/config.astro` (the `[packs]` form section and the `pack_request`/`pack_sink` inert labels from Task 5), `site/scripts/check-external.mjs` allowlist for `pkg.howdah.org` fetches on the pack page only if the guard flags them (it flags third-party requests; `pkg.howdah.org` is first-party — confirm, do not weaken the guard)
- Modify: `docs/coverage.md` wording comes from `site/scripts/gen-coverage.mjs`; add a "Policy packs" paragraph to the generator's static text stating per-rule verification status from Task 13's results.

- [ ] **Step 1: Write the docs**; `cd site && npm run build && npm test` green; `node scripts/check-external.mjs dist` green.
- [ ] **Step 2: Full verification**: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `sh tools/howdah-check.test.sh`, `sh packaging/layouts.test.sh`, `cd site && npm test`; paste the counts into the PR.
- [ ] **Step 3: Commit** — `docs,site: policy packs (1.6.0): docs/packs.md, [packs] reference, pack page, changelog`.

## Self-Review

- **Spec coverage.** §5.1 ids → Task 5. §5.2 grammar, bounds, validator, comparison rules → Tasks 1–2. §5.3 three positions, latching, RINIT refusal, sink arming, value rules independent of `[inspect]` → Tasks 2, 6, 8. §5.4 config and resolution, warning-not-error → Task 4 (+ Task 7 for pack-named exceptions). §5.5 loading, failure path, `--ri` → Tasks 6, 8. §5.6 line and exceptions → Tasks 5, 7. §5.7 files, key, CLI, no auto-update → Tasks 11, 12, 14 (cron text in `docs/packs.md`). §5.8 editor and `--ri` → Tasks 8, 14. §5.9 cadence, LTS, permanent names, `review_by` → Tasks 3 (lint), 9 (`retired`), 12 (pointers), 14 (policy text). §5.10 testing → Tasks 3, 9, 10, 11, 13. §6 packs → Task 9. §7, §8 → Task 14. §10 rulings 1–17 are each pinned above (dependency in Global Constraints; 2–4, 11 in Tasks 6 and 8; 5, 12–17 in Tasks 1–2 and 9; 6–7 in Task 11; 8 in Task 10; 9 nothing to build; 10 documented in Task 14).
- **Step scan.** Every test step names tests and assertions; every code step names the file, signature and pinned values; no step says "handle edge cases".
- **Type consistency.** `PackHit`, `PackRef`, `RequestFacts`, `RequestState`, `Packs::{compile, eval_value, eval_request, eval_sink, note_var, note_header, wants_values, wants_sink, wants_header_names, find}` are defined in Task 2 and used by those names in Tasks 3, 6, 7. `PacksConfig::resolve` (Task 4) is used in Task 6. `PackLine` (Task 5) is used in Task 6. `Pack::from_toml`, `compatible_with`, `PackError` (Task 1) are used in Tasks 6, 9, 10.
- **Review Focus.** Each of the six lines names the task and test that pins it.
- **Proportion.** The plan is shorter than the spec and carries signatures, test names and values, not bodies.
