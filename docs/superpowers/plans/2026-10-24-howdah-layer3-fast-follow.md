# Howdah Layer 3 fast-follow (1.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add phar:// guarding, SSRF egress guarding, and PHP 5.x include/eval guarding to Howdah's Layer 3, shipping as 1.3 — same flat-policy, log-first, mode-independent posture as 1.2.

**Architecture:** Pure-Rust policy in `howdah-core` (new `sinks/ssrf.rs` submodule for URL/IP classification; `phar_allowed` + two `SinkId`s in `sinks.rs`); ABI-variant hooking in C shims (`phar_hook.c` wrapper-ops proxy; `ssrf_hook.c` function-table trampolines + curl handle-map + getaddrinfo; a 5.x `zend_compile_file`/`zend_compile_string` swap added to `sink_hook.c`); glue + per-request lifecycle in `howdah-ext`.

**Tech Stack:** Rust (no new deps — hand-rolled linear-time IP/URL parsing, wasm-safe), C (PHP internals, NTS, `#if PHP_VERSION_ID`), existing cargo-feature build (php5/php7/php8).

**Spec:** `docs/superpowers/specs/2026-10-24-howdah-layer3-fast-follow-design.md` (read it + its "Builder-check resolutions" section — the tasks below are authoritative where they refine it).

## Global Constraints

- Defensive only; NO overclaiming — every coverage claim backed by a test or stated honestly as a limitation.
- Log-first: `include`/`eval` inherit `sinks.mode` default `detect`. **`phar` AND `ssrf` default `off`** (opt-in: phar to avoid noisy logs on phar-using apps; ssrf for DNS latency). A global `howdah.mode=block` NEVER arms a sink. All new rules `Severity::Standard`.
- Argument NEVER logged: no phar path; no full URL/userinfo/path/query. SSRF logs (in the existing `reason` field) `host`+`port`+matching `ip`+reserved `class` only; phar logs rule+action only.
- No new php.ini directives — new config lives in `[sinks.phar]` / `[sinks.ssrf]` TOML subsections.
- **Do NOT change the Layer-1 `log_line` JSON schema** (ts/request_id/rule/action/client_ip/method/uri/reason) — it would conflict with the peer `fix-multipart-count-wedge` rebase. SSRF detail goes in `reason`.
- No new runtime deps in `howdah-core`; no regex; all checks linear-time/bounded; wasm-safe (NO std::net / DNS in core — resolution is extension-side `getaddrinfo` only; core works on raw IP bytes).
- `catch_unwind` fail-open on every core check; null-ctx guarded. A Layer-3 bug must never break a working PHP call.
- PHP 5.4–8.5, NTS, FPM/Apache-prefork/CGI. C hooking stays in shims behind `#if PHP_VERSION_ID`.
- **Hook install order:** phar + ssrf hooks install at a **first-RINIT process-once guard** (after all MINITs — curl/phar are shared extensions that load AFTER howdah on Debian/Ondřej at equal priority 20), and **only when that sink is armed** (config is process-static, read at MINIT). The 5.x compile-swap installs at MINIT (global pointers always present), gated on include/eval armed. The 1.2 MINIT sink hooks are unchanged.
- Tests/fixtures: harmless shape only — a benign phar with an inert tracer-object metadata, a loopback/decimal-encoded URL. NEVER a runnable exploit/gadget.
- Commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Literal-IP decode bypasses** (ssrf.rs): decimal dword `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, short `127.1`, `0`→`0.0.0.0`, bracketed IPv6 — each classifies as its real reserved address, mirroring glibc `inet_aton`. *(Task 1 tests.)*
- **IPv4-mapped / NAT64 IPv6** (`::ffff:127.0.0.1`, `64:ff9b::7f00:1`) unwrapped to v4 and re-classified. *(Task 1 tests.)*
- **Scheme gate / HostForm**: `fopen("/etc/passwd")` and `fopen("config.php")` (SchemeRequired form) are NEVER parsed as hosts/resolved; `unix://` is skipped; a schemeless curl host (`127.0.0.1/admin`, BareHostOk form) IS parsed. *(Task 1 `parse_host(input, HostForm)` tests + Task 6 + Task 9.)*
- **5.x compile-swap scoping**: the main script, `auto_prepend_file`, `create_function`, `assert`-strings must produce NO events — only real include/require(_once)/eval do. *(Task 7 + Task 9 on 5.6.)*
- **Privacy**: full URL / userinfo / query / phar path never reach the log; assert `reason` has `class=…`+host but not path/query/userinfo (note: the `uri` field legitimately carries the inbound request URI, not the outbound URL). *(Task 4 + Task 9 grep-absent.)*
- **5.x neutralize safety**: `require`/`require_once` block does NOT fatal; computed-operand include block safe; eval block continues. *(Task 7 + Task 9 on 5.6.)*
- **phar neutralize safety**: denied access raises a normal warning, script continues, unrelated fs ops unaffected, no crash on 5.4/5.6/7.4/8.3/8.5. *(Task 5 + Task 9.)*
- **Handle-map lifecycle (lab, not Rust — map lives in C)**: `curl_init(loopback)`→`curl_close`→`curl_init()` (no URL)→`curl_exec` must NOT serve the old URL; a second request in the same worker must not see request one's map. *(Task 9.)*
- **Fail-open**: panic in any core check → allow+chain; null ctx → allow / armed()→0. *(Task 4 tests.)*

---

### Task 1: `sinks/ssrf.rs` — URL/host parse, literal-IP decode, reserved classification

**Files:**
- Create: `crates/howdah-core/src/sinks/ssrf.rs`
- Modify: `crates/howdah-core/src/sinks.rs` (add `pub mod ssrf;` — edition-2021 non-mod.rs submodule: keep `sinks.rs` as-is, add a `sinks/` dir beside it; do NOT convert to `sinks/mod.rs`)
- Test: inline `#[cfg(test)]` in `ssrf.rs`

**Interfaces:**
- Produces (all pure, no deps, no `std::net`, linear-time):
  - `pub enum Scheme { Http, Https, Ftp, Ftps, Tcp, Udp, Ssl, Tls, Gopher }`
  - `pub enum HostForm { SchemeRequired, BareHostOk }`
  - `pub struct Host { pub scheme: Option<Scheme>, pub name: Vec<u8>, pub port: Option<u16> }` — `name` = host with userinfo stripped, IPv6 brackets + zone-id (`%…`) removed, trailing dot removed, lowercased.
  - `pub fn parse_host(input: &[u8], form: HostForm) -> Option<Host>` — URL (`scheme://[user:pw@]host[:port]/…`) or, for `BareHostOk`, a bare `host[:port]`. Returns `None` for: a leading `/`, `./`, `../` path; a `unix://`/`file://`/non-network scheme; and (for `SchemeRequired`) any input without a recognized network scheme.
  - `pub enum IpRepr { V4([u8;4]), V6([u8;16]) }`
  - `pub fn decode_literal_ip(host: &[u8]) -> Option<IpRepr>` — glibc `inet_aton` forms (dotted, decimal dword, `0`-octal, `0x`-hex, short `a.b`/`a.b.c`) + plain/bracketed IPv6.
  - `pub enum ReservedClass { Loopback, Unspecified, Rfc1918, Cgnat, LinkLocal, Metadata, UniqueLocal, Benchmarking }` with `pub fn as_str(&self) -> &'static str` returning EXACTLY `loopback, unspecified, rfc1918, cgnat, link_local, metadata, unique_local, benchmarking`.
  - `pub fn classify_ip(ip: IpRepr) -> Option<ReservedClass>` — `::ffff:a.b.c.d` (IPv4-mapped) and `64:ff9b::/96` (NAT64) unwrap to v4 and re-classify; `169.254.169.254` and the AWS IMDSv6 addr classify `Metadata` (not the broader `LinkLocal`).
  - `pub fn host_allowed(host: &[u8], resolved: &[IpRepr], literal: Option<IpRepr>, allow: &[String]) -> bool` — allow entry matches a hostname (exact, ASCII-case-insensitive, NO wildcards), a literal IP, or a CIDR (`a.b.c.d/0..=32`, `v6/0..=128`) containing any of `resolved` or `literal`.
  - `pub fn valid_allow_entry(entry: &str) -> bool` — true iff `entry` is a well-formed `allow_hosts` entry: a non-empty, whitespace-free hostname, a literal IP, or a CIDR with an in-range prefix length (v4 `/0..=32`, v6 `/0..=128`). Task 3 uses this to validate `[sinks.ssrf] allow_hosts` at config-load time.

- [ ] **Step 1: Write failing tests** — Review-Focus lines 1–3 as `#[test]`s: `decode_dword`, `decode_octal_hex`, `decode_short_form`, `decode_zero_is_unspecified`, `ipv4_mapped_v6_unwraps`, `nat64_unwraps`, `metadata_beats_linklocal`, `classify_public_is_none`, `parse_strips_userinfo`, `parse_strips_zone_and_trailing_dot`, `parse_rejects_relative_filename_when_scheme_required`, `parse_accepts_schemeless_curl_host`, `parse_skips_unix_scheme`, `cidr_allow_matches`, `cidr_rejects_bad_prefixlen` (helper-level), `hostname_allow_ci_no_wildcard`, `reservedclass_as_str_pinned` (B9).
- [ ] **Step 2: Run, verify fail** — `cargo test -p howdah-core ssrf::`.
- [ ] **Step 3: Implement** the types + functions. Hand-rolled CIDR match on raw bytes. Note in a comment: resolved IPs are authoritative; literal decode is belt-and-braces (libcurl/musl parse differently).
- [ ] **Step 4: Run tests, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): ssrf URL/IP classification engine`).

### Task 2: `SinkId::{Phar,Ssrf}`, `phar_allowed`, `RuleId::{Phar,Ssrf}`, log rule-name

**Files:**
- Modify: `crates/howdah-core/src/sinks.rs` (add `Phar`,`Ssrf` to `SinkId`; `pub fn phar_allowed(url:&[u8], allow_paths:&[String])->bool`)
- Modify: `crates/howdah-core/src/limits.rs` (add `RuleId::Phar`, `RuleId::Ssrf` — variant names `Phar`/`Ssrf` so `rename_all="snake_case"` serde gives `phar`/`ssrf`, matching `Include`/`Eval`; both `Severity::Standard`)
- Modify: `crates/howdah-core/src/log.rs` (add `rule_name` arms for the two new `RuleId`s → `"phar"`,`"ssrf"`)
- Test: inline tests

**Interfaces:**
- Consumes: Task 1.
- Produces: `SinkId::{Phar,Ssrf}`; `phar_allowed`; `RuleId::{Phar,Ssrf}`.
- `phar_allowed` semantics (C5, pin exactly): strip an ASCII-case-insensitive `phar://` prefix; if the remainder is not absolute (`/…`) return false; lexically `normalize` (reuse `sinks.rs`'s existing `normalize`); the realpath-prefix compares against `allow_paths` up to and including the `.phar` archive segment; empty `allow_paths` → false (so every phar access is a hit in detect).

- [ ] **Step 1: Failing tests** — `phar_allowed_strips_scheme`, `phar_allowed_uppercase_scheme`, `phar_allowed_prefix_under_allow`, `phar_allowed_relative_false`, `phar_allowed_in_archive_dotdot_false`, `phar_allowed_empty_allow_false`; a `limits` test `phar_ssrf_rules_standard_and_serde` (severity Standard; serde `"phar"`/`"ssrf"` round-trip); a `log` test `rule_name_phar_ssrf`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** (update every exhaustive `match` on `SinkId`/`RuleId` the compiler flags).
- [ ] **Step 4: Run, verify pass** (whole `-p howdah-core` suite green).
- [ ] **Step 5: Commit** (`feat(core): phar/ssrf SinkIds + Standard RuleIds + log names`).

### Task 3: config — `PharConfig`, `SsrfConfig`, wire into `SinkConfig`

**Files:**
- Modify: `crates/howdah-core/src/config.rs`
- Test: inline tests

**Interfaces:**
- Consumes: Task 1 (CIDR/host validation helpers), Task 2 (`SinkId`).
- Produces: `PharConfig { mode: Option<Mode>, allow_paths: Vec<String> }` (Default: `mode: Some(Mode::Off)`, `allow_paths:[]`); `SsrfConfig { mode: Option<Mode>, allow_hosts: Vec<String> }` (Default: `mode: Some(Mode::Off)`, `allow_hosts:[]`); both added to `SinkConfig` + `effective_mode` arms for `Phar`/`Ssrf`.

- [ ] **Step 1: Failing tests** — `phar_defaults_off`, `ssrf_defaults_off`, `phar_enable_detect`, `ssrf_enable_block`, `sinks_block_arms_phar_but_not_ssrf` (B11: `[sinks] mode="block"` → `effective_mode(Phar,Detect)==Block` but `effective_mode(Ssrf,Detect)==Off` because ssrf's own default `Some(Off)` wins), `global_block_does_not_arm_phar`, `ssrf_allow_hosts_parse`, `phar_allow_paths_parse`, `ssrf_bad_cidr_rejected` (`/33`, `/129`, empty, whitespace), `sinks_phar_ssrf_unknown_key_rejected`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** structs, `Default`s, `effective_mode` arms, and `from_toml` validation of each `allow_hosts` entry as hostname | literal IP | CIDR via Task 1 helpers (reject bad prefix length, empty, whitespace; hostnames exact/no-wildcard).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): [sinks.phar]/[sinks.ssrf] config, both off by default`).

### Task 4: FFI — phar arm on `howdah_sink_check`, new `_ssrf` + `_ssrf_armed`, header

**Files:**
- Modify: `crates/howdah-core/src/ffi.rs` (APPEND new fns/consts after the existing entries, to minimize the peer rebase conflict)
- Regenerate (cbindgen, do NOT hand-edit): `crates/howdah-core/howdah_core.h` — it is cbindgen-generated (`crates/howdah-core/cbindgen.toml`; header says "do not edit"). The peer's merge fully regenerates it; after rebase, regenerate again so it carries both sides.
- Create: `crates/howdah-sys/howdah_sink.h` (hand-written shared `HOWDAH_SINK_*` + `HOWDAH_ACTION_BLOCK` defines for the three C shims; values MUST mirror `ffi.rs` — comment that. Separate from the cbindgen header, which lives in another crate.)
- Test: inline FFI tests (through the C ABI, as the existing sink FFI tests do)

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces (C ABI):
  - consts `HOWDAH_SINK_PHAR=4`, `HOWDAH_SINK_SSRF=5` (in `ffi.rs` AND the shared `howdah_sink.h`).
  - **phar reuses the existing** `howdah_sink_check(ctx, sink, name, name_len, arg, arg_len)` with a new `HOWDAH_SINK_PHAR` arm: resolves `effective_mode(Phar)`, calls `phar_allowed(arg, …)`, stashes `{"rule":"phar","action":…}` via the existing sink-log slot, NO path. (No new phar FFI entry.)
  - `howdah_sink_ssrf_armed(ctx) -> i32` — 1 iff `effective_mode(Ssrf,global) != Off`; null-ctx → 0; `catch_unwind` → 0. NEVER stashes a log line.
  - `howdah_sink_check_ssrf(ctx, scheme_ptr, scheme_len, host_ptr, host_len, port, ips_ptr, ips_count) -> i32` where `ips_ptr` is `ips_count` fixed **17-byte records** `[family: 4 or 6, then 16 address bytes]` (no stride param). Decodes the literal host AND classifies every record; `host_allowed` short-circuits to allow; stashes the hit in `reason` as `ssrf via <scheme/host>: host=<h> port=<p> ip=<matched> class=<class>` (rule `"ssrf"`) — scheme/host/port/matched-IP/class ONLY, never full URL/userinfo/path/query. Called AT MOST ONCE per intercepted call.

- [ ] **Step 1: Failing tests** — `phar_arm_block_no_path_in_log`, `ssrf_armed_reflects_mode`, `ssrf_armed_null_ctx_zero`, `ssrf_loopback_blocks_when_block`, `ssrf_literal_only_no_resolve` (ips_count=0, decimal host still classified), `ssrf_allow_host_allows`, `ssrf_reason_has_class_not_url` (reason contains `class=loopback` + host, NOT a path/query/`@`), `ssrf_resolve_failure_fails_open` (ips_count=0 + non-literal host → allow), `panic_in_check_fails_open`, `null_ctx_guarded`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** with `catch_unwind` fail-open (`unwrap_or(HOWDAH_ALLOW)` / armed→0), null-ctx guards, the `reason`-based privacy line. Add `pub const HOWDAH_SINK_PHAR/SSRF` to `ffi.rs` so cbindgen emits them; regenerate `howdah_core.h` via cbindgen; write the hand-held `howdah_sink.h` for the shims. Update the stale `howdah_sink_check` doc-comment about 5.x include/eval (B10).
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): phar arm + ssrf FFI (armed + check), privacy reason line`).

### Task 5: `phar_hook.c` — wrapper-ops proxy

**Files:**
- Create: `crates/howdah-sys/phar_hook.c`
- Modify: `crates/howdah-sys/build.rs` (`.file("phar_hook.c")` + `cargo:rerun-if-changed`), `crates/howdah-sys/src/lib.rs` (declare `howdah_install_phar_hook(cb)` taking the existing `HowdahSinkDecide` type)

**Interfaces:**
- Consumes: the existing `howdah_sink_decide_t` (sink id + name + arg ptr/len → i32); `#include "howdah_sink.h"`.
- Produces: `int howdah_install_phar_hook(howdah_sink_decide_t cb)` — returns 1 if the phar wrapper was found + proxied, 0 if phar is not registered (caller logs nothing; honest no-op).

- [ ] **Step 1:** Implement per design §5.1: find `phar` in `php_stream_get_url_stream_wrappers_hash_global()` (`zend_hash_find`/`zend_hash_str_find_ptr` by version); `memcpy` the `static const` wrapper AND its ops into our statics (patching in place SEGVs); override `stream_opener`/`url_stat`/`dir_opener`/`unlink`/`rename`/`stream_mkdir`/`stream_rmdir`; `php_unregister_url_stream_wrapper("phar")` + re-register ours. Each proxy op reads the URL, calls `cb(HOWDAH_SINK_PHAR,"phar",url,len)`; on `HOWDAH_ACTION_BLOCK` return the missing-file sentinel (NULL / -1 / 0) per op; else chain to the saved original. ABI diffs (`char*`/`const char*`, `char**`/`zend_string**` opened_path, TSRMLS, and `php_stream_wrapper_ops` layout across minors) behind `#if PHP_VERSION_ID`.
- [ ] **Step 2:** `cargo build -p howdah-ext --features php5|php7|php8` compiles clean (3 features).
- [ ] **Step 3: Commit** (`feat(sys): phar wrapper-ops proxy hook`).

### Task 6: `ssrf_hook.c` — URL-sink + curl trampolines, handle map, resolver

**Files:**
- Create: `crates/howdah-sys/ssrf_hook.c`
- Modify: `crates/howdah-sys/build.rs` (+ rerun-if-changed), `crates/howdah-sys/src/lib.rs` (declare `howdah_install_ssrf_hooks(decide, armed)` + `howdah_ssrf_request_reset()`)

**Interfaces:**
- Produces: `void howdah_install_ssrf_hooks(howdah_ssrf_decide_t decide, howdah_ssrf_armed_t armed)` and `void howdah_ssrf_request_reset(void)` (clears the C-owned per-request handle→URL map + per-host resolution cache; called at RSHUTDOWN). Callback types: `armed(void*ctx)->int`; `decide(void*ctx, scheme,scheme_len, host,host_len, port, ips,ips_count)->int` matching Task 4.

- [ ] **Step 1:** Implement per design §5.3 + C2/C3: generalize the arg macro to `ARG(n)`. Trampolines for `file_get_contents`,`fopen`,`get_headers` (SchemeRequired host), `fsockopen`,`pfsockopen`,`stream_socket_client` (BareHostOk host arg; skip `unix://`). curl: `curl_init`/`curl_setopt`(watch `CURLOPT_URL`=10002)/`curl_setopt_array`/`curl_copy_handle`/`curl_reset`/`curl_close` maintain a per-request handle→URL map keyed by resource id (5/7) / object handle (8); `curl_exec` looks up the URL (BareHostOk). **Per-call flow (C2 two-phase):** (1) `parse_host` the target in C (scheme-gate/HostForm); if `None`, chain. (2) call `armed(ctx)`; if 0, chain. (3) if the host is a literal IP, call `decide(…, ips=NULL, ips_count=0)`. (4) else consult the per-request per-host cache, else `getaddrinfo` (one lookup per distinct host per request; NO timeout — documented), fill 17-byte records, call `decide(…)` ONCE. (5) on resolve failure call `decide(…, ips_count=0)` (fails open). `HOWDAH_ACTION_BLOCK` → `RETVAL_FALSE; return;`.
- [ ] **Step 2:** 3-feature build clean.
- [ ] **Step 3: Commit** (`feat(sys): ssrf trampolines + curl handle map + resolver`).

### Task 7: `sink_hook.c` — PHP 5.x `zend_compile_file`/`zend_compile_string` swap (scoped)

**Files:**
- Modify: `crates/howdah-sys/sink_hook.c` (add a `#if PHP_VERSION_ID < 70000` block; update the header comment B10)

**Interfaces:**
- Consumes: existing `howdah_g_decide` + `howdah_install_sink_hooks`.
- Produces: on 5.x, include/eval routed through `howdah_g_decide` (INCLUDE/EVAL) via compile-pointer swap — **only for real include/eval**.

- [ ] **Step 1:** Implement per design §5.4 + C4 scoping: save+swap `zend_compile_file`/`zend_compile_string` in `howdah_install_sink_hooks` under `#if PHP_VERSION_ID < 70000`, gated on (`Include` or `Eval` armed — but since install is at MINIT and config is static, simplest: always swap on 5.x and let the per-call decide/mode gate; the scoping below is what prevents misfires). **Scope (verify the exact discriminator on 5.6 before relying on it):** `compile_file` acts only when `EG(current_execute_data) != NULL` (already executing, i.e. a runtime include — not the main script / `auto_prepend_file`) AND `type` ∈ `ZEND_INCLUDE|ZEND_REQUIRE|ZEND_INCLUDE_ONCE|ZEND_REQUIRE_ONCE`; `compile_string` acts only when the `filename` arg equals `"eval()'d code"` (so `create_function`, `assert`, `preg /e` are NOT treated as eval). Otherwise chain. `compile_file` reads `file_handle->filename`, decide(INCLUDE); BLOCK → return NULL (no compile; include→false, require does NOT fatal). `compile_string` reads the source zval, decide(EVAL); BLOCK → return NULL. Preserve TSRMLS. Comment the opcache first-compile-only caveat.
- [ ] **Step 2:** php5 build clean; php7/php8 builds unchanged (block compiled out).
- [ ] **Step 3: Commit** (`feat(sys): PHP 5.x include/eval via scoped compile-pointer swap`).

### Task 8: ext glue — `ssrf_filter.rs`, phar arm in `sink_filter.rs`, RINIT install, RSHUTDOWN reset

**Files:**
- Create: `crates/howdah-ext/src/ssrf_filter.rs` (decide + armed callbacks)
- Modify: `crates/howdah-ext/src/sink_filter.rs` (add the `HOWDAH_SINK_PHAR` dispatch arm → existing `howdah_sink_check`), `crates/howdah-ext/src/module.rs` (first-RINIT once-guard: install phar hook iff `effective_mode(Phar)!=Off`, install ssrf hooks iff `effective_mode(Ssrf)!=Off`; call `howdah_ssrf_request_reset()` at RSHUTDOWN), `crates/howdah-ext/src/lib.rs` (`mod ssrf_filter;`)

**Interfaces:**
- Consumes: Task 4 FFI, Task 5–7 installers.
- Produces: `ssrf_filter::{decide, armed}` matching the C callback types; `sink_filter::decide` gains a phar arm. The C shim owns the handle map/cache; the ext only triggers `howdah_ssrf_request_reset` at RSHUTDOWN.

- [ ] **Step 1: Failing test (host-testable only)** — in `ssrf_filter` (compiled under a `phpN` feature test, mirroring `sink_filter`'s existing test harness if present; otherwise assert via the FFI from Task 4): `armed` returns 0 on null ctx; `decide` fail-opens (returns ALLOW) on null ctx / panic. (Handle-map lifecycle is lab-tested in Task 9, NOT here — the map lives in C.)
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** `ssrf_filter` (mirror `sink_filter`: `catch_unwind`→`unwrap_or(HOWDAH_ALLOW)` / armed→0, null-CTX guard, `maybe_begin`, call FFI, take+write the sink-log line, `howdah_free_str`), the phar dispatch arm, the RINIT once-guard install (gated on armed), and the RSHUTDOWN reset.
- [ ] **Step 4: Run, verify pass** + `cargo build` all 3 features.
- [ ] **Step 5: Commit** (`feat(ext): ssrf glue + phar arm + RINIT-gated install + RSHUTDOWN reset`).

### Task 9: lab integration — `sinks_fastfollow.sh` (+ container half), 5 minors

**Files:**
- Create: `lab/integration/sinks_fastfollow.sh`, `lab/integration/sinks_fastfollow_container.sh`
- Create fixtures under `lab/integration/corpus/`: a benign phar builder (inert tracer-object metadata — harmless, carries no gadget)
- Modify: `lab/integration/sinks_container.sh` (remove/replace the stale "include/eval dormant on 5.x" block, lines ~80–90 — 5.x is now active)

**Interfaces:** Consumes the built `howdah.so`; mirrors `sinks.sh`/`sinks_container.sh` (feature arg php5|php7|php8). **Must load `phar` and `curl` as SHARED extensions** (not rely on built-ins) and run howdah with phar/curl loaded BEFORE it, to prove the first-RINIT install is order-independent.

- [ ] **Step 1:** Assertions:
  - **phar** (off by default → no events until enabled): detect logs a phar:// access with NO path in the log; block neutralizes + script continues + an unrelated fs op still works + no crash. Per version: 5.6/7.4 prove the tracer `__wakeup` fires WITHOUT the guard and is denied WITH block; 8.3 proves detection/denial only (documented, no deserialization claim). A `new Phar('/x.phar')` case asserts the documented direct-API gap (still fires without guard).
  - **ssrf** (off by default): off → silent + request proceeds; detect → a loopback URL and a decimal-encoded (`http://2130706433/`) URL each logged with `class=loopback` and the URL NOT in the log; block → `false` + script continues; `allow_hosts` → silent; `fopen('/etc/passwd')` and `fopen('config.php')` never resolved/logged; curl: `curl_init`+`curl_setopt(URL)`+`curl_exec` to loopback logged; **lifecycle**: `curl_init(loopback)`→`curl_close`→`curl_init()`(no URL)→`curl_exec` does NOT serve the old URL.
  - **5.x include/eval** (php5, NOW ACTIVE): include outside `allow_paths` detect logs + runs; block neutralizes + continues; `require`/`require_once` block does NOT fatal; `include_once` block case; eval block continues; computed operand (`$a.$b`) safe; **misfire guard**: the main script, an `auto_prepend_file`, and `create_function(...)` produce NO events.
- [ ] **Step 2:** Run on `howdah-dev-php5.4`, `5.6`, `7.4`, `8.3`, `8.5` → PASS (5.4/8.5 added to catch wrapper-struct layout breaks across minors). On a debug PHP build if available, note a leak check; otherwise record "leak review pending debug build" honestly.
- [ ] **Step 3: Commit** (`test(lab): phar/ssrf/5.x include-eval integration, 5 minors`).

### Task 10: docs, config sample, howdah-check, coverage matrix, CHANGELOG, version, blog

**Files:**
- Modify: `docs/config.md`, `packaging/howdah.ini`, `tools/howdah-check`, `README.md`, `CHANGELOG.md` (`[1.3.0]`), `site/src/lib/site.ts` (`VERSION='1.3.0'`), `site/src/pages/index.astro` (coverage matrix), `site/src/pages/{configuration,coverage}.astro`
- Create: `site/src/pages/blog/howdah-1-3.astro` + blog index entry

- [ ] **Step 1:** Document `[sinks.phar]`/`[sinks.ssrf]` (BOTH off by default; phar `allow_paths`; ssrf `allow_hosts`; the ssrf DNS-latency + no-timeout note; B11: `sinks.mode="block"` arms phar via inheritance but NOT ssrf). Coverage matrix + footnotes must state the REAL per-version exposure and EVERY limitation from design §7, specifically:
  - phar: **5.x/7.x** metadata-via-wrapper deserialization claim; **8.x detection/denial only** (no deserialization); direct-API gap names `new Phar`/`PharData`/`loadPhar`/`mapPhar`/`getMetadata`; `stream_wrapper_unregister`+`restore` untested; another ext re-registering phar / static builds = fail-open.
  - ssrf: best-effort resolve-at-check-time, NOT a connection-time boundary; bypasses = DNS rebinding, redirects to a new host, `curl_multi_*`, `CURLOPT_RESOLVE`/`CONNECT_TO`, non-string/absent `CURLOPT_URL`; NOT-hooked egress = `copy`/`file`/`readfile`/`SoapClient`/`DOMDocument::load*`/`simplexml_load_file`; blocked `fsockopen`/`stream_socket_client` leave `$errno`/`$errstr` unset; blocked `curl_exec` → `curl_errno 0`/empty `curl_error`; `getaddrinfo` no timeout.
  - 5.x include: compile-time inspection; **files served from a warm opcache are not re-inspected** (eval unaffected; 7.0+ opcode handler opcache-immune).
  - Provenance: "verified on PHP 5.4/5.6/7.4/8.3/8.5; other minors build and are expected but not independently verified." Debug-build leak review noted.
  - CHANGELOG `[1.3.0]`. Bump VERSION to 1.3.0. Blog "Howdah 1.3" in the honest 1.1/1.2 voice (what it catches AND what it explicitly does not).
- [ ] **Step 2:** `npm --prefix site run build` succeeds; then `git restore docs/coverage.md` (build wipes the generated file — never commit it).
- [ ] **Step 3: Commit** (`docs+site: Howdah 1.3 phar/SSRF/5.x include-eval`).

---

## Self-review notes
- Spec coverage: phar (T2,T4,T5,T8), SSRF (T1,T3,T4,T6,T8), 5.x include/eval (T7); config (T3), FFI (T4), lab (T9), docs/site (T10). `log.rs` now owned by T2. All design files mapped.
- Type consistency: `Scheme`/`HostForm`/`IpRepr`/`ReservedClass` defined T1, used T4; `SinkId::{Phar,Ssrf}` T2 → T3/T4; `RuleId::{Phar,Ssrf}` (serde `phar`/`ssrf`) T2; callbacks `howdah_ssrf_{decide,armed}_t` + `howdah_sink_decide_t` shared T4↔T5/T6/T8; `HOWDAH_SINK_PHAR=4`/`SSRF=5` in shared `howdah_sink.h` T4, used T5/T6/T8; 17-byte IP record ABI pinned T4=T6.
- Review Focus: every line mapped to a task's tests.
- Builder-check C1–C9 + B1–B12 all resolved inline (install model, phar-off default, phar via existing check, two-phase ssrf handshake, HostForm scheme gate, 5.x scoping, reason-field log, shared sink header, C-owned map + lab lifecycle test, version-provenance honesty).
- Rebase note: peer `fix/multipart-count-wedge` reverted its `limits.rs` change (NO conflict there) and `feeder.rs` is DELETED by it (I don't touch feeder.rs). Only real overlap is `ffi.rs` (append-only both sides — mine goes after the existing entries) and `howdah_core.h` (cbindgen-regenerated, not hand-merged). Do NOT touch the `log_line` schema. Hold PR until the peer's is on main; then rebase, regenerate `howdah_core.h`, re-run tests.
