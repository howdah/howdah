# Howdah Layer 3 fast-follow (1.3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add phar:// guarding, SSRF egress guarding, and PHP 5.x include/eval guarding to Howdah's Layer 3, shipping as 1.3 — same flat-policy, log-first, mode-independent posture as 1.2.

**Architecture:** Pure-Rust policy in `howdah-core` (new `sinks/ssrf.rs` for URL/IP classification; `phar_allowed` + two `SinkId`s in `sinks.rs`); ABI-variant hooking in C shims (`phar_hook.c` wrapper-ops proxy; `ssrf_hook.c` function-table trampolines + curl handle-map + getaddrinfo; a 5.x `zend_compile_file`/`zend_compile_string` swap added to `sink_hook.c`); glue + per-request lifecycle in `howdah-ext`.

**Tech Stack:** Rust (no new deps — hand-rolled linear-time IP/URL parsing, wasm-safe), C (PHP internals, NTS, `#if PHP_VERSION_ID`), existing cargo-feature build (php5/php7/php8).

**Spec:** `docs/superpowers/specs/2026-10-24-howdah-layer3-fast-follow-design.md` (read it — tasks argue from it).

## Global Constraints

- Defensive only; NO overclaiming — every coverage claim backed by a test or stated honestly as a limitation.
- Log-first: new sinks inherit `sinks.mode` default `detect`, EXCEPT `ssrf` defaults `off` (DNS-latency opt-in). A global `howdah.mode=block` NEVER arms a sink. All new rules `Severity::Standard`.
- Argument NEVER logged: no phar path; no full URL/userinfo/path/query. SSRF logs scheme+host+port+matching-IP+reserved-class only; phar logs sink+action only.
- No new php.ini directives — new config lives in `[sinks.phar]` / `[sinks.ssrf]` TOML subsections.
- No new runtime deps in `howdah-core`; no regex; all checks linear-time/bounded; wasm-safe (NO std::net / DNS in core — resolution is extension-side only).
- `catch_unwind` fail-open on every core check; null-ctx guarded. A Layer-3 bug must never break a working PHP call.
- PHP 5.4–8.5, NTS, FPM/Apache-prefork/CGI. C hooking stays in shims behind `#if PHP_VERSION_ID`.
- Tests/fixtures: harmless shape only — a benign phar with an inert tracer-object metadata, a loopback/decimal-encoded URL. NEVER a runnable exploit/gadget.
- Commit trailer `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

## Review Focus

- **Literal-IP decode bypasses** (ssrf.rs): decimal dword `2130706433`, octal `0177.0.0.1`, hex `0x7f000001`, short `127.1`, `0`→`0.0.0.0`, bracketed IPv6 — each must classify as its real reserved address, mirroring glibc `inet_aton`. *(Task 1 tests.)*
- **IPv4-mapped / NAT64 IPv6** (`::ffff:127.0.0.1`, `64:ff9b::7f00:1`) unwrapped to v4 and re-classified. *(Task 1 tests.)*
- **Scheme gate**: a local path (`fopen("/etc/passwd")`) is NEVER resolved or flagged — hot-path + false-positive guard. *(Task 1 `parse_host` + Task 6 trampoline + Task 9 lab.)*
- **Privacy**: full URL / userinfo / query / phar path never reach the log. *(Task 4 ffi tests + Task 9 lab grep-absent assertions.)*
- **5.x neutralize safety**: `require` block does NOT fatal; computed-operand include block safe; eval block continues. *(Task 7 + Task 9 lab on 5.6.)*
- **phar neutralize safety**: denied access raises normal warning, script continues, unrelated fs ops unaffected, no crash on 5.6/7.4/8.3. *(Task 5 + Task 9 lab.)*
- **Handle-map lifecycle**: freed at RSHUTDOWN; reused resource/object ids don't serve a stale URL. *(Task 8 + a host test.)*
- **Fail-open**: panic in any core check → allow+chain. *(Task 4 tests.)*

---

### Task 1: `sinks/ssrf.rs` — URL/host parse, literal-IP decode, reserved classification

**Files:**
- Create: `crates/howdah-core/src/sinks/ssrf.rs`
- Modify: `crates/howdah-core/src/sinks.rs` (add `pub mod ssrf;` — convert `sinks.rs` to `sinks/mod.rs` OR add a sibling module per the crate's module style; keep existing `sinks.rs` contents)
- Test: inline `#[cfg(test)]` in `ssrf.rs`

**Interfaces:**
- Produces:
  - `pub struct Host { pub scheme: Option<Scheme>, pub name: Vec<u8>, pub port: Option<u16> }` where `name` is the raw host with userinfo stripped and IPv6 brackets removed.
  - `pub fn parse_host(input: &[u8]) -> Option<Host>` — accepts a URL (`scheme://[user:pw@]host[:port][/...]`) or a bare `host[:port]`. Returns `None` for non-network schemes and for inputs that are clearly local filesystem paths (leading `/`, `./`, `../`, or a `scheme` not in the network set). Network schemes: http,https,ftp,ftps,tcp,udp,ssl,tls,gopher.
  - `pub enum ReservedClass { Loopback, Unspecified, Rfc1918, Cgnat, LinkLocal, Metadata, UniqueLocal, Benchmarking }` (+ `pub fn as_str(&self)->&'static str`).
  - `pub fn decode_literal_ip(host: &[u8]) -> Option<IpRepr>` where `IpRepr` is `V4([u8;4])`/`V6([u8;16])` — mirrors glibc inet_aton (dotted, dword, octal `0`-prefix, hex `0x`, short forms) + bracketed/plain IPv6.
  - `pub fn classify_ip(ip: IpRepr) -> Option<ReservedClass>` — IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::/96`) are unwrapped to v4 and re-classified; metadata (169.254.169.254 and the AWS IMDSv6 addr) wins over the broader link-local label.
  - `pub fn host_allowed(host: &[u8], resolved: &[IpRepr], allow: &[String]) -> bool` — allow entry matches a hostname (exact, case-insensitive), a literal IP, or a CIDR (`a.b.c.d/n`, `v6/n`) containing any resolved IP or the decoded literal.

- [ ] **Step 1: Write failing tests** — the adversarial matrix (Review Focus lines 1–2) as `#[test]`s: `decode_dword`, `decode_octal_hex`, `decode_short_form`, `ipv4_mapped_v6_unwraps`, `nat64_unwraps`, `metadata_beats_linklocal`, `parse_strips_userinfo`, `parse_rejects_local_path`, `parse_rejects_nonnetwork_scheme`, `classify_public_is_none`, `cidr_allow_matches`, `hostname_allow_ci`. Assert exact `ReservedClass` per input.
- [ ] **Step 2: Run, verify they fail** — `cargo test -p howdah-core ssrf::`.
- [ ] **Step 3: Implement** `parse_host`, `decode_literal_ip`, `classify_ip`, `host_allowed`, all linear-time, no deps, no std::net types for classification (operate on raw bytes/arrays). Minimal hand-rolled CIDR match.
- [ ] **Step 4: Run tests, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): ssrf URL/IP classification engine`).

### Task 2: `SinkId::{Phar,Ssrf}`, `phar_allowed`, new `RuleId`s

**Files:**
- Modify: `crates/howdah-core/src/sinks.rs` (add `Phar`,`Ssrf` to `SinkId`; `pub fn phar_allowed(path:&[u8], allow_paths:&[String])->bool` reusing the existing `normalize`/prefix logic used by `include_allowed`)
- Modify: `crates/howdah-core/src/limits.rs` (add `RuleId::{PharSink,SsrfSink}`, both `Severity::Standard`; wire any exhaustive matches / serde names `phar`,`ssrf`)
- Test: inline tests

**Interfaces:**
- Consumes: Task 1's module existing.
- Produces: `SinkId::Phar`, `SinkId::Ssrf`; `phar_allowed`; `RuleId::PharSink`, `RuleId::SsrfSink`.

- [ ] **Step 1: Failing tests** — `phar_allowed_prefix` (under allow_paths true; traversal-escape false; empty allow false), and a `limits` test asserting `RuleId::PharSink`/`SsrfSink` severity is `Standard` and their serde string round-trips.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, verify pass** (plus the whole `-p howdah-core` suite still green — exhaustive matches updated).
- [ ] **Step 5: Commit** (`feat(core): phar/ssrf SinkIds + Standard RuleIds`).

### Task 3: config — `PharConfig`, `SsrfConfig`, wire into `SinkConfig`

**Files:**
- Modify: `crates/howdah-core/src/config.rs`
- Test: inline tests in `config.rs`

**Interfaces:**
- Consumes: Task 2 `SinkId`.
- Produces: `PharConfig { mode: Option<Mode>, allow_paths: Vec<String> }` (Default: `mode:None` → inherits, `allow_paths:[]`); `SsrfConfig { mode: Option<Mode>, allow_hosts: Vec<String> }` (Default: `mode: Some(Mode::Off)`, `allow_hosts:[]`); both added to `SinkConfig` with `#[serde(default)]`; `effective_mode` extended for `Phar`/`Ssrf`.

- [ ] **Step 1: Failing tests** — `phar_defaults_detect_inherit` (`effective_mode(Phar,Detect)==Detect`), `ssrf_defaults_off` (`effective_mode(Ssrf,Detect)==Off`), `ssrf_enable_detect` (`[sinks.ssrf] mode="detect"` → Detect), `global_block_does_not_arm_phar`, `ssrf_allow_hosts_parse`, `phar_allow_paths_parse`, `sinks_phar_ssrf_unknown_key_rejected`. Validate an invalid CIDR in `allow_hosts` is rejected with a clear error.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** the structs, `Default`s, `effective_mode` arms, and `from_toml` validation of `allow_hosts` entries (hostname | IP | CIDR) via Task 1 helpers.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): [sinks.phar]/[sinks.ssrf] config`).

### Task 4: FFI — `howdah_sink_check_phar` / `_ssrf`, privacy log line, header

**Files:**
- Modify: `crates/howdah-core/src/ffi.rs`
- Modify: `crates/howdah-core/howdah_core.h`
- Test: inline FFI tests in `ffi.rs` (through the C ABI, as existing sink FFI tests do)

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces (C ABI):
  - consts `HOWDAH_SINK_PHAR=4`, `HOWDAH_SINK_SSRF=5`.
  - `howdah_sink_check_phar(ctx, path_ptr, path_len) -> i32` (0 allow / 1 log / 2 block) — resolves `effective_mode(Phar)`, checks `phar_allowed`, stashes a sink-log line `{"rule":"phar","action":...}` with NO path.
  - `howdah_sink_check_ssrf(ctx, scheme_ptr/len, host_ptr/len, port, ips_ptr, ips_len, ip_stride) -> i32` — `ips` is a packed buffer of resolved IPs (family tag + bytes); classifies the decoded literal host AND every resolved IP; `host_allowed` short-circuits to allow; stashes `{"rule":"ssrf","action":...,"host":...,"port":...,"ip":...,"class":...}` — scheme/host/port/matching-IP/class ONLY.
  - reuses the existing `sink_log` slot + `howdah_take_sink_log_line`.

- [ ] **Step 1: Failing tests** — `phar_block_no_path_in_log`, `ssrf_loopback_blocks_when_block`, `ssrf_off_allows_and_no_log`, `ssrf_allow_host_allows`, `ssrf_log_has_class_not_url` (assert the log line contains `"class":"loopback"` and the host but NOT a path/query/userinfo), `panic_in_check_fails_open` (feed input that would panic a naive parser → returns allow), `null_ctx_guarded`.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** both entries with `catch_unwind` fail-open (`unwrap_or(HOWDAH_ALLOW)`), null-ctx guard, and the privacy-filtered JSON line. Update `howdah_core.h` with matching decls + consts.
- [ ] **Step 4: Run, verify pass.**
- [ ] **Step 5: Commit** (`feat(core): phar/ssrf FFI checks, privacy-filtered log`).

### Task 5: `phar_hook.c` — wrapper-ops proxy

**Files:**
- Create: `crates/howdah-sys/phar_hook.c`
- Modify: `crates/howdah-sys/build.rs` (compile it), `crates/howdah-sys/src/lib.rs` (declare `howdah_install_phar_hook(cb)` + the `HowdahSinkDecide`-style type if not shared)
- Test: via Task 9 lab (C has no unit harness here); a build check per feature.

**Interfaces:**
- Consumes: the decide-callback type (sink id + name + arg ptr/len → i32), shared with `sink_hook.c`.
- Produces: `void howdah_install_phar_hook(howdah_sink_decide_t cb)`.

- [ ] **Step 1:** Implement per design §5.1: at MINIT find `phar` in `php_stream_get_url_stream_wrappers_hash_global()` (`zend_hash_find`/`zend_hash_str_find_ptr` by version), `memcpy` wrapper+ops into statics, override `stream_opener`/`url_stat`/`dir_opener`/`unlink`/`rename`/`stream_mkdir`/`stream_rmdir`, re-register. Each proxy op reads the URL, calls `cb(HOWDAH_SINK_PHAR,"phar",url,len)`; on BLOCK return the missing-file sentinel (NULL / -1 / 0) per op; else chain to the saved original. All ABI diffs behind `#if PHP_VERSION_ID` (`char*`/`const char*`, `char**`/`zend_string**` opened_path, TSRMLS). Guard: if phar not registered, no-op.
- [ ] **Step 2:** `cargo build -p howdah-ext --features php5|php7|php8` compiles clean (3 features).
- [ ] **Step 3: Commit** (`feat(sys): phar wrapper-ops proxy hook`).

### Task 6: `ssrf_hook.c` — URL-sink + curl trampolines, handle map, getaddrinfo

**Files:**
- Create: `crates/howdah-sys/ssrf_hook.c`
- Modify: `crates/howdah-sys/build.rs`, `crates/howdah-sys/src/lib.rs` (declare `howdah_install_ssrf_hooks(cb)`, `howdah_ssrf_request_reset()`)

**Interfaces:**
- Produces: `void howdah_install_ssrf_hooks(howdah_ssrf_decide_t cb)` where the ssrf decide callback carries (scheme,host,port, resolved-ip buffer); and `void howdah_ssrf_request_reset(void)` to clear the per-request handle map + resolution cache (called at RSHUTDOWN by the ext).

- [ ] **Step 1:** Implement per design §5.3: generalize the arg-read macro to `ARG(n)`. Trampolines for `file_get_contents`,`fopen`,`get_headers`,`fsockopen`(host arg1, port arg2),`stream_socket_client`. curl: `curl_init`/`curl_setopt`(watch CURLOPT_URL=10002)/`curl_setopt_array`/`curl_copy_handle`/`curl_reset`/`curl_close` maintain a handle→URL map keyed by resource id (5/7) / object handle (8); `curl_exec` looks up the URL. Scheme-gate in C (cheap) BEFORE resolving; resolve host via `getaddrinfo` ONLY when cb signals ssrf is armed (pass a pre-check, or have the ext gate by not installing resolution when off — simplest: the cb returns a "needs-resolve?" fast path; implement as: C calls `cb` with an empty ip list first to learn mode; if armed, getaddrinfo then re-calls with ips). Cache resolutions per host for the request. BLOCK = `RETVAL_FALSE; return;`.
- [ ] **Step 2:** 3-feature build clean.
- [ ] **Step 3: Commit** (`feat(sys): ssrf trampolines + curl handle map + resolver`).

### Task 7: `sink_hook.c` — PHP 5.x `zend_compile_file`/`zend_compile_string` swap

**Files:**
- Modify: `crates/howdah-sys/sink_hook.c` (add a `#if PHP_VERSION_ID < 70000` block)

**Interfaces:**
- Consumes: existing `howdah_g_decide` + `howdah_install_sink_hooks`.
- Produces: on 5.x, include/eval now routed through `howdah_g_decide` (sink ids INCLUDE/EVAL) via compile-pointer swap.

- [ ] **Step 1:** Implement per design §5.4: save `zend_compile_file`/`zend_compile_string`, install swaps in `howdah_install_sink_hooks` under `#if PHP_VERSION_ID < 70000`. compile_file reads `file_handle->filename`, calls decide(INCLUDE); on BLOCK return NULL (no compile); else chain. compile_string reads the source zval, decide(EVAL); on BLOCK return NULL; else chain. Preserve TSRMLS. Document the opcache first-compile-only caveat in a comment.
- [ ] **Step 2:** php5 build clean; php7/php8 builds unchanged (block compiled out).
- [ ] **Step 3: Commit** (`feat(sys): PHP 5.x include/eval via compile-pointer swap`).

### Task 8: ext glue — `phar_filter.rs`, `ssrf_filter.rs`, MINIT/RSHUTDOWN

**Files:**
- Create: `crates/howdah-ext/src/phar_filter.rs`, `crates/howdah-ext/src/ssrf_filter.rs`
- Modify: `crates/howdah-ext/src/module.rs` (install both at MINIT; `howdah_ssrf_request_reset` at RSHUTDOWN), `crates/howdah-ext/src/lib.rs` (mod decls)

**Interfaces:**
- Consumes: Task 4 FFI, Task 5–7 shim installers.
- Produces: decide callbacks matching the C callback types; `phar` routes to `howdah_sink_check_phar`; `ssrf` owns the per-request handle map/resolution-cache lifecycle and routes to `howdah_sink_check_ssrf`, taking+writing the log line and freeing with `howdah_free_str`.

- [ ] **Step 1: Failing test** — a host-side Rust test of the ssrf decide callback: catch_unwind fail-open on null ctx returns ALLOW; a stale-handle map entry is not served after reset.
- [ ] **Step 2: Run, verify fail.**
- [ ] **Step 3: Implement** both filters (mirror `sink_filter.rs`: `catch_unwind` → `unwrap_or(HOWDAH_ALLOW)`, null-CTX guard, `maybe_begin`, call FFI, take+write line, `howdah_free_str`), install at MINIT, reset at RSHUTDOWN.
- [ ] **Step 4: Run, verify pass** + `cargo build` all 3 features.
- [ ] **Step 5: Commit** (`feat(ext): phar/ssrf glue + per-request lifecycle`).

### Task 9: lab integration — `sinks_fastfollow.sh` (+ container half)

**Files:**
- Create: `lab/integration/sinks_fastfollow.sh`, `lab/integration/sinks_fastfollow_container.sh`
- Create fixtures under `lab/integration/corpus/` as needed (benign phar builder script; inert tracer metadata class)

**Interfaces:** Consumes the built `howdah.so`. Mirrors `sinks.sh`/`sinks_container.sh` structure (feature arg php5|php7|php8).

- [ ] **Step 1:** Assertions: (phar) detect logs phar:// access + path NOT in log; block neutralizes + script continues + unrelated fs ok; per-version — 5.6/7.4 prove the metadata tracer fires without guard and is denied with guard, 8.3 proves detection/denial only (documented). (ssrf) off → silent + request proceeds; detect → loopback/decimal URL logged with `"class":"loopback"` and URL NOT in log; block → false + continues; allow_hosts → silent; local path `fopen('/etc/passwd')` never logged. (5.x include/eval) on php5 NOW ACTIVE: include outside allow_paths detect logs + runs; block neutralizes + continues; `require` block does not fatal; eval block continues; computed operand safe. Replace the old 5.x "dormant" assertion.
- [ ] **Step 2:** Run on `howdah-dev-php5.6`, `howdah-dev-php7.4`, `howdah-dev-php8.3` → PASS.
- [ ] **Step 3: Commit** (`test(lab): phar/ssrf/5.x include-eval integration`).

### Task 10: docs, config sample, howdah-check, coverage matrix, CHANGELOG, version, blog

**Files:**
- Modify: `docs/config.md`, `packaging/howdah.ini`, `tools/howdah-check`, `README.md`, `CHANGELOG.md` (`[1.3.0]`), `site/src/lib/site.ts` (`VERSION='1.3.0'`), `site/src/pages/index.astro` (coverage matrix: add phar/SSRF rows + 5.x include/eval now-active cell + limitation footnotes), `site/src/pages/{configuration,coverage}.astro`
- Create: `site/src/pages/blog/howdah-1-3.astro` + blog index entry

- [ ] **Step 1:** Document `[sinks.phar]`/`[sinks.ssrf]` (defaults, allowlists, the ssrf-off-by-default + DNS-latency note). Coverage matrix states real per-version exposure + EVERY limitation from design §7 (8.x phar detection-only; direct new Phar gap; 5.x opcache; SSRF TOCTOU/redirects/multi). CHANGELOG `[1.3.0]`. Bump VERSION. Blog "Howdah 1.3" in the honest 1.1/1.2 voice (what it catches, what it does NOT).
- [ ] **Step 2:** `npm --prefix site run build` succeeds; `git restore docs/coverage.md` after (build wipes the generated file — never commit it).
- [ ] **Step 3: Commit** (`docs+site: Howdah 1.3 phar/SSRF/5.x include-eval`).

---

## Self-review notes
- Spec coverage: phar (T2,T5,T8), SSRF (T1,T3,T4,T6,T8), 5.x include/eval (T7); config (T3), FFI (T4), lab (T9), docs/site (T10) — all design sections mapped.
- Type consistency: `SinkId::{Phar,Ssrf}` (T2) used by T3/T4; callback types shared between T5/T6/T8; `HOWDAH_SINK_PHAR=4`/`SSRF=5` defined T4, used T5/T6/T8.
- Review Focus: every line mapped to a task's tests above.
- Rebase note: T2 (limits.rs) and T4 (ffi.rs, howdah_core.h) overlap the peer's `fix-multipart-count-wedge`; both append-only. Hold PR until that merges, rebase, resolve trivially.
