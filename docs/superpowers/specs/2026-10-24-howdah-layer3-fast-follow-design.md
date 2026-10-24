# Howdah Layer 3 fast-follow — phar://, SSRF, PHP 5.x include/eval (design)

**Status:** design, owner pre-authorized (autonomous build on the 1.2 pattern).
**Date:** 2026-10-24
**Parent design:** `docs/superpowers/specs/2026-10-22-howdah-design.md` §3 (four layers), §5.5 (modes).
**Builds on:** `docs/superpowers/specs/2026-10-23-howdah-layer3-sink-hardening-design.md` (Layer 3 / Howdah 1.2 — the posture, mode-independence, and privacy rules below are carried from it verbatim).
**Ships:** after 1.2, as **Howdah 1.3** — the Layer-3 fast-follow it named in §8.

> **Builder-check resolutions (binding — the plan refines this design):** a fresh
> builder review surfaced 9 load-bearing items, all resolved in the plan:
> (1) **phar AND ssrf default OFF** (opt-in), not detect — avoids noisy phar logs
> and DNS latency on stock installs. (2) **Install at a first-RINIT process-once
> guard, gated on the sink being armed** — because on Debian/Ondřej curl & phar
> are shared extensions loaded AFTER howdah (equal priority 20), so a MINIT install
> would silently no-op; config is process-static so gating is safe. (3) phar routes
> through the **existing `howdah_sink_check`** (new PHAR arm), not a new FFI entry.
> (4) SSRF uses a **two-phase FFI**: `howdah_sink_ssrf_armed` (no logging) then one
> `howdah_sink_check_ssrf`, with a pinned 17-byte IP-record ABI. (5) `parse_host`
> takes a **HostForm** (SchemeRequired vs BareHostOk) so local paths aren't resolved
> and schemeless curl hosts are. (6) the 5.x compile-swap is **scoped** to real
> include/eval (not the main script, auto_prepend_file, create_function, assert).
> (7) SSRF detail goes in the existing **`reason`** log field (no Layer-1 schema
> change). (8) the curl handle map lives **in C**, lifecycle is lab-tested.
> (9) coverage states provenance ("verified on 5.4/5.6/7.4/8.3/8.5"). See
> `docs/superpowers/plans/2026-10-24-howdah-layer3-fast-follow.md`.

---

## 1. Intent — the why

Layer 3 (1.2) stands at the moment PHP is about to **do** something dangerous —
run a shell command, include a file, eval code, unserialize attacker data — and
checks the call against a flat, operator-set policy. It shipped with three
deferred items, each needing a hook mechanism the 1.2 spike did not cover:

1. **phar:// deserialization.** Accessing a `phar://` path through almost any
   filesystem function unserializes the archive's metadata — object injection
   that never passes through the userland `unserialize()` Howdah already hooks.
2. **SSRF.** An outbound request (`curl`, `file_get_contents`, `fsockopen`, …)
   whose target resolves to a loopback / private / link-local / cloud-metadata
   address is the classic server-side request forgery primitive.
3. **include/eval on PHP 5.x.** 1.2's include/eval guard is a `ZEND_INCLUDE_OR_EVAL`
   user-opcode handler that is **7.0+ only** — on 5.x the VM stores opcode
   operands off `execute_data` behind an accessor an extension cannot call, so
   include/eval stay dormant on 5.x.

1.3 closes all three, keeping the exact Layer-3 posture: **flat policy at the
sink, log-first, independent mode, argument never logged, every claim backed by
a test, and honest about what each PHP version actually exposes.**

## 2. Goals

1. **phar:// guard** that detects (and, opt-in, denies) use of the `phar://`
   wrapper — one guard point covering filesystem functions, class entry points,
   `include`, and other extensions, via the wrapper's own ops.
2. **SSRF guard** that, for outbound-request sinks, resolves the target and logs
   (opt-in, denies) when it lands in a reserved/internal range — deny-reserved
   policy with an allowlist escape hatch.
3. **include/eval on PHP 5.x** via a second mechanism (global `zend_compile_file`
   / `zend_compile_string` pointer swap), completing the matrix cell 1.2 left
   dormant — with the opcache limitation stated plainly (§7).
4. **Fixed-knob TOML, NO new php.ini directives.** New `[sinks.phar]` and
   `[sinks.ssrf]` subsections in the existing `howdah.config` TOML. Install
   surface stays at exactly three ini directives, as since 1.0.
5. **Log-first; a global block flip does NOT arm any of it.** Each new sink has
   its own mode inheriting `sinks.mode` (default `detect`), independent of the
   global `howdah.mode`, exactly as the 1.2 sinks are. All new rules are
   `Severity::Standard`.
6. **Allowlist escape hatch per new sink** (phar realpath prefixes; SSRF
   allowed hosts/IPs/CIDRs), so `block` is usable without breaking apps that
   legitimately use a phar (composer.phar) or reach an internal service.
7. **The matched argument is NEVER logged** — no phar path, no full URL. SSRF
   events log scheme + host + port + the matching resolved IP + the reserved
   class (never userinfo, path, or query, which carry secrets). phar events log
   the sink + action only (the path can carry upload dirs / secrets), matching
   `include`.
8. **Bounded, opt-in overhead.** phar adds one wrapper-op indirection per
   `phar://` access only. SSRF performs DNS resolution **only when its mode is
   not off** (default off), so a default install pays near-zero — a cheap mode
   check and chain. Documented.
9. **Every guard backed by a test**, and public coverage states the real
   per-version exposure and every limitation (PHP 8.0 phar change; 5.x opcache;
   SSRF TOCTOU/redirects/multi) — no fabricated coverage.
10. **Off-able and tunable**, per new sink, like the 1.2 sinks.
11. Runs on supported PHP minors/SAPIs, **proven feasible by three throwaway
    spikes** on 5.6 / 7.4 / 8.3 before this design was committed (§5.1).

## 3. Non-goals and anti-goals

- **Not taint tracking.** Flat policy at the sink only, as in 1.2.
- **Not an airtight egress firewall.** SSRF is resolve-at-check-time, log-first
  best-effort **detection and visibility**, not a connection-time boundary. DNS
  rebinding, redirects to a new host, `curl_multi_*`, and `CURLOPT_RESOLVE`/
  `CONNECT_TO` retargeting are known bypasses (§7) — stated, never hidden.
- **No PHP 8.x phar deserialization claim.** PHP 8.0 stopped auto-unserializing
  phar metadata on filesystem access (measured, §5.2); on 8.x the phar guard is
  **detection + denial of phar:// use** only, not deserialization coverage.
- **No complete 5.x include coverage under a warm opcache** (§7).
- **Never a payload generator or exploitation cookbook.** Tests use
  representative static strings and harmless fixtures (a benign phar with an
  inert metadata object; a loopback URL) — never a runnable exploit.
- **No new block-by-default behavior.** Layer 1's request-shape limits remain
  the only out-of-the-box blocking rules.
- **Changes nothing about Layers 1 or 2, or the 1.2 sinks.** Purely additive.

## 4. Constraints (inherited, project-wide)

- Defensive tool only; never a hacking tool.
- No overclaiming: every coverage claim backed by a test or stated honestly.
- Reproducers/fixtures recreate only harmless request **shape**; never a generator.
- Private GPG master key stays offline; nothing here touches signing.
- Log-first by default (this layer).
- Pure-Rust core, chained PHP glue, PHP 5.4–8.5, NTS, FPM/Apache-prefork/CGI.
- No new runtime dependencies in `howdah-core` (kept the no-dep/no-regex stance
  through Layers 2–3; the IP/URL work here is hand-rolled linear-time, wasm-safe).

## 5. The how — decisions made, each proven by a throwaway spike first

Three independent spikes were built and run on PHP **5.6, 7.4 and 8.3** before
this design was committed (findings archived under the session scratchpad
`spikes/findings-{phar,ssrf,php5-include-eval}.md`). All three came back
**feasible**; the mechanism rulings below are what they proved.

### 5.1 phar:// — proxy the phar stream wrapper's ops (Mechanism 2)

Both candidate mechanisms were spiked. **Chosen: re-register the `phar` wrapper
with proxied ops**, because one guard point covers filesystem functions, class
entry points (SplFileObject, DOMDocument::load, …), `include`, and other
extensions — PHP itself does the scheme matching, so case-insensitivity
(`PHAR://`) is free, and it covers `include phar://` on 5.x where the opcode
hook is dormant. (The function-table-swap alternative needed ~40 enumerated
trampolines and still missed class entry points and `include` on 5.x.)

- At MINIT (after ext/phar has registered — a dynamic extension's MINIT runs
  later, confirmed on all three), find the wrapper in
  `php_stream_get_url_stream_wrappers_hash_global()`.
- **Critical:** phar's `php_stream_wrapper` and its `wops` are `static const`
  (read-only memory) — patching in place SEGVs. `memcpy` both the wrapper and
  its ops into our own statics, override the ops, then
  `php_unregister_url_stream_wrapper("phar")` + `php_register_url_stream_wrapper(
  "phar", &ours)`. Phar's MSHUTDOWN unregisters "phar" by name, cleanly removing
  our wrapper.
- Proxy ops: `stream_opener` (fopen / file_get_contents / include /
  getimagesize), `url_stat` (file_exists / is_file / is_dir), `dir_opener`,
  `unlink`, `rename`, `stream_mkdir`, `stream_rmdir`. Each receives the full URL;
  the trampoline asks Rust for a decision.
- **Neutralize (safe, proven):** opener/dir_opener return NULL, url_stat returns
  -1, unlink/rename/mkdir/rmdir return 0 — exactly how a missing file fails, so
  PHP raises its normal "failed to open stream" warning and the script continues.
- ABI: PHP5 uses `char*`, `char **opened_path`, `TSRMLS_DC`; PHP7/8 use
  `const char*`, `zend_string **opened_path`, no TSRMLS — all behind
  `#if PHP_VERSION_ID`, in the C shim.

### 5.2 phar:// — real per-version exposure (measured, drives the claim)

Measured with a benign metadata object carrying a `__wakeup` tracer, each access
in a fresh process:

| trigger | 5.6 | 7.4 | 8.3 |
|---|---|---|---|
| fs funcs (file_exists/get_contents/fopen/…) on `phar://` | unserializes | unserializes | **no** |
| `include 'phar://…'` | unserializes | unserializes | no (code still runs) |
| explicit `Phar::getMetadata()` | unserializes | unserializes | unserializes |

**Ruling for the public claim:** "PHP **5.x/7.x** phar:// metadata object
injection via filesystem functions and includes." On **8.x** the guard provides
**detection + denial of phar:// use** (incl. `include phar://` polyglots) only —
explicitly **not** a deserialization claim. Direct `new Phar($path)` /
`getMetadata()` bypass the wrapper (they unserialize before any wrapper op) and
are a **documented residual gap** for 1.3; closing them needs a
`Phar::__construct` method-table swap (same idea as `sink_hook.c`), deferred.

### 5.3 SSRF — function-table swap + handle map + getaddrinfo (extends sink_hook.c)

- **Direct URL sinks** (first string arg is the target): `file_get_contents`,
  `fopen`, `get_headers`, `fsockopen`, `stream_socket_client`. Same
  function-table swap as the 1.2 sinks; the arg-read macro is generalized to read
  argument *n* (fsockopen's host is arg 1; port is arg 2).
- **curl** (the hard one — `curl_exec($ch)` takes a handle, not a URL): hook
  `curl_init`, `curl_setopt`, `curl_setopt_array`, `curl_close`, `curl_reset`,
  `curl_copy_handle` to maintain a **handle→URL map**, and consult it in a
  `curl_exec` hook. Handle id = resource id on 5/7, object handle on 8. Proven
  end-to-end for URLs set via `curl_init($url)`, `curl_setopt`, and
  `curl_setopt_array`. (Reading the URL from the private `php_curl` struct was
  rejected — struct is private and varies across 5/7/8.)
- **Scheme gate first (required, cheap):** the trampoline acts only on values
  with a network scheme (`http`/`https`/`ftp`/`ftps`/`tcp`/`udp`/`ssl`/`tls`/
  `gopher`) or the bare `fsockopen`/`stream_socket_client` host — a local path
  (`fopen("/etc/passwd")`) is skipped early, before any resolution, so hot-path
  `fopen` is not penalized.
- **Resolution stays extension-side:** `getaddrinfo(3)` in the trampoline (DNS is
  not wasm-safe and must never enter `howdah-core`). `localhost` yields both
  `::1` and `127.0.0.1` — **every** result is classified; any reserved hit is a
  match. Resolution happens **only when the ssrf effective mode is not off**, and
  is cached per-request per-host (FPM workers persist — map + cache are freed at
  RSHUTDOWN).
- **Neutralize:** `RETVAL_FALSE; return;` (as the 1.2 sinks) — proven safe on all
  three, script continues. A blocked `curl_exec` returns false with `curl_errno`
  0 (so `curl_error()` is empty) — documented.

### 5.4 PHP 5.x include/eval — global compile-pointer swap (the Suhosin path)

At MINIT on **PHP 5.x only** (`#if PHP_VERSION_ID < 70000`), save and swap the
global function pointers:

- `zend_compile_file` — fires for include/require; the resolved path is in
  `file_handle->filename` (correct even for a runtime `include $p;`). Chain to
  the original for detect; **block = return NULL** (Suhosin-style — include
  yields false, `require` does **not** fatal; proven, computed operand `$a.$b`
  also safe).
- `zend_compile_string` — fires for `eval()`; code is the IS_STRING source zval.
  Same swap; eval is **never opcache-cached** → full coverage.

Hand-building a substitute op_array was tried and rejected (zend_add_literal /
get_next_op / pass_two are not exported from the 5.6 build); NULL return is the
mechanism. On PHP 7.0+ nothing changes — the existing opcode handler stays.

### 5.5 Engine — extend the pure-Rust `sinks` module + a new `ssrf` submodule

`howdah-core` gains, all pure/no-dep/linear-time/wasm-safe, host-unit-tested:

- `SinkId::{Phar, Ssrf}` added to the existing enum.
- **phar policy:** `phar_allowed(path, allow_paths) -> bool` — lexical realpath-
  prefix match reusing the `include` path-normalization already in `sinks.rs`.
  Inert (logs/blocks nothing in block mode beyond default) semantics documented.
- **ssrf submodule (`sinks/ssrf.rs`):**
  - `parse_host(url_or_host) -> Option<Host>` — extract scheme + host + port from
    a URL or bare host; reject/skip non-network schemes; strip userinfo.
  - `decode_literal_ip(host) -> Option<IpAddr>` — mirror glibc `inet_aton`
    permissiveness: dotted-decimal, decimal dword (`2130706433`), octal
    (`0177.0.0.1`), hex (`0x7f000001`), short forms (`127.1`), bracketed IPv6.
    This is the subtle part; adversarial tests are mandatory (§8, Review Focus).
  - `classify_ip(ip) -> Option<ReservedClass>` — loopback / unspecified / rfc1918
    / cgnat / link-local / metadata / ula / benchmarking; **IPv4-mapped and NAT64
    IPv6 are unwrapped to v4 and re-classified** (a known bypass the spike flagged
    its own code didn't handle).
  - `host_allowed(host, resolved_ips, allow) -> bool` — allowlist of
    hostnames / literal IPs / CIDRs.
  - The extension resolves hostnames and passes the resolved IP bytes in; core
    classifies both the literal-decoded host and every resolved IP.

The FFI mirrors `howdah_sink_check`: a phar entry taking the path, and an ssrf
entry taking (scheme/host/port + resolved-IP list) that returns an action and
stashes a privacy-filtered log line (scheme + host + port + matching IP +
reserved class; **never** the full URL). `catch_unwind` fail-open throughout — a
Layer-3 bug must never break a working call.

### 5.6 Config — two new independent-mode subsections

New `RuleId`s: `PharSink`, `SsrfSink`, each `Severity::Standard`. New sub-configs
under the existing `SinkConfig`, same `effective_mode(sink, global)` shape:

```toml
[sinks.phar]
# mode inherits sinks.mode (default "detect"); set "block" to deny, "off" to disable
allow_paths = ["/var/www/vendor"]   # realpath prefixes allowed even under block

[sinks.ssrf]
mode = "off"            # DEFAULT OFF (opt-in): enabling adds a DNS resolution per
                        # distinct outbound host; "detect" to log, "block" to deny
allow_hosts = ["10.1.2.3", "192.168.50.0/24", "internal-api.svc"]
```

- **phar defaults to `detect`** (inherits `sinks.mode`) — cheap, high-signal,
  rare in web requests.
- **ssrf defaults to `off`** (like `unserialize` in 1.2) — because enabling it
  imposes per-outbound-host DNS latency; operators opt in. Documented plainly.

## 6. File structure

- `crates/howdah-core/src/sinks.rs` — add `SinkId::{Phar,Ssrf}`, `phar_allowed`.
- `crates/howdah-core/src/sinks/ssrf.rs` (new) — URL/host parse, literal-IP
  decode, reserved classification, allowlist. (Split out: it is the largest and
  most adversarially-tested unit.)
- `crates/howdah-core/src/limits.rs` — `RuleId::{PharSink,SsrfSink}`, Standard.
- `crates/howdah-core/src/config.rs` — `PharConfig`, `SsrfConfig`, wire into
  `SinkConfig` + `effective_mode`; validate CIDR/host patterns.
- `crates/howdah-core/src/ffi.rs` — `howdah_sink_check_phar`,
  `howdah_sink_check_ssrf` (+ the existing sink-log slot; new consts
  `HOWDAH_SINK_PHAR=4`, `HOWDAH_SINK_SSRF=5`).
- `crates/howdah-sys/phar_hook.c` (new) — wrapper-ops proxy.
- `crates/howdah-sys/ssrf_hook.c` (new) — URL-sink + curl trampolines, handle
  map, getaddrinfo, per-request lifecycle.
- `crates/howdah-sys/sink_hook.c` — add the 5.x `zend_compile_file` /
  `zend_compile_string` swap (`#if PHP_VERSION_ID < 70000`).
- `crates/howdah-sys/build.rs`, `src/lib.rs` — compile + declare the new shims.
- `crates/howdah-ext/src/{phar_filter.rs,ssrf_filter.rs}` (new) + `module.rs`
  install at MINIT; `ssrf_filter` owns the per-request handle map/cache + RSHUTDOWN.
- `lab/integration/sinks_fastfollow.sh` + `_container.sh` (new) — per-version
  assertions (incl. 5.x include/eval now ACTIVE; phar per-version; ssrf resolve).
- Docs/site: `docs/config.md`, `packaging/howdah.ini`, `tools/howdah-check`,
  README, CHANGELOG `[1.3.0]`, coverage matrix (+ limitations), launch blog.

## 7. Honest limitations (stated in the design, docs, and coverage)

1. **phar on PHP 8.x is detection/denial, not deserialization coverage** (§5.2).
2. **Direct Phar API bypasses the wrapper** — `new Phar($path)`, `PharData`,
   `Phar::loadPhar`, `Phar::mapPhar`, `Phar::getMetadata()` unserialize before any
   wrapper op. Residual gap, documented; needs a `Phar::__construct` method-table
   swap (deferred). Also: `stream_wrapper_unregister('phar')` +
   `stream_wrapper_restore('phar')` is untested and could drop the proxy; another
   extension re-registering "phar" after us, or a statically-built phar, fails open.
3. **5.x include under a warm opcache:** a cache hit is served without calling
   `zend_compile_file`, so established app files are not re-inspected. eval is
   never cached (full coverage). include on **7.0+** is the runtime opcode
   handler and is opcache-immune — this gap is **5.x-only**. Stated in the matrix.
4. **SSRF is best-effort, resolve-at-check-time detection**, not a connection-
   time boundary. Known bypasses: DNS rebinding, redirects to a new host,
   `curl_multi_*` (not hooked), `CURLOPT_RESOLVE`/`CONNECT_TO` retargeting, a
   non-string or absent `CURLOPT_URL`.
5. **Not every outbound primitive is hooked.** Covered: `file_get_contents`,
   `fopen`, `get_headers`, `fsockopen`, `pfsockopen`, `stream_socket_client`, and
   curl via the handle map. **NOT covered** (documented): `copy`, `file`,
   `readfile`, `SoapClient`, `DOMDocument::load*`, `simplexml_load_file`.
6. **SSRF neutralize side effects:** a blocked `fsockopen`/`stream_socket_client`
   leaves the by-ref `$errno`/`$errstr` unset; a blocked `curl_exec` returns false
   with `curl_errno` 0 (so `curl_error()` is empty).
7. **SSRF latency:** enabling adds a `getaddrinfo` per distinct outbound host
   (cached per request, **no timeout** — a DNS stall blocks the call). Default off
   for this reason.
8. **Literal-IP decode mirrors glibc `inet_aton`;** libcurl and musl parse some
   encoded forms differently. Resolved IPs are authoritative; literal decode is
   belt-and-braces.

## 8. Review focus (inputs the spec implies; each pinned to a task's tests)

- **Literal-IP decode bypasses:** decimal dword, octal, hex, `127.1`, mixed,
  `[::ffff:127.0.0.1]`, `0`/`0.0.0.0` → each must classify as its real reserved
  address. (ssrf.rs tests — the highest-risk unit.)
- **IPv4-mapped / NAT64 IPv6** unwrapped and re-classified.
- **Scheme gate:** `fopen("/etc/passwd")` and other local paths must NOT be
  resolved or flagged (hot-path + false-positive guard).
- **phar neutralize safety:** denied access raises a normal warning, script
  continues, unrelated fs ops unaffected; no crash across 5.6/7.4/8.3.
- **5.x require block does not fatal**, computed-operand include block is safe,
  eval block neutralizes and continues.
- **Privacy:** no full URL / userinfo / query / phar path ever reaches the log;
  assert the log contains host+class but not the secret-bearing parts.
- **Fail-open:** panic in any core check → allow + chain; null ctx guarded.
- **Handle-map lifecycle:** freed at RSHUTDOWN; reused ids don't leak a stale URL.

## 9. Versions

| sink / mechanism | 5.4–5.6 | 7.0–7.4 | 8.0–8.5 |
|---|---|---|---|
| phar:// (wrapper proxy) | deny/detect + **deserialization** | deny/detect + **deserialization** | deny/detect **only** (8.0 removed auto-unserialize; **no deserialization claim**) |
| SSRF (fn-swap + curl map) | yes (opt-in, off by default) | yes (opt-in) | yes (opt-in) |
| include/eval (compile swap on 5.x; opcode handler 7.0+) | **now active** (include: opcache caveat; eval: full) | active (opcode handler) | active (opcode handler) |

Provenance: mechanisms verified on **PHP 5.4, 5.6, 7.4, 8.3, 8.5**; other minors
build and are expected to work but are not independently verified. A debug-build
memory-leak review is a release gate (the 5.x spike ran on non-debug images).

## 10. Testing

Mirror `lab/integration/sinks.sh`: per-version container assertions driven by
`php -d extension=… -r`, log-first and block, asserting the argument/payload is
never logged. Add fixtures: a benign phar with an inert tracer-object metadata
(harmless — proves the unserialize path fires, carries no gadget), a loopback /
decimal-encoded URL, a `new Phar` direct-API case asserting the documented gap.
Rust unit tests carry the adversarial IP-decode and classification matrix.
