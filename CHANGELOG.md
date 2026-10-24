# Changelog

All notable changes to Howdah are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0] - 2026-10-24

### Added
- Layer 3 `phar://` guard. The `phar` stream wrapper is re-registered with
  proxied operations, so filesystem functions, `include` and class entry points
  that open a `phar://` URL are checked. **Off by default** (opt in with
  `[sinks.phar] mode`); `allow_paths` lists realpath prefixes that are always
  allowed. On PHP 5.x and 7.x this covers phar metadata deserialization via the
  wrapper; on PHP 8.x it is detection and denial of `phar://` use only, not a
  deserialization claim. Direct Phar API use (`new Phar`, `PharData`,
  `Phar::loadPhar`, `Phar::mapPhar`, `Phar::getMetadata`) is not covered.
- Layer 3 SSRF egress guard for `file_get_contents`, `fopen`, `get_headers`,
  `fsockopen`, `pfsockopen`, `stream_socket_client` and curl (via a handle-to-URL
  map). **Off by default** (opt in with `[sinks.ssrf] mode`); `allow_hosts`
  takes hostnames, IPs and CIDRs. Best-effort, resolve-at-check-time detection,
  not a connection-time boundary: DNS rebinding, redirects, `curl_multi_*`,
  `CURLOPT_RESOLVE`/`CONNECT_TO` and a non-string `CURLOPT_URL` bypass it, and
  `copy`, `file`, `readfile`, `SoapClient`, `DOMDocument::load*` and
  `simplexml_load_file` are not hooked. Enabling it adds a `getaddrinfo` per
  distinct outbound host, with no timeout.
- `include`/`require` and `eval` guards are now **active on PHP 5.x** (they
  were PHP 7.0+ only). On 5.x they use a compile-pointer swap: `eval` is fully
  covered, but an `include` served from a warm opcache is not re-inspected.
- Verified on PHP 5.4, 5.6, 7.4, 8.3 and 8.5. Other minors build and are
  expected to work but are not independently verified. A debug-build leak
  review is still pending.

### Notes
- Both new sinks log first. A global `howdah.mode = block` or `[sinks]
  mode = "block"` does not arm them; only an explicit per-sink mode does.

### Added
- A config editor at https://howdah.org/config/: builds `howdah.ini` and
  `howdah.toml` from a form with every setting's default and effect, validates
  the TOML with the extension's own parser compiled to WebAssembly (the core's
  error text, verbatim), loads an existing file, and offers the result as copy,
  download or one `curl` command. The `curl` URL is served by `cfg.howdah.org`,
  a stateless Cloudflare Worker (`site/worker/`) that decodes the config from
  the URL, re-validates it with the same core, serves only files the editor
  itself wrote, and stores nothing; it is deployed on every push to `main`
  that touches it and on every release tag (`.github/workflows/worker.yml`).
- `howdah-wasm` exports `howdah_wasm_validate_config` (the parsed config as
  JSON, or the error), `howdah_wasm_rule_catalog` and `howdah_wasm_version`.

### Fixed
- `docs/config.md` claimed `[log] path` in the TOML overrides `howdah.log`;
  the extension never reads it. The log path is set only by the ini directive.
- The browser demo ran a stale core: `site/demo/howdah_wasm.wasm` was a
  committed binary last built at 1.0 and nothing in the site deploy rebuilt
  it. The wasm is no longer committed; the Pages workflow builds it from the
  same commit it deploys, and the site build fails if it is missing.
- The aarch64 build of the PHP 5.4 extension. PHP 5.4's tarball ships a 2008
  `config.guess` that cannot identify an aarch64 host, so `./configure` failed
  with "cannot guess build type" and every release so far has had no 5.4 arm64
  tarball. `build-one.sh` now passes an explicit `--build` triple when the
  shipped guesser fails; the per-PR arm64 CI smoke now includes 5.4.

## [1.2.1] - 2026-10-23

### Security
- Fixed a bypass of the multipart count rules (`max_parts`, `max_files`,
  `max_filename_bytes`, `max_field_name_bytes`) that affected every release
  from 0.1.0 to 1.2.0 in the shipped `detect` mode. The PHP glue used to
  re-synthesise multipart framing with a fixed internal boundary and push part
  data through the core's byte parser; a data chunk containing that boundary
  put the parser into its sticky failed state, after which no further part
  was counted or suppressed, so a flood behind one such chunk was allocated by
  PHP as if Howdah were not loaded. In `block` mode the request was still
  refused, as `malformed_multipart`. The glue now reports parts to the core
  structurally (`howdah_part`, `howdah_part_data`: kinds and lengths only);
  no request bytes reach a parser. The byte parser remains for the browser
  demo and tests. Reported and fixed internally; regression tests cover the
  host ABI (`crates/howdah-ext/tests/multipart_events.rs`), the lab
  (`block_shaped_container.sh`, poisoned flood on real PHP) and a new
  event-level fuzz target (`fuzz/fuzz_targets/events.rs`).

### Changed
- `howdah_core.h` is regenerated and now declares the Layer 2/3 entry points
  that were missing from the committed header.

## [1.2.0] - 2026-10-23

### Added
- Layer 3 sink hardening: Howdah now guards dangerous PHP functions
  ("sinks") with a flat allowlist policy. Version 1.2 actively guards two
  sinks: `command_exec` (`system`, `exec`, `shell_exec`, `passthru`, `popen`,
  `proc_open`) and `unserialize`.
- Detects and logs; **does not block by default.** Layer 3 is governed by its
  own `sinks.mode` (default `detect`), independent of `howdah.mode`: a global
  `howdah.mode = block` does not arm sinks. Sinks can block only
  when explicitly armed; set the allowlist
  first.
- `unserialize` is off by default. The sink argument (command line or
  serialized payload) is never logged.
- Configured under `[sinks]`; no new php.ini directives. See
  [docs/config.md](docs/config.md).
- Best-effort, bypassable virtual patching. Known limitation: `proc_open`
  with an array command (PHP 7.4+) is not inspected.

- `include` / `require` and `eval` are also active sinks, on **PHP 7.0+ only**
  (detect and block). They are not available on PHP 5.x. `include` is inert
  until `[sinks.include] allow_paths` is set. Block works by skipping the
  opcode: the include/eval never runs and the script continues.
  `command_exec` and `unserialize` work on every supported PHP (5.4-8.5).

### Roadmap (not shipped)
- `phar://` and SSRF coverage are roadmap.

## [1.1.0] - 2026-10-23

### Added
- Layer 2 input inspection: content inspection of decoded GET, POST, cookie and
  path values for SQL injection, path traversal and command/code injection.
- Detects and logs; **does not block by default.** Layer 2 is governed by its
  own `inspect.mode`, independent of `howdah.mode`: a global
  `howdah.mode = block` does not arm it.
- The matched value is never logged; log lines carry the variable name, the
  rule class and the source only.
- Linear-time scanning with per-value and per-request budgets, so inspection
  cannot be turned into a denial-of-service vector.
- Configured under `[inspect]`; see [docs/config.md](docs/config.md).
- Signature inspection is best-effort and can be bypassed, which is why it logs
  by default.

## [1.0.0]

### Added
- Layer 1 request parsing limits: multipart/form-data upload floods, input
  variable count and shape, and request headers.
