# Changelog

All notable changes to Howdah are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [1.6.1] - 2026-10-25

### Fixed
- Under php-fpm (FastCGI), an over-limit `multipart/form-data` request that
  tripped a bounded count limit (`max_parts`/`max_files`) was blocked and
  logged and the worker survived, but the client got a reset connection instead
  of the clean 403 that 1.5.0 (#44) delivers: the 1.6.0 §4.1 read_post scanner
  stopped the body (returned EOF) on those bounded limits too, leaving the
  request body undrained so php-fpm reset the FastCGI socket. The scanner now
  stops the body only for the unbounded-growth limits where it must —
  `post_too_large` (gap B), the raw-byte budget, the §4.5 parse-memory estimate,
  and the gap-A per-part header flood (`max_part_headers`/`max_part_header_bytes`,
  which the scanner alone enforces) — while a bounded count limit drains the
  (bounded) body and is answered with a clean 403. The security behaviour is
  unchanged: the request is still blocked, the amplifying allocation suppressed
  and the worker survives; only the client-facing delivery is restored. Verified
  on PHP 5.6 / 7.4 / 8.3 (php-fpm behind nginx).

## [1.6.0] - 2026-10-25

### Added
- An out-of-memory backstop for the PHP fatal the official PHP2Shell
  advisories name as the root cause (CVE-2026-109618): PHP's out-of-memory
  bailout `longjmp`s out of a half-built request, so Howdah installs its own
  `zend_error_cb` and, on that fatal — an out-of-memory `E_ERROR`
  (`"Allowed memory size of …"` / `"Out of memory"`) or any bailout-fatal
  raised while `PG(during_request_startup)` — logs the event without
  allocating and calls `_exit()` before the `longjmp`, so the worker leaves
  cleanly instead of running on over corrupt state. Web SAPIs only; a runtime
  probe (`memory_hard_limit_percent`) keeps it off on a patched engine, and it
  never arms under the CLI. Two Critical Layer 1 rules, `out_of_memory` and
  `startup_fatal`, and a new top-level `oom_exit` (default `true`;
  `php --ri howdah` shows the backstop and whether it is armed). Installed at
  MINIT, restored at MSHUTDOWN. `lab/integration/oom_backstop*.sh` passes on
  PHP 5.6/7.4/8.0/8.1 (armed) and 8.3 (patched → off). Run against a vulnerable
  PHP build with the backstop armed, the PHP2Shell exploit no longer lands —
  the worker exits on the out-of-memory fatal instead of carrying on over
  corrupt state. Design §4.6:
  `docs/superpowers/specs/2026-10-24-howdah-php2shell-gaps-design.md`.
- Request-parsing limits for the three PHP2Shell parse-amplification shapes
  the parsed-event path cannot see (PHP fires it only after it has parsed a
  part). Howdah wraps `sapi_module.read_post` and runs a second, independent
  multipart byte-scanner over the raw body, framed on the request's real
  boundary extracted the way PHP's `rfc1867.c` does and armed only for a body
  PHP itself resolved as `multipart/form-data`. It closes a header flood
  within one part (`max_part_headers`), a body past `post_max_size` counted as
  PHP buffers it including the in-flight field (`post_too_large`), and summed,
  widely-nested field and file names (`nesting_budget`); a parse-memory
  estimate (`parse_memory_estimate`) is sized against the request's live
  `memory_limit / 4`, so the limit holds on upload-heavy servers that raise
  their limits, not just at stock settings. Three Critical Layer 1 rules and
  two `[limits]` keys (`max_nesting_levels`, `memory_ceiling_bytes`, `0` =
  automatic). The scanner can only ever add a block — the structural counter
  (`max_parts`/`max_files`/name lengths) stays wired as the floor, so a
  scanner desync fails closed — and is deliberately lenient about shapes PHP
  accepts (LF-only line endings, header folding, non-`form-data`
  dispositions). Verified by a benign corpus (multi-file gallery, extra
  headers, nested arrays, chunked, LF-only, `attachment`) blocking nothing
  with the scanner active, and by the limits firing on over-threshold inputs,
  on PHP 5.6/7.4/8.3, plus a chunk-invariance fuzz target in CI. Confirmed
  against the PHP2Shell exploit on a vulnerable PHP build: with these limits
  active the parse-amplification shapes no longer reach the out-of-memory
  state the exploit relies on. Design §4.1–4.5 (same spec).

### Fixed
- The 1.5.0 Docker images were not published: the `docker.yml` run after the
  release (run 40140181320) failed every image. Two causes:
  - `docker/smoke.sh` still expected 1.4.0's php-fpm refusal (a worker exit
    with code 70) and failed when 1.5.0 refused cleanly (#44). It now reads
    the Howdah version in the image and expects a worker exit below 1.5.0
    and a 403 with the Howdah body from 1.5.0 (`FPM_BLOCK` can still force
    either).
  - The 1.5.0 musl build does not load on musl older than 1.1.24: the
    `[log] exec` hook uses Rust's `std::process::Command`, which links
    `posix_spawn_file_actions_addchdir_np` (added to musl in 1.1.24), and
    musl refuses a module with an unresolved symbol ("Error relocating
    howdah.so: posix_spawn_file_actions_addchdir_np: symbol not found" on
    `php:5.6/7.0/7.1-fpm-alpine`, Alpine 3.8/3.7/3.10). `-alpine` images are
    now built for PHP 7.2 to 8.5 only; 5.6, 7.0 and 7.1 use the Debian
    images. The musl release build fails if the module needs a C library
    symbol that musl 1.1.24 (Alpine 3.11) lacks, and lists them
    (`packaging/musl-floor-check.sh`).
- `howdah-check detect` prints the musl version (`host libc: musl 1.1.22`)
  and, on a musl older than 1.1.24, offers no tarball or `-alpine` image,
  since neither would load (it names the Debian image for an official
  Alpine php base).

## [1.5.0] - 2026-10-24

### Added
- Scoped `[[exceptions]]`: turn one rule off for one executing script
  (absolute path, glob, or SHA-256 of the file), one request parameter
  (exact or prefix), one URI prefix, one client CIDR (IPv4/IPv6), or any AND
  of those, with a mandatory `reason` that doubles as the decision record.
  `rule` is a rule id, a layer (`limits`, `inspect`, `sinks`, `behavior`) or
  `layer.rule`. Critical Layer 1 rules can never be excepted; Layer 1
  Standard rules take only `uri_prefix`/`client_cidr`; Layer 2 takes no
  `script` (its events are raised before any script runs); every validation
  error names `exceptions[i].key` and an invalid entry takes the
  `on_invalid_config` path. A facet that matches every request
  (`script = "/**"`, `uri_prefix = "/"`, a `/0` CIDR) is refused, a `param`
  may not name the `REQUEST_URI`/`PATH_INFO` pseudo-parameters, and a
  request path with a `.`/`..` segment, `//`, `\` or `%` never satisfies
  `uri_prefix` (fail toward protection). A match is decided after the
  finding and before the mode, never arms anything and never widens an
  allowlist. The `script`
  facet reuses the Layer 4 origin capture (`zend_get_executed_filename()`,
  exported once from `sink_hook.c`); the glue hashes a file (up to 4 MiB)
  only when an entry with `script_sha256` could apply, and re-reads it when
  its inode, size, mtime or ctime changes. New optional top-level
  `exceptions_log = true` writes each match as an event with the new
  `action: "excepted"` (the only schema-2 addition). `php --ri howdah` shows
  `Exceptions ([[exceptions]]) => N configured, M rejected` and the SAPI
  error log gets one summary line per process. Under php-fpm and Apache the
  client IP is known before any variable; the input filter now also feeds
  `REMOTE_ADDR` to the core where the SAPI exposes it only as a `$_SERVER`
  entry. `lab/integration/exceptions.sh` (21 checks) passes on PHP 5.6, 7.4
  and 8.3. Design: `docs/superpowers/specs/2026-10-24-howdah-exceptions-design.md`;
  how-to: `docs/exceptions.md`.
- Application profiles in `profiles/` (WordPress, Drupal 7, Magento 1 and 2,
  Joomla, PrestaShop 1.6): complete detect-mode configs whose
  `[[exceptions]]` entries and commented allowlist suggestions cover each
  application's own verified behaviours (compiled-template and cache writers,
  cron spawns, admin editors), every entry with a cited reason; anything
  unverified is commented out. Starting points, never applied automatically;
  a core test parses every profile and checks it arms nothing. Also served at
  https://howdah.org/profiles/.
- The config editor preserves `[[exceptions]]` and `exceptions_log` on load
  and re-emits them, offers a plain exceptions table (rule, script,
  param, uri_prefix, client_cidr, reason) validated by the wasm core, and a
  "start from an application profile" selector.
- Seven legacy-era Layer-3 sinks, each with its own `[sinks.<name>]` table
  whose `mode` inherits `sinks.mode` (log-only by default, armed to block only
  by an explicit mode; a global `howdah.mode = block` arms none of them), its
  own rule id (Standard, Layer 3), and the argument never logged. They are
  cheap checks on functions or behaviours that mostly matter on the PHP 5.x/7.x
  third of the web, no-ops where the function no longer exists:
  - `mail` (`mail_injection`): a 5th argument (`additional_parameters`)
    carrying any sendmail option other than `-f<address>` / `-r<address>` with
    a sane address (so `-oi`, `-t`, `-O...` are expected detect noise), or a
    4th-argument header string with a line break not followed by a header (the
    PHPMailer CVE-2016-10033 class; Suhosin `mail.protect`). Block refuses the
    call and returns false, so nothing reaches sendmail. All versions.
  - `preg_eval` (`preg_eval`): a `preg_replace`/`preg_filter` pattern with the
    `/e` modifier (Suhosin `disable_emodifier`). PHP 5.x only; the modifier was
    removed in 7.0, so the sink installs nothing there. Block returns null.
  - `create_function` (`create_function`): routed through the eval policy. PHP
    5.x and 7.x; removed in 8.0. Block returns false.
  - string `assert()` (`assert_string`): a string argument, which PHP 5.x/7.x
    evaluate as code. 8.0 stopped evaluating strings, so the sink is inert
    there. Block returns false.
  - string callbacks (`dangerous_callback`): `call_user_func`,
    `call_user_func_array`, `array_map`, `array_filter`, `array_walk`,
    `usort`/`uasort`/`uksort`, `preg_replace_callback`,
    `register_shutdown_function` and `ob_start` given a string callback that
    names `system`, `exec`, `passthru`, `shell_exec`, `popen`, `proc_open`,
    `pcntl_exec`, `assert` or `create_function`. Only the callback name is
    logged (never the data). This is how ThinkPHP-style RCE reaches `system`.
    Block refuses the call. All versions, with one honest gap: on PHP 7.0+
    the compiler turns a literal, unqualified `call_user_func(...)` /
    `call_user_func_array(...)` in the global namespace into
    `ZEND_INIT_USER_CALL` and never calls the function, so that one shape is
    not seen there (namespaced and dynamic calls, and the other hooked
    functions, are); PHP 5.x sees every form. Pinned per version in the lab.
  - XML external entities (`xxe`): a document passed to
    `simplexml_load_string` or `DOMDocument::loadXML` that declares an
    external entity (`<!ENTITY ... SYSTEM|PUBLIC>`, refused in block) or that
    merely references an external DTD (the XHTML/SVG doctypes: detect only,
    never blocked, so SVG sanitizers keep working) (Snuffleupagus
    `xxe_protection`). The prolog scan skips comments and processing
    instructions and squeezes the NULs out of a UTF-16 document first. Plus a
    `[sinks.xml] external_entities = "deny"` toggle that turns libxml's
    external entity loader off for every request through ext/libxml's C
    setter (`php_libxml_disable_entity_loader`, resolved at run time; the
    deprecated userland function is only a fallback), off by default; PHP 8
    already defaults to not substituting external entities.
  - curl TLS verification (`tls_verify`): `curl_setopt`/`curl_setopt_array`
    turning `CURLOPT_SSL_VERIFYPEER` off or `CURLOPT_SSL_VERIFYHOST` to 0
    (Snuffleupagus bundled rule). Detect-only this release (no block mode);
    only the option name is logged, never the URL.
  `php --ri howdah` gains a `Layer-3 legacy sinks` row naming what installed on
  this PHP and what is `absent or disabled` (PHP 8 deletes `disable_functions`
  entries, so the two look alike). Lab: `lab/integration/legacy_sinks.sh` on
  PHP 5.4, 5.6, 7.4 and 8.3, proving detect logs and block refuses for each
  sink that exists on that version, that the argument is never logged, and
  that `preg_eval`/`create_function`/`assert` fire nothing on 8.x.

- A malformed `howdah.config` is no longer silent. The extension writes one
  line to the SAPI error log at startup (file and parse error, once per
  process) and `phpinfo()` / `php --ri howdah` shows
  `Config status => INVALID (fell back to block): <error>`. The fallback is
  still block mode by default; the new optional top-level TOML key
  `on_invalid_config = "block" | "off"` picks `off` instead. The parser is
  all-or-nothing, so a failed file is scanned for that one top-level line
  (see `docs/config.md`). No new php.ini directive.
- A read-only "Risky ini settings" table in `php --ri howdah` / `phpinfo()`
  and a `howdah-check ini [php-binary]` command: flag `register_argc_argv`
  (Craft CMS CVE-2024-56145, Laravel CVE-2024-52301), `allow_url_include`,
  `session.upload_progress.enabled`, a world-readable or docroot
  `session.save_path`, `display_errors`, `expose_php`, `enable_dl`,
  `cgi.fix_pathinfo` under CGI/FastCGI, and exec-family functions missing from
  `disable_functions`, each with the reason and what to set instead.
  `allow_url_fopen` and an unset `open_basedir` are shown by `howdah-check` as
  information only. Nothing is changed. A list of known preconditions, not an
  audit.
- A config editor at https://howdah.org/config/: builds `howdah.ini` and
  `howdah.toml` from a form with every setting's default and effect (including
  the 1.3 `[sinks.phar]` and `[sinks.ssrf]` tables), validates the TOML with
  the extension's own parser compiled to WebAssembly (the core's error text,
  verbatim), loads an existing file, and offers the result as copy, download
  or one `curl` command. The `curl` URL is served by `cfg.howdah.org`, a
  stateless Cloudflare Worker (`site/worker/`) that decodes the config from
  the URL, re-validates it with the same core, serves only files the editor
  itself wrote, and stores nothing; it is deployed on every push to `main`
  that touches it and on every release tag (`.github/workflows/worker.yml`).
- `howdah-wasm` exports `howdah_wasm_validate_config` (the parsed config as
  JSON, or the error), `howdah_wasm_rule_catalog` and `howdah_wasm_version`.
- Packages for panel and distribution PHP, built from the same per-minor
  `howdah.so` and `howdah.ini` as the tarball: `ea-php<XY>-php-howdah` for
  cPanel EasyApache 4 (rpm, and deb for cPanel on Ubuntu),
  `plesk-php<XY>-howdah` for Plesk (rpm and deb), `alt-php<XY>-howdah` for
  CloudLinux alt-php, and `php-howdah` for the distribution PHP on RHEL,
  AlmaLinux, Rocky and Amazon Linux (one repository per PHP minor). Each goes
  into the vendor's own module and ini directories, depends on the vendor's
  PHP package for that minor, and has no install scripts. They are published
  as separate signed repositories under `https://pkg.howdah.org/cpanel/`,
  `plesk/`, `cloudlinux/` and `el/php<minor>/` by the next run of the publish
  workflow; the existing `apt/` and `yum/` repositories and the Surý and Remi
  packages are unchanged. Layouts are rows of `packaging/layouts.tsv`; paths,
  vendor sources and what was tested are in `docs/packaging-layouts.md`.
  CloudLinux packages were built but not install-tested (alt-php needs a
  CloudLinux licence); DirectAdmin stays on the tarball.
- `howdah-check detect` prints each PHP install's packaging layout (`sury`,
  `remi`, `cpanel`, `plesk`, `cloudlinux`, `directadmin`, `stock-rhel`,
  `stock-debian` or `unknown`) and the package and repository Howdah ships
  for it, or the tarball for its Zend API when there is none. It also always
  prints the ini scan directory.
- The install picker offers cPanel, Plesk, CloudLinux and distribution EL PHP,
  with the repository and package commands for each.
- Event log schema 2. Every line gains `schema` (the integer 2), `version`
  (the extension version) and `layer` (1 request-shape limits, 2 input
  inspection, 3 sinks, 4 after-breach behaviour, derived from the rule). The
  eight fields of 1.0 to 1.4.0 keep their names and types, so existing
  consumers keep working. The contract is `docs/log-schema.md`, with a JSON
  Schema in `docs/howdah-event.schema.json`; tests check both against what the
  code writes for every rule.
- `[log] destination = "file" | "syslog" | "stderr"` in the TOML file, with
  `syslog_facility` (default `local0`) and `syslog_ident` (default `howdah`).
  The default, `file`, is the 1.x behaviour. Syslog lines go to `/dev/log`
  framed as glibc frames them (severity warning for `block`, notice for
  `log`), written by Howdah itself rather than through `openlog()`, which PHP
  owns and resets at the end of every request. The socket is a non-blocking
  datagram socket: a missing socket, a full daemon queue or a stream socket
  (some syslog-ng setups; glibc's stream fallback is deliberately not copied)
  sends the line to stderr, and the request never waits.
  `lab/integration/log_contract.sh` tests it on PHP 7.4 and 8.3 under the
  built-in server, php-fpm and Apache mod_php prefork; a run against a real
  journald was done by hand.
- `[log] exec`: run a program once per event with the JSON line on stdin.
  Off unless set; the path must be absolute. The program gets no arguments,
  an environment of only `HOWDAH_RULE`, `HOWDAH_ACTION` and a fixed `PATH`,
  no inherited descriptors besides stdin/stdout/stderr (plus one for itself),
  and its own session. It is double-forked, so it is never a child or zombie
  of the PHP worker, and Howdah does not wait for it. At most
  `exec_rate_limit` starts per second per PHP process (default 10, 1 to 100).
  On every event the program is opened without following a symlink and
  checked on that descriptor (a regular executable file, not group- or
  world-writable, owned by root or the PHP user, in a directory that is not
  group- or world-writable), and that same file is run through
  `/proc/self/fd`, so it cannot be swapped between check and start. It runs
  as the PHP worker user: see the security notes in `docs/config.md`.
- `php --ri howdah` rows `Log hook ([log] exec)` (when set) and
  `Log schema => 2`.
- SIEM starting points in `docs/integrations/`: a Wazuh decoder and rules
  (event file or syslog) and a Promtail pipeline for Loki, run against real
  event lines in wazuh-manager 4.12.0 and Promtail 3.5.1 by
  `lab/integration/siem_snippets.sh`.
- `lab/integration/log_contract.sh`: `[log] path`, the three destinations and
  the hook against the real extension, under `php -S`, php-fpm and Apache
  mod_php prefork.
- Docker images: `ghcr.io/howdah/howdah:<version>-php<minor>` is the official
  `php:<minor>-fpm` image (5.6, 7.0 to 7.4, 8.0 to 8.5; amd64 and arm64) with
  the release's signed `howdah.so` installed in detect mode
  (`docker/Dockerfile`). The build verifies `SHA256SUMS` against the committed
  key and the tarball against `SHA256SUMS`, and keeps both in the image so it
  can be re-verified. Every image also carries its files under `/howdah/`, so
  `COPY --from=ghcr.io/howdah/howdah:<version>-php<minor> /howdah/ /` adds
  Howdah to any official image of that minor in one line.
  `.github/workflows/docker.yml` publishes them after the release workflow for
  a tag (and on demand, and weekly for the newest release), and pushes only
  after `docker/smoke.sh` passes: the lab self-test on the CLI server and
  `howdah-check web` through nginx to php-fpm. Nothing is published yet; see
  `docs/install-docker.md`, which also lists the end-of-life bases.
- Alpine (musl) builds: `HOWDAH_LIBC=musl packaging/build-release.sh` builds
  `howdah-<version>-php<minor>-<api>-linux-x86_64-musl.tar.gz` on Alpine 3.21
  (`packaging/release.musl.Dockerfile`); the release workflow builds one per
  minor (best effort, like aarch64), and `docker.yml` turns them into
  `-alpine` images. Loaded on musl 1.1.18 to 1.2.6; needs `apk add libgcc` on
  Alpine before 3.21. x86_64 only.
- `howdah-check detect` prints `host libc`, names the `-musl` tarball on
  Alpine, and recognises three more layouts: `docker` (official php images;
  it names the image and the `COPY --from` line), `alpine` (apk PHP) and
  `litespeed` (LiteSpeed's lsphp; tarball). The install picker has a Docker
  choice.
- `lab/integration/lsapi.sh`: the self-test under OpenLiteSpeed with
  LiteSpeed's lsphp 8.3, using the released tarball. It passed; recorded in
  `docs/coverage.md` with the other runs outside the matrix (new Table 5, from
  `lab/integration/runtime-results.tsv`; also on the site's coverage page).
- CI: non-blocking `lab-aarch64` jobs (the lab's block-shaped and self-test
  scripts for PHP 7.4 and 8.3 on native arm64 runners), a non-blocking musl
  build smoke, and a Docker image job that builds the 1.4.0 PHP 8.3 image and
  runs `docker/smoke.sh`.
- `docs/zts.md`: why there is no ZTS build (FrankenPHP, threaded Apache). A
  test build compiles with three small changes but crashed FrankenPHP under
  concurrent requests; the page lists every process-global (file:line) that
  has to move into per-thread module globals first.
- Drafts, not sent, of inclusion requests to Remi's repository and to
  deb.sury.org, with what a distribution `.spec` and `debian/` would need
  (`docs/distro-requests/`).
- Build provenance and SBOM attestations. The release workflow attests every
  tarball, `howdah-check` and `SHA256SUMS` with SLSA v1 build provenance
  (`actions/attest-build-provenance`, signed through Sigstore with the
  workflow's OIDC identity) and binds a CycloneDX SBOM of `howdah.so` to each
  flavour's tarballs (x86_64, aarch64, x86_64-musl), after the GPG signing,
  which is unchanged. The SBOM comes from `packaging/sbom.sh` (pinned,
  sha256-checked cargo-cyclonedx) in a separate read-only job; only the
  release job gets `id-token: write` and `attestations: write`. The Sigstore
  bundles ship as release assets (`*.sigstore.json`) for offline checks with
  cosign. `publish-repos.yml` attests the `.deb` and `.rpm` files each real
  publish builds (the pool `.deb`, the `.rpm` after `rpmsign`), main and
  layout repositories. `attest-selftest.yml` (manual) runs the same steps on
  dummy files and verifies them. Releases up to 1.4.0 have no attestations.
- Reproducible release tarballs: the same commit gives byte-identical
  tarballs. The release compiler is pinned in `packaging/rust-toolchain.toml`
  (Rust 1.99.1, the compiler that built 1.4.0) and every release image
  installs it; `centos:7` is pinned by digest; `--remap-path-prefix` drops
  builder paths from `howdah.so`; each tarball is written by a deterministic
  tar in the release image (sorted, modes normalised, owner 0/0, mtime
  `SOURCE_DATE_EPOCH` = the tag's commit date, `gzip -n`). Two clean builds
  of one commit gave identical PHP 7.4 and 8.3 x86_64 tarballs. `.deb`
  packages are reproducible for a given dpkg; `.rpm` payloads are, but EL7's
  rpm stamps the build time in the header.
- `packaging/verify-reproducible.sh <tag> <minor> [x86_64|aarch64|x86_64-musl]`:
  checks the signed `SHA256SUMS`, rebuilds the minor with the tag's own build
  scripts and reports `MATCH` or `MISMATCH`, with the `howdah.so` sha256 from
  both tarballs. Against 1.4.0 PHP 7.4 the tarball differs (it predates this)
  and the `howdah.so` is byte-identical.
- CI: a `deps` job. `cargo deny check` (advisories, licences, bans, sources;
  policy in `deny.toml`) is a hard check; it passes today, with warnings only
  (three duplicate crate versions, and the workspace path dependencies
  counted as wildcards). `npm audit --omit=dev` for the site and worker is
  reported but does not gate: `site/scripts/audit-summary.mjs` writes the
  counts by severity and every advisory to the job summary and adds one
  warning annotation, and the step's `continue-on-error` keeps the job green.
  At introduction it reports 5 vulnerable packages (1 critical, 3 high,
  1 low) and 16 advisories: astro 5.18.2 critical GHSA-26w7-cxv4-gfx2 (remote
  code execution through AVIF image optimisation) plus 2 high and 8 moderate
  or low astro advisories; sharp (libvips, libheif, librsvg), zod and
  zod-to-ts high; esbuild low. All of them need the upgrade to astro 7, a
  breaking change and a separate item for the owner.
- Measured numbers, published at https://howdah.org/docs/performance/ and in
  `docs/performance.md`, from three new lab harnesses under `lab/bench/`:
  `run.sh` (request latency with no extension, Layer 1, Layers 1+2 and
  Layers 1+2+3, for a GET with no body, a 1 KB form, a 50 KB multipart body
  and a `system()` + `include` script, on PHP 5.6, 7.4 and 8.3 under php-fpm
  behind nginx and Apache mod_php, with the machine spec recorded; Layer 4 is
  not measured), `corpus.sh`
  (what Layer 2 flags of the GoTestWAF corpus, and its false positives on
  GoTestWAF's benign set; framed as what a narrow log-only layer catches, not
  a WAF score) and `jit.sh` (whether the OPcache JIT stays on with Howdah at
  the shipped defaults and with `[sinks] hook = "opcode"`, plus the
  integration suite with the JIT configured; jit_on is reported as measured).
  The published JIT run predates #42 and shows the JIT off on PHP 8.1, 8.3
  and 8.5 with Howdah loaded; it has not been re-run against #42 yet. The
  latency and corpus runs also predate #42 and #44; the page names the commit
  each one measured.
- A `bench` CI job: a short latency run on PHP 8.3 that fails if Howdah adds
  more than 50 µs to the median GET with no body, or if any cell regresses
  more than 25% against `lab/bench/baseline-ci.json` (normalized to the same
  run's no-extension cell). The limits are deliberately loose because
  GitHub-hosted runners are noisy. No other job depends on it.

### Changed
- `lab/integration/selftest_container.sh` takes `PREINSTALLED=1` to test a PHP
  that already loads howdah from its own ini (the Docker images) instead of
  building the extension.
- Known behaviour, now documented (`docs/install-docker.md`): under php-fpm
  a refused multipart request ends the worker (`exited with code 70`), and
  behind nginx the 403 usually arrives without the Howdah body because the
  unread request body resets the connection. The event is logged either way.
  The fix is PR #44; the request ids that repeat across forked workers in
  1.4.0 are fixed by PR #39.
- `docs/install-repos.md` no longer says the apt index lists only the latest
  publish (it keeps every version), and says the Debian/Ubuntu package also
  fits the distribution's own PHP, which provides the same `phpapi-<N>`
  (checked with Ubuntu 20.04's PHP 7.4).
- The `php --ri howdah` row `Log (howdah.log)` is now `Log destination` and
  shows where lines actually go, for example
  `/var/log/howdah/events.log (from [log] path)` or
  `syslog (/dev/log, facility local0, ident howdah)`.
- The config editor and `cfg.howdah.org` refuse to load a file with any
  `[log]` key (before, only `path`), because the form cannot carry the new
  keys and a round trip would drop them.
- A log file Howdah creates now gets mode 0640 minus the umask (it was 0666
  minus the umask, usually world-readable). Existing files keep their mode.
- An armed Layer 2 class (`[inspect] mode = "block"`, or a `rule_modes`
  entry) now refuses the request **before the script runs** on php-fpm,
  Apache mod_php, php-cgi and the CLI server, instead of after it. `$_GET`,
  `$_POST` and `$_COOKIE` are scanned while PHP builds them at request
  startup; when Layer 2 is armed Howdah also builds `$_SERVER` at RINIT, so
  the request path (`REQUEST_URI`, `PATH_INFO`) is scanned before the script
  instead of at the script's first `$_SERVER` access, and the Layer 1 header
  count and size limits move in front of the script with it (header values
  are not a Layer 2 input). That `$_SERVER` build is the one cost
  of arming Layer 2 on an application that never reads it; the log-only
  default does not pay it. The Layer 1 input-shape rules (`max_input_vars`,
  `max_input_nesting_depth`, `max_input_key_bytes`) move with it and are also
  refused before the script. The request-header rules stay post-hoc when the
  script builds `$_SERVER` lazily. Lab-verified on 5.6, 7.4 and 8.3 under
  php-fpm behind nginx and Apache mod_php prefork: a SQLi-, traversal- or
  command-injection-shaped parameter in GET, POST or a cookie gets a 403 and
  the script's side effect does not happen (`lab/integration/refusal.sh`).
  `docs/config.md` "Enforcement timing" lists what is refused before the
  script and what stays post-hoc, per SAPI.
- Release tarball entries are owned by 0/0 (they were the CI user, uid 1001,
  so `sudo tar -x` left files owned by that uid) with fixed modes. The
  `Installed-Size` of the `.deb` packages is counted from file sizes, not
  `du -sk` (which gave 12 KiB on tmpfs and 40 KiB on ext4 for one test tree),
  so it is a few KiB different from earlier packages.

### Fixed
- Loading Howdah turned OPcache JIT off on PHP 8 whatever the configuration,
  even with `[sinks] enabled = false`: the `include`/`eval` guard on PHP 7.0+
  is a user opcode handler, installed unconditionally at startup, and PHP
  refuses to run the JIT alongside one ("JIT is incompatible with third party
  extensions that setup user opcode handlers"). A hook is now installed only
  when something needs it, decided once at startup: the `eval` sink is on
  (the shipped default), the `include` sink is on with `allow_paths`, or
  `[behavior] deny_exec_dirs` is set; with those off nothing is installed.
  New key `[sinks] hook = "auto" | "opcode" | "compile"`. `auto` (the
  default) uses the `zend_compile_file`/`zend_compile_string` swap PHP 5.x
  already uses when only `eval` needs the hook (it covers every `eval` and
  the JIT check does not see it), **so a default install now keeps the JIT
  on**, and the opcode handler when `include` has `allow_paths` or
  `deny_exec_dirs` is set, where an `include` served from a warm opcache
  matters (the compile swap does not re-inspect those). `opcode` and
  `compile` force one or the other. Whenever the opcode handler is what gets
  installed and php.ini has the JIT on, one startup line in the SAPI error log
  says PHP will turn it off and names `hook = "compile"`. `php --ri howdah`
  gains `Include/eval hook => none | opcode handler (JIT disabled by PHP; <why>) | compile pointer (JIT compatible; <why>)`
  with the reason (`auto: eval only`, `auto: include allow_paths set`,
  `auto: deny_exec_dirs set`, `configured`; "JIT disabled by PHP" is said
  only when php.ini has the JIT on). Files `require`d by an `opcache.preload`
  script chain through the compile hook unguarded. MINIT now refuses a
  `dl()` load (`MODULE_TEMPORARY`) with a clear error-log line, since the
  process-wide hooks cannot be unloaded at request end. `lab/integration/jit.sh` checks
  `opcache_get_status()['jit']['on']` in each state on PHP 8.1 and 8.3
  (default config on, `eval` detect still logging; include `allow_paths` off;
  `hook = "compile"` on) and the compile-mode behaviour on 7.4 and 5.6.
- `[log] path` in the TOML file was parsed but ignored. It is now used when
  `howdah.log` is empty; `howdah.log` still wins when both are set.
- Request ids repeated across php-fpm workers and Apache prefork children:
  each worker forked with the parent's id counter and hash keys, so the lab
  saw three FPM workers log the same id. The id now also hashes the process
  id and the clock.
- An event line was written to the log file in two `write()` calls (the line,
  then the newline), so lines from concurrent workers could interleave. It is
  one call now.
- Stale trust surfaces: `SECURITY.md` (supported versions, scope, response
  times, key fingerprint), the site status banner (now names all three
  layers), the config editor notes that said `include`/`eval` are PHP 7.0+
  only (they are active on 5.x since 1.3), and the "not live yet" banners in
  `docs/install-repos.md` and `packaging/repo/GO-LIVE.md`. Added issue and
  pull request templates.
- The browser demo ran a stale core: `site/demo/howdah_wasm.wasm` was a
  committed binary last built at 1.0 and nothing in the site deploy rebuilt
  it. The wasm is no longer committed; the Pages workflow builds it from the
  same commit it deploys, and the site build fails if it is missing.
- A Layer 1 refusal killed the php-fpm worker and lost the response body.
  The multipart callback and the Layer 4 main-script check refused with
  `zend_bailout()` from inside `php_request_startup()`, whose `zend_try` turns
  that into a startup failure; php-fpm answers a startup failure with a forced
  close and `exit(70)` (the master logs `child N exited with code 70` and
  respawns the worker on every blocked request), nginx logs `readv() failed
  (104: Connection reset by peer)` and forwards a 403 with an empty body, and
  `howdah-check web` reports "refused (HTTP 403) but not by Howdah". The same
  on 5.4 to 8.3; the matrix never saw it because it drives php-fpm with
  `cgi-fcgi`. A refusal decided during request startup is now recorded and
  delivered at the end of Howdah's RINIT: the 403/413 with the same body and
  request id goes out through the SAPI, and `zend_compile_file` is swapped for
  the rest of that request so the script (and `auto_prepend_file`) never
  compiles. No longjmp; the request ends normally and the worker survives.
  Output handlers started at request startup (`output_handler =
  ob_gzhandler`) are discarded after the refusal body, so no "headers already
  sent" warning follows it. A CLI main script refused by `deny_exec_dirs`
  prints the notice on stdout, does not run, and exits 0 (measured on 5.6,
  7.4 and 8.3); cron jobs should watch the log line, not the exit status.
  Armed Layer 3 sinks never bailed (they neutralise the call) and are
  unchanged. `lab/integration/refusal.sh` puts a real nginx in front of a
  single-worker php-fpm (plus Apache mod_php prefork) and checks the status,
  the body, the worker pid, the php-fpm log and nginx's error log on 5.6, 7.4
  and 8.3; run against 1.4.0 it reproduces the exits. Design note:
  `docs/superpowers/specs/2026-10-24-howdah-refusal-path-design.md`.

### Docs
- A compliance evidence page, `docs/compliance.md` and
  https://howdah.org/docs/compliance/ (linked from the docs index and the
  footer). It maps each bullet of PCI DSS 4.0.1 requirement 6.4.2 to what
  Howdah does, the evidence to collect and what Howdah does not do; states
  that acceptance of in-process enforcement for "installed in front of" is the
  assessor's call; documents the log fields against PCI DSS 10.2.2;
  gives a sample retention, rotation and off-host shipping setup, a
  decision-record template for rule modes and allowlists, and `jq`/`awk`
  one-liners for a blocked-attack summary; and covers end-of-life questions
  on cyber-insurance forms, NIS2, SOC 2 and HIPAA. It says plainly that it is
  not legal advice or a certification and that Howdah has had no third-party
  audit.
- The configuration page's log example used field names the extension never
  writes (`id`, `ip`, an ISO timestamp) and said events could go to syslog
  when they could not. It and the home page now show real lines from a lab
  run, and the configuration page documents every field, the three
  destinations, the hook and a "Ship to a SIEM" section. `docs/config.md`
  documents rotation (the file is opened per event, so rename-based rotation
  and `copytruncate` both work without a reload) and file permissions.
- `docs/verify.md` and https://howdah.org/docs/verify/ (linked from the docs
  index, the footer and the install page): the GPG fingerprint check,
  `SHA256SUMS.asc`, `gh attestation verify` and the cosign offline check,
  the SBOM, the reproducible rebuild with what is pinned and the residual
  causes of a mismatch, and how to tie an apt or yum package to the signed
  tarball. `SECURITY.md` and `docs/install-repos.md` link to it, and
  `SECURITY.md` names the reproducible rebuild as the independent
  verification path.
- `docs/security-audit-brief.md`: the scope (C shim and FFI boundary, hook
  installation and displacement, multipart parser, log writer and exec hook,
  config parsing, fail-open guarantees), threat model, artefacts and the
  assumptions we want an independent audit to challenge. Howdah has had no
  third-party audit yet.

## [1.4.0] - 2026-10-24

### Added
- Layer 4, "after a breach": a new `[behavior]` config section (no new php.ini
  directives). **Log-first and off-safe by default:** `behavior.mode` defaults
  to `detect`, is independent of `howdah.mode`, and every list is empty, so a
  fresh install blocks nothing. Four facets: `deny_exec_dirs` (PHP run from a
  denied directory, as the requested script or `require`d by another script),
  `allow_exec_binaries` (exec-family call to a program not on the list),
  `allow_egress_hosts` (outbound connection to a host not on the list) and
  `deny_php_writes` (a PHP file written into a denied directory or from a script
  under one; origin-scoped, so ordinary template compilation elsewhere is not
  flagged). New rule ids `upload_exec`, `unexpected_binary`,
  `unexpected_egress` and `php_write`, all Standard severity. Events name the
  script that made the call.
- `behavior.observe = true` logs would-be findings as `proposed` lines to help
  build the allowlists. It never blocks and never writes config.
- Verified by a lab script (27 checks) on PHP 5.4, 5.6, 7.4, 8.3, 8.4 and 8.5.
- The config editor labels the four new rule ids as having no effect under
  `[rules]` (use `[behavior] mode`).

### Known limits
- Howdah only sees what PHP itself does; a detached or forked process, or a
  dropper that never ran through PHP, is invisible.
- The main-script check does not depend on opcache; the `require`d-file check
  is first-compile, best-effort. A `require` with a relative path is not
  checked at include time on any version.
- Allowlists are best-effort and bypassable. `.php`-write detection is by
  target extension and can still flag frameworks that write compiled templates
  into a denied directory. Observe only proposes.
- On PHP 7.0+ Howdah installs a user opcode handler (for include/eval) at
  MINIT, which turns OPcache JIT off; this is unchanged since 1.3 and
  independent of Layer 4.

### Changed
- Version bumped to 1.4.0.

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

### Fixed
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
