# Howdah

**An open-source, defensive web application firewall for PHP, built as a native
extension.**

Howdah loads into PHP itself and inspects requests before PHP processes them,
so it can stop abuse that a network-level WAF never sees. It is a *defensive*
tool: it recognizes and blocks abusive input. It is not a hacking tool, and it
is not a replacement for patching PHP. Upgrade when you can; use Howdah when you
can't, or until you can.

> **Status: 1.6.1 is released** — Layer 1 (request-parsing limits), Layer 2 (input
> inspection, log-only), Layer 3 (sink hardening, log-first) and Layer 4
> (after-breach behaviour, log-first). 1.6 targets the out-of-memory class the
> PHP2Shell advisories describe (CVE-2026-109618): a last-resort backstop that
> logs and exits the worker cleanly on PHP's out-of-memory fatal, and
> preventive Layer-1 limits on multipart request parsing (header floods within
> a part, a body past `post_max_size`, deeply/widely nested field names). Run
> against a vulnerable PHP build, the PHP2Shell exploit can no longer land with
> Howdah active. 1.5 added scoped per-rule
> exceptions keyed on the executing script, request parameter, URI or client
> CIDR; more Layer-3 sink guards; a JIT-compatible hook mode so a default
> install keeps OPcache JIT on; structured logging (schema 2) with a syslog
> option; and signed, SLSA-attested releases with container images. Signed
> tarballs for PHP 5.4 to 8.5 are on the
> [v1.6.1 release page](https://github.com/howdah/howdah/releases/tag/v1.6.1).
> See the [changelog](CHANGELOG.md).
> Defaults may still change.
> Start in `detect` mode. Not every PHP version has been tested:
> see [docs/coverage.md](docs/coverage.md). Install, verify and rollback steps
> are on the project site (built from `site/`).

## What Layer 1 does

Layer 1 has one job: refuse abusive request shapes, starting with `multipart/form-data`
requests that carry a flood of parts or files (the *shape* of the PHP2Shell attack, and of
older issues such as CVE-2023-0662) before they exhaust worker memory.

- Counts parts and files as PHP parses the body and refuses the request once a
  limit is crossed. Runaway shapes are always blocked; the mode setting
  (`off`, `detect`, `block`) covers the rest.
- The core logic is pure Rust (`howdah-core`) behind a thin glue layer
  (`howdah-ext`), with unwinding panics caught at the FFI boundary.
- Logs are privacy-conscious: shape and counts, not request contents.

What it does **not** do: it is not a general-purpose signature WAF, it does not fix the
underlying PHP bug, and it does not detect XSS. Layer 2 (in 1.1, see below) detects and logs
SQL injection, path traversal and command/code injection in request values, but it does not
block by default — Layer 1's request-shape limits and the 1.6 out-of-memory backstop are what act out of the
box. In that default configuration Howdah stops the PHP2Shell exploit (CVE-2026-109618) on unpatched PHP: run
against a vulnerable build with Howdah active, the exploit does not land. See
[docs/coverage.md](docs/coverage.md) for the tested runtimes.

## Layer 2: input inspection (in 1.1)

Layer 2 ships in 1.1. It inspects decoded GET/POST/cookie/path values
for SQL injection, path traversal and command/code injection. It **detects and
logs; it does not block by default**, and the matched value is never logged.
Signature inspection is best-effort and can be bypassed. See the `[inspect]`
section of [docs/config.md](docs/config.md) and the [CHANGELOG](CHANGELOG.md).

## Layer 3: sink hardening (1.2, extended in 1.3)

Layer 3 guards dangerous PHP functions ("sinks") with a flat allowlist policy in
the Snuffleupagus style. It **detects and logs; it does not block by default.**
It has its own `sinks.mode`, which defaults to `detect` and is independent of
the global `howdah.mode`: `howdah.mode = block` does not arm sinks. The sink
argument (the command line, the serialized payload, the URL) is never logged.
This is not XSS or output inspection. It is best-effort virtual patching and can
be bypassed; one known gap is that `proc_open` with an array command (PHP 7.4+)
is not inspected.

- `command_exec`, `unserialize` (off by default), `include`/`require` (inert
  until `allow_paths` is set) and `eval`. As of 1.3, include and eval are active
  on PHP 5.x too. On 5.x an `include` served from a warm opcache is not
  re-inspected (`eval` is unaffected).
- **New in 1.3: `phar://` and SSRF guards, both off by default** and armed only
  by an explicit per-sink mode. Phar covers metadata deserialization via the
  wrapper on PHP 5.x/7.x; on 8.x it is detection and denial only. The direct Phar
  API (`new Phar`, `PharData`, `Phar::getMetadata`...) is not covered. SSRF is
  best-effort, resolve-at-check-time detection, not a connection-time boundary
  (DNS rebinding, redirects, `curl_multi_*` and others bypass it), several
  outbound primitives (`copy`, `file`, `readfile`, `SoapClient`...) are not
  hooked, and it adds a DNS lookup with no timeout per distinct outbound host.
- Verified on PHP 5.4, 5.6, 7.4, 8.3 and 8.5; other minors build and are
  expected to work but are not independently verified.

See the `[sinks]` section of [docs/config.md](docs/config.md) and the
[CHANGELOG](CHANGELOG.md).

## Layer 4: after a breach (1.4)

Layer 4 watches what PHP does once something has gone wrong, such as a webshell
dropped in an upload directory. It **detects and logs; it does not block by
default**, and it does nothing until you fill in its lists. It has its own
`behavior.mode` (default `detect`), independent of the global `howdah.mode`.
Four facets, each driven by its own setting:

- **Execution origin** (`deny_exec_dirs`): PHP run from a denied directory,
  either as the requested script or `require`d by another script.
- **Expected binaries** (`allow_exec_binaries`): `exec`/`system`/`popen`/
  `proc_open`/`shell_exec`/`passthru` to a program not on the list.
- **Expected egress** (`allow_egress_hosts`): an outbound connection to a host
  not on the list.
- **`.php` writes** (`deny_php_writes`): writing a PHP file into a denied
  directory, or from a script that lives in one.

`behavior.observe = true` logs what would have been flagged as `proposed` lines
to help you build the lists; it never blocks and never edits config.

Honest limits: Howdah only sees what PHP itself does, so a detached or forked
process, or a dropper that never touched PHP, is invisible. The main-script
check does not depend on opcache; the `require`d-file case is checked at first
compile and is best-effort. Allowlists can be bypassed. The `.php`-write facet
is scoped by origin and can still flag frameworks that compile templates into
such a directory. Observe only proposes. Verified on PHP 5.4, 5.6, 7.4, 8.3, 8.4
and 8.5.

**OPcache JIT.** PHP turns its JIT off whenever an extension installs a user
opcode handler, and one of Howdah's two `include`/`eval` mechanisms on PHP
7.0+ is one. By default (`[sinks] hook = "auto"`) Howdah uses the
compile-pointer mechanism when only `eval` needs guarding (the shipped
default), so **a default install keeps the JIT on**; it switches to the opcode
handler only when `[sinks.include] allow_paths` or `[behavior] deny_exec_dirs`
is set, where an include served from a warm opcache matters, and then writes
one startup line naming `hook = "compile"` as the way to keep the JIT on.
`php --ri howdah` shows which mechanism is in use and why. See `hook` in
[docs/config.md](docs/config.md).

See the `[behavior]` section of [docs/config.md](docs/config.md) and the
[CHANGELOG](CHANGELOG.md).

## Scoped exceptions

`[[exceptions]]` turns one rule off for one executing script (path, glob or
SHA-256), one request parameter, one URI prefix or one client network, with a
mandatory `reason` that is the decision record. Critical Layer 1 rules can
never be excepted. An exception never arms anything and never widens an
allowlist. Starting points for WordPress, Drupal 7, Magento 1 and 2, Joomla
and PrestaShop 1.6 are in [`profiles/`](profiles/README.md). See
[docs/exceptions.md](docs/exceptions.md).

## PHP versions

Built to target PHP 5.4 through 8.5 on Linux (NTS builds; CLI, FPM and Apache
mod_php). Release tarballs ship for **x86_64 and aarch64** on a glibc-2.17
baseline. x86_64 covers all 14 minors. aarch64 builds every minor from PHP
source in CI on native arm64 runners (Remi has no aarch64 EL7 packages); the
release assets are the definitive per-arch list. The core is arch-agnostic
pure Rust. The full scenario matrix has run on x86_64 alone; on arm64 only the
self-test and block-shaped scripts have run. Not every minor is tested yet.
[docs/coverage.md](docs/coverage.md) is the source of truth for which versions,
SAPIs and runtimes have been exercised (LiteSpeed LSAPI and the Docker images
are in its Table 5).

Also: Docker images on the official `php` images
([docs/install-docker.md](docs/install-docker.md)), musl builds for Alpine
from the release after 1.4.0 (x86_64), and LiteSpeed lsphp through the
tarball. There is no ZTS build, so no FrankenPHP or threaded Apache
([docs/zts.md](docs/zts.md)).

## Quickstart

Build and unit-test the pure-Rust parts on any host:

```sh
cargo test --locked -p howdah-core -p howdah-ext
```

The extension itself needs a PHP's headers, so it is built inside a lab dev
image (Rust plus one PHP minor):

```sh
# Shaped-upload block test and EICAR-style self-test on PHP 7.3
lab/integration/block_shaped.sh
lab/integration/selftest.sh

# Another minor, e.g. PHP 8.4
IMAGE=howdah-dev-php8.4 FEATURE=php8 BASE=lab-php-8.4 lab/integration/block_shaped.sh

# Cross-version matrix
lab/integration/matrix.sh 5.6 7.3 8.4
```

Lab base images come from `lab/images/php-X.Y.Dockerfile`; build them first
(tag them `lab-php-X.Y`).

`tools/howdah-check` is a read-only helper for installing and verifying
Howdah on a server. End users can download it on its own from the
[latest release](https://github.com/howdah/howdah/releases/latest/download/howdah-check)
(it is also bundled in each tarball):

```sh
tools/howdah-check detect              # list PHP installs, the Howdah package for each, and whether it is loaded
tools/howdah-check web https://host/   # self-test over HTTP
tools/howdah-check ini                 # read-only report of risky php.ini settings
```

## Documentation

- [Coverage](docs/coverage.md): what has been tested, and where
- [Package repositories](docs/install-repos.md) and [package layouts](docs/packaging-layouts.md): which package fits Surý, Remi, cPanel, Plesk, CloudLinux, distribution and DirectAdmin PHP
- [Config editor](https://howdah.org/config/): build and validate `howdah.toml` in the browser with the extension's own parser
- [Design document](docs/superpowers/specs/2026-10-22-howdah-design.md)
- [0.1 implementation plan](docs/superpowers/plans/2026-10-22-howdah-0.1-php2shell-shield.md)
- Project site: built from `site/` and published with GitHub Pages

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). Howdah's own
reproducers only reproduce the harmless request shape, never working exploits.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
