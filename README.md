# Howdah

**An open-source, defensive web application firewall for PHP, built as a native
extension.**

Howdah loads into PHP itself and inspects requests before PHP processes them,
so it can stop abuse that a network-level WAF never sees. It is a *defensive*
tool: it recognizes and blocks abusive input. It is not a hacking tool, and it
is not a replacement for patching PHP. Upgrade when you can; use Howdah when you
can't, or until you can.

> **Status: 0.1.0 is released ("PHP2Shell shield").** Signed tarballs for PHP
> 5.4 to 8.5 are on the [v0.1.0 release page](https://github.com/howdah/howdah/releases/tag/v0.1.0).
> It is an early 0.x release with a deliberately narrow scope, and defaults may
> still change. Start in `detect` mode. Not every PHP version has been tested:
> see [docs/coverage.md](docs/coverage.md). Install, verify and rollback steps
> are on the project site (built from `site/`).

## What 0.1 does

Version 0.1 has one job: block abusive `multipart/form-data` requests that
carry a flood of parts or files (the *shape* of the PHP2Shell attack, and of
older issues such as CVE-2023-0662) before they exhaust worker memory.

- Counts parts and files as PHP parses the body and refuses the request once a
  limit is crossed. Runaway shapes are always blocked; the mode setting
  (`off`, `detect`, `block`) covers the rest.
- The core logic is pure Rust (`howdah-core`) behind a thin glue layer
  (`howdah-ext`), with unwinding panics caught at the FFI boundary.
- Logs are privacy-conscious: shape and counts, not request contents.

What it does **not** do: it is not a general WAF in 0.1, it does not scan for
SQL injection or XSS, and it does not fix the underlying PHP bug. We do not
claim it blocks CVE-2026-109618 on a stock configuration; see
[docs/coverage.md](docs/coverage.md) for what has actually been tested.

## PHP versions

Built to target PHP 5.4 through 8.5 on Linux (NTS builds; CLI, FPM and Apache
mod_php). Release tarballs ship for **x86_64 and aarch64** on a glibc-2.17
baseline. x86_64 covers all 14 minors. aarch64 is provided for the minors whose
from-source build succeeds in CI on native arm64 runners (Remi has no aarch64
EL7 packages), and **PHP 5.x on aarch64 is best-effort** (old `./configure` may
not detect aarch64); the release assets are the definitive per-arch list. The
core is arch-agnostic pure Rust, but arm64 is build-verified only: the full
scenario matrix has run on x86_64 alone. Not every minor is tested yet. [docs/coverage.md](docs/coverage.md)
is the source of truth for which versions and SAPIs have been exercised.

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
[v0.1.0 release](https://github.com/howdah/howdah/releases/download/v0.1.0/howdah-check)
(it is also bundled in each tarball):

```sh
tools/howdah-check detect              # list PHP installs and whether Howdah is loaded
tools/howdah-check web https://host/   # self-test over HTTP
```

## Documentation

- [Coverage](docs/coverage.md): what has been tested, and where
- [Design document](docs/superpowers/specs/2026-10-22-howdah-design.md)
- [0.1 implementation plan](docs/superpowers/plans/2026-10-22-howdah-0.1-php2shell-shield.md)
- Project site: built from `site/` and published with GitHub Pages

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md). Howdah's own
reproducers only reproduce the harmless request shape, never working exploits.

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
