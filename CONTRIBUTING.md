# Contributing to Howdah

Thanks for your interest. Howdah is a **defensive** web application firewall for
PHP, and contributions are welcome — bug reports, test cases, documentation,
platform notes, and code.

## Ground rules

- **Defensive only.** Howdah recognizes and refuses abusive requests. We do not
  accept offensive tooling, exploit code, or working attack payloads. Test
  fixtures reproduce only the harmless *shape* of a request (counts and sizes),
  never a real exploit — see the design doc and `lab/integration/corpus`.
- **No overclaiming.** Every protection claim must be backed by a test or an
  honest measurement. If a change adds a rule, it adds the test that proves the
  rule fires, and the coverage data is regenerated (`node site/scripts/gen-coverage.mjs`).
- **Never take PHP down.** The extension fails open: a bug in Howdah must never
  crash or wedge the PHP it runs inside. Panic-guarded FFI, best-effort blocking.
- Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a security issue

Do **not** open a public issue for a vulnerability. Follow the
[security policy](SECURITY.md) (GitHub private vulnerability reporting).

## Bugs and features

Open a GitHub issue. For a bug, include the Howdah version, PHP version and SAPI
(FPM / Apache / CGI), your OS and how PHP was installed (distro, Surý, Remi,
panel), your relevant `howdah.*` config, and what you expected versus what
happened. `howdah-check detect` output is very helpful.

## Working on the code

The project is a pure-Rust core (`crates/howdah-core`, no PHP types — all logic,
tests and fuzzing live here) plus thin per-PHP-generation C-ABI glue
(`crates/howdah-sys`, `crates/howdah-ext`). The lab (`lab/`) builds each
supported PHP in a container to exercise the real extension.

- Run the core tests on your host: `cargo test -p howdah-core`.
- Run clippy before pushing: `cargo clippy --all-targets -- -D warnings`
  (CI enforces this, and the lab images do not ship clippy).
- Glue changes **must** be exercised against real php-fpm and Apache in the lab,
  not just the CLI server — several SAPI-specific lifecycle bugs have only shown
  up there.
- Keep commits focused; follow the existing code's style, comment density and
  honesty of wording.

By contributing you agree your work is licensed under the project's dual
**MIT OR Apache-2.0** license.
