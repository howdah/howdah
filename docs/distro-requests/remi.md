# Draft: request to Remi Collet to package Howdah (not sent)

For the maintainer to read, check and send himself. Nothing here has been
sent. Where it goes: an issue on https://github.com/remicollet/remirepo/issues
(the repository README says that tracker is the support and request channel;
package sources are on https://git.remirepo.net/cgit/).

## Read this before sending

- **Remi's AI policy.** The remirepo README (read 24 October 2026) says: "We
  do not accept contributions containing code or other content made, in whole
  or in part, using generative AI tools", and it asks contributors whether AI
  tools were used. This draft was written by an AI agent, and Howdah's own
  source is AI-assisted (the commit trailers say so). A packaging request is
  not a patch to his repositories, but he may well apply the same rule to what
  he packages. Say so plainly in the request rather than let him find out, or
  do not send it. Do not send him a spec file written by an AI tool.
- **Rewrite the request text in your own words.** The facts below are
  checked; the prose is a starting point.
- **Naming clash with our own yum repository.** Remi's convention for a
  non-PECL extension is `php-<name>` in the base and module repositories and
  `phpXY-php-<name>` for the Software Collections (his own spec:
  `Name: %{?scl_prefix}php-snuffleupagus`). Our repository publishes
  `phpXY-howdah` for the same Remi SCL paths. Both would install
  `/opt/remi/phpXY/root/usr/lib64/php/modules/howdah.so` and
  `/etc/opt/remi/phpXY/php.d/40-howdah.ini`, so they conflict. If Remi takes
  it, our `phpXY-howdah` should stop being published for those minors, or
  get `Obsoletes:`/`Conflicts:` so a switch is clean. Decide which before
  asking.

## The request (draft)

> **Title:** Package request: php-howdah (Howdah, a request-shape firewall extension for PHP 5.4 to 8.5)
>
> Hello Remi,
>
> Would you consider packaging Howdah, a PHP extension that refuses abusive
> multipart uploads and oversized request inputs before PHP allocates memory
> for them, and logs (by default does not block) SQL-injection-shaped input
> and dangerous calls such as `system()` and `unserialize()`? It is aimed at
> servers that still run PHP versions with no security support, which is why
> your repository is the natural home: it supports PHP 5.4 to 8.5 from one
> source tree.
>
> - Project: https://github.com/howdah/howdah (site: https://howdah.org/)
> - Licence: MIT OR Apache-2.0 (dual)
> - Latest release: 1.4.0 (tag `v1.4.0`). Source archive:
>   https://github.com/howdah/howdah/archive/v1.4.0/howdah-1.4.0.tar.gz
> - Language: a Rust core and a Rust PHP extension, with a small C shim
>   compiled against the target PHP's headers. It builds with `cargo build
>   -p howdah-ext --features php5|php7|php8 --release --locked`, using
>   `php-config` (set `PHP_CONFIG=%{__phpconfig}`) and `bindgen`, so the
>   build needs `cargo`/`rustc` 1.85 or newer, `clang-devel` (libclang for
>   bindgen) and `php-devel`. The result is `target/release/libhowdah_ext.so`,
>   installed as `howdah.so`.
> - Dependencies linked into the module: 16 crates from crates.io (serde,
>   serde_json, toml and its parsers, hashbrown, indexmap, memchr, itoa, zmij,
>   winnow), all MIT, MIT OR Apache-2.0, or Unlicense OR MIT. Build-only:
>   bindgen (BSD-3-Clause), clang-sys (Apache-2.0), cc and a few others. We
>   can publish a `cargo vendor` tarball with each release so the build needs
>   no network.
> - Runtime: one ini drop-in (`40-howdah.ini`, `extension=howdah.so` plus
>   three settings: `howdah.mode`, `howdah.config`, `howdah.log`), no install
>   scripts, no other files. Optional rules file in TOML.
> - NTS only. There is no ZTS build: the extension keeps per-request state in
>   process globals, so it is not thread-safe yet (documented in
>   `docs/zts.md`).
> - Tests: `cargo test -p howdah-core` (no PHP needed), and a load test
>   `php -n -d extension=.../howdah.so --ri howdah`, which must show
>   `Panic guard (catch_unwind active) => yes`.
>
> We already publish our own yum repository for your SCL layout
> (`phpXY-howdah`, https://pkg.howdah.org/yum), built from a glibc 2.17
> binary. If you package it, we would stop publishing ours for the
> collections you cover, to avoid the file conflict.
>
> Parts of Howdah were written with AI assistance. I mention it because of
> your policy, so you can decide with that in mind.
>
> Thank you for considering it.

## What a proper `.spec` needs beyond `packaging/rpm/`

`packaging/rpm/howdah.spec.in` and `layout.spec.in` wrap the already-built
release binary (`Source0` is the release `howdah.so`). A distribution spec
builds from source in a clean buildroot (mock or Koji) with no network, so it
needs things this repository does not have yet:

1. **A source build.** `%build` runs `cargo build --offline --frozen` with the
   feature for the PHP generation (`php5` for 5.x, `php7`, `php8`), picking it
   from `%{php_version}`, with `PHP_CONFIG=%{__phpconfig}` so the SCL's
   headers are used. `BuildRequires: php-devel`, `cargo`/`rust-toolset`,
   `clang-devel`. The locked dependency set needs Rust 1.85 or newer; check
   what `rust-toolset` provides on each EL target.
2. **Vendored crates.** Fedora's Rust guidelines (rendered copy read through
   a search engine; docs.fedoraproject.org refused automated access, so re-read
   them) say packages SHOULD NOT bundle crates and that a vendor tarball is a
   last resort; when it is used, `%cargo_prep -v vendor`,
   `%cargo_vendor_manifest` in `%build`, `cargo-vendor.txt` under `%license`,
   and automatically generated `Provides: bundled(crate(...))`. Remi is not
   Fedora and may simply use a vendor tarball (`Source1`); we should publish
   one (`howdah-<version>-vendor.tar.xz`) as a signed release asset either way.
3. **License tag** for the binary: Howdah's `MIT OR Apache-2.0` plus the
   statically linked crates, roughly `(MIT OR Apache-2.0) AND MIT AND
   (Unlicense OR MIT)`; generate it rather than trust this line
   (`%cargo_license_summary` or `cargo license`).
4. **ABI requires** the way Remi's own extensions do:
   `Requires: %{?scl_prefix}php(zend-abi) = %{php_zend_api}` and
   `Requires: %{?scl_prefix}php(api) = %{php_core_api}` (our spec has only
   the first).
5. **No ZTS subpackage.** Fedora's PHP guidelines expect a ZTS build where
   the extension is thread-safe; Howdah is not, so the spec builds NTS only
   and says why.
6. **`%check`**: the module loads with `--no-php-ini --define
   extension=%{buildroot}%{php_extdir}/howdah.so --modules`, the panic guard
   line, and `cargo test -p howdah-core --offline`.
7. **Debuginfo and flags.** Fedora's `%build_rustflags` must not turn on
   `panic=abort`; the panic guard is what keeps a bug from crashing PHP. The
   `%check` line above catches that.

## Sources

- remirepo README and contributing notes:
  https://github.com/remicollet/remirepo (README read 24 October 2026)
- Remi's spec for a comparable non-PECL extension:
  https://git.remirepo.net/cgit/rpms/php/php-snuffleupagus.git/plain/php-snuffleupagus.spec
  (`Name: %{?scl_prefix}php-snuffleupagus`, `40-%{pecl_name}.ini`,
  `php(zend-abi)` and `php(api)` requires, the `--no-php-ini ... --modules`
  load test)
- Fedora PHP and Rust packaging guidelines:
  https://docs.fedoraproject.org/en-US/packaging-guidelines/PHP/ and
  https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/ (behind a
  bot check when this was written; the points above come from rendered copies
  and should be re-read)
- Crate licences: `cargo metadata --features howdah-ext/php8` on the 1.4.0
  lock file, runtime dependencies only.
