# Draft: deb.sury.org feature request for Howdah (not sent)

For the maintainer to read, check and send himself. Nothing here has been
sent. Where it goes: a new issue at
https://codeberg.org/oerdnj/deb.sury.org/issues using the **Feature Request**
template, after reading the FAQ
(https://codeberg.org/oerdnj/deb.sury.org/wiki/Frequently-Asked-Questions).
The FAQ asks people to try to solve things themselves first, to use the
templates, and says Ondřej does this in his own time and does no user
support; it lists Freexian LTS contracts and Patreon as the ways to support
the repository. A comparable open request, #97 (ext-deepclone, May 2026),
had no reply when this was written.

## Read this before sending

- **This draft was written by an AI agent, and Howdah's source is
  AI-assisted.** No AI policy was found for deb.sury.org, but rewrite the
  text in your own words and be ready to say so if asked.
- **The package name is the same as ours.** Howdah's apt repository already
  ships `phpX.Y-howdah` (`Depends: phpapi-N, phpX.Y-common`), the per-version
  naming Surý's own extension builds use. A Surý build would carry the same
  name with a higher version string (`1.4.0-1+...deb.sury.org+1` sorts after
  our `1.4.0-1`), so apt would take his when both repositories are enabled.
  The files are the same paths, so nothing breaks, but say in the request
  which repository users should keep, and update `docs/install-repos.md` if
  he accepts.
- **The Rust toolchain is the hard part.** Howdah's locked dependencies need
  Rust 1.85 or newer. Debian 12 (bookworm) ships rustc 1.63 and Debian 13
  (trixie) 1.85. On Ubuntu 22.04 and 24.04 the default `rustc` is, as far as
  we know, older than 1.85, though versioned `rustc-1.8x` packages exist on
  some releases; check. A clean source build for bookworm and those releases
  therefore needs a newer toolchain in his builders, or Howdah lowering its
  minimum Rust version (pinning older crates). Find out which before asking;
  it decides whether the request is realistic.

## The request (draft)

> **Title:** Feature request: phpX.Y-howdah (Howdah request-shape firewall extension, PHP 5.6 to 8.5)
>
> - [x] I have read the FAQ
>
> **What:** Howdah, a PHP extension that refuses abusive multipart uploads
> and oversized request inputs before PHP allocates memory for them, and logs
> (by default does not block) SQL-injection-shaped input and dangerous calls
> such as `system()` and `unserialize()`. Its main audience runs PHP versions
> that no longer get upstream fixes, many of them from this repository, which
> is why I am asking here.
>
> - Project: https://github.com/howdah/howdah, release 1.4.0 (tag `v1.4.0`)
> - Licence: MIT OR Apache-2.0
> - Builds against PHP 5.4 to 8.5 from one source tree; NTS only (not
>   thread-safe yet).
> - Build: `cargo build -p howdah-ext --features php5|php7|php8 --release
>   --locked` with `PHP_CONFIG` pointing at `php-configX.Y`; needs rustc 1.85
>   or newer, `libclang-dev` (bindgen) and `phpX.Y-dev`. 16 crates from
>   crates.io are linked in (MIT, MIT OR Apache-2.0, Unlicense OR MIT); we can
>   publish a `cargo vendor` tarball with each release for an offline build.
> - Install footprint: `howdah.so` in the extension directory and one
>   `mods-available/howdah.ini` (`extension=howdah.so` and three settings),
>   enabled with `phpenmod`. No other files, no services.
>
> **Why here:** we already publish `phpX.Y-howdah` in our own signed apt
> repository (https://pkg.howdah.org/apt) for your PHP builds, from a
> prebuilt glibc 2.17 binary. Built in your infrastructure it would follow
> your PHP updates and your release cadence, and users would not need a
> second repository.
>
> **Help offered:** I can maintain the `debian/` directory upstream, keep a
> vendor tarball in every release, and fix build failures on your
> distributions. Parts of Howdah were written with AI assistance; I mention it
> so you can decide with that in mind.

## What a proper `debian/` needs beyond `packaging/deb/`

`packaging/deb/build-deb.sh` builds binary-only packages around the release
`howdah.so`; there is no source package. Surý and Debian both build from
source, so a `debian/` directory needs:

1. **A source package with per-version binaries.** Surý's extension sources
   build one `phpX.Y-<ext>` binary for every PHP version installed in the
   build environment (the `dh-php` tooling the Debian PHP team keeps on
   salsa.debian.org; compare a current Surý source such as `php-redis`).
   `debian/rules` loops over the versions, runs `cargo build --offline` with
   the right feature and `PHP_CONFIG=php-configX.Y`, and installs into
   `$(php-configX.Y --extension-dir)`.
2. **No network in the build.** Debian policy and the Debian Rust team policy
   (https://wiki.debian.org/Teams/RustPackaging/Policy) say "Package builds
   must not allow Cargo to access the network when building." For Surý's
   repository a vendor tarball as a second upstream tarball
   (`howdah_1.4.0.orig-vendor.tar.xz`) would do it.
3. **For Debian proper, no vendoring.** The Rust team policy has application
   packages build-depend on the packaged crates (`librust-*-dev`) via
   `dh-cargo`/`debcargo`, and says it "does not yet specify any policies for
   'cdylib' crates". All 16 runtime crates and the build-time ones (bindgen,
   clang-sys, cc, ...) would have to be in Debian at versions that satisfy
   Howdah's `Cargo.toml`. That is a separate, larger project than Surý's
   repository, and it starts with an ITP bug against `wnpp`, a sponsor (for
   example through mentors.debian.net) and a lintian-clean package.
4. **`debian/copyright` in DEP-5 form** covering Howdah and, if vendored,
   every crate's copyright holders and licences.
5. **`Depends: phpapi-N`** as our package has, so a build cannot be installed
   on the wrong ABI, plus the `phpenmod` handling `dh-php` provides instead
   of our hand-written `postinst`/`prerm`.
6. **Build-Depends:** `debhelper-compat`, the PHP `-dev` packages,
   `cargo`/`rustc` at 1.85 or newer, `libclang-dev`. See "The Rust toolchain
   is the hard part" above.
7. **Tests:** `cargo test -p howdah-core` and an autopkgtest that loads the
   module (`php -n -d extension=... --ri howdah` showing
   `Panic guard (catch_unwind active) => yes`).

## Sources

- deb.sury.org FAQ and issue #97:
  https://codeberg.org/oerdnj/deb.sury.org/wiki/Frequently-Asked-Questions,
  https://codeberg.org/oerdnj/deb.sury.org/issues/97 (read 24 October 2026)
- Debian Rust packaging policy: https://wiki.debian.org/Teams/RustPackaging/Policy
- Rust 1.85 minimum: `cargo` 1.83 refuses the 1.4.0 lock file
  (`serde_spanned 1.1.2` needs `edition2024`), seen while testing an Alpine
  3.21 build.
- Crate licences: `cargo metadata --features howdah-ext/php8` on the 1.4.0
  lock file, runtime dependencies only.
