# Install Howdah with Docker

> **Status:** the 1.4.0 Debian images are on GHCR (`ghcr.io/howdah/howdah:1.4.0-php<minor>`,
> published by a manual run of `.github/workflows/docker.yml`). The run for
> 1.5.0 (run 40140181320) published nothing: the smoke test still expected
> 1.4.0's php-fpm refusal behaviour, and the 5.6, 7.0 and 7.1 `-alpine`
> builds could not load the module (see "Alpine"). Both are fixed; the 1.5.0
> images come from the next run. You can always build the same image
> yourself (see "Build the image yourself").

The image is the official `php:<minor>-fpm` image with the signed `howdah.so`
from a GitHub release installed and enabled. Nothing is compiled when the
image is built. The build downloads the release tarball for that PHP minor and
CPU, checks `SHA256SUMS` against the committed release key
(`packaging/howdah-release-signing.asc`, primary fingerprint
`1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B`) and the tarball against
`SHA256SUMS`, and fails if `php -m` or `php-fpm -m` does not then list howdah.

Howdah ships in `detect` mode, as in every other package: the critical
multipart limits still block, everything else only logs.

## Tags

| Tag | Base image | Platforms |
|---|---|---|
| `ghcr.io/howdah/howdah:<version>-php<minor>` | `php:<minor>-fpm` (Debian) | `linux/amd64`, and `linux/arm64` when the release has that minor's aarch64 tarball (1.4.0 has all of them) |
| `ghcr.io/howdah/howdah:<version>-php<minor>-alpine` | `php:<minor>-fpm-alpine` | `linux/amd64` only; PHP 7.2 to 8.5 only (see "Alpine"); from 1.5.0, the first release with `*-linux-x86_64-musl.tar.gz` tarballs |
| `ghcr.io/howdah/howdah:php<minor>` and `php<minor>-alpine` | as above | moves to the newest release |

`<minor>` is one of 5.6, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4,
8.5 (`-alpine`: 7.2 and later). There is no image for 5.4 or 5.5: `php:5.4-fpm` is a schema-1 manifest
that current Docker refuses to pull ("no longer supported since containerd
v2.1", seen with Docker 29.9), and `php:5.5-fpm`
has a layer Docker Hub no longer serves. Use the tarball for those.

Most of these bases are end of life and no longer rebuilt upstream, but they
are still pulled. On Docker Hub, 24 October 2026:

| Base | Debian / Alpine | Last updated upstream |
|---|---|---|
| `php:5.6-fpm` | stretch / 3.8 | 2019-01 |
| `php:7.0-fpm` | stretch / 3.7 | 2018-12 |
| `php:7.1-fpm`, `7.2-fpm` | buster / 3.10, 3.12 | 2019-11, 2020-12 |
| `php:7.3-fpm`, `7.4-fpm` | bullseye / 3.15, 3.16 | 2022-03, 2022-11 |
| `php:8.0-fpm` | bullseye / 3.16 | 2023-11 |
| `php:8.1-fpm` | trixie / 3.21 | 2025-12 |
| `php:8.2-fpm` to `8.5-fpm` | trixie / 3.24 | maintained |

### Alpine

The `-alpine` images exist for PHP 7.2 to 8.5 only. For 5.6, 7.0 and 7.1
use the Debian images. Their official Alpine bases are Alpine 3.8, 3.7 and
3.10, with musl 1.1.19, 1.1.18 and 1.1.22, and Howdah's musl build needs
musl 1.1.24 (Alpine 3.11) or newer: the `[log] exec` hook (added in 1.5.0)
uses Rust's `std::process::Command`, which links
`posix_spawn_file_actions_addchdir_np`, a function musl added in 1.1.24.
musl binds every symbol when a module is loaded, so on those bases PHP
refuses the whole extension:

```
PHP Warning:  PHP Startup: Unable to load dynamic library '.../howdah.so' - Error relocating .../howdah.so: posix_spawn_file_actions_addchdir_np: symbol not found
```

The musl release build now fails if the module needs any C library symbol
that musl 1.1.24 lacks (`packaging/musl-floor-check.sh`), and
`howdah-check detect` says so on an older musl instead of offering a
tarball that would not load.

Howdah does not patch these bases. An image built on `php:7.4-fpm` carries
the PHP and Debian packages of November 2022. That is the reason to run Howdah
at all, but it also means the rest of the image is as old as its base.
`docker.yml` rebuilds the newest release every week, so the maintained bases
(8.2 to 8.5) pick up upstream security rebuilds.

## Use the image

```dockerfile
FROM ghcr.io/howdah/howdah:1.4.0-php8.3
COPY . /var/www/html
```

It runs `php-fpm` on port 9000 like the base image; put nginx or Apache in
front of it as you would with `php:8.3-fpm`.

## Add Howdah to your own image (one line)

Every image also carries the installed files as a tree under `/howdah/`, laid
out like the official images (`/usr/local/lib/php/extensions/...`,
`/usr/local/etc/php/conf.d/`). Copy it onto any official PHP image of the same
minor and C library:

```dockerfile
FROM php:8.3-apache
COPY --from=ghcr.io/howdah/howdah:1.4.0-php8.3 /howdah/ /
```

That one line is the whole install, the way `docker-php-ext-enable` would do
it: `howdah.so` goes into the extension directory and the unchanged
`howdah.ini` becomes `conf.d/docker-php-ext-howdah.ini`. `howdah-check` comes
along as `/usr/local/bin/howdah-check`.

It works on the `-fpm`, `-apache` and `-cli` variants of the same minor (all
three keep PHP in `/usr/local`; the `-apache` and `-cli` cases were checked
with 8.3). It does not work on:

- **A different minor.** The Zend module API differs and PHP refuses the module.
- **A `-zts` image.** Howdah is NTS only; see [zts.md](zts.md).
- **Alpine with a Debian tag, or the reverse.** Use the `-alpine` tag for
  `php:<minor>-*-alpine` bases (7.2 and later), and on Alpine before 3.21
  (the PHP 7.2 to 8.0 images) add `RUN apk add --no-cache libgcc` (the musl
  build needs `libgcc_s`; the `-alpine` images install it themselves).
- **Alpine before 3.11** (`php:5.6`, `7.0`, `7.1` `-alpine`): no musl build
  loads there (see "Alpine").

Pin by digest (`@sha256:...`) if your build must be reproducible.

## Configure

The image changes no PHP default other than loading Howdah. Override it the
way you override any PHP setting in these images, with an ini file later in
`conf.d`:

```dockerfile
COPY zz-howdah.ini /usr/local/etc/php/conf.d/
COPY howdah.toml /etc/howdah/howdah.toml
```

```ini
; zz-howdah.ini
howdah.mode = detect
howdah.config = /etc/howdah/howdah.toml
howdah.log = /var/log/howdah/events.log
```

With `howdah.log` empty (the default), events go to stderr, so `docker logs`
shows them as `howdah-event {...}` lines (php-fpm 7.2 and older wraps them in
`child N said into stderr`). To log to a file instead, mount a volume and make
it writable by `www-data`. The TOML keys are in [config.md](config.md); the
config editor at https://howdah.org/config/ writes both files.

## Check that it works

```sh
docker run --rm ghcr.io/howdah/howdah:1.4.0-php8.3 php --ri howdah
# Howdah => enabled, Version => 1.4.0, Mode => detect ...
docker run --rm --network <your network> ghcr.io/howdah/howdah:1.4.0-php8.3 \
  howdah-check web http://<your web container>/
```

`howdah-check web` sends a harmless marker request (it must come back
`flagged`) and a request with 2001 empty parts. On PHP's default
`max_input_vars` and `max_file_uploads`, PHP stops parsing that request
before Howdah's limit is reached; that is PHP protecting itself, and
`howdah-check` then says "not blocked". Behind php-fpm the second check can
also say "refused (HTTP 403) but not by Howdah" when Howdah did refuse it: see
"Known limitations".

## Verify an image against the signed release

The image keeps the tarball it was built from, and the signed `SHA256SUMS`,
in `/howdah/usr/share/doc/howdah/`. On a machine with gpg:

```sh
img=ghcr.io/howdah/howdah:1.4.0-php8.3
id=$(docker create "$img")
docker cp "$id:/howdah/usr/share/doc/howdah" howdah-doc
docker cp "$id:/howdah/usr/local/lib/php/extensions" howdah-ext
docker rm "$id"
cd howdah-doc
cat PROVENANCE                                    # tarball, sha256s, key fingerprint
gpg --import howdah-release-signing.asc           # check the fingerprint above
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS          # the tarball in the image
tar -xOzf howdah-1.4.0-php8.3-*.tar.gz howdah-1.4.0-php8.3/howdah.so | cmp - ../howdah-ext/*/howdah.so && echo "same .so"
```

Compare the key with the one in the repository rather than trusting the copy
in the image. The images are also pushed with BuildKit provenance and SBOM
attestations (`docker buildx imagetools inspect --format '{{json .Provenance}}' <image>`).

## Build the image yourself

```sh
docker buildx build -f docker/Dockerfile \
  --build-arg HOWDAH_VERSION=1.4.0 --build-arg PHP_MINOR=8.3 \
  -t howdah:1.4.0-php8.3 .
sh docker/smoke.sh howdah:1.4.0-php8.3
```

Run it from the repository root (the build needs the committed key). Add
`--platform linux/arm64` for arm64, or `--build-arg PHP_VARIANT=fpm-alpine
--build-arg HOWDAH_LIBC=musl` for Alpine (PHP 7.2 and later, release 1.5.0
and later).
To test a release you built and signed yourself, serve its files and pass
`--build-arg HOWDAH_DIST_URL=<url>` and `--build-arg
HOWDAH_KEY_FILE=packaging/out/<your key>.asc`; the key's fingerprint is written
to `PROVENANCE`, so such an image cannot pass for an official one.

`docker/smoke.sh <image> [platform]` is the test `docker.yml` runs before it
pushes anything: `php -m` and `php-fpm -m`, the lab's self-test scenario
(`lab/integration/selftest_container.sh`) on the CLI server inside the image
in detect and block mode, and `howdah-check web` through nginx to the image's
own php-fpm. What it expects of the php-fpm refusal follows the Howdah
version in the image (worker exit 70 below 1.5.0, a clean 403 from 1.5.0);
`FPM_BLOCK=bailout|clean` forces one.

## How the images are published

`.github/workflows/docker.yml` runs when the `release` workflow for a `v*`
tag completes (so the signed assets exist), on demand
(`workflow_dispatch`, any published release) and weekly for the newest
release. It reads the release's `SHA256SUMS`, plans one image per minor and C
library that has tarballs (`docker/matrix.sh`), smoke-tests each image on
amd64 and, where there is one, on arm64 under QEMU, and only then pushes the
multi-arch image to GHCR with the repository's `GITHUB_TOKEN`. Pre-release
tags publish draft releases and get no images.

## What was tested

With the 1.4.0 release, before this was published:

| Image | Platforms | Result |
|---|---|---|
| `-php5.6` to `-php8.5` (12 images, Debian bases) | amd64 | `docker/smoke.sh` passed on all 12 |
| `-php8.3` | arm64, under QEMU on an amd64 host | passed (the first run of a scenario on the released aarch64 build) |
| `-php5.6-alpine` to `-php8.5-alpine` (12 images) | amd64 | passed on all 12, built from musl tarballs of the 1.4.0 source made with `HOWDAH_LIBC=musl packaging/build-release.sh` and signed with a throwaway key (1.4.0 has no musl assets) |

With the 1.5.0 release, after the fix for docker run 40140181320:

| Image | Platforms | Result |
|---|---|---|
| `-php5.6` to `-php8.5` (12 images) | amd64 | passed on all 12; the php-fpm refusal is a 403 with the Howdah body and no worker exit |
| `-php8.3` | arm64, under QEMU | passed |
| `-php7.2-alpine` to `-php8.5-alpine` (9 images) | amd64 | passed on all 9 |
| `php:5.6`, `7.0`, `7.1` `-fpm-alpine` | amd64 | the module does not load (musl below 1.1.24, see "Alpine"); no image |

The smoke test is one scenario (marker, over-limit, a normal form), not the
lab matrix: the multipart, input-shape and benign-corpus results in
[coverage.md](coverage.md) were recorded on the lab images, not on these.

## Known limitations

- **In 1.4.0, php-fpm ends the worker when it refuses a multipart request**
  (fixed in 1.5.0 by #44: the 403 carries the Howdah body and no worker
  exits). Measured
  with the over-limit (`max_parts`) request; the input-shape and header
  refusals, which land later in the request, were not checked. In 1.4.0 the refusal
  calls `zend_bailout` from the multipart callback, so `php_request_startup`
  fails and php-fpm logs `child N exited with code 70` and starts a new
  worker. It has not read the rest of the request body, so the FastCGI socket
  is reset: nginx logs `readv() failed (104: Connection reset by peer) while
  reading upstream` and passes on the 403, usually with an empty body, so the
  client does not see the request id (in the final smoke runs of the 24 amd64
  images, the body was lost in 23). The event is in the log either way. This
  is not specific to Docker: the worker exit and the reset come from php-fpm
  itself (measured with nginx 1.27 in front). `docker/smoke.sh` expects
  whichever behaviour the Howdah version in the image has (`FPM_BLOCK`
  bailout below 1.5.0, clean from 1.5.0), so it fails if either regresses.
- **Request ids repeat across forked workers in 1.4.0.** Every php-fpm (and
  Apache prefork) worker is forked from the parent with the same id generator
  state, so two workers log the same `request_id` for different requests.
  Fixed in PR #39.
- **No ZTS image** (no FrankenPHP, no threaded Apache): [zts.md](zts.md).
- **Alpine images are amd64 only**: there is no aarch64 musl build. And
  PHP 7.2 and later only: musl 1.1.24 is the floor (see "Alpine").
- **No Apache image.** Use `COPY --from` onto `php:<minor>-apache`. That was
  checked once by hand, not by the smoke test: on `php:8.3-apache` the module
  loaded and `howdah-check web` passed under `mod_php` (marker flagged, the
  over-limit request blocked with the Howdah body).
- The `/howdah/` overlay adds about 1.7 MB (the `.so`, the tarball and the
  signed checksums) to an image it is copied into.
