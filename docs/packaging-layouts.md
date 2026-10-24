# Package layouts: which Howdah package fits which PHP

Howdah builds one `howdah.so` per PHP minor (5.4 to 8.5, NTS, glibc 2.17
floor), plus, from 1.5.0, a musl build of each minor for
Alpine (x86_64 only, musl 1.1.24 or newer; see "Alpine (musl)" below). The same glibc file goes
into every package for that minor. What differs
between packages is where the vendor's PHP keeps its extensions and ini
drop-ins, the package name, and the package the Howdah package depends on.

The Surý/Debian apt package and the Remi SCL yum package are built by
`packaging/deb/build-deb.sh` and `packaging/rpm/build-rpm.sh`, which this
change does not touch. Every other layout is a row of
[`packaging/layouts.tsv`](../packaging/layouts.tsv), rendered by
`packaging/build-layouts.sh` from `packaging/rpm/layout.spec.in` and
`packaging/deb/layout-control.in`. A new layout is a new row.

`howdah-check detect` names the layout of every PHP install it finds and the
package (or tarball) to use for it; `tools/howdah-check.test.sh` fails if
`detect` and `layouts.tsv` disagree.

## The table

`XY` is the PHP minor without the dot (`74`), `X.Y` with it (`7.4`), `API` the
Zend module API number (`20190902` for 7.4).

| Layout (`detect` name) | PHP binary | Module dir (`extension_dir`) | Ini drop-in | Package | Depends on | Repository | Arches |
|---|---|---|---|---|---|---|---|
| `sury` | `/usr/bin/phpX.Y` | `/usr/lib/php/API` | `/etc/php/X.Y/mods-available/howdah.ini`, enabled with `phpenmod` | `phpX.Y-howdah` | `phpapi-API`, `phpX.Y-common` | `https://pkg.howdah.org/apt` `stable main` | amd64, arm64 |
| `stock-debian` | same as `sury` | same | same | same package | same | same | same |
| `remi` | `/opt/remi/phpXY/root/usr/bin/php` | `/opt/remi/phpXY/root/usr/lib64/php/modules` | `/etc/opt/remi/phpXY/php.d/40-howdah.ini` | `phpXY-howdah` | `phpXY-php(zend-abi) = API-64`, `phpXY-php-common` | `https://pkg.howdah.org/yum` | x86_64, aarch64 |
| `cpanel` (EL) | `/opt/cpanel/ea-phpXY/root/usr/bin/php` | `/opt/cpanel/ea-phpXY/root/usr/lib64/php/modules` | `/opt/cpanel/ea-phpXY/root/etc/php.d/20-howdah.ini` | `ea-phpXY-php-howdah` | `ea-phpXY-php-common` | `https://pkg.howdah.org/cpanel/yum` | x86_64 |
| `cpanel` (Ubuntu) | same | same (EA4 uses `lib64` on Ubuntu too) | same | `ea-phpXY-php-howdah` | `ea-phpXY-php-common` | `https://pkg.howdah.org/cpanel/apt` `stable main` | amd64 |
| `plesk` (EL) | `/opt/plesk/php/X.Y/bin/php` | `/opt/plesk/php/X.Y/lib64/php/modules` | `/opt/plesk/php/X.Y/etc/php.d/howdah.ini` | `plesk-phpXY-howdah` | `plesk-phpXY` | `https://pkg.howdah.org/plesk/yum` | x86_64 |
| `plesk` (Debian/Ubuntu) | same | `/opt/plesk/php/X.Y/lib/php/modules` | same | `plesk-phpXY-howdah` | `plesk-phpXY` | `https://pkg.howdah.org/plesk/apt` `stable main` | amd64, arm64 |
| `cloudlinux` | `/opt/alt/phpXY/usr/bin/php` | `/opt/alt/phpXY/usr/lib64/php/modules` | `/opt/alt/phpXY/etc/php.d.all/howdah.ini` and `/opt/alt/phpXY/etc/php.d.std/howdah.ini` | `alt-phpXY-howdah` | `alt-phpXY` | `https://pkg.howdah.org/cloudlinux/yum` | x86_64 |
| `stock-rhel` | `/usr/bin/php` | `/usr/lib64/php/modules` (Amazon Linux 2023: `/usr/lib64/phpX.Y/modules`) | `/etc/php.d/40-howdah.ini`, loading the `.so` by absolute path | `php-howdah` (release `N.phpXY`) | `php(zend-abi) = API-64` | `https://pkg.howdah.org/el/phpX.Y/yum` (one repository per minor) | x86_64, aarch64 |
| `directadmin` | `/usr/local/phpXY/bin/php` | `/usr/local/phpXY/lib/php/extensions/no-debug-non-zts-API` | `/usr/local/phpXY/lib/php.conf.d/` | none: tarball | | | |
| `docker` | `/usr/local/bin/php` (official `php:X.Y-*` images, Debian and Alpine) | `/usr/local/lib/php/extensions/no-debug-non-zts-API` | `/usr/local/etc/php/conf.d/docker-php-ext-howdah.ini` | image `ghcr.io/howdah/howdah:<version>-phpX.Y[-alpine]` (`-alpine`: PHP 7.2+), or `COPY --from` of its `/howdah/` tree ([install-docker.md](install-docker.md)) | | GHCR | amd64, arm64 (Alpine: amd64) |
| `alpine` | `/usr/bin/phpXY` (`apk add php83`) | `/usr/lib/phpXY/modules` | `/etc/phpXY/conf.d/40_howdah.ini` | none: the `-musl` tarball, plus `apk add libgcc` (musl 1.1.24+, Alpine 3.11+) | | | x86_64 |
| `litespeed` | `/usr/local/lsws/lsphpXY/bin/php` (CLI) and `bin/lsphp` (LSAPI) | `/usr/local/lsws/lsphpXY/lib/php/API` (LiteSpeed's deb packages) | `/usr/local/lsws/lsphpXY/etc/php/X.Y/mods-available/40-howdah.ini` (lsphp scans `mods-available` itself) | none: tarball | | | |
| `unknown` | anything else | | | none: tarball | | | |

Every package depends on the vendor package that is named after the PHP
minor, and the minor fixes the Zend module API, so a package cannot be
installed against the wrong PHP ABI. The stock EL package has no minor in its
name, so it uses the exact `php(zend-abi)` provide instead. The panel
packages follow the dependency each vendor's own add-on modules use (cPanel's
`ea-php54-php-memcache` requires `ea-php54-php-common`; Plesk's
`plesk-php74-redis` requires `plesk-php74`; CloudLinux's
`alt-php74-snuffleupagus` requires `alt-php74`). Plesk's Debian packages also
provide `plesk-phpapi-N`, but for PHP 5.4 that number is the PHP API
(`20100412`), not the Zend module API (`20100525`), so Howdah does not depend
on it.

No package has maintainer scripts. Enabling is the ini drop-in; each ini is
`%config(noreplace)` (rpm) or a conffile (deb), so local edits survive
upgrades. The ini is the same `howdah.ini` as in the tarball, byte for byte,
except that the stock EL package writes `extension=/usr/lib64/php/modules/howdah.so`
because Amazon Linux 2023's `extension_dir` differs from RHEL's.

Why the stock EL repository is split per minor: a RHEL-family box has one
distribution PHP, and its package names carry no minor (`php-common`), so
`php-howdah` cannot either. One repository holding `php-howdah` for every
minor would offer the newest build to every host and fail on the ABI
requirement. Each `el/phpX.Y` repository holds only that minor's build; the
release tag (`1.php74`) keeps the files distinct. If you switch PHP minor
(for example `dnf module switch-to php:8.2`), remove `php-howdah`, point the
repository at the new minor and install it again.

## How each layout loads the module

- **cPanel.** Install with `dnf` or `yum` on AlmaLinux/Rocky/CloudLinux/CentOS,
  or `apt` on Ubuntu. The EasyApache 4 interface does not install it: cPanel's
  documentation says "You can only install cPanel-provided PHP packages in the
  EasyApache 4 interface. You must use a package manager to install custom PHP
  packages." The name follows EA4's `ea-php##-php-<module>` convention, and
  "When you provision a profile, the system will install that profile's
  packages, and uninstall other packages." After provisioning a profile in
  EasyApache 4, check `rpm -q ea-php74-php-howdah` (or `dpkg -s`) and install
  it again if it was removed. Restart PHP-FPM from WHM (Restart Services) or
  with `/scripts/restartsrv_apache_php_fpm`.
- **Plesk.** Install with `dnf`/`yum` or `apt`. The module loads from
  `php.d` on the next PHP restart (`systemctl restart plesk-php74-fpm`).
  Run `plesk bin php_handler --reread` so Plesk's PHP settings page lists it.
- **CloudLinux alt-php.** The ini goes into `php.d.all`, which the PHP
  Selector uses; the per-user `php.d` only links the modules a user (or the
  default list) has enabled. After installing, run
  `cagefsctl --setup-cl-selector`, then enable it for a version, for example
  `selectorctl --version=7.4 --enable-extensions=howdah` (all users on that
  version), or per user in the PHP Selector. The `php.d.std` copy is what
  alt-php reads when it runs outside the selector, following CloudLinux's own
  module packages.
- **Stock RHEL / Alma / Rocky / Amazon Linux.** Install with `dnf`/`yum` from
  the repository for your minor; reload `php-fpm` or `httpd`.
- **DirectAdmin.** No package. CustomBuild compiles PHP from source into
  `/usr/local/phpXY`; no rpm or deb owns that PHP, so a package would have
  nothing to depend on for its ABI guard. Use the tarball:
  `cp howdah.so "$(/usr/local/php74/bin/php-config --extension-dir)/"` and
  `cp howdah.ini /usr/local/php74/lib/php.conf.d/90-howdah.ini`, then restart
  that version's PHP-FPM (on CustomBuild servers the unit is usually
  `php-fpm74`) and Apache. The `no-debug-non-zts-20190902` directory name
  carries the Zend module API number, which is fixed for a PHP minor, so a
  rebuild of the same minor keeps the same directory; run
  `howdah-check detect` after a CustomBuild rebuild and copy the file again if
  it is gone.
- **Docker (official `php` images).** Use the runtime image or copy its
  `/howdah/` tree onto your own image of the same minor:
  `COPY --from=ghcr.io/howdah/howdah:<version>-php8.3 /howdah/ /`. Details,
  tags and how to verify an image: [install-docker.md](install-docker.md).
- **LiteSpeed lsphp.** No package. LiteSpeed's lsphp deb packages put PHP in
  `/usr/local/lsws/lsphpXY` and the LSAPI binary scans
  `etc/php/X.Y/mods-available/` directly (there is no separate enable step):
  `cp howdah.so "$(/usr/local/lsws/lsphp83/bin/php -r 'echo ini_get("extension_dir");')/"`
  and `cp howdah.ini /usr/local/lsws/lsphp83/etc/php/8.3/mods-available/40-howdah.ini`,
  then `/usr/local/lsws/bin/lswsctrl restart` so the lsphp processes restart.
  The rpm builds (`lib64/php/modules`, `etc/php.d`) are recognised by
  `howdah-check detect` but were not checked against a real install.
- **Alpine (apk PHP).** Use the `-musl` tarball: `apk add libgcc`, copy
  `howdah.so` into `/usr/lib/php83/modules/` and `howdah.ini` to
  `/etc/php83/conf.d/40_howdah.ini`, restart `php-fpm83`.

## Alpine (musl)

A `howdah.so` linked against glibc does not load on Alpine, which uses musl.
From 1.5.0 each minor also has
`howdah-<version>-phpX.Y-API-linux-x86_64-musl.tar.gz`, with the same three
files as the glibc tarball, signed in the same `SHA256SUMS`. It is built by
`HOWDAH_LIBC=musl packaging/build-release.sh` on Alpine 3.21
(`packaging/release.musl.Dockerfile`) with PHP headers from source, and the
build fails unless the module links only `libc.musl-x86_64.so.1` and
`libgcc_s.so.1`. `libgcc_s` is Rust's unwinder, which the panic guard needs;
Alpine images before 3.21 do not have it, so `apk add libgcc` first.

There is no apk package: the tarball is the install. `howdah-check detect`
on a musl host prints `host libc: musl <version>` and names the `-musl`
tarball, or says the musl is too old (below).

**The floor is musl 1.1.24 (Alpine 3.11).** From 1.5.0 the `[log] exec` hook
uses Rust's `std::process::Command`, which links
`posix_spawn_file_actions_addchdir_np`; musl added that function in 1.1.24.
musl binds every symbol when a module is loaded, so on an older musl PHP
refuses the whole extension (`Error relocating .../howdah.so:
posix_spawn_file_actions_addchdir_np: symbol not found`, seen in docker run
40140181320 on `php:7.1-fpm-alpine`, Alpine 3.10, musl 1.1.22). The release
build keeps Alpine 3.11's loader in the build image and fails if the module
needs any C library symbol it lacks, listing them
(`packaging/musl-floor-check.sh`, tested by `packaging/musl-floor.test.sh`
against the real 1.5.0 build: passes on 1.1.24, fails on 1.1.22 naming that
one symbol). So the `-alpine` Docker images are for PHP 7.2 to 8.5 only; the
official 5.6, 7.0 and 7.1 Alpine bases (Alpine 3.8, 3.7, 3.10) are below the
floor, and those minors use the Debian images.

The musl build of the 1.4.0 source, which had no `[log] exec` hook, loaded
on musl 1.1.18 (Alpine 3.7) through 1.2.6 (Alpine 3.24). Measured on 1.5.0:
it loads on musl 1.1.24 (`php:7.2-fpm-alpine`) and later, and in Alpine
3.21's own `php83` and `php-fpm83`. No aarch64 musl build exists.

## Example: `howdah-check detect`

Real output from the validation containers below. AlmaLinux 8 with cPanel's
ea-php74, one install in full:

```
php: /opt/cpanel/ea-php74/root/usr/bin/php
  version: 7.4.33
  api: 20190902
  thread_safety: NTS
  matching release asset: howdah-<VERSION>-php7.4-20190902-linux-x86_64.tar.gz
  extension_dir: /opt/cpanel/ea-php74/root/usr/lib64/php/modules
  php_ini: /opt/cpanel/ea-php74/root/etc/php.ini
  ini_scan_dir: /opt/cpanel/ea-php74/root/etc/php.d
  layout: cpanel
  howdah package: ea-php74-php-howdah (yum/dnf repo https://pkg.howdah.org/cpanel/yum)
  sapi cli: present  howdah=not-loaded
  sapi fpm: absent
  sapi apache: absent
```

The `extension_dir`, `layout` and `howdah package` lines from three others:

```
# Debian 12 with Plesk PHP 7.4
  extension_dir: /opt/plesk/php/7.4/lib/php/modules
  layout: plesk
  howdah package: plesk-php74-howdah (apt repo https://pkg.howdah.org/plesk/apt, suite stable, component main)

# Amazon Linux 2023 with its own PHP 8.2
  extension_dir: /usr/lib64/php8.2/modules
  layout: stock-rhel
  howdah package: php-howdah (yum/dnf repo https://pkg.howdah.org/el/php8.2/yum)

# Ubuntu 20.04 with its own PHP 7.4 (version 7.4.3-4ubuntu2.29)
  extension_dir: /usr/lib/php/20190902
  layout: stock-debian
  howdah package: php7.4-howdah (apt repo https://pkg.howdah.org/apt, suite stable, component main)
```

For DirectAdmin and anything unrecognised it prints
`howdah package: not yet packaged: use the tarball for API 20190902 (howdah-<VERSION>-php7.4-20190902-linux-x86_64.tar.gz)`;
for a ZTS PHP, `none: Howdah is built for NTS PHP only and this PHP is ZTS`;
for a layout with no package for the host CPU (cPanel, Plesk on EL and
CloudLinux are x86_64 only), `not yet packaged for aarch64: use the tarball ...`.

## Sources

Where a path in an early plan differed from the vendor, the vendor won. Every
row was checked against the vendor's documentation and, where the vendor
publishes its PHP packages, against the files and dependency metadata of
those packages.

**cPanel EasyApache 4**
- [EasyApache 4 file system layout](https://docs.cpanel.net/ea4/basics/easyapache-4-file-system-layout/):
  "`/opt/cpanel/ea-php##/root/etc/php.d/` ... The system scans this directory for PHP `.ini` files."
- [How to locate and install a PHP version or extension](https://docs.cpanel.net/ea4/php/how-to-locate-and-install-a-php-version-or-extension/):
  module packages "use the `ea-php##-php-module` naming convention"; "You can
  only install cPanel-provided PHP packages in the EasyApache 4 interface";
  "You must use a package manager to install custom PHP packages"; Ubuntu
  uses `apt install`.
- [EasyApache 4 interface](https://docs.cpanel.net/whm/software/easyapache-4-interface/):
  "When you provision a profile, the system will install that profile's packages, and uninstall other packages."
- [The restartsrv script](https://docs.cpanel.net/whm/scripts/the-restartsrv-script/).
- cPanel's spec for ea-php74, [CpanelInc/ea-php74 `SPECS/ea-php74.spec`](https://github.com/CpanelInc/ea-php74):
  SCL root `/opt/cpanel/ea-php74/root`, `EXTENSION_DIR=%{_libdir}/php/modules`,
  `--with-config-file-scan-dir=%{_sysconfdir}/php.d`, modules as
  `php.d/20-<module>.ini`; its Ubuntu build settings (`debify/settings.json`)
  set `pkg_php_extdir` to `/opt/cpanel/ea-php74/root/usr/lib64/php/modules`.
  cPanel's own add-on module [CpanelInc/ea-php54-php-memcache](https://github.com/CpanelInc/ea-php54-php-memcache)
  requires `ea-php54-php-common`.
- Packages on cPanel's public EA4 mirror (`httpupdate.cpanel.net` mirror list):
  `ea-php74-php-common-7.4.33-19.26.1.cpanel` (EL8) ships
  `/opt/cpanel/ea-php74/root/usr/lib64/php/modules` and `.../root/etc/php.d`
  and provides `ea-php74-php(zend-abi) = 20190902-64`;
  `ea-php81-php-common 8.1.34-5+12.1.cpanel` (Ubuntu 22.04) ships the same
  paths. The Ubuntu 22.04 EA4 repository carries ea-php81 to ea-php85; the
  EL8 one ea-php72 to ea-php85.

**Plesk**
- [Adding Custom PHP Module in Plesk](https://www.plesk.com/blog/adding-custom-php-modules-in-plesk/):
  `/opt/plesk/php/5.6/etc/php.d/memcached.ini` and `plesk bin php_handler --reread`.
- Plesk's own packages on [autoinstall.plesk.com](https://autoinstall.plesk.com/PHP74_17/)
  (build 261021): `plesk-php74-redis` for RHEL 8 installs
  `/opt/plesk/php/7.4/lib64/php/modules/redis.so` and
  `/opt/plesk/php/7.4/etc/php.d/redis.ini` and requires `plesk-php74`; for
  Debian 12 it installs `/opt/plesk/php/7.4/lib/php/modules/redis.so` and
  depends on `plesk-php74, plesk-phpapi-20190902`. `plesk-php74-fpm` ships
  `plesk-php74-fpm.service`. `plesk-php54` for Ubuntu 16.04 provides
  `plesk-phpapi-20100412`.

**CloudLinux alt-php**
- [CloudLinux OS components, Compiling your own extensions](https://docs.cloudlinux.com/cloudlinuxos/cloudlinux_os_components/#compiling-your-own-extensions):
  "`cp -rp modules/*.so /opt/alt/phpXX/usr/lib64/php/modules/`", "Add ini
  file for module to `/opt/alt/phpXX/etc/php.d.all`", "`cagefsctl --setup-cl-selector`".
- [PHP Selector](https://docs.cloudlinux.com/cloudlinuxos/cloudlinux_os_components/#php-selector):
  "`/etc/cl.php.d/alt-php*` - Links to enabled modules"; "Select default
  extensions (enable comma-separated list of extensions globally for a
  version): `/usr/bin/selectorctl --version=5.6 --enable-extensions=pdo,json,mysql`".
- CloudLinux's source packages on
  [repo.cloudlinux.com](https://repo.cloudlinux.com/cloudlinux/8/cloudlinux-x86_64-server-8/Source/Packages/):
  `alt-php74-7.4.33-81.el8` provides `alt-php74(zend-abi) = 20190902`, sets
  `EXTENSION_DIR` to `/opt/alt/php74/usr/lib64/php/modules` and scans
  `/opt/alt/php74/link/conf` (a link to `etc/php.d`);
  `alt-php74-snuffleupagus-0.14.0-1.2.el8` installs its ini into both
  `php.d.all/` and `php.d.std/` and requires `alt-php74`.

**DirectAdmin CustomBuild**
- [PHP extensions](https://docs.directadmin.com/webservices/php/php-extensions.html):
  builds with `/usr/local/php72/bin/phpize` and `php-config`, loads from
  `/usr/local/php72/lib/php.conf.d/90-apcu.ini`, and "you have to compile the
  custom extension for each version". The extension directory is PHP's
  default for the `/usr/local/phpXY` prefix. No package mechanism for
  third-party extensions was found in DirectAdmin's documentation.

**Stock RHEL / Alma / Rocky / Amazon Linux** (package metadata read in containers)
- AlmaLinux 8, `php:7.4` stream: `php-common-7.4.33-8.module_el8.10.0` provides
  `php(zend-abi) = 20190902-64`; `extension_dir => /usr/lib64/php/modules`,
  scan dir `/etc/php.d`, modules as `20-<module>.ini`.
- Amazon Linux 2023: `php8.2-common-8.2.35-1.amzn2023.0.1` provides
  `php(zend-abi) = 20220829-64` and `php-common`; `extension_dir => /usr/lib64/php8.2/modules`,
  scan dir `/etc/php.d`. The repository carries php8.1 to php8.5.

**Stock Debian / Ubuntu** (package metadata read in containers)
- Debian 12: `php8.2-cli`, `php8.2-fpm`, `php8.2-cgi` and
  `libapache2-mod-php8.2` provide `phpapi-20220829`;
  `extension_dir => /usr/lib/php/20220829`.
- Ubuntu 20.04: `php7.4-cli` provides `phpapi-20190902`.

## What was validated, and what was not

Built for PHP 7.4, 8.1 and 8.2 (x86_64) with `packaging/build-layouts.sh`,
then installed with the vendor's own PHP in containers
(`packaging/validate-layout.sh`): `php -m` lists howdah, `php --ri howdah`
shows `Mode => detect`, removal leaves PHP running.

| Layout | Container | PHP | Wrong-ABI package refused |
|---|---|---|---|
| stock-rhel | AlmaLinux 8, `php:7.4` stream | 7.4.33 | |
| stock-rhel | Amazon Linux 2023 | 8.2.35 | 8.1 build refused (`php(zend-abi) = 20210902-64 is needed`) |
| cpanel (rpm) | AlmaLinux 8 + EA4 mirror | ea-php74 7.4.33 | |
| cpanel (deb) | Ubuntu 22.04 + EA4 mirror | ea-php81 8.1.34 | 8.2 build left unconfigured by dpkg |
| plesk (rpm) | AlmaLinux 8 + autoinstall.plesk.com | plesk-php74 7.4.33 | 8.1 build refused (`plesk-php81 is needed`) |
| plesk (deb) | Debian 12 + autoinstall.plesk.com | plesk-php74 7.4.33 | 8.1 build left unconfigured by dpkg |
| stock-debian | Ubuntu 20.04 | 7.4.3 (distribution) | the unchanged `php7.4-howdah` deb |

The cpanel (rpm), stock-rhel (EL8) and plesk (deb) packages were also
installed through signed test repositories built by
`packaging/repo/build-layout-repos.sh` with a throwaway key, with
`gpgcheck=1`, `repo_gpgcheck=1` and apt `signed-by`.

Not validated:
- **CloudLinux.** The packages are built and their file lists checked, but
  alt-php binaries come from CloudLinux's licensed channels, so no install was
  run. The PHP Selector enable step above is CloudLinux's documented
  procedure, not something this project has exercised.
- **Panel integration.** cPanel and Plesk were exercised as their PHP
  packages in containers, not on a full panel server: EasyApache 4 profile
  provisioning, MultiPHP, the Plesk PHP settings page and panel-driven
  PHP-FPM restarts were not run.
- The other PHP minors and aarch64 builds use the same templates and were not
  installed separately. cPanel's Ubuntu PHP packages need `libxml2`,
  `libedit2` and `libargon2-1`, which a cPanel server already has, but which
  they do not declare; the validation container installs them.
- ZTS PHP (for example CloudLinux `alt-php72-zts`), LiteSpeed `lsphp`,
  Alpine and DirectAdmin get no package. ZTS gets no build at all
  ([zts.md](zts.md)). LiteSpeed lsphp 8.3.36 under OpenLiteSpeed 1.9.3 ran the
  self-test with the released 1.4.0 tarball (`lab/integration/lsapi.sh`, see
  [coverage.md](coverage.md), Table 5); no other lsphp minor and no rpm lsphp
  was run.
