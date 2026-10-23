# Task 2 report: RPM (.rpm) packaging

## Naming / files (packaging/rpm/)
- Package `php<XY>-howdah` (Remi SCL, XY = minor without dot). File `php<XY>-howdah-<ver>-1.<arch>.rpm`, e.g. `php74-howdah-0.1.0-1.x86_64.rpm`, `php81-howdah-0.1.0-1.x86_64.rpm`, `php74-howdah-0.1.0-1.aarch64.rpm`, in `packaging/out/` (gitignored, unsigned).
- Files: `build-rpm.sh`, `howdah.spec.in`, `builder.Dockerfile` (CentOS 7 + rpm-build/redhat-rpm-config, vault.centos.org), `validate.sh`, `validate-in-container.sh`.
- `build-rpm.sh <minor> <x86_64|aarch64> [tarball]`: tarball arg, else packaging/out, else `HOWDAH_ARCH=<arch> build-release.sh`; `HOWDAH_NO_BUILD=1` skips auto-build. Checks ELF arch, reads API from tarball name. Renders spec, runs rpmbuild in the EL7 container (aarch64 uses `--target aarch64` on the x86 builder; payload is a prebuilt binary so no QEMU needed). gzip payload, no strip/debuginfo.
- Layout (Remi SCL): `/opt/remi/php<XY>/root/usr/lib64/php/modules/howdah.so`, `/etc/opt/remi/php<XY>/php.d/40-howdah.ini` (`%config(noreplace)`). Stock/non-SCL variant (`/usr/lib64/php/modules` + `/etc/php.d`, `php-howdah`) noted in spec comment, not built.
- URL https://github.com/howdah/howdah (real), License MIT OR Apache-2.0, Packager Howdah Maintainers <packages@howdah.org> (placeholder address, owner to confirm).

## Spec Requires
```
Requires: php74-php(zend-abi) = 20190902-64
Requires: php74-php-common
```
(8.1: `php81-php(zend-abi) = 20210902-64`.) Plus auto glibc deps (max GLIBC_2.14 symbol; fine on EL7).

## %post/%postun
None. Remi autoloads every `php.d/*.ini`, so shipping `40-howdah.ini` IS enabling; removal deletes it. No scriptlet => cannot fail the transaction or wedge PHP. Edited ini is kept as .rpmsave on removal (noreplace).

## Wrong-PHP guard
Remi's `php<XY>-php-common` Provides `php<XY>-php(zend-abi) = <api>-64`. Our package requires the exact one, so rpm refuses (`rpm -i`: "Failed dependencies: php81-php(zend-abi) = 20210902-64 is needed by php81-howdah") and yum/dnf resolve it by pulling the matching php81 SCL side by side (never loading into 7.4; the ini lives only under the php81 dir). Verified.

## Validation (`packaging/rpm/validate.sh <el> <minor> <arch> [other-minor]`; Remi remi-safe SCL php<XY>-php-cli)
All: install -> `/opt/remi/php<XY>/root/usr/bin/php -m` shows `howdah` -> `--ri howdah` (Howdah enabled, Version 0.1.0, Mode detect) -> `yum/dnf remove` (so + ini gone, module not loaded, php runs, `rpm -V php<XY>-php-common` clean).
- CentOS 7 (vault) PHP 7.4.33 x86_64: PASS, + wrong-ABI guard vs php81-howdah (refused by rpm)
- CentOS 7 PHP 8.1.29 x86_64: PASS, + guard vs php74-howdah (refused)
- AlmaLinux 9 PHP 8.1.34 x86_64: PASS, + guard vs php74-howdah (refused)
- AlmaLinux 8 PHP 7.4.33 x86_64: PASS
- AlmaLinux 9 PHP 7.4.33 aarch64 (QEMU, aarch64 rpm): PASS
Key output (CentOS 7, 7.4): `howdah` in `php -m`; `Howdah => enabled / Version => 0.1.0 / Mode => detect`; after remove `package php74-howdah is not installed`, `howdah modules loaded: 0`, `php still runs: 7.4.33`. Full logs were in the scratch dir /tmp/claude-1000/val/*.log (not committed).
Deviation: Remi publishes no EL7 aarch64, so the aarch64 run used Alma 9 (arm64). Rocky not run separately (Alma is binary-compatible).

## Concerns
- CentOS 7 is EOL: builder and validation need vault.centos.org; Remi EL7 still served at test time.
- Only SCL layout built; stock-PHP (`php-howdah`) packages for non-Remi EL boxes are a follow-up if wanted.
- Packager email is a placeholder. The Debian task's Source URL guess `howdah-org` is wrong (packaging/deb/build-deb.sh copyright says github.com/howdah-org/howdah) and should be fixed to github.com/howdah/howdah.
