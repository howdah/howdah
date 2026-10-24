# Installing Howdah from the package repositories

Howdah is published as signed apt and yum repositories at `https://pkg.howdah.org`
(HTTPS only). One package per PHP minor: `php<minor>-howdah` on Debian/Ubuntu
(for example `php7.4-howdah`) and `php<XY>-howdah` on RPM systems using the Remi
layout (for example `php74-howdah`). Panel and distribution PHP builds have
their own repositories and package names: [cPanel](#cpanel-easyapache-4),
[Plesk](#plesk), [CloudLinux alt-php](#cloudlinux-alt-php) and
[stock RHEL, Alma, Rocky and Amazon Linux](#stock-rhel-alma-rocky-and-amazon-linux-php).
`howdah-check detect` names the right one for every PHP on the box; the full
table and its vendor sources are in [packaging-layouts.md](packaging-layouts.md).

> **Status: live.** The repositories are published and signed with the
> project key (see [Key](#key) below), and the commands in this document work
> today. The tarballs on the GitHub release remain available as an alternative.
> How publishing is set up is described in `packaging/repo/GO-LIVE.md`.
>
> **Validation honesty.** Install, `php -m`, remove and purge were exercised in
> containers on Debian bookworm (PHP 7.4, 8.1), CentOS 7 (7.4, 8.1) and
> AlmaLinux 8/9. For Ubuntu xenial, only the signature chain (an old apt
> verifying our `InRelease`) was proven; a full end-to-end xenial install was
> not. Ubuntu jammy/noble and Debian bullseye use the same package and repo
> format as the validated bookworm run but were not each run separately.

The packages only install against a PHP with the matching ABI (the deb depends
on `phpapi-<N>`, the rpm on `php<XY>-php(zend-abi)`), so you cannot load a
mismatched `.so`. Find your PHP minor with `php -v`. Howdah builds are for
non-debug, non-threaded (NTS) PHP.

## Debian and Ubuntu (apt)

Supported: Ubuntu 16.04 (xenial), 22.04 (jammy), 24.04 (noble); Debian 11
(bullseye), 12 (bookworm). Architectures: amd64, arm64.

The same package fits the distribution's own PHP as well as Surý's: Debian's
and Ubuntu's PHP SAPI packages provide `phpapi-<N>` too, and use the same
paths. Checked with Ubuntu 20.04's own PHP 7.4.

**Ubuntu 16.04 only** (apt 1.2 cannot fetch HTTPS without this):

```sh
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl
```

**Modern apt (jammy, noble, bullseye, bookworm)**, key pinned to this repo only:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://howdah.org/key.asc | sudo tee /etc/apt/keyrings/howdah.asc >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/howdah.asc] https://pkg.howdah.org/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/howdah.list
```

**Ubuntu 16.04 (xenial, no `signed-by`)**:

```sh
curl -fsSL https://howdah.org/key.asc | sudo apt-key add -
echo "deb https://pkg.howdah.org/apt stable main" | sudo tee /etc/apt/sources.list.d/howdah.list
```

Install (replace `7.4` with your PHP minor):

```sh
sudo apt-get update
sudo apt-get install php7.4-howdah
```

The package enables the module for its own PHP (`phpenmod -v 7.4 howdah`). The
suite is `stable` for every distribution; it is not tied to a release codename.

Verify:

```sh
php -m | grep -i howdah
php --ri howdah          # Howdah => enabled, Mode => detect
```

If `php` is run by FPM or Apache, reload it: `sudo systemctl reload php7.4-fpm`
(or `apache2`).

Roll back:

```sh
sudo phpdismod -v 7.4 howdah        # stop loading it, keep the package
sudo apt-get remove php7.4-howdah   # remove, keep the ini
sudo apt-get purge php7.4-howdah    # remove everything including the ini
sudo systemctl reload php7.4-fpm    # or apache2
```

The repository index keeps every published version, so you can pin or roll
back through the repo, for example `sudo apt-get install php7.4-howdah=1.2.0-1`.

Removal never breaks PHP: the maintainer scripts only enable/disable the module
and never fail the transaction.

## CentOS 7, AlmaLinux / Rocky 8 and 9 (yum / dnf)

Supported: CentOS 7, AlmaLinux and Rocky Linux 8 and 9 (and RHEL equivalents).
Architectures: x86_64, aarch64 (CentOS 7 aarch64 depends on your PHP source;
Remi publishes no EL7 aarch64). Packages follow the Remi software-collection
layout: `php<XY>-howdah` installs into `/opt/remi/php<XY>/` and requires
`php<XY>-php-common` from Remi. For the distribution's own PHP, see
[stock RHEL, Alma, Rocky and Amazon Linux](#stock-rhel-alma-rocky-and-amazon-linux-php).

```sh
sudo rpm --import https://howdah.org/key.asc

sudo tee /etc/yum.repos.d/howdah.repo >/dev/null <<'REPO'
[howdah]
name=Howdah (defensive WAF for PHP)
baseurl=https://pkg.howdah.org/yum
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://howdah.org/key.asc
REPO
```

Install (replace `74` with your PHP minor without the dot):

```sh
sudo yum install php74-howdah      # dnf install on 8/9
```

Both package signatures (`gpgcheck`) and repository metadata signatures
(`repo_gpgcheck`) are enforced. Dropping the ini into `php.d` is the enable step;
there is no scriptlet.

Verify:

```sh
/opt/remi/php74/root/usr/bin/php -m | grep -i howdah
/opt/remi/php74/root/usr/bin/php --ri howdah
```

Reload FPM or httpd afterwards (for example `sudo systemctl reload php74-php-fpm`).

Roll back:

```sh
sudo yum remove php74-howdah       # removes the .so and the 40-howdah.ini
sudo systemctl reload php74-php-fpm
```

A locally edited ini is kept as `40-howdah.ini.rpmsave`.

## Panel and distribution PHP

The repositories in this section are separate from the two above, one per
layout, signed with the same key. They are new: they appear at their URLs
after the next run of the publish workflow. Until
`https://pkg.howdah.org/<layout>/...` answers, use the tarball as described
in [packaging-layouts.md](packaging-layouts.md). Each package installs the
same `howdah.so` and `howdah.ini` as the tarball for that PHP minor, into the
vendor's paths, and depends on the vendor's PHP package for that minor, so it
cannot load into a PHP with a different ABI. None has install scripts; the
ini drop-in is the enable step. Validation status per layout is in
[packaging-layouts.md](packaging-layouts.md#what-was-validated-and-what-was-not).

Run `howdah-check detect` first: it prints a `layout:` and a
`howdah package:` line for every PHP install, including the repository URL.

### cPanel (EasyApache 4)

Package `ea-php<XY>-php-howdah` for cPanel's `ea-php<XY>` (for example
`ea-php74-php-howdah`): `/opt/cpanel/ea-php<XY>/root/usr/lib64/php/modules/howdah.so`
and `/opt/cpanel/ea-php<XY>/root/etc/php.d/20-howdah.ini`. Requires
`ea-php<XY>-php-common`. x86_64 only.

Install it with the package manager. The EasyApache 4 interface only installs
cPanel-provided PHP packages; cPanel's documentation says custom PHP packages
must go through the package manager.

AlmaLinux, Rocky, CloudLinux or CentOS 7 with cPanel:

```sh
sudo rpm --import https://howdah.org/key.asc
sudo tee /etc/yum.repos.d/howdah-cpanel.repo >/dev/null <<'REPO'
[howdah-cpanel]
name=Howdah for cPanel EasyApache 4
baseurl=https://pkg.howdah.org/cpanel/yum
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://howdah.org/key.asc
REPO
sudo dnf install ea-php74-php-howdah     # yum on CentOS 7
```

Ubuntu with cPanel:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://howdah.org/key.asc | sudo tee /etc/apt/keyrings/howdah.asc >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/howdah.asc] https://pkg.howdah.org/cpanel/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/howdah-cpanel.list
sudo apt-get update
sudo apt-get install ea-php81-php-howdah
```

Verify, then restart PHP-FPM (WHM, Restart Services, or the restartsrv script):

```sh
/opt/cpanel/ea-php74/root/usr/bin/php -m | grep -i howdah
sudo /scripts/restartsrv_apache_php_fpm
```

EasyApache 4 updates: this package is not in cPanel's EA4 repository, and
provisioning an EasyApache 4 profile installs that profile's packages and
uninstalls the others. After you provision a profile, check
`rpm -q ea-php74-php-howdah` (`dpkg -s` on Ubuntu) and install it again if it
is gone. Updating the `ea-php` packages with `dnf`/`yum`/`apt` leaves it in
place.

Roll back: `sudo dnf remove ea-php74-php-howdah` (or `apt-get purge`), then
restart PHP-FPM.

### Plesk

Package `plesk-php<XY>-howdah` for Plesk's PHP `X.Y` (for example
`plesk-php74-howdah`): `/opt/plesk/php/X.Y/lib64/php/modules/howdah.so` on
RPM systems, `/opt/plesk/php/X.Y/lib/php/modules/howdah.so` on Debian and
Ubuntu, and `/opt/plesk/php/X.Y/etc/php.d/howdah.ini`. Requires
`plesk-php<XY>`. RPM: x86_64; deb: amd64 and arm64.

RPM systems: the `.repo` file is the one for cPanel above with
`[howdah-plesk]` and `baseurl=https://pkg.howdah.org/plesk/yum`, then:

```sh
sudo dnf install plesk-php74-howdah
```

Debian and Ubuntu: the apt line is
`deb [signed-by=/etc/apt/keyrings/howdah.asc] https://pkg.howdah.org/plesk/apt stable main`, then:

```sh
sudo apt-get update
sudo apt-get install plesk-php74-howdah
```

Verify and restart:

```sh
/opt/plesk/php/7.4/bin/php -m | grep -i howdah
sudo plesk bin php_handler --reread      # Plesk's PHP settings page lists the module
sudo systemctl restart plesk-php74-fpm
```

Roll back: `sudo dnf remove plesk-php74-howdah` (or `apt-get purge`), then
restart `plesk-php74-fpm`.

### CloudLinux alt-php

Package `alt-php<XY>-howdah` for CloudLinux's `alt-php<XY>` (for example
`alt-php74-howdah`): `/opt/alt/php<XY>/usr/lib64/php/modules/howdah.so`, and
`howdah.ini` in both `/opt/alt/php<XY>/etc/php.d.all/` (the PHP Selector's
module list) and `/opt/alt/php<XY>/etc/php.d.std/`, as CloudLinux's own
module packages do. Requires `alt-php<XY>`. x86_64 only. Not install-tested:
alt-php binaries need a CloudLinux licence.

The `.repo` file is the one for cPanel above with `[howdah-cloudlinux]` and
`baseurl=https://pkg.howdah.org/cloudlinux/yum`, then:

```sh
sudo yum install alt-php74-howdah
sudo cagefsctl --setup-cl-selector
sudo selectorctl --version=7.4 --enable-extensions=howdah   # default for every user on alt-php 7.4
```

or enable it per user in the PHP Selector. On a CloudLinux server with cPanel,
`ea-php` versions take the cPanel package above and `alt-php` versions this
one; `howdah-check detect` says which applies to each PHP.

### Stock RHEL, Alma, Rocky and Amazon Linux PHP

Package `php-howdah` for the distribution's own PHP (`/usr/bin/php`):
`/usr/lib64/php/modules/howdah.so` and `/etc/php.d/40-howdah.ini`, which loads
the module by absolute path (Amazon Linux 2023 keeps its own modules in
`/usr/lib64/php<X.Y>/modules`). Requires `php(zend-abi) = <API>-64`, the exact
ABI of your PHP. x86_64 and aarch64.

The distribution PHP's package names carry no minor, so there is one
repository per minor. Use the one for your PHP (`php -v`), here 7.4:

```sh
sudo rpm --import https://howdah.org/key.asc
sudo tee /etc/yum.repos.d/howdah-el.repo >/dev/null <<'REPO'
[howdah-el]
name=Howdah for the distribution PHP 7.4
baseurl=https://pkg.howdah.org/el/php7.4/yum
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://howdah.org/key.asc
REPO
sudo dnf install php-howdah              # yum on CentOS 7
php -m | grep -i howdah
sudo systemctl reload php-fpm            # or httpd
```

If you change PHP minor later (for example `dnf module switch-to php:8.2`),
remove `php-howdah` first, change `baseurl` to the new minor, then install it
again. Roll back: `sudo dnf remove php-howdah`.

### DirectAdmin and other builds

DirectAdmin's CustomBuild compiles PHP from source into `/usr/local/php<XY>`,
which no package owns, so there is no package. Use the tarball:
`howdah-check detect` names it and the extension directory; copy `howdah.so`
there and `howdah.ini` to `/usr/local/php<XY>/lib/php.conf.d/90-howdah.ini`,
then restart that PHP's FPM and Apache. The same tarball route covers any
PHP `detect` reports as `layout: unknown`. Details:
[packaging-layouts.md](packaging-layouts.md#how-each-layout-loads-the-module).

## Key

The repository signing key is published at `https://howdah.org/key.asc` (the
same key that signs the GitHub release `SHA256SUMS`). Check its fingerprint
against the one on the release page before trusting it. The primary
fingerprint is `1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B`:

```sh
curl -fsSL https://howdah.org/key.asc | gpg --show-keys --with-fingerprint
```
