# Installing Howdah from the package repositories

Howdah is published as signed apt and yum repositories at `https://pkg.howdah.org`
(HTTPS only). One package per PHP minor: `php<minor>-howdah` on Debian/Ubuntu
(for example `php7.4-howdah`) and `php<XY>-howdah` on RPM systems using the Remi
layout (for example `php74-howdah`).

> **Status: not live yet.** The repositories, signing and CI are built and were
> validated against a throwaway key and local containers. These commands start
> working once the project owner runs the publish workflow (see
> `packaging/repo/GO-LIVE.md`). Until then, use the tarballs from the GitHub
> release.
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

The repository index lists only the most recent publish, so older versions
cannot be pinned or rolled back to through the repo until that is changed (a
tracked follow-up before the second release). Keep the previous package file if
you may need to downgrade.

Removal never breaks PHP: the maintainer scripts only enable/disable the module
and never fail the transaction.

## CentOS 7, AlmaLinux / Rocky 8 and 9 (yum / dnf)

Supported: CentOS 7, AlmaLinux and Rocky Linux 8 and 9 (and RHEL equivalents).
Architectures: x86_64, aarch64 (CentOS 7 aarch64 depends on your PHP source;
Remi publishes no EL7 aarch64). Packages follow the Remi software-collection
layout: `php<XY>-howdah` installs into `/opt/remi/php<XY>/` and requires
`php<XY>-php-common` from Remi. Stock distribution PHP (non-Remi) is not
packaged yet; use the tarball.

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

## Key

The repository signing key is published at `https://howdah.org/key.asc` (the
same key that signs the GitHub release `SHA256SUMS`). Check its fingerprint
against the one on the release page before trusting it. The primary
fingerprint is `1152 1035 C600 F638 31F8 2551 2087 B872 0997 807B`:

```sh
curl -fsSL https://howdah.org/key.asc | gpg --show-keys --with-fingerprint
```
