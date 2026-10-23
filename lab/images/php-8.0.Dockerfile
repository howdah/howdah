# Lab image: PHP 8.0 (NTS, Debian bullseye-based php:8.0-fpm).
#
# Not a production image. 8.0 is EOL, so the php:8.0-fpm image is frozen and its
# baked apt metadata pins point-release versions that have rolled off the mirror
# (plain `apt-get update` 404s). Point apt at the live Debian bullseye mirror
# (bullseye is still served) for a current, consistent package set.

FROM php:8.0-fpm

# Only the main suite: the bullseye-security pool has rolled some point
# versions (libc6, curl) that the frozen 8.0 image pins, so including
# -security 404s. main carries the build tools we need. (Matches dev.Dockerfile.)
RUN printf 'deb http://deb.debian.org/debian bullseye main\n' > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
