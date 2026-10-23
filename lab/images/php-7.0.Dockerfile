# Lab image: PHP 7.0 (NTS, Debian stretch-based php:7.0-fpm).
#
# Not a production image. Debian stretch is long EOL and deb.debian.org no
# longer serves it; point apt at archive.debian.org (its signing keys have
# expired and the suite is frozen, so skip Valid-Until and accept the
# unauthenticated archive packages — fine for a throwaway lab build-tools layer).
# Mirrors lab/images/php-5.6.Dockerfile (also stretch).

FROM php:7.0-fpm

RUN printf 'deb http://archive.debian.org/debian stretch main\ndeb http://archive.debian.org/debian-security stretch/updates main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends --allow-unauthenticated \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
