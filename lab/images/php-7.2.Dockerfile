# Lab image: PHP 7.2 (NTS, Debian buster-based php:7.2-fpm).
#
# Not a production image. Debian buster is EOL and has moved to the archive;
# point apt at archive.debian.org buster (skip Valid-Until, accept
# unauthenticated — fine for a throwaway lab build-tools layer).

FROM php:7.2-fpm

RUN printf 'deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends --allow-unauthenticated \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
