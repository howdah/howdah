# Lab image: PHP 8.6.0, NTS, built from source on Debian bookworm.
#
# Not a production image. Provides build tools so the howdah extension can be
# compiled against this PHP's headers (dev.Dockerfile adds Rust + libclang).
#
# Why from source: the official php:8.6 docker images are ZTS (thread-safe)
# builds, and Howdah is NTS-only by design, so the extension cannot compile
# against them. FPM / Apache-prefork PHP in production is NTS, so we build NTS
# (the configure default; no --enable-zts). For the same reason php:8.6-apache
# (ZTS) is not used here.

FROM debian:bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c bison curl ca-certificates \
        libssl-dev libxml2-dev libcurl4-openssl-dev libzip-dev libonig-dev zlib1g-dev \
        libsqlite3-dev xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV PHP_VERSION=8.6.0 \
    PHP_SHA256=62337dccde3d9fcc39797d4529f42637613036eaf3875353c206874e5813a3c1

RUN set -eux; \
    cd /usr/src; \
    for base in https://www.php.net/distributions https://museum.php.net/php8; do \
      if curl -fsSL -o php.tar.gz "$base/php-${PHP_VERSION}.tar.gz"; then \
        if echo "${PHP_SHA256}  php.tar.gz" | sha256sum -c -; then break; fi; \
      fi; \
      rm -f php.tar.gz; \
    done; \
    echo "${PHP_SHA256}  php.tar.gz" | sha256sum -c -; \
    mkdir php; tar -xzf php.tar.gz -C php --strip-components=1; \
    cd php; \
    ./configure \
        --prefix=/usr/local \
        --with-config-file-path=/usr/local/etc/php \
        --with-config-file-scan-dir=/usr/local/etc/php/conf.d \
        --enable-fpm --with-fpm-user=www-data --with-fpm-group=www-data \
        --with-openssl --enable-soap --with-zlib --with-curl \
        --enable-phar --enable-simplexml --enable-dom --enable-ftp \
        --enable-session --enable-mbstring --with-libxml \
        --disable-cgi; \
    make -j"$(nproc)"; \
    make install; \
    mkdir -p /usr/local/etc/php/conf.d; \
    cd /; rm -rf /usr/src/php /usr/src/php.tar.gz

CMD ["sleep", "infinity"]
