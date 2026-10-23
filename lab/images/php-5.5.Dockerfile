# Milestone-0 lab image: PHP 5.5 (NTS, Debian-based php:5.5-fpm).
#
# Not a production image. Provides build tools so the throwaway milestone-0
# spike extension (lab/spike/probe.c) can be compiled against this PHP's
# headers inside the container. See docs/superpowers/specs/milestone-0-findings.md.
#
# NOTE (see milestone-0-findings.md): this image's layer could not be pulled
# in the milestone-0 lab environment (a registry/content-store error
# unrelated to this Dockerfile -- confirmed reproducible against multiple
# php:5.5* tags). 5.5 was therefore not independently measured; the finding
# relies on 5.4 and 5.6 bracketing it with an unchanged rfc1867 ABI. This
# Dockerfile follows the same archive-pinning pattern used successfully for
# 5.6 (php-5.6.Dockerfile) and should be revisited once the image pulls.

FROM php:5.5-fpm

RUN printf 'deb http://archive.debian.org/debian jessie main\ndeb http://archive.debian.org/debian-security jessie/updates main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends --allow-unauthenticated \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
