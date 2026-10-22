# Milestone-0 lab image: PHP 5.6 (NTS, Debian stretch-based php:5.6-fpm).
#
# Not a production image. Provides build tools so the throwaway milestone-0
# spike extension (lab/spike/probe.c) can be compiled against this PHP's
# headers inside the container. See docs/superpowers/specs/milestone-0-findings.md.

FROM php:5.6-fpm

# Debian stretch is long EOL; deb.debian.org no longer serves it at all.
# Point apt at archive.debian.org instead. Its signing keys have since
# expired (this suite will never be updated again), so skip the
# Valid-Until check and accept the unauthenticated archive packages --
# acceptable for a throwaway build-tools layer in an isolated lab
# container, never done for a production image.
RUN printf 'deb http://archive.debian.org/debian stretch main\ndeb http://archive.debian.org/debian-security stretch/updates main\n' > /etc/apt/sources.list \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Acquire::Check-Valid-Until=false install -y --no-install-recommends --allow-unauthenticated \
        autoconf dpkg-dev file g++ gcc libc-dev make pkg-config re2c curl \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
