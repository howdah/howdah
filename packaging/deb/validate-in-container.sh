#!/bin/sh
# Runs INSIDE a Debian container (driven by packaging/deb/validate.sh): install
# the given php<minor>-howdah .deb against Sury PHP, check it loads, check the
# wrong-API guard, then remove / purge.
#   validate-in-container.sh <minor> <deb> [<deb-for-another-minor>]
set -eu
export DEBIAN_FRONTEND=noninteractive
MINOR="$1"; DEB="$2"; OTHER="${3:-}"
step() { echo; echo "### $*"; }
apt-get update -qq >/dev/null
apt-get install -y -qq ca-certificates curl lsb-release apt-transport-https >/dev/null 2>&1
curl -fsSL https://packages.sury.org/php/apt.gpg -o /etc/apt/trusted.gpg.d/php.gpg
echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
apt-get update -qq >/dev/null
apt-get install -y -qq "php$MINOR-cli" >/dev/null 2>&1
PKG="php$MINOR-howdah"

step "baseline"; php -v | head -1; echo "howdah modules loaded: $(php -m | grep -ci howdah || true)"

if [ -n "$OTHER" ]; then
  step "WRONG-API GUARD: $(basename "$OTHER") against PHP $MINOR must be refused"
  dpkg-deb -f "$OTHER" Depends
  OPKG="$(dpkg-deb -f "$OTHER" Package)"
  echo "-- apt, Sury repo reachable (simulate): it can only satisfy the dep by adding the matching PHP side by side, never by loading into 7.4:"
  apt-get install -s "$OTHER" 2>&1 | grep -E '^(Inst php[0-9.]+-(common|howdah)|The following NEW)' || true
  echo "-- apt, host whose repos only offer this PHP (pin the other minor out): refused up front, installs nothing:"
  OMINOR="$(dpkg-deb -f "$OTHER" Package | sed -E 's/^php([0-9.]+)-howdah$/\1/')"
  printf 'Package: php%s* libapache2-mod-php%s php%s-common\nPin: release *\nPin-Priority: -1\n' "$OMINOR" "$OMINOR" "$OMINOR" > /etc/apt/preferences.d/no-other-php
  if apt-get install -y "$OTHER" 2>&1 | tail -6; then :; fi
  echo "-- installed? $(dpkg -s "$OPKG" 2>&1 | head -1)"
  echo "-- raw dpkg -i (bypasses apt): unpacks but will NOT configure (so no phpenmod runs)"
  if dpkg -i "$OTHER"; then echo "UNEXPECTED: installed"; exit 1; else echo "dpkg refused to configure (rc=$?)"; fi
  dpkg -s "$OPKG" | grep '^Status'
  dpkg --purge "$OPKG" >/dev/null 2>&1; echo "-- cleaned up: $(dpkg -s "$OPKG" 2>&1 | head -1)"
  echo "howdah modules loaded: $(php -m | grep -ci howdah || true)"; php -v | head -1
fi

step "INSTALL: dpkg -i $(basename "$DEB")"
dpkg-deb -f "$DEB" Package Version Architecture Depends
dpkg -i "$DEB"
step "state after install"
dpkg -s "$PKG" | grep -E '^(Status|Version|Architecture)'
ls -l /etc/php/$MINOR/*/conf.d/ | grep howdah
php -m | grep -i howdah
php --ri howdah | head -8
php -v | head -2

step "REMOVE: dpkg -r"
dpkg -r "$PKG"
echo "conf.d howdah links left: $(ls /etc/php/$MINOR/*/conf.d/ | grep -c howdah || true)"
echo "howdah modules loaded: $(php -m | grep -ci howdah || true)"
ls /usr/lib/php/*/howdah.so 2>&1 || true
php -v 2>&1 | head -2
ls /etc/php/$MINOR/mods-available/howdah.ini   # conffile kept on remove (Debian policy)

step "REINSTALL then PURGE: apt-get purge"
dpkg -i "$DEB" >/dev/null; php -m | grep -i howdah
apt-get purge -y "$PKG" 2>&1 | tail -4
ls /etc/php/$MINOR/mods-available/howdah.ini 2>&1 || true
echo "conf.d howdah links left: $(ls /etc/php/$MINOR/*/conf.d/ | grep -c howdah || true)"
echo "howdah modules loaded: $(php -m | grep -ci howdah || true)"
php -v 2>&1 | head -2
php -r 'echo "PHP works: ", PHP_VERSION, "\n";'
