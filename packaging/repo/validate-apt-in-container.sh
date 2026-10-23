#!/bin/sh
# Runs INSIDE a Debian/Ubuntu container (driven by validate.sh): the REAL apt
# client flow against a served repo, key verified.
#   validate-apt-in-container.sh <minor> <base-url> <mode>
# mode=ok       install must succeed and howdah must load
# mode=tamper   apt must REFUSE (update fails verification, or install of the
#               tampered package is rejected); howdah must NOT be installed
set -u
export DEBIAN_FRONTEND=noninteractive
MINOR="$1"; BASE="$2"; MODE="$3"
step() { echo; echo "### $*"; }
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq ca-certificates curl lsb-release apt-transport-https gnupg >/dev/null 2>&1
if [ -r /etc/os-release ] && grep -q '^ID=debian' /etc/os-release; then
  curl -fsSL https://packages.sury.org/php/apt.gpg -o /etc/apt/trusted.gpg.d/php.gpg
  echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
else
  apt-get install -y -qq software-properties-common >/dev/null 2>&1
  add-apt-repository -y ppa:ondrej/php >/dev/null 2>&1
fi
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq "php$MINOR-cli" >/dev/null 2>&1
php -v | head -1

step "import throwaway public key + add repo ($BASE stable main)"
if apt-get -v 2>/dev/null | head -1 | grep -qE 'apt 1\.[0-3]\.'; then
  echo "legacy apt ($(apt-get -v | head -1)): apt-key add, no signed-by"
  apt-key add /key.asc
  echo "deb $BASE stable main" > /etc/apt/sources.list.d/howdah.list
else
  mkdir -p /etc/apt/keyrings; cp /key.asc /etc/apt/keyrings/howdah.asc
  echo "deb [signed-by=/etc/apt/keyrings/howdah.asc] $BASE stable main" > /etc/apt/sources.list.d/howdah.list
fi
cat /etc/apt/sources.list.d/howdah.list

step "apt-get update"
apt-get update -o Debug::Acquire::gpgv=true 2>&1 | grep -E 'howdah|repo/|GOODSIG|VALIDSIG|BADSIG|NO_PUBKEY|EXPKEYSIG|Hash|[Ss]ignature|^(W|E|Err):'
step "apt-cache policy php$MINOR-howdah"
apt-cache policy "php$MINOR-howdah" | head -6

step "apt-get install php$MINOR-howdah"
apt-get install -y "php$MINOR-howdah" 2>&1 | tail -12
if dpkg -s "php$MINOR-howdah" >/dev/null 2>&1 && [ "$(dpkg -s "php$MINOR-howdah" | grep -c '^Status: install ok installed')" = 1 ]; then
  echo "RESULT: php$MINOR-howdah INSTALLED"
  php -m | grep -i howdah && echo "RESULT: howdah loaded"
  php --ri howdah | head -4
  [ "$MODE" = ok ] && exit 0
  echo "UNEXPECTED: tampered repo was accepted"; exit 1
else
  echo "RESULT: php$MINOR-howdah NOT installed"
  [ "$MODE" = tamper ] && { echo "RESULT: tampering REFUSED (as required)"; exit 0; }
  exit 1
fi
