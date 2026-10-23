#!/bin/sh
# Runs INSIDE an EL container (driven by packaging/rpm/validate.sh): install the
# Remi SCL php<XY>, install the given howdah rpm, check load, the wrong-ABI
# guard, then remove.
#   validate-in-container.sh <elmajor> <minor> <rpm> [<rpm-for-another-minor>]
set -eu
EL="$1"; MINOR="$2"; RPM="$3"; OTHER="${4:-}"
XY="$(echo "$MINOR" | tr -d .)"
step() { echo; echo "### $*"; }
PHP="/opt/remi/php$XY/root/usr/bin/php"
if [ "$EL" = 7 ]; then
  sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' /etc/yum.repos.d/CentOS-*.repo
  yum install -y -q epel-release >/dev/null
  yum install -y -q https://rpms.remirepo.net/enterprise/remi-release-7.rpm >/dev/null
  YUM=yum; yum install -y -q yum-utils >/dev/null; yum-config-manager --enable remi-safe >/dev/null
else
  dnf install -y -q epel-release >/dev/null 2>&1 || dnf install -y -q epel-release
  dnf install -y -q "https://rpms.remirepo.net/enterprise/remi-release-$EL.rpm" >/dev/null
  YUM=dnf
fi
$YUM install -y -q "php$XY-php-cli" >/dev/null
PKG="php$XY-howdah"

step "baseline"; $PHP -v | head -1; echo "howdah modules loaded: $($PHP -m | grep -ci howdah || true)"

if [ -n "$OTHER" ]; then
  step "WRONG-ABI GUARD: $(basename "$OTHER") (Requires below) with only PHP $MINOR present"
  rpm -qp --requires "$OTHER" | grep -E 'php[0-9]+-php'
  OPKG="$(rpm -qp --qf '%{NAME}' "$OTHER")"
  echo "-- rpm -i (no yum): must refuse"
  if rpm -i "$OTHER"; then echo "UNEXPECTED: installed"; exit 1; else echo "rpm refused (rc=$?)"; fi
  echo "-- installed? $(rpm -q "$OPKG" 2>&1)"
  echo "-- yum/dnf install with the other PHP repo-available: pulls the MATCHING php side by side (SCL), never loads into $MINOR:"
  $YUM install -y --setopt=tsflags=test "$OTHER" 2>&1 | grep -E 'php[0-9]+-(php|howdah)\b|Installing|Install ' | head -8 || true
  echo "howdah modules loaded in php$XY: $($PHP -m | grep -ci howdah || true)"
fi

step "INSTALL: rpm -i $(basename "$RPM")"
rpm -qp --requires "$RPM" | grep -E 'php[0-9]+-php'
$YUM install -y "$RPM" 2>&1 | tail -6
step "state after install"
rpm -q "$PKG"; rpm -ql "$PKG"
$PHP -m | grep -i howdah
$PHP --ri howdah | head -8
$PHP -v | head -2

step "REMOVE"
$YUM remove -y "$PKG" 2>&1 | tail -3
rpm -q "$PKG" 2>&1 || true
ls /opt/remi/php$XY/root/usr/lib64/php/modules/howdah.so /etc/opt/remi/php$XY/php.d/40-howdah.ini 2>&1 || true
echo "howdah modules loaded: $($PHP -m | grep -ci howdah || true)"
$PHP -v | head -2
$PHP -r 'echo "php still runs: ", PHP_VERSION, "\n";'
rpm -V "php$XY-php-common" && echo "php-common verifies clean"
