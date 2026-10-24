#!/bin/sh
# Runs INSIDE a container (driven by packaging/validate-layout.sh): install the
# vendor's own PHP for one layout, run howdah-check detect, install the Howdah
# layout package, check it loads, then remove it and check PHP still runs.
#   validate-layout-in-container.sh <layout> <minor> <package-file> [<wrong-abi-package-file>]
# layouts: stock-rhel (EL8/EL9 module stream or Amazon Linux 2023), cpanel-rpm,
# cpanel-deb (Ubuntu), plesk-rpm, plesk-deb. Needs network (vendor repos).
set -eu
LAYOUT="$1"; MINOR="$2"; PKGF="$3"; WRONG="${4:-}"
XY="$(echo "$MINOR" | tr -d .)"
step() { echo; echo "### $*"; }
. /etc/os-release
echo "container: $PRETTY_NAME"

case "$LAYOUT" in
  stock-rhel)
    PHP=/usr/bin/php
    if [ "$ID" = amzn ]; then dnf -y -q install "php$MINOR-cli" >/dev/null
    else dnf -y -q module enable "php:$MINOR" >/dev/null 2>&1; dnf -y -q install php-cli >/dev/null; fi ;;
  cpanel-rpm)
    PHP=/opt/cpanel/ea-php$XY/root/usr/bin/php
    # cPanel's public EA4 mirror (the repo a cPanel server already has enabled)
    printf '[EA4]\nname=EA4\nbaseurl=http://184.94.200.4/cpanelsync/repos/CentOS/%s/EA4/\ngpgcheck=0\nenabled=1\n' \
      "${VERSION_ID%%.*}" > /etc/yum.repos.d/EA4.repo
    dnf -y -q install epel-release >/dev/null 2>&1 || true
    dnf -y -q install "ea-php$XY-php-cli" >/dev/null ;;
  plesk-rpm)
    PHP=/opt/plesk/php/$MINOR/bin/php
    for k in dist thirdparty; do
      printf '[plesk-php-%s]\nname=Plesk PHP %s\nbaseurl=https://autoinstall.plesk.com/PHP%s_17/%s-rpm-RedHat-el%s-x86_64/\ngpgcheck=0\nenabled=1\n' \
        "$k" "$k" "$XY" "$k" "${VERSION_ID%%.*}" > "/etc/yum.repos.d/plesk-php-$k.repo"
    done
    dnf -y -q install epel-release >/dev/null 2>&1 || true
    dnf -y -q install "plesk-php$XY-cli" >/dev/null ;;
  plesk-deb|cpanel-deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null; apt-get install -y -qq ca-certificates curl >/dev/null 2>&1
    if [ "$LAYOUT" = plesk-deb ]; then
      PHP=/opt/plesk/php/$MINOR/bin/php
      echo "deb [trusted=yes] https://autoinstall.plesk.com/PHP${XY}_17 $VERSION_CODENAME all" > /etc/apt/sources.list.d/plesk-php.list
      apt-get update -qq >/dev/null; apt-get install -y -qq "plesk-php$XY-cli" >/dev/null
    else
      PHP=/opt/cpanel/ea-php$XY/root/usr/bin/php
      echo "deb [trusted=yes] http://184.94.200.4/cpanelsync/repos/Ubuntu/${VERSION_ID%%.*}/EA4 ./" > /etc/apt/sources.list.d/ea4.list
      apt-get update -qq >/dev/null; apt-get install -y -qq "ea-php$XY-php-cli" >/dev/null
      # cPanel's Ubuntu ea-php builds link these without declaring them (a cPanel
      # server already has them); a bare container does not.
      apt-get install -y -qq libxml2 libedit2 libargon2-1 >/dev/null
    fi ;;
  *) echo "unknown layout $LAYOUT" >&2; exit 2 ;;
esac

step "vendor PHP"; $PHP -v | head -1
step "howdah-check detect (before install)"
PATH="$(dirname "$PHP"):$PATH" sh /howdah-check detect | sed -n "\#^php: $PHP#,/sapi apache/p"

if [ -n "$WRONG" ]; then
  step "WRONG-ABI GUARD: $(basename "$WRONG") must be refused on PHP $MINOR"
  case "$WRONG" in
    *.rpm) rpm -i "$WRONG" 2>&1 | tail -3
           if rpm -q "$(rpm -qp --qf '%{NAME}' "$WRONG" 2>/dev/null)" >/dev/null 2>&1; then
             echo "UNEXPECTED: installed"; exit 1; fi
           echo "refused by rpm (as required)" ;;
    *.deb) if dpkg -i "$WRONG" >/tmp/w.log 2>&1; then echo "UNEXPECTED: configured"; exit 1; fi
           tail -3 /tmp/w.log; echo "dpkg refused to configure (as required)"
           dpkg --purge "$(dpkg-deb -f "$WRONG" Package)" >/dev/null 2>&1 || true ;;
  esac
fi

step "INSTALL $(basename "$PKGF")"
case "$PKGF" in
  *.rpm) dnf -y install "$PKGF" 2>&1 | tail -4; NAME=$(rpm -qp --qf '%{NAME}' "$PKGF" 2>/dev/null); rpm -ql "$NAME" ;;
  *.deb) dpkg -i "$PKGF" 2>&1 | tail -3; NAME=$(dpkg-deb -f "$PKGF" Package); dpkg -L "$NAME" | grep -E 'howdah\.(so|ini)$' ;;
esac
step "loaded?"
$PHP -m | grep -ix howdah
$PHP --ri howdah | head -6
$PHP -v | head -1

step "REMOVE"
case "$PKGF" in
  *.rpm) dnf -y remove "$NAME" 2>&1 | tail -2 ;;
  *.deb) dpkg --purge "$NAME" 2>&1 | tail -2 ;;
esac
echo "howdah modules loaded after removal: $($PHP -m | grep -ci howdah || true)"
$PHP -r 'echo "PHP still runs: ", PHP_VERSION, "\n";'
