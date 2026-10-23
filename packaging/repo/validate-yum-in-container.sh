#!/bin/sh
# Runs INSIDE an EL container (driven by validate.sh): the REAL yum/dnf client
# flow against a served repo with gpgcheck=1 + repo_gpgcheck=1.
#   validate-yum-in-container.sh <elmajor> <minor> <base-url> <mode>
# mode=ok | tamper (see validate-apt-in-container.sh)
set -u
EL="$1"; MINOR="$2"; BASE="$3"; MODE="$4"
XY="$(echo "$MINOR" | tr -d .)"
step() { echo; echo "### $*"; }
PHP="/opt/remi/php$XY/root/usr/bin/php"
if [ "$EL" = 7 ]; then
  sed -i -e 's|^mirrorlist=|#mirrorlist=|' -e 's|^#baseurl=http://mirror.centos.org/centos/$releasever|baseurl=https://archive.kernel.org/centos-vault/7.9.2009|' /etc/yum.repos.d/CentOS-*.repo  # vault.centos.org 403s some CI IPs
  yum install -y -q epel-release >/dev/null
  yum install -y -q https://rpms.remirepo.net/enterprise/remi-release-7.rpm >/dev/null
  YUM=yum; yum install -y -q yum-utils >/dev/null; yum-config-manager --enable remi-safe >/dev/null
else
  dnf install -y -q epel-release >/dev/null 2>&1
  dnf install -y -q "https://rpms.remirepo.net/enterprise/remi-release-$EL.rpm" >/dev/null
  YUM=dnf
fi
$YUM install -y -q "php$XY-php-cli" >/dev/null 2>&1
[ -x "$PHP" ] || { echo "SETUP FAILED: $PHP missing (mirror hiccup?) - rerun"; exit 3; }
$PHP -v | head -1

step "import throwaway public key + drop .repo (gpgcheck=1, repo_gpgcheck=1)"
rpm --import /key.asc
# Same file as packaging/repo/howdah.repo with only baseurl/gpgkey swapped for the local test server.
sed -e "s|^baseurl=.*|baseurl=$BASE|" -e "s|^gpgkey=.*|gpgkey=file:///key.asc|" /howdah.repo > /etc/yum.repos.d/howdah.repo
cat /etc/yum.repos.d/howdah.repo
rpm -qa 'gpg-pubkey*' --qf '%{NAME}-%{VERSION}-%{RELEASE}  %{SUMMARY}\n' | grep -i throwaway

step "$YUM makecache"
$YUM clean all >/dev/null 2>&1
$YUM -y --disablerepo="*" --enablerepo=howdah makecache 2>&1 | grep -iE "howdah|gpg|key|import|fingerprint|userid|retriev|error|fail|verif|signature" | head -20

step "$YUM install php$XY-howdah"
$YUM install -y "php$XY-howdah" 2>&1 > /tmp/inst.log 2>&1; grep -vE "^\s*$" /tmp/inst.log | tail -14
if rpm -q "php$XY-howdah" >/dev/null 2>&1; then
  echo "RESULT: php$XY-howdah INSTALLED"
  rpm -qi "php$XY-howdah" | grep -E '^(Name|Version|Signature)'
  $PHP -m | grep -i howdah && echo "RESULT: howdah loaded"
  [ "$MODE" = ok ] && exit 0
  echo "UNEXPECTED: tampered repo was accepted"; exit 1
else
  echo "RESULT: php$XY-howdah NOT installed"
  echo "-- why:"; grep -iE "signature|GPG|checksum|not signed|does not match" /tmp/inst.log | sort -u | head -5
  # Only count it as a refusal if the client says it was a verification failure.
  [ "$MODE" = tamper ] && grep -qiE "signature|GPG|checksum|does not match" /tmp/inst.log && { echo "RESULT: tampering REFUSED (as required)"; exit 0; }
  exit 1
fi
