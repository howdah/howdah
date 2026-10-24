#!/bin/sh
# Shared by the layout-repo scripts: list "<prefix> <kind>" for every
# <prefix>/<kind>/ directory under $1 that holds packages (kind = apt | yum),
# e.g. "cpanel yum", "el/php7.4 yum", "plesk apt". A prefix is the repository
# path under https://pkg.howdah.org/. The main repository lives at apt/ and
# yum/ at the bucket root, so a prefix that is empty or starts with apt or yum
# is refused: the layout repos can never write into the main repo's paths.
#   layout-prefixes.sh <LAYOUT_DIR>
set -eu
DIR="${1:?usage: layout-prefixes.sh <LAYOUT_DIR>}"
[ -d "$DIR" ] || exit 0
find "$DIR" -mindepth 2 -type d \( -name apt -o -name yum \) | sort | while IFS= read -r d; do
  kind=$(basename "$d")
  prefix=${d#"$DIR"/}; prefix=${prefix%/"$kind"}
  case "$kind" in apt) ls "$d"/*.deb >/dev/null 2>&1 || continue ;; yum) ls "$d"/*.rpm >/dev/null 2>&1 || continue ;; esac
  case "$prefix" in
    ''|apt|apt/*|yum|yum/*) echo "FATAL: layout prefix '$prefix' would overlap the main apt/yum repo" >&2; exit 1 ;;
  esac
  if ! printf '%s\n' "$prefix" | grep -Eq '^[a-z0-9][a-z0-9.-]*(/[a-z0-9][a-z0-9.-]*)*$'; then
    echo "FATAL: unexpected layout prefix '$prefix'" >&2; exit 1
  fi
  echo "$prefix $kind"
done
