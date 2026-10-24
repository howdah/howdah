#!/bin/sh
# In-container half of the latency benchmark (lab/bench/run.sh drives it with
# `docker exec`). Runs inside a howdah-dev-php<ver> image (php-fpm) or a
# howdah-dev-apache-php<ver> image (Apache mod_php, prefork).
#
#   server.sh build <php5|php7|php8>   build the extension, install the app
#   server.sh start <fpm|apache> <noext|l1|l12|l123|default>
#                                      write the php ini for that config, start
#                                      the SAPI, check the config took effect,
#                                      print the probe ("default" = the shipped
#                                      howdah.ini: howdah.mode=detect, no TOML)
#   server.sh stop <fpm|apache>        stop the SAPI and wait until it is gone
#   server.sh reset                    empty the Howdah event log
#   server.sh events                   print the number of Howdah event lines
#
# Every configuration has OPcache enabled with the JIT off (PHP 8.x), because
# that is how PHP is normally deployed and because loading Howdah turns the JIT
# off anyway (see docs/performance.md). php-fpm uses its own config file
# (static pool, $WORKERS children); Apache uses the image's prefork defaults
# with keep-alive made unlimited and the access log disabled.
set -eu

CMD="${1:-}"
[ $# -gt 0 ] && shift

B=/tmp/bench                 # runtime state: event log, fpm config, pid
EXT=/opt/howdah-bench        # built extension + benchmark configs
DOCROOT=/var/www/html
WORKERS="${WORKERS:-4}"

confd() {
  _d=$(php -r 'echo PHP_CONFIG_FILE_SCAN_DIR;' 2>/dev/null || true)
  [ -n "$_d" ] || _d=/usr/local/etc/php/conf.d
  echo "$_d"
}
INI="$(confd)/zz-howdah-bench.ini"

ap() { if command -v apache2ctl >/dev/null 2>&1; then apache2ctl "$@"; else apachectl "$@"; fi; }

url_for() { # sapi -> base URL
  if [ "$1" = apache ]; then echo "http://127.0.0.1:80"; else echo "http://127.0.0.1:8080"; fi
}

wait_up() { # url
  _j=0
  while [ "$(curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null || true)" != 200 ]; do
    _j=$((_j + 1))
    if [ "$_j" -gt 150 ]; then echo "server.sh: $1 never answered 200" >&2; return 1; fi
    sleep 0.1
  done
}

case "$CMD" in
  build)
    FEATURE="${1:?feature}"
    mkdir -p "$B" "$EXT" "$DOCROOT"
    chmod 777 "$B"
    export CARGO_TARGET_DIR=/tmp/t
    cd /src
    if ! cargo build --locked -p howdah-ext --features "$FEATURE" --release > "$B/build.log" 2>&1; then
      tail -20 "$B/build.log" >&2
      exit 1
    fi
    cp /tmp/t/release/libhowdah_ext.so "$EXT/howdah.so"
    cp /src/lab/bench/configs/*.toml "$EXT/"
    cp /src/lab/bench/app/*.php "$DOCROOT/"
    mkdir -p /var/www/corpus
    cp /src/lab/bench/corpus/app.php /var/www/corpus/app.php
    chmod -R a+rX "$EXT" "$DOCROOT" /var/www/corpus
    # Load OPcache ourselves only where the image does not already (5.x/7.x
    # images ship it as a shared extension that is not enabled).
    rm -f "$INI"
    if php -m 2>/dev/null | grep -qx 'Zend OPcache'; then echo 0 > "$EXT/load-opcache"; else echo 1 > "$EXT/load-opcache"; fi
    if command -v apache2ctl >/dev/null 2>&1 || command -v apachectl >/dev/null 2>&1; then
      # Unlimited keep-alive (wrk keeps its connections) and no access log, so
      # the cells measure PHP, not log writes or reconnects.
      printf 'MaxKeepAliveRequests 0\nKeepAliveTimeout 60\nServerName localhost\n' > /etc/apache2/conf-enabled/zz-howdah-bench.conf
      sed -i 's/^\([[:space:]]*CustomLog\)/#\1/' /etc/apache2/sites-enabled/000-default.conf 2>/dev/null || true
      rm -f /etc/apache2/conf-enabled/other-vhosts-access-log.conf
    fi
    php -r 'echo PHP_VERSION, "\n";'
    ;;

  start)
    SAPI="${1:?sapi}"; CONF="${2:?config}"
    mkdir -p "$B"; chmod 777 "$B"
    {
      if [ "$(cat "$EXT/load-opcache")" = 1 ]; then echo "zend_extension=opcache.so"; fi
      echo "opcache.enable=1"
      echo "opcache.enable_cli=0"
      if php -r 'exit(PHP_VERSION_ID >= 80000 ? 0 : 1);'; then echo "opcache.jit_buffer_size=0"; fi
      if [ "$CONF" = default ]; then
        # The shipped packaging/howdah.ini: no TOML file, howdah.mode = detect.
        echo "extension=$EXT/howdah.so"
        echo "howdah.log=$B/events.log"
        echo "howdah.mode=detect"
      elif [ "$CONF" != noext ]; then
        echo "extension=$EXT/howdah.so"
        echo "howdah.log=$B/events.log"
        echo "howdah.config=$EXT/$CONF.toml"
      fi
    } > "$INI"
    : > "$B/events.log"; chmod 666 "$B/events.log"
    if [ "$SAPI" = fpm ]; then
      cat > "$B/fpm.conf" <<EOF
[global]
error_log = $B/fpm.err
pid = $B/fpm.pid
daemonize = yes
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = $WORKERS
pm.max_requests = 0
catch_workers_output = yes
EOF
      php-fpm -R -y "$B/fpm.conf"
    else
      ap start 2> "$B/apache.err"
    fi
    wait_up "$(url_for "$SAPI")/probe.php"
    # Behavioural config check. A TOML the core rejects silently falls back to
    # safe defaults, so `php --ri` alone cannot prove the config took effect;
    # instead one request exercises Layer 2 (an injection-shaped value), the
    # command_exec sink and the phar sink, and the event log must show exactly
    # the layers this config enables.
    : > "$B/events.log"
    curl -s -o /dev/null "$(url_for "$SAPI")/probe.php?check=1&q=%27%20OR%201%3D1%20--"
    sleep 0.2
    _sql=$(grep -c '"rule":"sql_injection"' "$B/events.log" || true)
    _cmd=$(grep -c '"rule":"command_exec"' "$B/events.log" || true)
    _phar=$(grep -c '"rule":"phar"' "$B/events.log" || true)
    case "$CONF" in
      noext|l1) _want="0 0 0" ;;
      l12)      _want="1 0 0" ;;
      l123)     _want="1 1 1" ;;
      default)  _want="1 1 0" ;;   # shipped defaults: phar is off
      *)        _want="? ? ?" ;;
    esac
    if [ "$_sql $_cmd $_phar" != "$_want" ]; then
      echo "server.sh: config $CONF check failed: sql_injection/command_exec/phar events = $_sql $_cmd $_phar, want $_want" >&2
      cat "$B/events.log" >&2
      exit 1
    fi
    : > "$B/events.log"
    curl -s "$(url_for "$SAPI")/probe.php"
    ;;

  stop)
    SAPI="${1:?sapi}"
    if [ "$SAPI" = fpm ]; then
      if [ -f "$B/fpm.pid" ]; then
        _p=$(cat "$B/fpm.pid")
        kill "$_p" 2>/dev/null || true
        _j=0
        while kill -0 "$_p" 2>/dev/null; do
          _j=$((_j + 1)); [ "$_j" -gt 100 ] && { kill -9 "$_p" 2>/dev/null || true; break; }
          sleep 0.1
        done
        rm -f "$B/fpm.pid"
      fi
    else
      ap stop 2>/dev/null || true
      _j=0
      while curl -s -o /dev/null http://127.0.0.1:80/ 2>/dev/null; do
        _j=$((_j + 1)); [ "$_j" -gt 100 ] && break
        sleep 0.1
      done
      # prefork children can outlive the parent's exit by a moment
      sleep 0.5
    fi
    ;;

  reset)
    : > "$B/events.log"
    ;;

  events)
    if [ -f "$B/events.log" ]; then wc -l < "$B/events.log" | tr -d ' '; else echo 0; fi
    ;;

  *)
    echo "usage: server.sh build|start|stop|reset|events ..." >&2
    exit 2
    ;;
esac
