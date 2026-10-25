# Use Howdah's events in other tools

Howdah writes one JSON line per event ([schema](../log-schema.md)). Any tool
that can read a JSON-lines file or syslog can take it. This folder has small,
tested starting points:

| file | for |
|---|---|
| [`fail2ban/filter.d/howdah.conf`](fail2ban/filter.d/howdah.conf), [`fail2ban/jail.d/howdah.conf`](fail2ban/jail.d/howdah.conf) | fail2ban: ban an address after 3 refused requests in 10 minutes |
| [`crowdsec/parsers/s01-parse/howdah-logs.yaml`](crowdsec/parsers/s01-parse/howdah-logs.yaml), [`crowdsec/scenarios/howdah-blocked.yaml`](crowdsec/scenarios/howdah-blocked.yaml), [`crowdsec/acquis.d/howdah.yaml`](crowdsec/acquis.d/howdah.yaml) | CrowdSec: the same, as a parser, a leaky-bucket scenario and the file acquisition |
| [`wazuh/howdah_decoders.xml`](wazuh/howdah_decoders.xml), [`wazuh/howdah_rules.xml`](wazuh/howdah_rules.xml) | Wazuh: the event file or syslog lines, with alerts at level 10 for `block` and 5 for `log` |
| [`promtail-howdah.yaml`](promtail-howdah.yaml) | Grafana Loki via Promtail: the event file, with `rule`, `action` and `layer` as labels |

How they are checked:

- `lab/integration/log_consumers.sh` puts php-fpm 8.3 behind nginx, sends a
  known mix of requests, and feeds the real event lines to fail2ban 1.1.0
  (`fail2ban-regex`, then a running jail) and CrowdSec v1.7.0
  (`cscli explain`, then a running agent). It checks that exactly the
  expected addresses are banned. It also feeds both tools the same lines in
  the syslog form, with the prefix rsyslog writes to a file added, and checks
  the client-address setups in the next section with nginx and with Apache
  mod_php.
- `lab/integration/siem_snippets.sh` runs the Wazuh and Promtail files against
  real event lines in the real tools (Promtail 3.5.1 `--dry-run`, and
  `wazuh-logtest` in wazuh-manager 4.12.0).

Both need Docker and network access to pull the images.
`site/test/log-contract.test.mjs` checks on every CI run that the files still
parse and only use fields the schema defines.

## Behind a proxy: the client address

`client_ip` is `REMOTE_ADDR` as PHP's server API reports it. Howdah never
reads `X-Forwarded-For`, because a client can set that header to anything.
Behind a reverse proxy, load balancer or CDN, `REMOTE_ADDR` is the proxy's
address. A ban on it would ban every visitor.

Restore the client address in the web server, trusting only your own proxy.
nginx in front of php-fpm:

```nginx
set_real_ip_from 10.0.0.5;      # your proxy or load balancer; never 0.0.0.0/0
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

Apache with mod_php (`a2enmod remoteip` on Debian and Ubuntu):

```apache
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy 10.0.0.5
```

The lab checks both setups: with the module, a request from the trusted hop
logs the forwarded address; a request from any other address keeps its own,
whatever `X-Forwarded-For` it sends; without the module, `client_ip` is the
hop. Also put the proxy's address in the ban tool's ignore list.

## Trust in the log

Howdah writes the event log from the PHP worker, so the worker user can write
to it, and any local process can send a syslog line tagged `howdah`. After a
compromise, code running as that user can add lines that get any address
banned. Keep the addresses you must never lose, such as your office and your
monitoring, in fail2ban's `ignoreip` or a CrowdSec allowlist, and keep ban
times bounded.

## fail2ban

Copy `filter.d/howdah.conf` to `/etc/fail2ban/filter.d/` and
`jail.d/howdah.conf` to `/etc/fail2ban/jail.d/`, set `logpath` to your event
log if it is not `/var/log/howdah/events.log`, then run
`fail2ban-client reload`. Check the filter against your own log first:

```sh
sudo fail2ban-regex /var/log/howdah/events.log /etc/fail2ban/filter.d/howdah.conf
```

The jail bans an address for an hour after 3 refused requests within 10
minutes, with your default `banaction`. Only `"action":"block"` lines count.
Detect-mode lines (`log`), observe's `proposed: ` lines and `excepted` lines
never do. A detect-mode rule is not tuned to be a ban signal: tune it, then arm
it in Howdah. Lines with an empty `client_ip` (the command line) never match.
The filter reads keys in any order. A request cannot plant a match inside a
value, because Howdah writes a quote inside a value as `\"`. The lab sends a
variable named `a"client_ip":"192.0.2.66"` to check this.

The event time comes from `ts`. The filter also matches the syslog form
(`howdah[pid]: {...}`) in a file such as `/var/log/syslog`, so with
`[log] destination = "syslog"` point `logpath` at that file.

## CrowdSec

Copy the three files to the same paths under `/etc/crowdsec/`, set the path in
`acquis.d/howdah.yaml` to your event log, then reload CrowdSec
(`systemctl reload crowdsec`). Check the parse first:

```sh
sudo cscli explain --file /var/log/howdah/events.log --type howdah
```

The parser reads each field by name, takes the event time from `ts`, and sets
`source_ip` from `client_ip`. The scenario is a leaky bucket per address
(capacity 2, leaking one every 3 minutes), so 3 refused requests in quick
succession raise an alert. Your profiles turn the alert into a decision (the
default profile bans for 4 hours), and a remediation component (bouncer)
applies it. As with fail2ban, only `block` lines count. CrowdSec's
`crowdsecurity/whitelists` parser ignores private and loopback addresses.

With `[log] destination = "syslog"`, your existing syslog acquisition already
reads the lines, and the hub's `syslog-logs` parser hands them to this parser.
Leave out `acquis.d/howdah.yaml` in that case.

## Why not `[log] exec`?

The `[log] exec` hook runs as the PHP worker user. That user must not be able
to change the firewall, so a ban belongs to a log reader that runs with its own
privileges. Use the hook for notifications, such as a webhook or a chat
message.

## Wazuh

On the manager, copy `howdah_decoders.xml` to `/var/ossec/etc/decoders/` and
`howdah_rules.xml` to `/var/ossec/etc/rules/`, then restart the manager. On
the agent of each web server, read the event file as JSON:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/howdah/events.log</location>
</localfile>
```

With `[log] destination = "syslog"`, lines reach Wazuh through whatever already
collects the host's syslog; the decoder matches the `howdah` program name (any
`syslog_ident` that starts with `howdah`). Rule 100703 (level 10) fires for
`block`, 100702 (level 5) for `log`; the alert description names the rule,
layer and path, for example `Howdah blocked max_parts (layer 1) on /index.php`.

`action` is a static field in Wazuh, so the rules use `<action>` rather than
`<field name="action">`; the other event fields are dynamic and can be matched
with `<field name="rule">`, `<field name="layer">` and so on.

## Loki

`promtail-howdah.yaml` tails `/var/log/howdah/events.log`, takes the entry
time from `ts`, and labels each entry with `rule`, `action` and `layer`. It
does not label `client_ip` or `request_id`: they have too many values for
Loki labels. Query them with LogQL instead:

```
{job="howdah", action="block"} | json | client_ip="203.0.113.7"
```

Grafana has deprecated Promtail in favour of Grafana Alloy, which has the
same stages (`stage.json`, `stage.labels`, `stage.timestamp` in
`loki.process`) and a `convert` command for Promtail files. The Alloy form
has not been tested here.

## Not covered

- The lab checks who gets banned, not the ban itself. fail2ban runs with the
  `dummy` action (a container has no firewall to change), and no CrowdSec
  bouncer is installed: the lab reads CrowdSec's decision list.
- fail2ban's journal backend (`backend = systemd`) is not tested. Only the
  event file and a syslog file are.
- IPv6 client addresses, and CDN-specific headers such as
  `CF-Connecting-IP`, are not tested.
- The lab runs on PHP 8.3, nginx 1.27 and Apache 2.4.
- No other SIEM (Splunk, Elastic, Graylog, Sentinel) has a tested snippet.
  The line is plain JSON, so their generic JSON input works; we have not
  checked any of them.
- The `journal` and `syslog` scrape targets of Promtail are not tested; only
  the file is.
- Howdah ships no events off the host itself. Off-host shipping is the
  job of the collector you run.
