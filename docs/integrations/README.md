# Ship Howdah events to a SIEM

Howdah writes one JSON line per event ([schema](../log-schema.md)). Any tool
that can read a JSON-lines file or syslog can take it. This folder has two
small, tested starting points:

| file | for |
|---|---|
| [`wazuh/howdah_decoders.xml`](wazuh/howdah_decoders.xml), [`wazuh/howdah_rules.xml`](wazuh/howdah_rules.xml) | Wazuh: the event file or syslog lines, with alerts at level 10 for `block` and 5 for `log` |
| [`promtail-howdah.yaml`](promtail-howdah.yaml) | Grafana Loki via Promtail: the event file, with `rule`, `action` and `layer` as labels |

`lab/integration/siem_snippets.sh` runs both against real event lines in the
real tools (Promtail 3.5.1 `--dry-run`, and `wazuh-logtest` in
wazuh-manager 4.12.0). It needs Docker and network access to pull the images.
`site/test/log-contract.test.mjs` checks on every CI run that the files still
parse and only use fields the schema defines.

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

- No other SIEM (Splunk, Elastic, Graylog, Sentinel) has a tested snippet.
  The line is plain JSON, so their generic JSON input works; we have not
  checked any of them.
- The `journal` and `syslog` scrape targets of Promtail are not tested; only
  the file is.
- Howdah sends nothing over the network itself. Off-host shipping is the
  job of the collector you run.
