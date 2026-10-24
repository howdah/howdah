# Compliance evidence

This page is for the person who has to explain Howdah to an assessor, an
auditor or an insurer. It maps what Howdah does to PCI DSS 4.0.1 requirement
6.4.2, lists the evidence you can collect from a server running it, and says
what Howdah does not cover. It also gives short notes on cyber-insurance
questionnaires, NIS2, SOC 2 and HIPAA.

Facts about Howdah on this page come from the source and from
[`docs/config.md`](config.md) and [`docs/coverage.md`](coverage.md). Every
external claim has a link. The sources are listed again at the end.

> **What this page is not**
>
> - **Not legal advice.** Nothing here tells you what a law, standard or policy
>   requires of you. Ask your assessor, auditor, counsel or broker.
> - **Not a certification.** Howdah is not certified, validated, listed or
>   approved by the PCI Security Standards Council, the AICPA, HHS, ENISA or any
>   insurer. It has no SOC 2 report and no PCI attestation of its own.
> - **No third-party audit.** Howdah's code has had no third-party security
>   audit yet. Its coverage claims come from the project's own lab
>   ([`docs/coverage.md`](coverage.md)), not from an independent test.
> - **Not reviewed by an assessor.** No QSA, auditor or insurer has reviewed
>   this page. Whether Howdah meets a requirement in your environment is their
>   decision, not ours.

## PCI DSS 4.0.1 requirement 6.4.2

### The requirement

PCI DSS v4.0.1 (June 2024), requirement 6.4.2, page 152:

> For public-facing web applications, an automated technical solution is
> deployed that continually detects and prevents web-based attacks, with at
> least the following:
>
> - Is installed in front of public-facing web applications and is configured
>   to detect and prevent web-based attacks.
> - Actively running and up to date as applicable.
> - Generating audit logs.
> - Configured to either block web-based attacks or generate an alert that is
>   immediately investigated.

The applicability note says it was "a best practice until 31 March 2025, after
which it will be required", and that it replaces requirement 6.4.1. The testing
procedure is to "examine the system configuration settings and audit logs, and
interview responsible personnel". The standard is in the
[PCI SSC document library](https://www.pcisecuritystandards.org/document_library/).
The same bullet text is reproduced at
[Cloudaware](https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/06/04/02).

### Bullet by bullet

| 6.4.2 bullet | What Howdah does | Evidence to collect | What Howdah does not do |
|---|---|---|---|
| Installed in front of public-facing web applications and configured to detect and prevent web-based attacks | Loads into every PHP worker as an extension. Checks the request as PHP parses it, which for most inputs is before the application's first line runs (Layers 1 and 2; see the timing note below). Checks dangerous function calls while the application runs (Layer 3). | `php --ri howdah` for each PHP build; `howdah-check web` output against the live site; the `howdah.ini` and `howdah.toml` files in use. | It is not on the network. It never sees requests that do not reach PHP: static files, non-PHP applications, and bugs that fire before PHP extensions load. It does not cover XSS, CSRF, authentication, access control or business logic. See [the 6.2.4 table](#which-attack-classes-howdah-sees). |
| Actively running and up to date as applicable | Runs on every request while loaded. Its rules are compiled into the extension; there is no separate signature feed. "Up to date" means the latest release for your PHP minor and a reviewed config. | Installed package version and `php --ri howdah` "Version" row, compared with the [latest release](https://github.com/howdah/howdah/releases); a daily `howdah-check web` run and the `self_test` log line it leaves. | It does not update itself. It does not alert you if it stops loading: PHP starts without an extension it cannot load, and a malformed TOML falls back to built-in defaults. Watch for the daily `self_test` line. |
| Generating audit logs | Writes one JSON line per security event to a log file (`howdah.log`, or `[log] path`) or to the local syslog socket (`[log] destination = "syslog"`): `schema`, `version`, `ts`, `request_id`, `layer`, `rule`, `action`, `client_ip`, `method`, `uri`, `reason`. | The `php --ri howdah` "Log destination" row, sample lines, the rotation config and the off-host shipping config ([below](#3-the-audit-log)). | No network transport of its own: it writes a file, the local syslog socket or stderr, and shipping off the host is your collector's job. Lines are not signed or chained. A log file is writable by the PHP user. It logs security events, not every request. It never logs bodies, cookies, `Authorization` headers, query strings, matched values or sink arguments. |
| Configured to either block web-based attacks or generate an alert that is immediately investigated | Layer 1 Critical rules block (403/413) in both `block` and `detect` mode. Standard rules block in `block` mode. Layer 2 and the Layer 3 sinks only log (and `unserialize`, `phar` and `ssrf` are off) until you arm a class or sink with `mode = "block"`. | `howdah.toml` with each mode and the reason for it ([decision record](#5-the-decision-record)); for log-only rules, the alert rule in your log system (or the `[log] exec` program) and records of alerts being investigated. | It has no built-in email, webhook or pager integration. Alerts come from your log pipeline, or from a program you write that Howdah runs once per event (`[log] exec`, at most 10 starts per second per PHP process by default; beyond that events are logged but not passed on). An armed Layer 2 class does not stop the script: the variable reaches the application and the 403 is set at the end of the request. Treat Layer 2 as detection. |

Enforcement timing differs by layer. The multipart limits refuse the request
while the body is parsed, before the script runs. The input-shape and header
limits drop the offending variable and log; their 403 is best-effort and can
arrive after the script has produced output. An armed Layer 3 sink refuses the
call and the script continues. Details:
[`docs/config.md`, "Enforcement timing"](config.md#enforcement-timing-honest-caveat).

### "Installed in front of": the in-process question

Howdah does not sit in front of the web server. It runs inside the PHP
process. It inspects the request after PHP has parsed it and before the
application code runs, and it checks dangerous calls as the application makes
them. Whether that placement meets "installed in front of public-facing web
applications" is your assessor's call. These are the points to put to them:

- **The standard's own guidance names RASP.** The guidance for requirement
  6.4.1, which 6.4.2 replaces, says: "Another example of an automated technical
  solution is Runtime Application Self-Protection (RASP) technologies. When
  implemented correctly, RASP solutions can detect and block anomalous behavior
  by the software during execution. While WAFs typically monitor the
  application perimeter, RASP solutions monitor and block behavior within the
  application." (PCI DSS v4.0.1, page 151.) The guidance for 6.4.2 itself
  (page 152) gives only a WAF as its example.
- **Some assessors have accepted in-process tools.** Coalfire, a PCI QSA
  company, evaluated Contrast Security's Assess and Protect tools (Protect is
  a RASP) and said they "may be used to replace some of the traditional
  approaches to assessing and protecting applications" (vendor-published
  summary, 2019,
  [Contrast Security](https://www.contrastsecurity.com/security-influencers/coalfire-pci-compliance)).
  GuidePoint Security writes that RASP is a route to meeting requirement 6.6
  in PCI DSS 3.2.1 and 6.4.1 in 4.0
  ([GuidePoint](https://www.guidepointsecurity.com/blog/using-rasp-to-protect-applications-and-comply-with-the-pci-dss/)).
- **Nothing settles it.** We found no PCI SSC FAQ that rules on in-process
  enforcement for 6.4.2, either way.
- **Howdah is partly WAF, partly RASP.** Layers 1 and 2 inspect the request
  the way a WAF does, but after PHP's own parser has decoded it. Layer 3 works
  like a RASP: it checks `system`, `include`, `eval`, `unserialize`, `phar://`
  and outbound requests at the moment they are called.

Howdah complements a network WAF; it does not replace one. Keep or add a WAF,
CDN rule or web server rule for:

- **non-PHP assets on the same host:** static files, other languages, admin
  panels that are not PHP;
- **bugs that fire before PHP extensions load.** php-cgi argument injection
  (CVE-2012-1823, and CVE-2024-4577, its 2024 bypass on Windows
  ([PHP advisory GHSA-3qgc-jrrr-25jv](https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv)))
  is consumed by php-cgi at startup, before any extension hook runs. So is the
  php-fpm bug CVE-2019-11043. Howdah cannot see these
  ([`docs/coverage.md`](coverage.md), caveat 7). Howdah also builds for Linux
  only, so it does not run on Windows at all;
- **volume:** Howdah has no rate limiting and no bot management.

### Which attack classes Howdah sees

The 6.4.2 guidance points at the attacks listed in requirement 6.2.4. This is
how they line up with Howdah 1.3.

| 6.2.4 attack class | Howdah 1.3 |
|---|---|
| Injection: SQL, LDAP, XPath, command and other injection | SQL-injection and command-injection shapes in GET, POST, cookie and path values: Layer 2, detection only, best-effort and bypassable. OS command execution: the `command_exec` sink, which blocks when armed. LDAP and XPath: not inspected. |
| Attacks on data and data structures | Layer 1 limits on multipart parts and files, input variable count, array nesting, key and header sizes (Critical rules block). Object injection: the `unserialize` and `phar` sinks, off by default. Memory-safety bugs in PHP itself are covered only where they need one of these shapes. |
| Attacks on cryptography | Not covered. |
| Attacks on business logic, including XSS and CSRF | Not covered. Howdah does not inspect responses or output. |
| Attacks on access control | Not covered. Path-traversal shapes: Layer 2 detection. File includes outside an allowlist: the `include` sink, which blocks when armed. |
| "High-risk" vulnerabilities (6.3.1) | Case by case. [`docs/coverage.md`](coverage.md) lists the CVEs the lab has tested and the ones Howdah cannot reach. |

## What to hand your assessor

The evidence below comes from the server itself. Collect it per host, date it,
and keep it with your other PCI evidence.

### 1. Where Howdah is loaded, and proof it is running

```sh
howdah-check detect                      # every PHP build on the host, and whether Howdah is loaded in each SAPI
php --ri howdah                          # CLI: version, mode, config file, log path
howdah-check web https://shop.example/   # the web SAPI: a harmless self-test over HTTP
```

`php --ri howdah` only proves the CLI loads it. PHP-FPM and Apache `mod_php`
have their own configuration, so the web check is the one that counts.
`howdah-check web` sends two requests. The first carries a self-test marker:
Howdah writes a `self_test` line to the log and adds an `X-Howdah-Selftest`
header. The second sends 2001 empty form fields, one over the default
`max_parts` limit, which Howdah refuses with a 403 even in `detect` mode.
Neither request carries an attack payload.

`howdah-check` is a read-only POSIX shell script. It ships in every release
tarball and as a
[standalone release asset](https://github.com/howdah/howdah/releases/latest/download/howdah-check).

Run `howdah-check web` once a day from cron and keep the output. Together with
the `self_test` lines in the log, that shows the control was running
continuously, not only on the day of the assessment.

### 2. Proof it is up to date

```sh
dpkg-query -W 'php*-howdah'           # Debian/Ubuntu: installed package and version
apt-cache policy php7.4-howdah        # installed vs. newest available in the repository
rpm -qa 'php*-howdah'                 # RHEL family
yum check-update php74-howdah         # exit code 100 means an update is waiting
php --ri howdah | grep -i version     # the version PHP actually loaded
```

Compare the loaded version with the
[latest release](https://github.com/howdah/howdah/releases) and the
[changelog](https://github.com/howdah/howdah/blob/main/CHANGELOG.md). Howdah's
rules are part of the extension, so upgrading the package is the whole update.
A package upgrade needs a PHP-FPM or Apache reload before the new version is
loaded; the `php --ri` line confirms it.

### 3. The audit log

Set the log path explicitly:

```ini
howdah.log = /var/log/howdah/events.log
```

or send the lines to the host's syslog (journald or rsyslog) in the TOML file,
which avoids file permissions and gives you the host's existing shipping:

```toml
[log]
destination = "syslog"   # facility local0, tag "howdah" unless set
```

If neither is set, or the file cannot be opened, or there is no syslog socket,
Howdah writes the line to the process's stderr with a `howdah-event` prefix.
PHP-FPM sends worker stderr to `/dev/null` unless `catch_workers_output = yes`
([php.net](https://www.php.net/manual/en/install.fpm.configuration.php)), so an
unset log path on FPM can mean no log at all. `php --ri howdah` shows where
lines go in its "Log destination" row.

Each line is one JSON object with exactly these fields (from
`crates/howdah-core/src/log.rs`; the full contract is
[log-schema.md](log-schema.md)):

| Field | Content | PCI DSS 10.2.2 element |
|---|---|---|
| `schema` | Version of the line format, `2`. Lines from Howdah 1.0 to 1.4.0 have no `schema` key. | (format) |
| `version` | Version of the Howdah extension that wrote the line. | (provenance) |
| `ts` | UTC time of the event, Unix epoch milliseconds, as a string. Taken from the system clock, so keep NTP running (10.6.1). | Date and time |
| `request_id` | An id for the request. The block response body prints it, so a user's report maps to one line. | (correlation) |
| `layer` | Which protection layer the rule belongs to: 1 request-shape limits, 2 input inspection, 3 sinks, 4 after-breach behaviour. | Type of event |
| `rule` | The rule or sink that fired, for example `max_parts`, `sql_injection`, `command_exec`. | Type of event |
| `action` | `block` (refused) or `log` (allowed and recorded). | Success and failure indication |
| `client_ip` | `REMOTE_ADDR` as PHP sees it. Behind a proxy or CDN this is the proxy's address. | Origination of event |
| `method` | The HTTP method. | Identity of affected resource |
| `uri` | The request path. The query string is removed. | Identity of affected resource |
| `reason` | A short description. Layer 2 adds the source and the variable name, never the value. `ssrf` adds host, port, resolved IP and range class. | Type of event (detail) |

Howdah does not know who the application user is, so there is no user
identification field (10.2.2's first element). Correlate with your web server
and application logs by time, client IP and path.

Sample lines from a lab run (PHP 7.4, php-fpm; keys are written in sorted
order):

```json
{"action":"block","client_ip":"203.0.113.7","layer":1,"method":"POST","reason":"multipart part count exceeds limit","request_id":"11eccf6d90ad2987d","rule":"max_parts","schema":2,"ts":"1792864974141","uri":"/index.php","version":"1.4.0"}
{"action":"log","client_ip":"203.0.113.7","layer":2,"method":"GET","reason":"sql_injection pattern in get variable 'q'","request_id":"1a2d239820e2f06bc","rule":"sql_injection","schema":2,"ts":"1792864974146","uri":"/index.php","version":"1.4.0"}
{"action":"log","client_ip":"203.0.113.7","layer":3,"method":"GET","reason":"non-allowlisted command via system","request_id":"1fa7c36ea3c170856","rule":"command_exec","schema":2,"ts":"1792864974151","uri":"/index.php","version":"1.4.0"}
```

Layers 1 and 2 write at most one line per request: the most severe hit. Each
Layer 3 sink event is its own line.

### 4. Retention, rotation and shipping off the host

PCI DSS 10.5.1: "Retain audit log history for at least 12 months, with at
least the most recent three months immediately available for analysis." 10.3.3
asks for logs to be "promptly backed up to a secure, central, internal log
server(s) or other media that is difficult to modify." A sample setup that
does both:

```sh
# The directory belongs to the PHP worker user (www-data on Debian, apache or nginx on RHEL).
sudo install -d -m 0750 -o www-data -g www-data /var/log/howdah
```

```conf
# /etc/logrotate.d/howdah: three months on the host
/var/log/howdah/events.log {
    daily
    rotate 92
    dateext
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data www-data
}
```

Howdah opens the file for each line it writes, so rename-based rotation is
safe. No `copytruncate` and no PHP reload are needed.

```conf
# /etc/rsyslog.d/30-howdah.conf: copy each line to a central log server
module(load="imfile")
input(type="imfile" File="/var/log/howdah/events.log" Tag="howdah:" Facility="local6" Severity="notice")
local6.* @@logs.example.internal:514
```

`@@` is TCP. Add TLS to match your logging setup. Keep 12 months or more on the
central server. Any shipper that tails a file works the same way (Vector,
Fluent Bit, Filebeat).

Two things to say plainly to the assessor:

- The log file is writable by the PHP worker user, because PHP writes it. A
  compromised application could alter the local copy. The central copy is the
  one to rely on (10.3.2, 10.3.3). Point file-integrity monitoring (10.3.4) at
  the rotated files. With `[log] destination = "syslog"` the PHP user cannot
  rewrite lines already written, but any local process can send lines tagged
  `howdah`, so the central copy is still the one to rely on.
- Read access should be limited (10.3.1). The `0750` directory and `0640`
  files above do that. The `uri` path is logged; if your URLs carry personal
  data in the path, treat the log as containing it.

### 5. The decision record

Reviewers look for "documented rationales for rule removals" and "a clear
understanding of what's being excluded and why"
([OWASP CRS on PCI DSS](https://coreruleset.org/20250810/how-crs-contributes-to-pci-dss-compliance/)).
Howdah's levers are a rule's mode (`block`, `detect`, `off`), a sink's
allowlist, and, since 1.5, scoped `[[exceptions]]` (one rule off for one
script, parameter, URI prefix or client network; see
[exceptions.md](exceptions.md)). An exception cannot be written without a
`reason`, so the exceptions in the file **are** the exclusions record: `grep
-n reason /etc/howdah/howdah.toml` prints it, the file's version history dates
it, and `exceptions_log = true` writes each exercised exception to the event
log as `action: "excepted"` when an assessor wants to see them in use. Record
every other change from the defaults in one table:

| Rule or sink | Mode | Justification | Owner | Date |
|---|---|---|---|---|
| `max_request_headers` | `detect` | Our SSO proxy adds about 40 headers. Watching for 30 days before `block`. | J. Doe, web ops | 2026-10-24 |
| `command_exec` | `block`, allow `/usr/bin/convert *` | The thumbnailer is the only legitimate shell call. | J. Doe, web ops | 2026-10-24 |
| `sql_injection` | `detect` (default) | Layer 2 is bypassable and does not stop the script. Used as a SIEM detection feed; alerts go to on-call. | A. Smith, security | 2026-10-24 |
| `unserialize` | `off` (default) | Not opted in. The app unserializes only its own session data. Review at next release. | A. Smith, security | 2026-10-24 |

Then make the config file carry the same record, so the rationale lives next
to the setting it explains:

```toml
# /etc/howdah/howdah.toml, kept in version control.
# Every change from a default has a DECISION comment: date, owner, why.
mode = "block"

[rules]
# DECISION 2026-10-24 owner=jdoe(web ops): SSO proxy adds ~40 headers.
# Watch 30 days, then remove this line to return to block.
max_request_headers = "detect"

[sinks.command_exec]
# DECISION 2026-10-24 owner=jdoe(web ops): the thumbnailer is the only
# legitimate shell call. Allowlist set first, then armed.
allow = ["/usr/bin/convert *"]
mode = "block"

# Scoped exclusions carry their own record in the mandatory `reason`.
[[exceptions]]
rule   = "sinks.command_exec"
script = "/var/www/html/cron.php"
reason = "DECISION 2026-10-24 owner=jdoe(web ops): cron.php shells out to the mailer with per-run temp paths, so no allow pattern can be anchored. This means command_exec is not checked for cron.php. Reviewed quarterly."
```

`grep -n DECISION /etc/howdah/howdah.toml` prints the record, and the version
history of the file shows when each decision changed. Validate the file before
deploying it: the [config editor](https://howdah.org/config/) checks it with
the extension's own parser.

### 6. Blocked-attack summary

A count of blocks by rule, across the current and rotated files:

```sh
zcat -f /var/log/howdah/events.log* | jq -r 'select(.action == "block") | .rule' | sort | uniq -c | sort -rn
```

Blocks per day and rule, tab-separated for a spreadsheet:

```sh
zcat -f /var/log/howdah/events.log* \
  | jq -r 'select(.action == "block") | [(.ts | tonumber / 1000 | floor | strftime("%Y-%m-%d")), .rule] | @tsv' \
  | sort | uniq -c
```

The same count by rule on a host without `jq`:

```sh
zcat -f /var/log/howdah/events.log* | awk -F'"rule":"' '/"action":"block"/ { split($2, a, /"/); print a[1] }' | sort | uniq -c | sort -rn
```

Replace `block` with `log` to see what the log-only rules recorded. PCI DSS
10.4.1 asks for security events to be reviewed at least once daily; this output
is a starting point for that review, not a substitute for it.

## Cyber-insurance questionnaires and end-of-life PHP

Insurance applications ask about end-of-life software directly. Beazley's
application asks the applicant to confirm: "You do not have any End of Life
(Eol) software or Operating System (OS) exposed to the internet", Yes or No
([Beazley application](https://beazley.com/globalassets/product-documents/app-form/beazley-cyber-insurance-application-long-sub-20m.pdf)).
If an internet-facing server runs PHP 8.1 or older (October 2026; check
[php.net](https://www.php.net/supported-versions.php)), the true answer is
No, with or without Howdah. Howdah does not make an end-of-life PHP supported
and does not patch it. It is a compensating control: it reduces exposure to
some attack classes while the old runtime stays in place. It mitigates the
multipart and input-flood shapes before they exhaust memory, refuses armed
sink calls (`system`, `include`, `eval`, `unserialize`, `phar://`, internal
outbound requests), and logs SQL-injection, traversal and command-injection
shapes. It does not fix bugs in PHP's own code, does not see anything that
fires before PHP extensions load, and does not cover the classes listed above
as "Not covered". The full list is in [`docs/coverage.md`](coverage.md).
Answer the question as asked and attach a short note: which hosts run which
PHP version, why they cannot be upgraded yet, the planned upgrade date, which
controls sit in front of them, and what those controls do not cover. Policies
can limit or exclude cover for incidents involving end-of-life software or
known unpatched vulnerabilities, "not tied to the organisation having actual
knowledge of the issue"
([Allens, 2023](https://www.allens.com.au/insights-news/insights/2023/05/a-ticking-time-bomb-limitations-in-cyber-cover-for-known-vulnerabilities-and-end-of-life-hardware/)).
A compensating control does not change those terms. Read your policy wording.

## Other frameworks

None of these frameworks names a WAF or requires Howdah. Each asks for
outcomes. Howdah can be one of the measures you describe, and its log can be
part of your evidence.

### NIS2

NIS2 Article 21(1) asks essential and important entities to "take appropriate
and proportionate technical, operational and organisational measures to manage
the risks posed to the security of network and information systems". Article
21(2) lists areas the measures must cover, including "(b) incident handling"
and "(e) security in network and information systems acquisition, development
and maintenance, including vulnerability handling and disclosure"
([Directive (EU) 2022/2555, EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)).
It is a directive, so the binding text is your country's transposing law. If you
run an end-of-life PHP application while a migration is under way, Howdah can
be one documented measure for that risk, and its log can feed incident
handling. It is not a substitute for the vulnerability handling itself.

### SOC 2

SOC 2 reports test your controls against the AICPA Trust Services Criteria. The
criteria describe outcomes, and you choose the controls. Three criteria are
specific enough to map:

| Criterion | Text | What Howdah contributes | What it does not |
|---|---|---|---|
| CC6.6 | "The entity implements logical access security measures to protect against threats from sources outside its system boundaries." | Refuses some malicious request shapes from outside: Layer 1 limits, and sinks you arm. | Network access control, authentication, anything outside PHP. |
| CC7.1 | "To meet its objectives, the entity uses detection and monitoring procedures to identify (1) changes to configurations that result in the introduction of new vulnerabilities, and (2) susceptibilities to newly discovered vulnerabilities." | A version-controlled `howdah.toml` with decision comments is a configuration change record. The log can show probes against a newly disclosed bug. | It does not scan for vulnerabilities or track your software versions. |
| CC7.2 | "The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives; anomalies are analyzed to determine whether they represent security events." | A structured event log of attack shapes for your monitoring. | The analysis. Someone, or your SIEM, has to read the log. |

Criterion text: AICPA, TSP Section 100, 2017 Trust Services Criteria (March
2020 edition), from the
[AICPA](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022).

### HIPAA

The HIPAA Security Rule is risk-based. One standard is specific enough to map:

| Standard | Text | What Howdah contributes | What it does not |
|---|---|---|---|
| 45 CFR 164.312(b), Audit controls | "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information." | Records one kind of activity: requests and calls that hit a Howdah rule. Bodies, cookies, `Authorization` headers and query strings are never logged. | It does not record who accessed which records. That has to come from the application. The `uri` path is logged, so a route that carries a patient identifier puts it in the log. |

Text: [45 CFR 164.312, eCFR](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312).

## Sources

- PCI SSC, *PCI DSS v4.0.1 Requirements and Testing Procedures*, June 2024:
  requirement 6.4.1 guidance (p. 151), 6.4.2 (p. 152), 6.2.4, 10.2.2, 10.3.1
  to 10.3.4, 10.4.1, 10.5.1, 10.6.1.
  [Document library](https://www.pcisecuritystandards.org/document_library/).
- Cloudaware, PCI DSS v4.0.1 6.4.2 text:
  <https://ce.prod.cloudaware.com/frameworks/pci-dss-v4.0.1/06/04/02>
- Contrast Security on Coalfire's evaluation (5 August 2019):
  <https://www.contrastsecurity.com/security-influencers/coalfire-pci-compliance>
- GuidePoint Security, using RASP for PCI DSS:
  <https://www.guidepointsecurity.com/blog/using-rasp-to-protect-applications-and-comply-with-the-pci-dss/>
- OWASP CRS, how CRS contributes to PCI DSS compliance (10 August 2025):
  <https://coreruleset.org/20250810/how-crs-contributes-to-pci-dss-compliance/>
- PHP security advisory for CVE-2024-4577:
  <https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv>
- PHP-FPM `catch_workers_output`:
  <https://www.php.net/manual/en/install.fpm.configuration.php>
- PHP supported versions: <https://www.php.net/supported-versions.php>
- Beazley cyber insurance application:
  <https://beazley.com/globalassets/product-documents/app-form/beazley-cyber-insurance-application-long-sub-20m.pdf>
- Allens, limitations in cyber cover for known vulnerabilities and end-of-life
  systems (17 May 2023):
  <https://www.allens.com.au/insights-news/insights/2023/05/a-ticking-time-bomb-limitations-in-cyber-cover-for-known-vulnerabilities-and-end-of-life-hardware/>
- Directive (EU) 2022/2555 (NIS2), Article 21:
  <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>
- AICPA, 2017 Trust Services Criteria:
  <https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022>
- 45 CFR 164.312:
  <https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-C/section-164.312>
