# Event log schema

Howdah writes one JSON object per line for every security event: a request
refused, or a request or call recorded in log-only mode. This page is the
contract for that line. The machine-readable form is
[`howdah-event.schema.json`](howdah-event.schema.json) (JSON Schema 2020-12);
`crates/howdah-core/tests/event_schema.rs` checks that it matches what the
code writes, for every rule and action, and that the samples on this page
validate against it.

Where the lines go (a file, syslog or stderr) and the per-event hook are
configured in the `[log]` table: see [config.md](config.md#log--event-log-destination-and-hook).

## Schema version 2

Schema 2 is the eight fields Howdah has written since 1.0, unchanged in name
and type, plus three new ones: `schema`, `version` and `layer`. A consumer
written for the old line keeps working.

| Field | JSON type | Since | Content |
|---|---|---|---|
| `schema` | integer | schema 2 | Version of this line format: `2`. A line without `schema` is from Howdah 1.0 to 1.3 (schema 1). |
| `version` | string | schema 2 | Version of the extension that wrote the line, for example `"1.3.0"`. |
| `ts` | string | 1.0 | Time of the event, UTC Unix epoch milliseconds as a decimal string (`"1792862615157"`). A string, not a number, since 1.0; kept for compatibility. |
| `request_id` | string | 1.0 | Lowercase hex, at most 64 characters. The block response body prints the same id, so a user's report maps to its line. Every event from one request carries the same id. |
| `layer` | integer | schema 2 | The protection layer of `rule`: `1`, `2` or `3` (table below). A future layer adds the next integer. |
| `rule` | string | 1.0 | Rule name, the same spelling as the config keys (`max_parts`, `sql_injection`, `command_exec`, ...). |
| `action` | string | 1.0 | `"block"` (request refused or call denied) or `"log"` (recorded, allowed). `"allow"` is reserved and not written. |
| `client_ip` | string | 1.0 | `REMOTE_ADDR` as the SAPI reports it: the proxy's address behind a reverse proxy (`X-Forwarded-For` is not read). Empty when the SAPI reports none, as on the command line and under the built-in `php -S` server. |
| `method` | string | 1.0 | HTTP method. Empty when the SAPI reports none. |
| `uri` | string | 1.0 | Request path. The query string is removed before logging, because it can carry secrets. |
| `reason` | string | 1.0 | Human-readable explanation. It may name a variable, function, class, host or port. Its wording is not part of the contract: match on `rule` and `action`, not on `reason`. |

Keys are written in alphabetical order, but consumers must not depend on key
order.

### Compatibility rules

- Adding a field does not change `schema`. Parse leniently: ignore keys you
  do not know.
- Removing a field, renaming it, or changing its JSON type increments
  `schema`.
- A new rule or a new layer number is not a schema change. Treat unknown
  `rule` values and `layer` values above 3 as valid.

## Layers and rules

| `layer` | What it is | Rules |
|---|---|---|
| 1 | Request-shape limits: multipart, input shape, request headers, and the self-test marker | `max_parts`, `max_files`, `max_part_headers`, `max_part_header_bytes`, `max_field_name_len`, `max_filename_len`, `parse_memory_budget`, `malformed_multipart`, `upload_progress_abuse`, `self_test`, `max_input_vars`, `max_input_nesting_depth`, `max_input_key_bytes`, `max_request_headers`, `max_request_header_bytes` |
| 2 | Input inspection (log-only by default) | `sql_injection`, `path_traversal`, `command_injection` |
| 3 | Sink hardening (log-only by default) | `command_exec`, `include`, `eval`, `unserialize`, `phar`, `ssrf` |

The layer is computed from the rule by `rule_layer` in
`crates/howdah-core/src/log.rs`, an exhaustive match: a new rule does not
compile until it has a layer.

`self_test` is the marker `howdah-check web` sends. It is always
`action: "log"`, never a block. An internal error caught at the extension
boundary is also logged as `self_test`, with the reason
`internal panic caught at FFI boundary; failed open`.

## What is never in a line

Request bodies, cookies, `Authorization` headers, query strings, the value a
Layer 2 rule matched, and the argument a Layer 3 sink was called with
(command line, path, payload, URL). `crates/howdah-core/src/log.rs`
(`privacy_cookie_body_auth_never_logged`) checks this. `schema`, `version` and
`layer` come from the build and the rule id, never from the request.

The `uri` path is logged. If your application puts personal data in paths
(`/patient/12345`), the log contains it.

## Samples

These three lines are from a lab run (`lab/integration/log_contract.sh`,
PHP 7.4, php-fpm, `REMOTE_ADDR` set to a documentation address): a field
flood refused by `max_parts`, a Layer 2 SQL-injection shape in `?q=`, and a
Layer 3 `system()` call that is not on the allowlist.

```json
{"action":"block","client_ip":"203.0.113.7","layer":1,"method":"POST","reason":"multipart part count exceeds limit","request_id":"12feab0bc42ea29d0","rule":"max_parts","schema":2,"ts":"1792862615157","uri":"/index.php","version":"1.3.0"}
{"action":"log","client_ip":"203.0.113.7","layer":2,"method":"GET","reason":"sql_injection pattern in get variable 'q'","request_id":"1aa8be308b30a2f10","rule":"sql_injection","schema":2,"ts":"1792862615161","uri":"/index.php","version":"1.3.0"}
{"action":"log","client_ip":"203.0.113.7","layer":3,"method":"GET","reason":"non-allowlisted command via system","request_id":"16fbb40494928d080","rule":"command_exec","schema":2,"ts":"1792862615164","uri":"/index.php","version":"1.3.0"}
```

With `destination = "syslog"` the same line is the syslog message. The frame
on the socket (same run, default facility `local0`; `<132>` is local0 +
warning, `<133>` local0 + notice):

```
<132>Oct 24 17:23:35 howdah[1424]: {"action":"block","client_ip":"203.0.113.7","layer":1,...}
```

and journald stores it as (`journalctl -t howdah -o json`, a run against a
real journald):

```
SYSLOG_IDENTIFIER=howdah
SYSLOG_FACILITY=16
PRIORITY=5
MESSAGE={"action":"log","client_ip":"","layer":3,"method":"GET","reason":"non-allowlisted command via system",...}
```

## Reading schema 1 lines

Lines from 1.0 to 1.3 have the eight original fields only. To treat old and
new lines alike, read a missing `schema` as `1` and derive `layer` from `rule`
with the table above. `version` has no equivalent; the package version in use
at the time is the best substitute.

## Not covered

- Lines are not signed or hash-chained. Anyone who can write the file (the
  PHP user, for the file destination) can alter it. Ship lines off the host
  if you need tamper evidence ([integrations](integrations/README.md)).
- Only security events are logged, not every request.
- Layers 1 and 2 write at most one line per request (the most severe hit);
  each Layer 3 sink event is its own line.
