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
| `schema` | integer | schema 2 | Version of this line format: `2`, in releases after 1.4.0. A line without `schema` is from Howdah 1.0 to 1.4.0 (schema 1). |
| `version` | string | schema 2 | Version of the extension that wrote the line, for example `"1.4.0"`. |
| `ts` | string | 1.0 | Time of the event, UTC Unix epoch milliseconds as a decimal string (`"1792864974141"`). A string, not a number, since 1.0; kept for compatibility. |
| `request_id` | string | 1.0 | Lowercase hex, at most 64 characters. The block response body prints the same id, so a user's report maps to its line. Every event from one request carries the same id. |
| `layer` | integer | schema 2 | The protection layer of `rule`: `1`, `2`, `3` or `4` (table below). |
| `rule` | string | 1.0 | Rule name, the same spelling as the config keys (`max_parts`, `sql_injection`, `command_exec`, ...). |
| `action` | string | 1.0 | `"block"` (request refused or call denied), `"log"` (recorded, allowed), or `"excepted"` (a finding a `[[exceptions]]` entry turned off; written only when `exceptions_log = true`, see `docs/exceptions.md`). `"allow"` is reserved and not written. |
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
- A new rule is not a schema change. A new layer number is added to the
  `layer` enum in the JSON Schema file without changing `schema`. Treat
  unknown `rule` values and `layer` values above 4 as valid.

## Layers and rules

| `layer` | What it is | Rules |
|---|---|---|
| 1 | Request-shape limits: multipart, input shape, request headers, the self-test marker, and the out-of-memory backstop | `max_parts`, `max_files`, `max_part_headers`, `max_part_header_bytes`, `max_field_name_len`, `max_filename_len`, `parse_memory_budget`, `malformed_multipart`, `upload_progress_abuse`, `self_test`, `max_input_vars`, `max_input_nesting_depth`, `max_input_key_bytes`, `max_request_headers`, `max_request_header_bytes`, `out_of_memory`, `startup_fatal`, `post_too_large`, `nesting_budget`, `parse_memory_estimate` |
| 2 | Input inspection (the content classes are log-only by default; `cgi_arg_injection` blocks by default) | `sql_injection`, `path_traversal`, `command_injection`, `cgi_arg_injection` |
| 3 | Sink hardening (log-only by default; `xxe` blocks by default, only when a dangerous libxml flag meets an external entity) | `command_exec`, `include`, `eval`, `unserialize`, `phar`, `ssrf`, and the legacy-era sinks `mail_injection`, `preg_eval`, `create_function`, `assert_string`, `dangerous_callback`, `xxe`, `tls_verify` |
| 4 | After-breach behaviour (log-only by default; inert until its lists are set) | `upload_exec`, `unexpected_binary`, `unexpected_egress`, `php_write` |

The layer is computed from the rule by `rule_layer` in
`crates/howdah-core/src/log.rs`, an exhaustive match: a new rule does not
compile until it has a layer.

`self_test` is the marker `howdah-check web` sends. It is always
`action: "log"`, never a block. An internal error caught at the extension
boundary is also logged as `self_test`, with the reason
`internal panic caught at FFI boundary; failed open`.

`xxe` (Layer 3) is written at the XML parse call, not for the request, and only
when a dangerous libxml flag (`LIBXML_NOENT`, `DTDLOAD`, `DTDATTR`, `DTDVALID`) meets
an external entity or an entity-expansion bomb in the string being parsed. By
default Howdah neutralizes it by removing the dangerous flags and letting the
parse continue: the line is `action: "block"` (the dangerous operation was
denied; the request is not refused) and the `reason` ends `dangerous flags
removed, parse continued`. Where stripping cannot help (libxml older than 2.9.0)
the call is refused and the reason ends `call refused`. With `[sinks.xml] mode =
"detect"` the line is `action: "log"` and nothing is changed. A bare external
DTD that a flag really fetches is always `action: "log"`. The `reason` names the
guarded function and the flag names, never the document or a path in it.

`out_of_memory` and `startup_fatal` are written by the out-of-memory backstop
(`oom_exit`, see `docs/config.md`) the moment before it ends the worker: PHP ran
out of memory, or hit a fatal during request startup, on an unpatched engine.
Both are `action: "block"`. The line is the only record of that request — the
worker is gone before it could respond — so it carries no `client_ip`, `method`
or `uri`; the `reason` names the script and line where the error struck (the
operator's locus, since PHP never gets to write its own message). In the rare
genuine host out-of-memory (an `mmap` failure, not `memory_limit`), the system
allocator the log writer uses may itself fail, so the line can be lost — the
worker still exits (fail-stop).

Layer 4 in observe mode (`[behavior] observe = true`) writes its proposals
as ordinary `action: "log"` lines whose `reason` starts with `proposed: `.
That prefix is kept stable so proposals can be told apart.

With `exceptions_log = true`, a finding that a `[[exceptions]]` entry turned
off is written as `action: "excepted"` with the rule it would have had and a
`reason` of the form `exception #<index> (<selector>): <the entry's reason>`.
Nothing is enforced for such a line. Layers 1 and 2 write at most one
excepted line per request; Layers 3 and 4 one per excepted call.

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
{"action":"block","client_ip":"203.0.113.7","layer":1,"method":"POST","reason":"multipart part count exceeds limit","request_id":"11eccf6d90ad2987d","rule":"max_parts","schema":2,"ts":"1792864974141","uri":"/index.php","version":"1.5.0"}
{"action":"log","client_ip":"203.0.113.7","layer":2,"method":"GET","reason":"sql_injection pattern in get variable 'q'","request_id":"1a2d239820e2f06bc","rule":"sql_injection","schema":2,"ts":"1792864974146","uri":"/index.php","version":"1.5.0"}
{"action":"log","client_ip":"203.0.113.7","layer":3,"method":"GET","reason":"non-allowlisted command via system","request_id":"1fa7c36ea3c170856","rule":"command_exec","schema":2,"ts":"1792864974151","uri":"/index.php","version":"1.5.0"}
```

With `destination = "syslog"` the same line is the syslog message. The frame
on the socket (same run, default facility `local0`; `<132>` is local0 +
warning, `<133>` local0 + notice):

```
<132>Oct 24 18:02:54 howdah[1429]: {"action":"block","client_ip":"203.0.113.7","layer":1,...}
```

and journald stores it as (`journalctl -t howdah -o json`; a run against a
real journald, done by hand with an earlier build because the lab images
have no journald):

```
SYSLOG_IDENTIFIER=howdah
SYSLOG_FACILITY=16
PRIORITY=5
MESSAGE={"action":"log","client_ip":"","layer":3,"method":"GET","reason":"non-allowlisted command via system",...}
```

## Reading schema 1 lines

Lines from 1.0 to 1.4.0 have the eight original fields only. To treat old and
new lines alike, read a missing `schema` as `1` and derive `layer` from `rule`
with the table above. `version` has no equivalent; the package version in use
at the time is the best substitute.

## Not covered

- Lines are not signed or hash-chained. Anyone who can write the file (the
  PHP user, for the file destination) can alter it. Ship lines off the host
  if you need tamper evidence ([integrations](integrations/README.md)).
- Only security events are logged, not every request.
- Layers 1 and 2 write at most one line per request (the most severe hit);
  each Layer 3 or Layer 4 event is its own line.
