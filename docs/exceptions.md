# Scoped exceptions: from a log line to an `[[exceptions]]` entry

An exception turns **one rule off for one scope**: a script, a request
parameter, a URI prefix, a client network, or a combination of those. It is
how you keep a rule armed for the whole site while letting one known,
legitimate behaviour through, and it carries a mandatory `reason`, so the
config file is also the decision record a reviewer asks for.

The reference for every key is the `[[exceptions]]` section of
[config.md](config.md). This page is the working method.

## 1. Start from the detect log

Run with the rule in `detect` and read the events it writes. One line:

```json
{"action":"log","client_ip":"203.0.113.7","layer":3,"method":"POST","reason":"non-allowlisted command via shell_exec","request_id":"2c07d4e1a96b3f8c25","rule":"command_exec","schema":2,"ts":"1792834977000","uri":"/cron.php","version":"1.5.0"}
```

Three questions decide the entry:

1. **Which rule?** `rule` in the line: `command_exec`. That is the `rule`
   key of the exception (or its family, `sinks.command_exec`, or the whole
   layer, `sinks`; see the grammar below).
2. **Which scope is the narrowest that still covers the legitimate case?**
   For a Layer 3 or 4 event, the script that made the call. For a Layer 2
   event, the parameter named in `reason` (`... in post variable 'content'`).
   For a Layer 1 Standard event, the URI prefix or the client network. Prefer
   `script` over `uri_prefix` whenever the layer offers it: the script is the
   file that actually ran, the URI is what the client asked for.
3. **Why is it legitimate?** Write that down as `reason`, with a date and an
   owner. This text is the audit record; the file's version history is its
   change log.

## 2. Find the script

Layers 3 and 4 attribute an event to the **PHP file that contains the call**,
not to the page the request hit. A `require`d file, a framework's filesystem
class, a vendored library: whichever file holds the `system()`, the
`file_put_contents()` or the `curl_exec()` is the executing script. This is the
Layer 4 origin primitive, and it is why a WordPress plugin update shows up as
`wp-admin/includes/class-wp-filesystem-direct.php`, not as `update.php`.

The path compared is exactly what PHP reports for that file: `__FILE__`
inside it. Copy it from there; do not derive it from `ls`. The rule PHP
applies:

- a `require`d/`include`d file is resolved by `zend_resolve_path`: absolute,
  `.`/`..` removed, **symlinks followed** (realpath);
- the main script is opened through PHP's stream layer, whose `opened_path`
  is also realpath'd, so on the CLI, php-fpm and the built-in server
  `__FILE__` of a script reached through a symlinked docroot is the target
  (`/srv/releases/42/...`, not `/var/www/current/...`); the lab asserts this
  for a symlinked CLI main script and a symlinked `require` on PHP 5.6, 7.4
  and 8.3;
- the one place that sees the unresolved spelling is Layer 4's
  `upload_exec` check of the **main script**, which compares the path the
  SAPI handed PHP (`SCRIPT_FILENAME` as nginx or Apache passed it); a
  `script` exception for `upload_exec` on a main script must match that
  spelling, `require`d files are realpath'd as above;
- code inside `eval()` is reported as `/var/www/a.php(12) : eval()'d code`.
  A `**` glob on the directory (`/var/www/**`) therefore also covers eval'd
  code from those files; a literal path or a `script_sha256` does not.

Matching is byte-wise and case-sensitive; Howdah normalizes nothing.

The event line does not carry the script path (the log keeps to its eight
fields plus the schema fields). To find it:

- turn `exceptions_log = true` on while you tune; the `excepted` lines tell
  you which entry matched, so you can narrow or widen it;
- put a candidate entry in with `script = "/path/you/expect.php"` and see
  whether the event stops; if not, widen with a glob and narrow back;
- for Layer 4 events, `reason` names the directory, host or program, which
  usually identifies the code.

`php -r 'echo __FILE__;'` from the docroot shows the resolved path prefix
your entries should start with.

## 3. Write the entry

```toml
[[exceptions]]
rule   = "sinks.command_exec"
script = "/var/www/html/cron.php"
reason = "DECISION 2026-10-24 jdoe (web ops): cron.php shells out to the mailer with per-run temp paths, so an allow pattern cannot be anchored. Reviewed quarterly."
```

Facets are **ANDed**: every facet you set must match. Unset facets match
anything. The first entry that matches wins (only the index in the log
differs). At least one facet is required, and a facet that would match every
request is refused as if it were missing: `script = "/**"` or `"/*"`,
`uri_prefix = "/"`, `client_cidr` with prefix length 0 (`0.0.0.0/0`, `::/0`).
`param`/`param_prefix` may not name or prefix `REQUEST_URI` or `PATH_INFO`
(the pseudo-parameters of the Layer 2 path scan); use `uri_prefix` for paths.

| Facet | Matches | Layers |
|---|---|---|
| `script` | the executing file, absolute path or glob (`*` within one path segment, `**` across segments, `/**/` also matches a single `/`, `?` one character) | 3, 4 |
| `script_sha256` | SHA-256 of the executing file's bytes, 64 hex characters (`sha256sum file.php`) | 3, 4 |
| `param` | the request variable name, exact, as submitted (`q`, `jform[articletext]`) | 2 |
| `param_prefix` | the request variable name by prefix (`jform[`) | 2 |
| `uri_prefix` | the request path (query string removed), raw byte prefix, must start with `/` | 1 Standard, 2, 3, 4 |
| `client_cidr` | `REMOTE_ADDR`, IPv4 or IPv6 CIDR or a bare address | 1 Standard, 2, 3, 4 |

`rule` is one of: a rule id as it appears in the log (`sql_injection`,
`command_exec`, `php_write`, `max_request_headers`); a layer name, which is
the config section name (`limits`, `inspect`, `sinks`, `behavior`); or
`layer.rule` (`sinks.command_exec`, `inspect.sql_injection`,
`behavior.php_write`). `*` is not accepted: an exception must say what it
turns off.

### What an exception does, exactly

A matching exception sets that rule to `off` for that event. It is decided
**after** the rule found something and **before** the mode is applied, so it
never changes what counts as a finding and it can never arm anything. It is
not an allowlist entry: **an exception on `sinks.command_exec` means that sink
is not checked for that script**, every command it runs is invisible to the
rule. When an allowlist can express the case (`[sinks.command_exec] allow =
["/usr/bin/convert *"]`), the allowlist is the narrower control; use the
exception when it cannot (per-run temp paths, a vendored file you cannot
change, a docroot that differs per tenant).

### Which facets apply where, and why

- **Layer 1 Critical rules** (`max_parts`, `max_files`, `max_input_vars`,
  `max_input_nesting_depth` and the byte and memory limits) take **no
  exception**. They stop PHP from being exhausted before any script runs; a
  hole in them is a hole in the floor. The validator refuses the entry and
  the file does not load (loudly: see below).
- **Layer 1 Standard rules** (`malformed_multipart`, `upload_progress_abuse`,
  `self_test`, `max_input_key_bytes`, `max_request_headers`,
  `max_request_header_bytes`) take `uri_prefix` and `client_cidr` only. They
  fire while PHP registers the request, before any script exists.
- **Layer 2** takes `param`, `param_prefix`, `uri_prefix`, `client_cidr`,
  **not `script`**: Layer 2 values are inspected while PHP registers request
  variables, before any script runs, on every SAPI. The validator says so and
  points at `uri_prefix`. On an application with a front controller every
  path may be `/index.php`, so Layer 2 scoping there is by parameter and
  client.
- **Layers 3 and 4** take `script`, `script_sha256`, `uri_prefix`,
  `client_cidr`, not `param`: a sink call is not tied to one request variable.
- **A GET value is also part of the request path.** Layer 2 scans
  `REQUEST_URI` (and `PATH_INFO`) as the path source under the pseudo-parameter
  name `REQUEST_URI` on SAPIs that register it through the input filter
  (php-fpm, Apache, `php -S` before 8.0). A `param` exception on a GET
  parameter therefore silences the `get variable 'q'` finding and leaves the
  `path variable 'REQUEST_URI'` finding for the same bytes. `param` exceptions
  are at their best on POST fields and cookies; for a GET parameter, decide
  whether the path finding is noise you accept, or scope by `uri_prefix`.

### The hash facet

`script_sha256` pins the file's bytes instead of (or as well as) its path.
Use it when the path differs per host or you want the exception to expire when
the file changes. Howdah reads and hashes the file once per path per PHP
process and only when an entry with a hash facet could apply to that path (an
exception with a `script` glob that does not match never causes a read). The
cached digest is reused only while the file's device, inode, size, mtime
**and ctime** are unchanged, so a same-size rewrite that keeps the mtime
(`cp -p`, `touch -r`, `rsync -t`, `tar`) is still re-read. Files over 4 MiB
are not hashed (a script that large cannot use the facet) and an unreadable
file never matches: in both cases the rule stays armed. The cache holds 256
paths; this is a facility for a handful of pinned scripts, not hundreds.

## 4. Validate, then load

Every error names the entry and the key:

```
invalid howdah config: exceptions[0].rule: "max_parts" is a Critical rule and cannot be excepted
invalid howdah config: exceptions[1].reason: required (write why this exception exists; it is the audit record)
invalid howdah config: exceptions[2].script: not allowed for inspect rule "sql_injection" (Layer 2 events are raised ...; use param, param_prefix, uri_prefix or client_cidr)
```

An invalid entry makes the **whole file** invalid, which takes the
`on_invalid_config` path: one line in the SAPI error log naming the file and
the entry, `Config status => INVALID (fell back to block): ...` in `php --ri
howdah`, and the fallback mode (`block`, or `off` if the file says
`on_invalid_config = "off"`). The [config editor](https://howdah.org/config/)
runs the same validator in the browser; use it before deploying.

Once loaded:

- `php --ri howdah` shows `Exceptions ([[exceptions]]) => N configured, M
  rejected` (M is counted by a lenient second pass, so a refused file still
  reports how many entries were bad).
- The SAPI error log gets one line per process start: `Howdah: N
  exception(s) active from '/etc/howdah/howdah.toml'; exceptions_log = off`.
  This is the once-per-process summary; matched exceptions are otherwise
  silent.
- With `exceptions_log = true`, every match is written to the event log as
  `"action":"excepted"` with the rule it would have had and `reason` set to
  `exception #<index> (<selector>): <your reason>`. Layers 3 and 4 write one
  line per excepted call; Layers 1 and 2 at most one per request. Turn it on
  while tuning and when an auditor wants to see exceptions being exercised;
  turn it off if the volume is a problem.

## 5. Keep the register

`grep -n reason /etc/howdah/howdah.toml` prints every exception's
justification. Keep the file in version control and the decision record from
[compliance.md](compliance.md#5-the-decision-record) is the diff history. The
shipped [application profiles](../profiles/README.md) are starting points
written in the same form.

## Limits, stated plainly

- `client_cidr` is `REMOTE_ADDR`. Behind a reverse proxy or CDN that is the
  proxy's address and the exception covers everything the proxy forwards;
  Howdah does not read `X-Forwarded-For`. The client must also be known when
  the rule fires: php-fpm and Apache supply it before any variable is parsed
  (the lab proves `client_cidr` on Layer 1 under php-fpm); the CLI built-in
  server (`php -S`) does not, so under `php -S` a `client_cidr` exception does
  not match Layer 1 or Layer 2 events. `php -S` is not a production SAPI.
- `uri_prefix` is a raw byte prefix: not percent-decoded, not case-folded.
  `/wp-admin/` does not match `/WP-ADMIN/` or `/wp%2Dadmin/`. A path that
  Howdah cannot trust to mean what it says **never satisfies the facet**: one
  with a `.` or `..` segment, an empty segment (`//`), a backslash, or any
  `%`. So `/wp-admin/../index.php`, which nginx passes through unnormalized
  and which executes `/index.php`, is not excepted as `/wp-admin/` (the lab
  asserts this and the `%2e%2e`, `/./` and `//` spellings). The cost is that
  a legitimate request spelled that way is not excepted either, which is the
  right way round. Prefer `script` where the layer offers it.
- `script` follows symlinks because PHP does. Use `__FILE__`, not `ls`.
- An exception is a deliberate, recorded hole. The threat model is the same as
  setting the rule to `off`, narrowed to the scope you wrote. Review the
  register when the application changes.
- No per-vhost config: two tenants that need the same exception under
  different docroots write two entries, or one glob
  (`/home/*/public_html/cron.php`) with a reason that says so.
