# Configuration

Howdah is configured by a TOML file whose path is given to PHP as an ini
setting. Two more ini settings pick the global mode and the log destination:

```ini
; php.ini (or a conf.d/*.ini, or -d on the CLI)
extension=howdah.so
howdah.config=/etc/howdah/howdah.toml   ; path to the TOML below (optional)
howdah.mode=block                       ; block | detect | off (TOML can override)
howdah.log=/var/log/howdah.log          ; event log file (wins over [log] path)
```

If `howdah.config` is unset, or the file is missing or unreadable, Howdah uses
`howdah.mode` with the built-in limits below. If the file is present but
malformed, Howdah falls back to its **safe defaults** (block mode, the limits
below) and keeps serving — a bad config never takes PHP down. The fallback is
loud, not silent: at startup Howdah writes one line to the SAPI error log
(PHP's `error_log`, or stderr on the CLI) naming the file and the parse error,
once per process, and `phpinfo()` / `php --ri howdah` shows a row
`Config status => INVALID (fell back to block): at line 3, column 1: unknown
field ...` (it reads `ok` for a good file). Validate the file before deploying;
the [config editor](https://howdah.org/config/) does this with the extension's
own parser. A file that cannot be read at all is reported as `UNREADABLE`, and
Howdah then uses `howdah.mode`.

### `on_invalid_config`

```toml
on_invalid_config = "block"   # "block" (default) | "off"
```

Chooses the mode Howdah runs in when the file does not parse. `"block"` is the
long-standing behaviour. `"off"` runs with Howdah disabled instead, for a site
where a typo must not start refusing requests.

The parser is all-or-nothing, so the key cannot be read from the parsed file.
When parsing fails, Howdah scans the raw text for a top-level
`on_invalid_config = "off"` line (before the first `[table]` header, value in
double or single quotes, optional trailing comment) and uses that. Anything else
(no such line, another value, a bare word, the key inside a table, a file that
is not valid UTF-8) means `block`. So the key works even when a sub-table is the
broken part, but it is not a general parse: a typo in the line itself falls back
to `block`. It is a TOML key, not a php.ini directive.

### `oom_exit`

```toml
oom_exit = true   # true (default) | false
```

On by default. If PHP runs out of memory — or hits a fatal error during request
startup — on an engine without upstream's fix, Howdah ends the worker before any
code runs on the half-built request state (the PHP2Shell backstop,
CVE-2026-109618 / CVE-2026-109619). The worker is replaced; the one request that
ran out of memory gets a dropped connection (nginx answers 502). The event is
logged with rule `out_of_memory` (or `startup_fatal`) and action `block`.

The backstop runs only on web SAPIs (`apache2handler`, `fpm-fcgi`, `cgi-fcgi`,
`litespeed`), never on the command line, and turns itself off on PHP versions
that ship the upstream fix (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 and later),
detected at runtime so distro backports count too. It is also off whenever the
global `mode` is `off` (including the `on_invalid_config = "off"` fallback) —
`off` disables every layer, this one included; `detect` keeps it armed, since a
worker running out of memory cannot be "detected only". The
`OOM backstop (oom_exit)` row in `phpinfo()` served by the **web SAPI** shows
the decision (`php --ri howdah` runs under the CLI SAPI, where it always reads
off).

The event names the script and line in its `reason` (the worker exits before
PHP writes its own "exhausted in … on line …" message, so this is the operator's
locus); it carries no URI.

Set `oom_exit = false` to keep PHP's default behaviour (a fatal error page, the
worker surviving) — on an unpatched engine that reopens the PHP2Shell window.
Howdah does not fix the underlying PHP bug; patching remains the fix. It is a
TOML key, not a php.ini directive.

### `recycle_on_fatal`

```toml
recycle_on_fatal = false   # false (default) | true
recycle_observe  = false   # true -> log a "would-recycle" event, do not recycle
```

Off by default, opt-in. A companion to `oom_exit` for the other half of the
PHP2Shell window: a poisoning-class bailout fatal (an uncaught `Error`, a parse
or compile error, a failed `require`, `max_execution_time`) during the script
can leave request state half-built for the **next** request to read, on an
engine without upstream's fix (CVE-2026-109619). With `recycle_on_fatal = true`,
Howdah ends the worker after such a fatal, so it never serves another request on
that state; the worker is replaced and the event is logged with rule
`fatal_recycle`. Like `oom_exit`, it runs only on web SAPIs and turns itself off
on engines that ship the upstream fix. On every supported web SAPI the worker
takes the immediate exit (the 500 is not flushed before teardown there anyway),
so the producing request's response is dropped and the next-request window is
closed either way. Set `recycle_observe = true` to log a would-recycle event
without ending the worker, to size your fatal rate before enforcing. Both are
TOML keys, not php.ini directives.

The backstop writes its one event line with an **async-signal-safe, allocation-free**
path: the line is built on the stack and written with a single `write(2)` to a
log-file descriptor captured at startup (or stderr for a syslog/stderr
destination). So a `max_execution_time` timeout on PHP &le; 7.0 — which raises
its fatal from the `SIGPROF` handler — and a genuine *system* out-of-memory
(where the allocator itself fails) both log and `_exit` cleanly, without
touching `malloc` on that path.

## Build a config in the browser

[howdah.org/config/](https://howdah.org/config/) builds `howdah.ini` and
`howdah.toml` from a form, with every setting's default and effect next to it,
and validates the TOML with the extension's own parser (`howdah-core` compiled
to WebAssembly), so what it calls valid is what the extension accepts. The
result can be copied, downloaded, or fetched with one `curl` command from
`cfg.howdah.org`, a stateless service that re-validates the config with the
same core and stores nothing (the URL carries the whole file).

## The TOML file

```toml
# Global enforcement mode: "block" refuses offending requests, "detect" logs
# only, "off" disables everything. Per-rule overrides live in [rules].
mode = "block"

[limits]
# --- multipart body limits (0.1) ---
max_parts              = 2000        # parts in one multipart body
max_files              = 200         # file parts in one body
max_part_headers       = 16          # header lines in any one part
max_part_header_bytes  = 8192        # bytes (name+value) of any one part header
max_field_name_bytes   = 1024        # bytes of a form-field name
max_filename_bytes     = 512         # bytes of an uploaded filename
max_parse_memory_bytes = 268435456   # total body bytes Howdah will process (256 MiB)

# --- input-shape limits (1.0) ---
max_input_vars           = 2000      # GET+POST+cookie variables in one request
max_input_nesting_depth  = 64        # array nesting of one name: a[b][c] = 2
max_input_key_bytes      = 1024      # bytes of any single variable name / array key

# --- request-header limits (1.0) ---
max_request_headers      = 200       # request headers in one request
max_request_header_bytes = 16384     # bytes (name+value) of any one request header

[log]
# Where event lines go: "file" (default), "syslog" or "stderr". See the [log]
# section below. The howdah.log ini value wins over `path` when both are set.
destination = "file"
path = "/var/log/howdah/events.log"

[rules]
# Override the mode for a single rule by its name (see the table below).
# Example: watch the header-count rule before enforcing it.
max_request_headers = "detect"
self_test           = "off"
```

Any limit set to `0` is rejected (`0` would block every request); set a large
number instead. There is no "unlimited".

## `[limits]` directives and their defaults

Defaults are validated by the cross-version lab matrix and the false-positive
corpus (`lab/integration/matrix.sh`, `lab/integration/corpus/`); the corpus is
zero-block at every value below. See `docs/coverage.md` /
`docs/coverage-data.md`.

| directive | default | one-line rationale |
|---|---|---|
| `max_parts` | 2000 | 2× stock PHP `max_input_vars` (1000); a memory-exhausting flood needs tens of thousands of parts, so it fires with a wide margin and never false-positives a stock-config form |
| `max_files` | 200 | no legitimate form uploads hundreds of files at once; caps a raised-`max_file_uploads` flood before the per-file temp-file cost dominates |
| `max_part_headers` | 16 | browsers send 1–3 headers per part; best-effort lower bound (only Content-Disposition reaches the callback) |
| `max_part_header_bytes` | 8192 | a part header is normally <200 bytes; 8 KiB tolerates long UTF-8 filenames |
| `max_field_name_bytes` | 1024 | field names are identifiers/array keys; 1 KiB is very generous |
| `max_filename_bytes` | 512 | filesystems cap names near 255 bytes; 512 allows percent-encoded forms |
| `max_parse_memory_bytes` | 256 MiB | well above PHP's default `post_max_size` (8 MiB) and common raised values, below host memory exhaustion |
| `max_input_vars` | 2000 | 2× stock PHP `max_input_vars` (1000): a real 1500-field form passes, while a hash-collision / variable flood is var-dropped and logged well before it stresses the symbol table |
| `max_input_nesting_depth` | 64 | real forms nest a handful of levels (our legit corpus peaks at 5); 64 is far beyond legitimate use yet below depths that stress recursive array handling |
| `max_input_key_bytes` | 1024 | same generous bound as field names: keys are identifiers |
| `max_request_headers` | 200 | browsers send ~10–30 headers and proxies add a few; 200 is far beyond legitimate use (our 50-header corpus request passes) |
| `max_request_header_bytes` | 16384 | 16 KiB tolerates large cookies and auth tokens in one header line (servers commonly cap a header line at 8–16 KiB) |
| `max_nesting_levels` | 10000 | summed array-nesting levels across every variable/field/file name in one request (gap C); file names are weighted (PHP builds several metadata arrays per file). Bounds total array-building cost, which a flood of nested names drives up regardless of any one depth |

`memory_ceiling_bytes` (default `0`) is a related `[limits]` key that overrides the
§4.5 parse-memory estimate ceiling: `0` means automatic — the request's live
`memory_limit / 4`, or a fixed fallback when `memory_limit = -1`; a byte value
pins it. It is the one `[limits]` key whose `0` is valid (it selects the
automatic ceiling). On a host with a **small `memory_limit` and a large
`post_max_size`** (`post_max_size > memory_limit / 4`), the automatic ceiling can
sit below `post_max_size`, so a single very large non-file field could trip
`parse_memory_estimate` before PHP's own `post_max_size` would reject it; raise
`memory_ceiling_bytes` or lower `post_max_size` there. `nesting_budget`
(`max_nesting_levels`) fires before `max_parts` only once the summed, file-weighted
levels pass 10000, so a form needs either very many fields or deep nesting to
reach it — a benign 1500-field form at shallow depth stays well under.

## `[rules]` — per-rule mode and severity

Each `[rules]` key is a **rule name**; the value is `block`, `detect`, or `off`.
Rule names: `max_parts`, `max_files`, `max_part_headers`, `max_part_header_bytes`,
`max_field_name_len`, `max_filename_len`, `parse_memory_budget`,
`malformed_multipart`, `upload_progress_abuse`, `self_test`, `max_input_vars`,
`max_input_nesting_depth`, `max_input_key_bytes`, `max_request_headers`,
`max_request_header_bytes`, `post_too_large`, `nesting_budget`,
`parse_memory_estimate`. (A few byte-limit **rule**
names end `_len` where the matching `[limits]` **directive** ends `_bytes`.)
The core also accepts the Layer 2 and 3 names (`sql_injection`,
`path_traversal`, `command_injection`, `command_exec`, `include`, `eval`,
`unserialize`) under `[rules]`, but the extension does not read them there:
set Layer 2 classes in `[inspect.rule_modes]` and sinks in `[sinks.<sink>]
mode`.

Rules carry a **severity**:

- **Critical** rules (`max_parts`, `max_files`, `max_input_vars`,
  `max_input_nesting_depth`, and the byte/memory limits)
  block even when the global `mode` is `detect` — a detect-mode deployment still
  refuses the unambiguous resource-exhaustion shapes. Set the rule to `off` to
  fully disable it.
- **Standard** rules (`malformed_multipart`, `upload_progress_abuse`,
  `max_input_key_bytes`, `max_request_headers`, `max_request_header_bytes`,
  `self_test`) log in `detect` and block only in `block` mode — these are the
  shapes an unusual-but-legitimate client can hit.

## `[inspect]` — Layer 2 input inspection (log-only by default)

**The three content classes only LOG; they do not block any request.** Layer 2
looks at decoded request values for SQL-injection, path-traversal and
command-injection shapes and writes an event when it sees one. A global
`howdah.mode = block` does **not** arm them. To block, set `inspect.mode` (or
one class via `[inspect.rule_modes]`) to `block` explicitly. The one
exception is `cgi_arg_injection` (php-cgi argument injection, below), which is
enforced by default.

Signature inspection is best-effort and can be bypassed by a determined
attacker. That is why it logs by default: use the log to see what is
happening, and fix the application (parameterized queries, path
normalization, no shell calls on user input) rather than rely on this layer.

`[inspect]` lives in the TOML file named by the `howdah.config` php.ini
setting, not in `howdah.ini` itself. Its mode is independent of the global
`mode`.

```toml
[inspect]
enabled = true          # master on/off for Layer 2
mode = "detect"         # detect = log only (default); block; off. INDEPENDENT of the global howdah.mode.
sqli = true             # per-class toggles
traversal = true
cmdi = true
cgi_arg = "block"       # php-cgi argument injection (CVE-2012-1823, CVE-2024-4577): block (default), detect = log only, off

[inspect.limits]
max_value_bytes = 16384   # scan at most this many bytes of one value
max_total_bytes = 2097152 # per-request aggregate scan budget
max_values = 2000         # per-request value count budget

[inspect.rule_modes]      # optional per-class mode override; keys are the rule names
# sql_injection = "block" # example only: opt ONE class into blocking (default is log-only). Also: path_traversal, command_injection
# cgi_arg_injection = "detect" # overrides inspect.cgi_arg for that rule
```

The rule names are `sql_injection`, `path_traversal`, `command_injection` and
`cgi_arg_injection`.
A `[inspect.rule_modes]` entry overrides `inspect.mode` for that class only (for
`cgi_arg_injection`, it overrides `inspect.cgi_arg`).
The `[inspect.limits]` budgets bound the scanning work per value and per
request; values past a budget are not scanned.

When a class is armed (`block`), the refusal happens **before the script
runs** on php-fpm, Apache mod_php, php-cgi and the CLI server: GET, POST and
cookie values are scanned while PHP builds the superglobals at request
startup, and Howdah then builds `$_SERVER` at RINIT so the request path
(`REQUEST_URI`, `PATH_INFO`) is scanned there too, instead of whenever the
script first touches `$_SERVER`. Header values are not a Layer 2 input (only
the path is taken from `$_SERVER`); what the forced `$_SERVER` also buys is
that the Layer 1 header count and size limits move in front of the script.
That `$_SERVER` build is the one cost of arming Layer 2 on an application that
never reads it; log-only mode does not pay it. Details and
what stays post-hoc: "Enforcement timing" below.

### `cgi_arg_injection` — php-cgi argument injection (blocks by default)

When PHP runs as php-cgi behind a CGI front end (Apache `mod_cgi`, IIS), a
query string that contains **no literal `=`** is handed to php-cgi as
command-line words (RFC 3875 section 4.4: split on `+`, percent-decoded). A
client can then drive php-cgi's own options: `?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input`
is code execution and `?-s` is source disclosure (CVE-2012-1823).
CVE-2024-4577 revives the same shape on Windows, where a soft hyphen (byte
`0xAD`, written `%AD`) stands in for the `-` that the 2012 fix filters. Howdah
refuses such a request **before the script runs** (clean 403, the worker
survives) because the check reads only the request's query string. One caveat
for the php-cgi SAPI itself: php-cgi parses the options during its own startup,
before RINIT, so the refusal is in time only for what takes effect *after*
RINIT — the code-execution shape (`-d auto_prepend_file`, `allow_url_include`),
where the injected prepend compiles with the script. The `-s`/`-i`
source/info-disclosure forms php-cgi emits during that same startup, before
RINIT, so the check does not stop them under php-cgi (instrumentation: RINIT
fired for `?x=1` but not `?-s`); under php-fpm, Apache and the CLI server, which
never interpret the query string as argv, a `?-s` request is harmless anyway.
Keep a web-server or front-proxy rule, or a patched php-cgi, for the `-s` form
and for CVE-2019-11043.

The match is deliberately narrow. The raw query string must contain no literal
`=` (every working exploit writes it `%3d`), and then one of these:

- a `+`/space-separated word that is a php-cgi option: a flag used on its own
  (`-s`, `-w`, `-i`, `-m`, `-v`, `-h`, `-n`, `--info`, ...), or an option that
  takes an argument (`-d`, `-c`, `-z`, `-f`, `-b`, `-T`, `-r`, `--define`, ...) followed by its
  argument word or carrying an attached `name=value` or `scheme://` argument.
  The dash may be a literal `-`, `%2d`, or a soft hyphen (`%AD`, `%C2%AD`);
- a word that names a php-cgi directive (`auto_prepend_file`,
  `auto_append_file`, `allow_url_include`, `cgi.force_redirect`,
  `cgi.redirect_status_env`, `cgi.fix_pathinfo`);
- a stray soft-hyphen byte (`0xAD`) in the decoded query that is not the
  continuation byte of a well-formed UTF-8 character. (A bare `0xAD` test
  would block every query containing an accented `i`, `C3 AD`, or many CJK
  characters, `E4 B8 AD`; the UTF-8 walk avoids that.)

Ordinary `=`-less queries stay clean: search words, ids, dates, slugs,
negative numbers (`?-1`), dash-leading words (`?-sale`, `?-created`), base64 and
base64url tokens, front-controller paths (`?/users/12/edit`) and UTF-8 text.
Any query with a literal `=`, which is every ordinary form or API request, is
never a match.

Unlike the three classes above this rule is **on and enforcing by default**,
under every global mode except `off`: `inspect.cgi_arg` is `"block"`, and
neither `inspect.mode` nor the global `howdah.mode` changes it (a shipped
`howdah.mode = detect` install still blocks it, as it does a Critical limit).
The rule is Standard severity and Layer 2. Set `inspect.cgi_arg = "detect"` to
log without refusing, or `"off"` to disable it. `inspect.enabled = false` (the
Layer 2 master switch) and `howdah.mode = off` also silence it. The query
string is scanned, never logged: the event carries the rule and a fixed reason
only. It does not use the per-request value and byte budgets, so a flood of
ordinary variables cannot spend a budget ahead of it. An `[[exceptions]]`
entry for `inspect.cgi_arg_injection` with a `client_cidr` or `uri_prefix`
facet exempts a scanner or a path.

## `[sinks]` — Layer 3 sink hardening (log-only by default)

**Sinks log by default; they do not block.** Layer 3 watches dangerous PHP
functions ("sinks") and writes an event when one is called with something your
allowlist does not cover. Two checks are enforced by default instead: `xxe`
(XML external entities, under "Legacy-era sinks" below), but only when a
dangerous libxml parse flag and an external entity meet in the same XML string;
and the include/open stream-wrapper firewall (`wrapper` and `poison`, under
"`include` / `require` and `eval`" below). Layer 3 **actively guards six sinks**
(four since 1.2; `phar` and `ssrf` were added in 1.3):

- `command_exec` — `system`, `exec`, `shell_exec`, `passthru`, `popen` and
  `proc_open`.
- `unserialize` — object unserialization. Off by default.
- `include` / `require` — inert until `allow_paths` is set. Active on every PHP
  version since 1.3 (PHP 5.x via a compile-pointer swap; see below).
- `eval` — active on every PHP version since 1.3.
- `phar` — `phar://` use. **Off by default** (1.3).
- `ssrf` — outbound requests to internal addresses. **Off by default** (1.3).

| Sink | PHP 5.4–5.6 | PHP 7.0–7.4 | PHP 8.0–8.5 |
|------|-------------|-------------|-------------|
| `command_exec` | detect + block | detect + block | detect + block |
| `unserialize` (off by default) | detect + block | detect + block | detect + block |
| `include` / `require` | detect + block (opcache caveat) | detect + block | detect + block |
| `eval` | detect + block | detect + block | detect + block |
| `phar` (off by default) | detect + block, with deserialization | detect + block, with deserialization | detect + block, **no deserialization claim** |
| `ssrf` (off by default) | detect + block | detect + block | detect + block |

Provenance: verified on PHP 5.4, 5.6, 7.4, 8.3 and 8.5. Other minors build and
are expected to work but are not independently verified. A debug-build leak
review is still pending.

`sinks.mode` defaults to `detect` (log only) and is **independent of the global
`howdah.mode`**: a global `howdah.mode = block` does **not** arm any sink. To
block, set a sink's mode to `block` explicitly, and **set its allowlist first**
— with an empty allowlist every call is "not allowlisted". Every active sink
except `tls` (detect-only in this release) can block when explicitly armed.

**The sink argument is never logged.** An event records only the sink and the
function name (plus the class name for `unserialize`) — never the command line
or the serialized payload.

Like `[inspect]`, `[sinks]` lives in the TOML file named by the `howdah.config`
php.ini setting. It adds **no new php.ini directives**.

```toml
[sinks]
enabled = true            # master on/off for Layer 3
mode = "detect"           # detect = log only (default); block; off. INDEPENDENT of the global howdah.mode.
# hook = "auto"           # include/eval mechanism on PHP 7.0+: "auto" (default: "compile" when
                          # only eval needs it, "opcode" when include has allow_paths or
                          # [behavior] deny_exec_dirs is set), "opcode" (full coverage, OPcache JIT
                          # off) or "compile" (JIT stays on; a warm-opcache include is not
                          # re-inspected). See below.

[sinks.command_exec]      # system/exec/shell_exec/passthru/popen/proc_open
# mode = "block"          # optional per-sink override; unset inherits sinks.mode. Set allow FIRST.
allow = []                # commands that are fine; anything else is logged (or blocked in block mode)

[sinks.unserialize]       # OFF by default: object unserialize is high-volume
# mode = "detect"         # opt in (log only). "block" refuses non-allowlisted classes.
allow_classes = []        # class names that may be unserialized

[sinks.include]           # include/require. The allowlist check is inert until allow_paths is set.
# mode = "block"          # optional per-sink override for the ALLOWLIST check; unset inherits sinks.mode
allow_paths = []          # directories include/require may load from
# wrapper = "block"       # include/open wrapper-scheme firewall (default BLOCK; "detect"/"off"). See below.
# poison  = "block"       # poisonable-local-target firewall (default BLOCK; "detect"/"off"). See below.
[sinks.eval]              # eval

# New in 1.3. Both are OFF by default and are armed only by an explicit
# per-sink mode (neither sinks.mode nor howdah.mode arms them).
[sinks.phar]              # phar:// guard
# mode = "detect"         # opt in (log only); "block" denies
allow_paths = []          # realpath prefixes allowed even under block
[sinks.ssrf]              # outbound requests to internal addresses
# mode = "detect"         # opt in (log only); "block" denies
allow_hosts = []          # hostname | IP | CIDR; no wildcards
# Hardening on top of the range check (T6). Each is OFF by default, takes
# "detect" or "block", and is independent of mode and of the other two:
# rebind   = "block"      # resolve-at-connect (anti DNS rebinding)
# scheme   = "block"      # only http/https may leave (curl gopher/dict/file/ldap/... refused)
# redirect = "block"      # a curl 3xx to an internal target is not followed
```

### `command_exec`

`allow` patterns are **anchored literal strings with an optional single
trailing `*`** (any suffix). They are not regular expressions.

- `"id"` matches only the command `id`.
- `"/usr/bin/convert *"` matches any command starting with `/usr/bin/convert `.
- A bare `"*"` allows every command (useful to keep the sink silent).

### `unserialize`

Off by default. Opt in with `[sinks.unserialize] mode = "detect"` to log
unserialize calls that create objects of classes not listed in `allow_classes`.
Set `mode = "block"` only after the log shows your application's legitimate
classes are all in `allow_classes`.

### `include` / `require` and `eval`

Active in detect and block modes. `include`/`require` is **inert until
`allow_paths` is set**. Blocking stops the included file or evaluated code from
running and the script continues. As always, the argument is never logged.

- **PHP 7.0+:** a runtime opcode handler by default, which is not affected by
  opcache; or, with `[sinks] hook = "compile"`, the compile-time check below.
- **PHP 5.x (new in 1.3):** a compile-time check (`zend_compile_file` /
  `zend_compile_string`). `eval` is never cached, so it is fully covered. An
  `include` served from a **warm opcache** is not compiled again and is **not
  re-inspected**, so already-cached application files are not checked.

#### `wrapper` / `poison`: the include/open stream-wrapper firewall

Separate from the `allow_paths` allowlist above, and **enforced by default**,
is a firewall that classifies the fully resolved target (the string after
concatenation, variables and decoding, which an in-process hook sees but a
network WAF cannot). It governs both `include`/`require` and the file-open sinks
`fopen`, `file_get_contents` and `readfile`, through two keys under
`[sinks.include]`:

- **`wrapper`** (default `block`) — the stream-wrapper scheme. For
  `include`/`require`, every non-`file` wrapper is refused: `php://filter`
  chains, `php://input`, any other `php://*`, `data:`, `expect://`, remote
  `http(s)`/`ftp(s)` and any other scheme (`zip://`, `compress.*://`, …).
  Including a stream wrapper is never legitimate. `phar://` is **left to the
  `phar` sink** (not double-guarded). For the file-open sinks the set is tighter
  — only the near-zero-benign-use wrappers `php://filter`, `data:` and
  `expect://` — so `file_get_contents('php://input')` (reading the request
  body), `fopen('php://temp'|'php://memory', …)` and remote fetches (the `ssrf`
  sink's job) are never false positives.
- **`poison`** (default `block`) — a tight poisonable-local-target set:
  `/proc/self/environ` and other `/proc/*`, a file under the runtime
  `session.save_path`, and PHP's configured `error_log`. These are the classic
  LFI->RCE log/session/proc poisoning sinks; nothing legitimate includes or
  opens them. The match is anchored at the effective root (so a relative
  `templates/…` or a plain app path never matches) and the `error_log` match is
  exact.

Both keys are **independent of the global `howdah.mode` and of `sinks.mode`**,
like `xxe` and `cgi_arg_injection`: `block` (the default) refuses, `detect`
logs only, `off` disables. A global `howdah.mode = off` or `[sinks] enabled =
false` silences them. A block is a clean sink neutralization, not a
request-level refusal: the `include` is skipped (returns `false`) or the open
returns `false`, and the **script continues and the worker survives**. Rules:
`include_wrapper` (the include path) and `file_open` (the open sinks), both
Layer 3, Standard. Only a scheme/category label (`php://filter`, `data://`,
`proc_environ`, `session`, `log`, …) and the guarded function name are logged;
the target content is not. The file-open sinks are hooked whenever this firewall
is armed. On PHP 5.x the firewall rides the compile-swap and shares its
warm-opcache caveat (an already-cached include is not re-inspected); an attack
include of a wrapper/poison target is a dynamic cache-miss, so it is compiled
and seen.

#### `hook`: the include/eval mechanism and OPcache JIT

PHP's OPcache JIT refuses to run alongside any extension that installs a user
opcode handler (`zend_jit_check_support` logs "JIT is incompatible with third
party extensions that setup user opcode handlers. JIT disabled."). The
`include`/`eval` guard on PHP 7.0+ is such a handler. Up to 1.4.0 Howdah
installed it unconditionally at startup, so loading Howdah turned the JIT off
on PHP 8 even with `[sinks] enabled = false`. Now:

- **A hook is installed only when something needs it**, decided once at
  startup from the config: the include/open firewall (`wrapper`/`poison`) is on
  (it is, in the shipped defaults: `block`), or the `eval` sink is on (it is:
  `detect`), or the `include` sink is on **and** has `allow_paths` (with no
  `allow_paths` it never produces an event, so it needs no hook), or Layer 4
  `[behavior] deny_exec_dirs` is set (its `require`d-file check runs in the same
  hook). With all of those off nothing is installed and the JIT stays on. Like
  every other key, changing these needs a php-fpm/Apache restart.
- **`hook = "auto"` (the default)** picks the mechanism from what needs it:
  `compile` when only `eval` and/or the include firewall need it (the compile
  pointers cover every `eval`, and an attack include of a wrapper/poison target
  is a dynamic cache-miss that the compile swap still sees, so the opcode
  handler would only cost the JIT), `opcode` when `include` has `allow_paths` or
  `deny_exec_dirs` is set (the cases where an *already-cached* include matters).
  So **a default install keeps the JIT on** with the firewall and `eval` fully
  guarded.
- **`hook = "opcode"`:** the opcode handler. Full coverage: every
  `include`/`require` and `eval`, including files served from a warm opcache.
  The JIT is off. Whenever the opcode handler is what gets installed
  (explicitly, or `auto` choosing it) and `opcache.jit` /
  `opcache.jit_buffer_size` in php.ini say the JIT is on, Howdah writes one
  line to the SAPI error log at startup saying PHP will turn it off and naming
  `hook = "compile"` as the way to keep it on.
- **`hook = "compile"`:** the `zend_compile_file` / `zend_compile_string`
  pointer swap, the mechanism PHP 5.x always uses. The JIT check does not look
  at it, so the JIT stays on. `eval` is still fully covered (it is never
  cached). The trade-off is the 5.x one: **an `include` served from a warm
  opcache is not compiled again and is not re-inspected**; only the first
  compile of a file after a worker starts or the cache is invalidated is
  checked (`lab/integration/jit.sh` shows two includes of the same file
  logging two events in `opcode` mode and one in `compile` mode).
  `opcache_compile_file()` also goes through this hook and is treated as an
  include. Files `require`d by an `opcache.preload` script (PHP 7.4+) are
  compiled at server startup, outside any request, and are chained through
  unguarded: no event, nothing refused. A blocked `require_once` /
  `include_once` still marks the file as included (PHP records it before
  compiling), so a later `include_once` of the same path in that request
  returns `true` without running it, as on 5.x. The Layer 4 `deny_exec_dirs`
  `require`d-file check runs in whichever mechanism is installed and shares
  its caveat.
- **Load Howdah from php.ini, never with `dl()`.** The hooks are installed
  for the life of the process; a `dl()`'d module is unloaded at request end
  and would leave them dangling, so MINIT refuses a `dl()` load with one line
  in the SAPI error log and PHP reports the `dl()` as failed.
- `php --ri howdah` / `phpinfo()` show the result and why:
  `Include/eval hook => none | opcode handler (JIT disabled by PHP; <why>) | compile pointer (JIT compatible; <why>)`
  where `<why>` is `auto: include firewall on`, `auto: eval only`,
  `auto: include allow_paths set`, `auto: deny_exec_dirs set` or `configured`
  (the JIT parentheticals appear on PHP 8.0+, where the JIT exists).

The rest of Layer 3 (`command_exec`, `unserialize`, `phar`, `ssrf`) and
Layers 1, 2 and 4 are function-table swaps, stream-wrapper proxies and
request hooks; none of them affects the JIT. Verified on PHP 8.1 and 8.3
(`opcache_get_status()['jit']['on']`), with the compile-mode behaviour also
checked on 7.4 and 5.6.

### `phar`

**Off by default.** Enable with `[sinks.phar] mode = "detect"` (log) or
`"block"` (deny). `[sinks] mode = "block"` and the global `howdah.mode` do
**not** arm it; only an explicit `[sinks.phar] mode` does. `allow_paths` is a
list of realpath prefixes that stay allowed even under `block` (for example your
own vendored phars). Blocking makes the open fail the way a missing file does:
PHP raises its normal "failed to open stream" warning and the script continues.

- **PHP 5.x and 7.x:** covers phar metadata deserialization triggered through the
  wrapper (filesystem functions and `include` on a `phar://` URL).
- **PHP 8.x:** detection and denial of `phar://` use only. PHP 8.0 removed the
  automatic deserialization, so there is **no deserialization claim** here.
- **Not covered:** the direct Phar API (`new Phar`, `PharData`,
  `Phar::loadPhar`, `Phar::mapPhar`, `Phar::getMetadata`) unserializes before
  any wrapper operation. Calling `stream_wrapper_unregister('phar')` then
  `stream_wrapper_restore('phar')` is untested and could drop the guard. If
  another extension re-registers `phar` after Howdah, or phar is built
  statically into PHP, the guard fails open.

### `ssrf`

**Off by default.** Enable with `[sinks.ssrf] mode = "detect"` or `"block"`.
Like `phar`, it is armed only by an explicit per-sink mode, never by
`[sinks] mode` or `howdah.mode`. `allow_hosts` takes exact hostnames, IP
addresses and CIDRs; wildcards and malformed CIDRs are rejected when the config
loads.

Hooked: `file_get_contents`, `fopen`, `get_headers`, `fsockopen`, `pfsockopen`,
`stream_socket_client`, and curl (`curl_exec`, tracked through
`curl_init`/`curl_setopt`/`curl_setopt_array`). Every address a host resolves to
is checked, and a hit on a reserved or internal range is a match.

- **DNS cost:** enabling it adds one `getaddrinfo` per distinct outbound host
  (cached for the request). There is **no timeout**: a stalled DNS server stalls
  the call. This is why it is off by default.
- **Best effort, not a connection-time boundary.** `mode` alone resolves the
  host when the call is made and PHP / libcurl resolve it again at connect. It is
  bypassed by DNS rebinding, redirects to a new host, `curl_multi_*` (not
  hooked), `CURLOPT_RESOLVE` / `CURLOPT_CONNECT_TO`, and a non-string or absent
  `CURLOPT_URL`. The opt-in `rebind`, `scheme` and `redirect` knobs below close
  several of these where PHP allows it, and say plainly where they cannot.
- **Not hooked:** `copy`, `file`, `readfile`, `SoapClient`, `DOMDocument::load*`
  and `simplexml_load_file` can still make outbound requests unseen.
- **Side effects of a block:** a blocked `fsockopen` / `stream_socket_client`
  leaves `$errno` and `$errstr` unset; a blocked `curl_exec` returns false with
  `curl_errno` 0 and an empty `curl_error`.
- A host that resolves to **more than 32 addresses**, or a host longer than 256
  bytes, is treated as suspicious — logged, and blocked when armed — never
  silently skipped, so an attacker DNS answer cannot hide an internal address
  past the cap. A curl URL longer than 8192 bytes is likewise treated as
  suspicious rather than parsed from a truncated copy, so a padded `#fragment`
  or a long userinfo cannot steer the cut to drop the handle out of the guard. Literal-IP decoding mirrors glibc `inet_aton`; libcurl and musl
  parse some encoded forms differently, so the resolved addresses are the
  authority. The host parse matches PHP and libcurl on the tricky shapes: a
  `\` before `@` stays in the userinfo (the host is taken after the last `@`),
  an unknown or nesting scheme (`dict://`, `compress.zlib://http://…`) is peeled
  so the inner host is still classified, and an out-of-range or garbage port
  classifies the host with no port rather than dropping it. A **NUL anywhere in
  the authority** is treated as suspicious (blocked when armed): no legitimate
  host has one, and PHP's URL parser (keeps the userinfo) and libc (stops at the
  NUL) would otherwise resolve to different hosts, so both `public\0@127.0.0.1`
  and its mirror `127.0.0.1\0@public` are caught.
- **`allow_hosts` requires every resolved address.** A name is allowed by an IP
  or CIDR entry only when *all* of its resolved addresses match it; a name that
  answers `[an allowed address, 169.254.169.254]` is **not** allowed (PHP could
  connect to the internal one). A hostname entry trusts the name itself — pair
  it with the `rebind` knob for resolve-time safety.
- **Not tracked:** a URL passed as a `Stringable` object instead of a string, a
  `curl_setopt` using the numeric option id (`10002`) instead of the
  `CURLOPT_URL` constant, and more than 256 live curl handles at once (the
  per-request handle map is bounded and fails open when full).

#### SSRF hardening: `rebind`, `scheme`, `redirect`

Three opt-in knobs sit beside the range check. Each is **off by default**,
takes `"detect"` or `"block"`, and is **independent** of `mode`, of
`[sinks] mode` and of the other two (a global `howdah.mode = off` or
`[sinks] enabled = false` still silences them). They log as the same `ssrf`
rule (so `[[exceptions]]` `rule = "ssrf"` applies) and never log a URL, path or
query: only a scheme *category*, or host, port, resolved IP and class.

```toml
[sinks.ssrf]
mode     = "block"        # the range check at call time (above)
rebind   = "block"        # resolve-at-connect
scheme   = "block"        # only http/https may leave
redirect = "block"        # a curl 3xx to an internal target is not followed
allow_hosts = ["api.partner.example", "10.0.5.0/24"]
```

**`scheme`: only `http` and `https` may leave.**

- *curl:* `gopher://`, `dict://`, `file://`, `ldap(s)://`, `tftp://`,
  `ftp(s)://`, `sftp`, `scp`, `smb`, `imap`, `pop3`, `smtp`, `telnet`, `rtsp`,
  `rtmp`, `mqtt` and any unknown scheme are refused, plus libcurl's host-prefix
  protocol guess for a scheme-less URL (`ftp.example.com` is FTP; likewise
  `dict.`, `ldap.`, `imap.`, `smtp.`, `pop3.`). `file://` reads a local file and
  `gopher://` / `dict://` smuggle raw bytes to an internal service (Redis,
  memcached), which is why curl gets an allowlist, not a denylist.
- In `block` the curl handle is also given `CURLOPT_PROTOCOLS = HTTP|HTTPS` at
  `curl_exec`, so libcurl itself refuses anything else, redirect hops included,
  even where Howdah's URL parse and libcurl's differ. That **overrides a script's
  own `CURLOPT_PROTOCOLS`** on that handle.
- *`file_get_contents`, `fopen`, `get_headers`:* only the remote wrappers are
  refused (`ftp`, `ftps`, `sftp`, `scp`, `gopher`, `dict`, `ldap(s)`, `tftp`,
  `telnet`, `smb`, `imap`/`pop3`/`smtp`, `ssh2.*`). `http`, `https` and the local
  wrappers (`file`, `php`, `data`, `glob`, `zip`, `compress.*`) are untouched;
  `phar` stays the `phar` sink's and `php://filter` / `data:` / `expect://` the
  include/open wrapper firewall's. The socket openers (`fsockopen`, ...) take
  `tcp://` / `ssl://` transports, not URLs, so `scheme` does not apply to them.
- `allow_hosts` does not apply (it names destinations; this is a protocol
  policy). Exempt a trusted script with `[[exceptions]]`.
- Log: `ssrf scheme via curl: scheme=gopher is not http/https`. The label is the
  scheme (`other` for an unknown one, `guessed-ftp` for the host-prefix guess).

**`rebind`: validate the address the connection really uses.** The range check
resolves the host when the call is made and PHP / libcurl resolve it again when
they connect, so a name can answer "public" to the first lookup and "internal"
to the second. `rebind` closes that gap *where PHP lets it be closed*, and the
guarantee differs per path:

| Path | What `block` does | What it guarantees | What it cannot do |
|---|---|---|---|
| `curl_exec`, PHP 5.5+ | Judges the resolved set, then **pins** it into the handle with `CURLOPT_RESOLVE` (`host:port:ip`; a comma list on libcurl 7.59+, otherwise the first address). After the transfer it judges `CURLINFO_PRIMARY_IP`. | For the first hop libcurl connects to exactly the addresses that were checked; a rebinding name's second answer is never asked for. | Redirect hops are not pinned (the last hop is judged after the fact, see below). An IPv6-only host is not pinned (only the after-the-fact check applies). A literal IP has nothing to rebind. |
| `curl_exec`, PHP 5.4 | PHP 5.4 has no `CURLOPT_RESOLVE`, so **nothing is pinned**. After the transfer `CURLINFO_PRIMARY_IP` (the address libcurl connected to) is judged and an internal one discards the response. | The response never reaches the script. | The request **was sent** to the internal address (a body already streamed to `CURLOPT_FILE` / `WRITEFUNCTION`, or echoed without `RETURNTRANSFER`, is out too). |
| `fsockopen`, `pfsockopen`, `stream_socket_client` | After the connect, the **peer address of the returned stream** (what `getpeername` reports) is judged; an internal peer closes the stream the way `fclose` would and the call returns false. | Authoritative for the address the kernel used, however the name was resolved; nothing has been written yet (the script never held the stream). | The TCP handshake happened (a connect oracle). An unconnected `STREAM_CLIENT_ASYNC_CONNECT` socket and `unix://` are not judged. |
| `fopen` of a URL | The same peer check on the returned stream. | The script cannot read the response. | The HTTP request had already been sent when `fopen` returned. |
| `file_get_contents`, `get_headers` | **Nothing**: no stream or peer comes back. Only the call-time range check applies. | none beyond `mode` | A rebinding name is served. |

- It judges with the same classifier and `allow_hosts` as `mode`, so a host,
  IP or CIDR you allow is accepted at connect time too. It does not need `mode`:
  `rebind = "block"` alone refuses a curl name that resolves to an internal
  address at call time, before the connect, on every PHP version (pin or no pin).
- *Ordering:* Howdah resolves with `getaddrinfo(AF_UNSPEC)` through the system
  resolver (RFC 6724 sorting and `gai.conf` apply) and pins the IPv4 addresses in
  the order returned; a name with A and AAAA records is pinned to its IPv4 set.
  On libcurl before 7.59 only the first address is pinned, so a dead first A
  record is not retried against the others.
- *Resolve failure is fail-open (as for `mode`):* a name that does not resolve
  when Howdah looks it up is allowed and cannot be pinned, so a resolver that
  fails the first query and answers the second still gets through to libcurl's own
  lookup; the after-the-fact check then judges the address it connected to (the
  request has been sent by then).
- A pin lives on the handle (libcurl keeps `CURLOPT_RESOLVE` entries until the
  handle is freed or the entry is replaced); Howdah re-pins at every `curl_exec`
  from that request's own resolution.
- A proxy (`CURLOPT_PROXY`, or `http_proxy` / `https_proxy` / `all_proxy` in the
  environment) means the connection goes to the proxy, which resolves the target
  itself: neither the pin nor the connected-address check is applied. A script's
  own `CURLOPT_RESOLVE` / `CURLOPT_CONNECT_TO` also suppresses the pin; the
  connected-address check still catches it.
- Log: `ssrf rebind via curl-connect: host=H port=P ip=I class=C` (the connected
  address), `curl-resolve` (the set about to be pinned), `tcp-connect` (sockets),
  `stream-connect` (`fopen`). `detect` pins nothing and discards nothing.

**`redirect`: a curl `3xx` to an internal target is not followed.**

- When `CURLOPT_FOLLOWLOCATION` is on (via `curl_setopt` or `curl_setopt_array`)
  and the script has not set its own `CURLOPT_HEADERFUNCTION`, Howdah installs an
  internal function, `howdah_curl_header_guard`, as the handle's header callback
  at `curl_exec`. libcurl hands it every response header line *before it acts on
  it*. On a `3xx` `Location` that is absolute or scheme-relative (`//host/..`),
  whose host resolves to a reserved or internal address (the `mode` classifier,
  `allow_hosts` honoured), or whose scheme is not http(s) while `scheme` is armed,
  it returns a wrong length and libcurl aborts with `CURLE_WRITE_ERROR`
  (`curl_errno` 23): the redirect is never followed, so the internal service is
  never contacted. A relative `Location`, a `Location` on a non-3xx response and
  `FOLLOWLOCATION` off are not new targets.
- The function is registered at PHP startup, and only when `redirect` or `scheme`
  is armed (it is visible in `get_defined_functions()['internal']`); a default
  install registers nothing.
- Log: `ssrf redirect via http: host=H port=P ip=I class=C`.
- **Not covered:** a script that sets its own `CURLOPT_HEADERFUNCTION` together
  with `FOLLOWLOCATION` (its hops are only judged after the fact when `rebind` is
  armed); `curl_multi_*`; the PHP http stream wrapper's own redirect following
  (`file_get_contents` / `fopen` follow up to 20 redirects internally and Howdah
  never sees the hops: pass `'follow_location' => 0` in the stream context, or use
  curl); and a hop to a *rebinding name*, which passes the hop check and is only
  caught after the fact by `rebind` (the request was sent). Libraries that follow
  redirects themselves (WordPress's curl transport and Guzzle do) call `curl_exec`
  once per hop, so every hop gets the full call-time check.

**Why not `CURLOPT_PREREQFUNCTION` / `CURLOPT_OPENSOCKETFUNCTION`?** They are the
right tools (they see the address libcurl is about to connect to, once per hop)
but they are C callbacks on the `CURL*`, which PHP keeps in a private `php_curl`
struct whose layout differs per PHP version and whose headers are not installed
on 5.x/7.x builds. PHP exposes `CURLOPT_PREREQFUNCTION` as a PHP callable only
from 8.5 (libcurl 7.80+) and `CURLOPT_OPENSOCKETFUNCTION` not at all, so Howdah
uses the controls every supported PHP shares: `CURLOPT_RESOLVE`,
`CURLOPT_PROTOCOLS`, `CURLOPT_HEADERFUNCTION`, `CURLINFO_PRIMARY_IP` and the
stream peer name. Howdah sets `CURLOPT_PROTOCOLS` (`scheme = "block"`) and
`CURLOPT_RESOLVE` (`rebind = "block"`) only in `block`; the header callback for
`redirect` / `scheme` is installed in `detect` too (it only observes there and
never aborts). All of it goes through `curl_setopt` with errors silenced and is
not logged.

Verified by `lab/integration/sinks_fastfollow.sh` on PHP 5.4, 5.6, 7.0, 7.4, 8.0,
8.1, 8.3 and 8.5 against a loopback target, a DNS server that rebinds a name from
a decoy to `127.0.0.1` after the first answer, and a self-signed HTTPS target; the
known gaps above are pinned by checks that fail if they ever close. Results in
`docs/coverage-data.md`.

### Legacy-era sinks

Seven more sinks guard functions and behaviours that mostly matter on the PHP
5.x/7.x third of the web; each is a no-op where the function no longer exists.
Each has its own `[sinks.<name>]` table. For six of them `mode` inherits
`sinks.mode` (so they log by default and block only when you set a mode to
`"block"`; a global `howdah.mode = block` arms none of them). **`xml` (the
`xxe` rule) is the exception: its `mode` defaults to `block`, whatever the
global mode and `sinks.mode`**, like `[inspect] cgi_arg`; `[sinks.xml] mode =
"off"`, `[sinks] enabled = false` or `howdah.mode = off` silence it, and
`mode = "detect"` makes it log only. As everywhere in Layer 3, the argument is
never logged. `php --ri howdah` shows a `Layer-3 legacy
sinks` row naming which ones installed on your PHP.

```toml
[sinks.mail]              # mail() header / additional_parameters injection
# mode = "block"          # block refuses the call (returns false); nothing reaches sendmail
[sinks.preg_eval]         # preg_replace/preg_filter with the /e modifier (PHP 5.x only)
[sinks.create_function]   # create_function() (PHP 5.x/7.x)
[sinks.assert]            # assert("string") evaluated as code (PHP 5.x/7.x)
[sinks.callback]          # a string callback naming a command/code-exec function
[sinks.xml]               # XML external entities parsed with a dangerous libxml flag (ENFORCED by default)
# mode = "detect"         # default "block"; detect logs only, off disables. NOT inherited from [sinks] mode
# external_entities = "deny"   # also turn libxml's external entity loader off (off by default)
[sinks.tls]               # curl TLS verification turned off (detect-only this release)
```

| Sink (rule) | PHP 5.x | PHP 7.x | PHP 8.x | What it flags |
|---|---|---|---|---|
| `mail` (`mail_injection`) | detect + block | detect + block | detect + block | `mail()` 5th arg with a sendmail option other than `-f<addr>`, or a 4th-arg header string with a line break not followed by a header |
| `preg_eval` (`preg_eval`) | detect + block | not covered | not covered | `preg_replace`/`preg_filter` pattern with the `/e` modifier (removed in PHP 7.0) |
| `create_function` (`create_function`) | detect + block | detect + block | not covered | any `create_function()` call (removed in PHP 8.0) |
| `assert` (`assert_string`) | detect + block | detect + block | not covered | a string passed to `assert()` (needs `assert.active`/`zend.assertions`; PHP 8.0 stopped evaluating strings) |
| `callback` (`dangerous_callback`) | detect + block | detect + block | detect + block | a string callback naming a command/code-exec function, passed to a callback-taking function |
| `xml` (`xxe`) | **block by default** | **block by default** | **block by default** | an XML string parsed with a dangerous libxml flag (`LIBXML_NOENT`, `DTDLOAD`, `DTDATTR`, `DTDVALID`) while it declares an external entity or an entity bomb: `simplexml_load_string`, `new SimpleXMLElement`, `DOMDocument::loadXML`, `XMLReader::XML`, `Dom\XMLDocument::createFromString` (8.4+) |
| `tls` (`tls_verify`) | detect | detect | detect | `curl_setopt`(`_array`) turning `CURLOPT_SSL_VERIFYPEER` off or `CURLOPT_SSL_VERIFYHOST` to 0 |

- **`mail`.** The 5th argument is split on whitespace; anything that is not
  `-f<address>`/`-f <address>` (or Postfix's alias `-r<address>`) with a sane
  address (one `@`, address characters only) is flagged. That includes the
  benign-looking `-oi`, `-t` and `-O...` options some applications pass: under
  the default detect mode they are **expected noise** in the log until you set
  `[sinks.mail] mode = "off"` or move those options into `sendmail_path`.
  The 4th argument is flagged when a CR or LF is followed by an empty line
  (body injection) or a line that is not `name:` (folded continuations are
  allowed). An array of headers (PHP 7.2+) is left to PHP. `Bcc:`-style extra
  headers that look like headers are **not** flagged. Block refuses the call
  and returns false. `mail` has its own check entry point and does not consult
  `[[exceptions]]` in this release.
- **`callback`.** The dangerous names are `system`, `exec`, `passthru`,
  `shell_exec`, `popen`, `proc_open`, `pcntl_exec`, `assert` and
  `create_function`. Only a **string** callback is matched (a leading `\` and
  case are ignored); a `Class::method` string, a closure or an array callback
  is not matched, and `eval` is a language construct, not a callback. Only the
  callback name reaches the log. Hooked functions: `call_user_func`,
  `call_user_func_array`, `array_map`, `array_filter`, `array_walk`,
  `usort`, `uasort`, `uksort`, `preg_replace_callback`,
  `register_shutdown_function`, `ob_start`.
  **`call_user_func` / `call_user_func_array` on PHP 7.0+:** the compiler
  turns a literal, unqualified call in the **global namespace**
  (`call_user_func('system', ...)` at the top of a file) into its own opcode
  (`ZEND_INIT_USER_CALL`) and never calls the internal function, so the hook
  does not see the classic webshell shape there. A call inside a `namespace`,
  a fully dynamic call (`$f = 'call_user_func'; $f(...)`) or any of the other
  hooked functions is seen. On PHP 5.x every form goes through the function
  and is seen. `lab/integration/legacy_sinks.sh` pins this per version.
- **`xml` (rule `xxe`): flag-aware, and enforced by default.** Howdah reads
  the libxml *options* argument of the call as well as the XML string and acts
  only when **both** are dangerous: a flag that makes libxml act on a DOCTYPE
  (`LIBXML_NOENT` 2, `LIBXML_DTDLOAD` 4, `LIBXML_DTDATTR` 8 or `LIBXML_DTDVALID`
  16) **and** an external entity declared in the document's internal subset
  (`<!ENTITY ... SYSTEM|PUBLIC ...>`, general or parameter: the shape of every
  file-read and out-of-band XXE payload) or a nested-entity expansion bomb
  (internal entities whose references expand past 1 MiB: billion laughs and its
  variants, in any declaration order). A call with none of those flags (the
  default, `$options = 0`) is never looked at, and a document with a bare
  `<!DOCTYPE>`, ordinary internal entities, or an external DTD reference
  (SAML, SVG, XHTML, RSS, plist, ODF and Office XML legitimately carry them)
  never triggers it. Hooked: `simplexml_load_string`, `new SimpleXMLElement`
  (not when `$dataIsURL` is true), `DOMDocument::loadXML`, `XMLReader::XML`
  (called statically or on an instance) and, on PHP 8.4+,
  `Dom\XMLDocument::createFromString`. The scan reads the prolog only (up to
  the root element, within the first 1 MiB), skipping comments and processing
  instructions and quoted literals, and squeezes the NULs out of a UTF-16 or
  UTF-32 document (BOM or NUL-interleaved `<`) before looking. It also reads
  through the usual disguises: a `>` or `[` inside the DOCTYPE's system
  literal, and a parameter entity whose literal declares the external entity
  and is then expanded (`<!ENTITY % p "<!ENTITY x SYSTEM 'f'>"> %p;`, with
  character references decoded).

  **Documents it cannot read are reported, not waved through.** With a
  dangerous flag set, a document is treated as an attack (the flags are removed)
  when its text is in an encoding an ASCII scan cannot see into (UTF-7, an
  EBCDIC code page, or a UTF-16/32 or UCS-2/4 encoding declared on a document
  that does not look wide, which libxml honours mid-stream) or when its prolog
  is still open after 1 MiB (padding with comments or whitespace to push the
  DOCTYPE out of the window). Real documents are neither; the reason says
  `encoding that hides its DOCTYPE` or `prolog is longer than the inspection
  window`.

  **What `block` does.** It removes the dangerous flags from the call's options
  argument and lets the parse go on: the application keeps working and the
  entity is simply not expanded (`&xxe;` stays an unresolved reference). The
  event is logged as `action: block` with a reason ending `dangerous flags
  removed, parse continued`. Only the callee sees the rewritten flags; the
  caller's own variable keeps its value. It refuses the call (`false`, or the
  "String could not be parsed as XML" exception from the `SimpleXMLElement`
  constructor) only where stripping cannot help: **libxml older than 2.9.0**
  (CentOS 6 era), which resolves external entities whatever the flags say, so
  on that engine the flag test is skipped and the document alone decides. `detect`
  logs (`action: log`) and changes nothing; `off` disables the rule. The
  document and any path it names are never logged, only the rule, the guarded
  function and the flag names.

  **Bare external DTD.** A DOCTYPE that only references an external DTD is
  never blocked, in any mode. It is logged (`action: log`, "references an
  external DTD") only when a flag really fetches it (`LIBXML_DTDLOAD` or
  `LIBXML_DTDATTR`), so an XHTML or SVG pipeline that sets those flags sees
  `xxe` log lines and keeps working; without them nothing is logged. An
  external entity with no dangerous flag is silent: libxml 2.9+ neither expands
  nor fetches it.
- **`[sinks.xml] external_entities = "deny"`** is a separate libxml-level
  toggle (off by default). When set, Howdah calls ext/libxml's C setter
  (`php_libxml_disable_entity_loader(1)`, found at run time) at every request
  start, which turns off **all** external entity loading for that request —
  including, as a side effect on every PHP version, loading a document *by
  path* through libxml (`DOMDocument::load`, `simplexml_load_file`,
  `XMLReader::open`): read the file yourself and parse the string instead. On a
  PHP whose libxml does not export that setter, Howdah falls back to the
  userland `libxml_disable_entity_loader(true)` with the deprecation silenced
  (on PHP 8 that fallback still sets `error_get_last()` for the request). PHP
  8 already defaults to not substituting external entities (you need
  `LIBXML_NOENT` to opt in), so the toggle mainly matters on 5.x/7.x. It
  writes no event of its own.
- **`tls` is detect-only in this release.** A `block` mode (inherited or
  explicit) is logged, not enforced: the call always proceeds. Only the option
  name (`verifypeer`/`verifyhost`) is logged, never the URL or the handle.

### Not covered (legacy sinks)

- `preg_eval`, `create_function` and `assert` fire nothing on the PHP versions
  where the function or modifier no longer exists (7.0+ for `/e`, 8.0+ for
  `create_function` and string `assert`), nor when `disable_functions` has
  removed the function (PHP 8 deletes the entry); the `Layer-3 legacy sinks`
  phpinfo row says which installed and lists the rest as `absent or disabled`.
- The `callback` sink matches a **string** callback name only; an array
  `[$obj, 'method']`, a closure, a first-class callable or a variable function
  is not matched, and a callback reached through a function Howdah does not
  hook is not seen. A literal global-namespace `call_user_func` /
  `call_user_func_array` on PHP 7.0+ is compiled to its own opcode and is not
  seen (above).
- The `xml` sink needs the XML as a **string** to scan. Not hooked: the
  by-path readers (`simplexml_load_file`, `DOMDocument::load`,
  `XMLReader::open`, `new SimpleXMLElement($path, ..., true)`), whose content
  Howdah cannot see; `[sinks.xml] external_entities = "deny"` closes that
  door. Also not hooked: `simplexml_import_dom`, `xml_parse()` /
  `xml_parser_create` (ext/xml, no libxml flags, no external fetch without a
  user handler) and `DOMDocument::loadHTML` / `loadHTMLFile` (the HTML parser
  does not resolve entities). `LIBXML_XINCLUDE` (XInclude file reads) is not a flag it acts on,
  and a quadratic blow-up (one large entity referenced many times in the body,
  past the prolog) is left to libxml's own limits. Signature inspection can be
  bypassed by an encoding it does not know; the families above are the ones
  libxml2 decodes in practice. An attacker-hosted external DTD that
  `LIBXML_DTDLOAD` fetches is indistinguishable by shape from an XHTML doctype,
  so it is logged (`action: log`) but not stopped: avoid `DTDLOAD` on
  untrusted input, or set `[sinks.xml] external_entities = "deny"`. A
  flag that is not a plain integer, string or boolean (an array, an object) is
  left to PHP. A bare external DTD is never blocked. It does not prove an
  entity was fetched.
- `tls` cannot block in this release and does not see verification disabled
  through a `CURLOPT_*` constant passed as a variable the shim cannot read, nor
  through a stream context.
- `mail` events cannot be excepted with `[[exceptions]]` in this release.

### Known limitations

- **Only a string first argument is inspected.** A guarded call whose first
  argument is not a plain string — an array (e.g. `proc_open` with an array
  command on PHP 7.4+), or any non-string value — fails open and is chained
  unguarded. In practice real injection targets (request values, concatenated
  strings) are always strings and are guarded.
- As with `[inspect]`, this is best-effort hardening, not a substitute for
  fixing the application. The `phar`, `ssrf` and legacy-sink limits are listed
  in their sections above.

## `[behavior]` — Layer 4 after-breach behaviour (log-only by default, plus two enforced file guards)

**The four list-driven facets below log by default; they do not block, and they
do nothing until you set their lists.** They watch what PHP does once something
has gone wrong, such as a webshell dropped in an upload directory. Each is
switched on by its own setting:

| Facet | Setting | Flags |
|---|---|---|
| Execution origin | `deny_exec_dirs` | a PHP file under a listed directory that runs as the requested script, or is `require`d/`include`d (rule `upload_exec`) |
| Expected binaries | `allow_exec_binaries` | `exec`/`system`/`popen`/`proc_open`/`shell_exec`/`passthru` to a program not on the list (rule `unexpected_binary`) |
| Expected egress | `allow_egress_hosts` | an outbound connection to a host not on the list (rule `unexpected_egress`) |
| Executable / handler-config writes | `deny_php_writes` | writing a PHP-executable or handler-config file name (`.php`, `.phtml`, `.pht`, `.php3`-`.php8`, `.phar`, `.inc`, `.htaccess`, `.user.ini`, `web.config`) into a denied directory, or from a script that lives in one (rule `php_write`) |

`behavior.mode` defaults to `detect` (log only) and is **independent of the
global `howdah.mode`**: `howdah.mode = block` does **not** arm Layer 4. As with
Layer 3, set the allowlists before you switch to `block`: with an empty list,
nothing is expected, so under `detect` every matching call is logged and under
`block` it is refused. Layer 4 adds **no new php.ini directives**. Events name
the script that made the call, so a finding points at the webshell even when a
legitimate script `require`d it.

**Three file guards sit beside those facets and carry their own mode** (so they
do not follow the log-only `behavior.mode`):

| Guard | Setting (default) | What it does | Rule |
|---|---|---|---|
| Delete guard | `delete_guard = "block"` | refuses `unlink`, `rmdir` and the source of `rename` for a sensitive file, or `unlink`/`rmdir` through a `..` traversal that lands in a system directory | `file_delete` |
| Upload-write guard | `upload_write = "block"` | refuses `move_uploaded_file` into a PHP-executable or handler-config file name (the durable upload bypass) | `php_write` |
| Secret-read guard | `secret_read = "off"` | with `"detect"` observes, with `"block"` refuses, a read of `.env`, `wp-config.php`, key material and `/etc/passwd`-class files | `secret_read` |

Each takes `"off"`, `"detect"` or `"block"`. The delete and upload-write guards
are **enforced by default**, like `xxe` and the include/open wrapper firewall,
under every mode but `off`: a global `off`, `[behavior] enabled = false` and
`[behavior] mode = "off"` silence all of Layer 4, and `observe = true` turns a
guard `block` into a `proposed` line. They need no list. A blocked call is a
clean neutralization like the Layer 3 sinks: the function returns `false`, the
file is untouched, the script continues, the worker survives.

*Delete guard (`file_delete`).* Deleting `wp-config.php` makes WordPress fall
back to its installer, a takeover; arbitrary-file-delete bugs in plugins are
usually exploited exactly that way. The sensitive set is deliberately tight:
`wp-config.php`; `.env` and `.env.*` (except the templates `.env.example`,
`.sample`, `.dist`, `.template`); private-key material (`id_rsa`, `id_dsa`,
`id_ecdsa`, `id_ed25519`; a `.pem` named *private*/*privkey*/*secret*; a `.key`
named exactly `private`, `privkey`, `server`, `ssl`, `tls` or `oauth-private`;
a bare `.key` is not enough, because Keynote files end in `.key`). The name is tested on
the lexically normalized path, so `uploads/../wp-config.php` is caught. A `..`
traversal that resolves into `/etc`, `/root`, `/proc`, `/sys`, `/boot`, `/bin`,
`/sbin`, `/usr` or `/lib*` is refused too. For `rename` only the live files
`wp-config.php` and `.env` count as a source (moving them away is a delete;
`.env.production` -> `.env` is an ordinary deploy step). Cache, temp, session, log,
thumbnail and upload deletes, `.htaccess`, `.maintenance`, `wp-config-sample.php`
and `cacert.pem` are never touched. Migration and restore tools (Duplicator's
`installer.php`, restore plugins) legitimately move `wp-config.php`: add an
`[[exceptions]]` entry with `rule = "behavior.file_delete"` and the tool's
`script`.

*Upload-write guard (`php_write`, upload tier).* An uploaded `.htaccess` or
`.user.ini` re-enables PHP for the next `.jpg`, so it outlives any file-extension
filter on the upload itself. `move_uploaded_file` is refused when the destination
name ends in `.php`, `.php3`-`.php8`, `.phtml`, `.pht`, `.phar` or is
`.htaccess`, `.user.ini` or `web.config` (case-insensitive). Nothing legitimate
moves an HTTP upload to such a name; admin file managers that do (elFinder-class
plugins) need an `[[exceptions]]` entry with `rule = "behavior.php_write"`. The
other write sinks are **not** blocked by default, because applications legitimately
write `.php` (Blade/Twig/Smarty caches, WordPress updates) and `.htaccess`
(WordPress permalinks, WooCommerce download protection). They are covered by the
scoped `deny_php_writes` tier below. `.inc` and double extensions
(`shell.php.jpg`, which Apache's `AddHandler` runs) are not part of the upload
tier.

*Secret-read guard (`secret_read`).* Off by default because applications read
their own `.env` and `wp-config.php` constantly. Armed, it covers
`file_get_contents`, `readfile`, `file` and `fopen` in read mode: the delete
guard's sensitive set plus `.htpasswd`, `/etc/passwd`/`shadow`/`gshadow`/`sudoers`,
anything under a `.ssh` directory, `.pgpass`/`.my.cnf`/`.netrc`, and a `..`
traversal into `/etc`, `/root`, `/proc`, `/sys` or `/var/log`. Start with
`"detect"`, read the log, add `[[exceptions]]` for the scripts that own those files
(your framework's config loader), and only then consider `"block"`.

**What is logged.** Only the rule, a path *category* (`wp-config`, `dotenv`,
`private-key`, `htpasswd`, `system-account`, `ssh`, `credentials`, `system
directory`; for writes `php`, `phtml`, `phar`, `htaccess`, `user-ini`,
`web-config`), the guarded function and the calling script as `file:line`, never
the target path, its name or any content. For example:
`unlink deletes a wp-config file at /var/www/html/wp-content/plugins/x/x.php:42`.

```toml
[behavior]
enabled = true              # master on/off for Layer 4; false -> off regardless of mode
mode = "detect"             # "off" | "detect" | "block". INDEPENDENT of the global howdah.mode.
observe = false             # true -> log would-be findings as `proposed`; never blocks

deny_exec_dirs = []         # e.g. ["/var/www/uploads", "/var/www/storage", "/tmp"]
allow_exec_binaries = []    # e.g. ["/usr/bin/gs", "convert"]  (empty = none expected)
allow_egress_hosts = []     # e.g. ["api.stripe.com"]          (empty under detect = log all egress)
deny_php_writes = false     # true -> flag writing a PHP-executable or handler-config name
                            # (.php .phtml .pht .php3-8 .phar .inc .htaccess .user.ini web.config)
                            # via file_put_contents / fopen('w') / copy / rename / move_uploaded_file
                            # into a denied directory or from a script under one (origin-scoped;
                            # NOT any such write)

# The file guards: their own modes, "off" | "detect" | "block".
delete_guard = "block"      # enforced by default: wp-config.php, .env, key files, '..' into /etc...
upload_write = "block"      # enforced by default: move_uploaded_file to .php/.phtml/.phar/.htaccess/...
secret_read  = "off"        # opt-in: "detect" observes reads of .env / wp-config.php / keys
```

**Observe mode.** `observe = true` logs the binary that was run, the host
contacted, or the directory PHP ran from, as a `proposed` line. Use it to
build `allow_exec_binaries` and `allow_egress_hosts` from real traffic. It
never blocks and never edits your config; review every proposal yourself.

### Verification

The Layer 4 lab script (27 checks) passed on PHP 5.4, 5.6, 7.4, 8.3, 8.4 and
8.5. Other minors are not independently verified. The checks cover each facet in
`detect` and `block`, that a framework-style view write and a plain read of a
`.php` file are not flagged, that the default and empty configs are inert, and
that observe proposes without blocking.

The file guards have their own lab, `lab/integration/file_guard.sh`, run on PHP
5.4, 5.6, 7.0, 7.4, 8.0, 8.1, 8.3 and 8.5: wp-config.php, `.env`, key-file and
`..`-traversal deletes and renames refused (target survives, script continues,
origin `file:line` logged, name never logged); real multipart uploads to twelve
dangerous names refused with no configuration; the scoped tier across
`file_put_contents`, `fopen`, `copy` and `rename`; secret reads logged but not
blocked under `detect`; and a benign corpus (cache, tmp, session, upload and
thumbnail deletes, `.jpg`/`.txt`/`.json`/`.log`/`.zip`/`.pdf` uploads and writes, reads of
the app's own config) producing zero blocks.

### Known limitations

- **Howdah only sees what PHP itself does.** A process PHP launches and then
  detaches, a reverse shell that forks away, or anything dropped by a non-PHP
  route is invisible to Layer 4. It covers the webshell/dropper phase while PHP
  is the actor.
- **`deny_exec_dirs`: the requested-script case does not depend on opcache; the
  included-file case is first-compile and best-effort.** A direct request to a
  script under a denied directory is checked on every request. A `require` of
  such a file rides the compile hook (PHP 7.0+: operand string only), so a file
  served from a warm opcache may not be re-checked. A `require` with a relative
  path is not checked at include time on any version. The binary, egress and
  write facets fire on every call.
- **Allowlists are best-effort and can be bypassed.** Binary matching is by
  program path or basename; a shell builtin, a path variant or an interpreter
  can evade it. Egress matching shares the Layer 3 `ssrf` limits (DNS rebinding,
  redirects, `curl_multi_*`, a non-string URL).
- **`deny_php_writes` is origin-scoped and can still flag legitimate writes.**
  An application that compiles templates or caches PHP into a denied directory
  will be flagged, and one that rewrites `.htaccess` there (WooCommerce
  protecting a downloads directory) too. Scope `deny_exec_dirs` before you ever
  use `block`. Detection is by file extension and the three handler-config
  names, applied to the destination as written (a relative path outside a denied
  directory is only caught through the calling script), so a write to a harmless
  name that is renamed later is caught only if the rename target is dangerous.
  It was widened from `.php`/`.php5`/`.phtml`/`.phar` to the full set in 1.7;
  an existing `deny_php_writes = true` now also flags `.pht`, `.php3`/`4`/`7`/`8`,
  `.inc`, `.htaccess`, `.user.ini` and `web.config` under `deny_exec_dirs`, and
  also sees `copy()` targets.
- **The file guards classify the path argument as written, lexically.** They
  never touch the filesystem: a symlink named innocently that points at
  `wp-config.php` is not seen, nor is a deletion through an open handle, a
  Stringable passed to `unlink`, `SplFileObject`, `ZipArchive::extractTo`,
  `fwrite` on an already-open handle, or a `rename` whose destination is the
  sensitive name. `highlight_file`, `show_source`, `parse_ini_file` and
  `SplFileObject` are not hooked by the secret-read guard (`readfile`,
  `file_get_contents`, `file` and `fopen` are). The delete guard does not treat
  `.htaccess` as sensitive (cache plugins delete their own), and the
  `..`-traversal rule only fires when the path lands in a system directory,
  because Howdah does not know your document root and apps legitimately delete
  outside it (`/tmp`, `/var/cache`). Verified on PHP 5.4, 5.6, 7.0, 7.4, 8.0,
  8.1, 8.3 and 8.5; the same function-table swaps as the Layer 3 sinks, so other
  minors are expected to work but are not independently verified.
- **Observe only proposes.** On a box that is already breached, the observed
  set may include attacker behaviour; do not accept it unreviewed.
- Setting `deny_exec_dirs` arms the include/eval hook (its `require`d-file
  check runs there) and makes the default `[sinks] hook = "auto"` choose the
  opcode handler, which turns OPcache JIT off on PHP 8; `hook = "compile"`
  keeps it on at the cost of the warm-opcache caveat. See `hook` under
  `[sinks]`.

## `[log]` — event log destination and hook

Every event is one JSON line (schema 2: the fields are listed below and
specified in [log-schema.md](log-schema.md)). `[log]` decides where the lines
go and can run a program for each one. With no `[log]` table, Howdah behaves
as 1.0 to 1.4.0 did: lines go to the `howdah.log` file, or to stderr when it is
unset.

```toml
[log]
destination = "file"            # "file" (default) | "syslog" | "stderr"
path = "/var/log/howdah/events.log"   # for "file"; the howdah.log ini value wins
syslog_facility = "local0"      # for "syslog"
syslog_ident = "howdah"         # for "syslog": the tag, 1-32 characters
# exec = "/usr/local/sbin/howdah-alert"   # off unless set; see below
# exec_rate_limit = 10          # hook starts per second per PHP process, 1-100
```

| key | default | effect |
|---|---|---|
| `destination` | `"file"` | `file`: append to the log file. `syslog`: send to the local syslog socket. `stderr`: write to the process's stderr. |
| `path` | none | Log file for `destination = "file"` when the `howdah.log` ini setting is empty. |
| `syslog_facility` | `"local0"` | `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0` to `local7`. |
| `syslog_ident` | `"howdah"` | The syslog tag (journald's `SYSLOG_IDENTIFIER`). Printable ASCII with no spaces, `:`, `[` or `]`. |
| `exec` | none | Absolute path of a program to run once per event, with the line on stdin. |
| `exec_rate_limit` | `10` | Most hook starts in any one second, per PHP process. |

No php.ini directive was added: these keys live only in the TOML file. A
config file that does not parse is ignored as a whole (see
`on_invalid_config` above), `[log]` included, so the destination falls back
to `howdah.log` or stderr and no hook runs.

**Precedence.** `destination` decides where lines go. For `file`, the path is
the `howdah.log` ini value if it is set, else `[log] path`, else stderr.
`syslog` and `stderr` ignore both paths, including `howdah.log`.
`php --ri howdah` shows the result:

```
Log destination => /var/log/howdah/events.log (from [log] path)
Log hook ([log] exec) => /usr/local/sbin/howdah-alert (at most 10 per second)
Log schema => 2
```

### The event line (schema 2)

| field | type | content |
|---|---|---|
| `schema` | integer | `2`. Lines from 1.0 to 1.4.0 have no `schema` key. |
| `version` | string | Version of the extension that wrote the line. |
| `ts` | string | UTC Unix epoch milliseconds, as a decimal string. |
| `request_id` | string | Lowercase hex; also printed in the block response. |
| `layer` | integer | `1` request-shape limits, `2` input inspection, `3` sinks, `4` after-breach behaviour. |
| `rule` | string | Rule name (the config spelling). |
| `action` | string | `block` or `log`. |
| `client_ip` | string | `REMOTE_ADDR`; empty when the SAPI has none (CLI, `php -S`). |
| `method` | string | HTTP method. |
| `uri` | string | Request path, query string removed. |
| `reason` | string | Human-readable detail; not part of the contract. |

The eight fields from 1.x keep their names and types; `schema`, `version`
and `layer` are new. The full contract, the rule-to-layer table and the
compatibility rules are in [log-schema.md](log-schema.md);
[howdah-event.schema.json](howdah-event.schema.json) is the JSON Schema.

### File destination

- **One write per line.** The line and its newline go out in one `write()` on
  a descriptor opened with `O_APPEND`, so lines from concurrent workers do not
  interleave on a local filesystem. (NFS does not make `O_APPEND` atomic.)
- **Opened per event.** Howdah opens the file for each line and closes it
  again; it holds no descriptor. Rotation therefore needs no signal or
  reload, and Howdah does not handle `SIGHUP`. Rename-based rotation
  (logrotate's default, with `create`) works: the next event creates a new
  file. `copytruncate` also works.

  ```
  # /etc/logrotate.d/howdah
  /var/log/howdah/events.log {
      daily
      rotate 90
      compress
      delaycompress
      missingok
      notifempty
      create 0640 www-data adm
  }
  ```

- **Permissions.** The PHP worker user writes the file. If the file does not
  exist, the worker creates it, owned by that user, with mode 0640 minus the
  process umask (so not world-readable); an existing file keeps its mode. To
  choose the owner, group and mode, create it first:

  ```sh
  sudo install -d -m 0750 -o www-data -g adm /var/log/howdah
  sudo install -m 0640 -o www-data -g adm /dev/null /var/log/howdah/events.log
  ```

  The PHP user can rewrite its own log. If you need tamper evidence, ship the
  lines off the host ([integrations](integrations/README.md)).
- **Failure.** If the file cannot be opened or written, Howdah prints
  `howdah: ERROR: cannot write the event log '<path>': <error> (continuing to
  serve)` and writes the line to stderr as `howdah-event {...}`. Apache sends
  stderr to its error log. **php-fpm discards worker stderr unless the pool
  sets `catch_workers_output = yes`**, so on FPM a log path the workers cannot
  write loses events. The `syslog` destination avoids file permissions
  altogether.

### Syslog destination

- Howdah sends each line to `/dev/log`, the socket journald and rsyslog read,
  framed the way glibc's `syslog()` frames it:
  `<PRI>Oct 24 18:02:54 howdah[1429]: {"action":"block",...}`. The message
  is exactly the JSON line. Severity is `warning` for `block` and `notice` for
  `log`. With journald, `journalctl -t howdah -o cat` prints one JSON line
  per event.
- Howdah does not call `openlog(3)`. openlog state is per process and PHP
  owns it: `error_log = syslog` and PHP's own `openlog()` set it, and PHP
  (8.3, for one) calls `closelog()` at the end of every request, which resets
  the tag.
  Sharing it would label PHP's messages `howdah`, or Howdah's `php-fpm`.
- The socket is a non-blocking datagram socket, opened in each worker on
  first use (never in the parent process); it reconnects once if the daemon
  restarted. The send never blocks: if `/dev/log` is missing (a container or
  chroot without a syslog daemon), the daemon's queue is full, or the send
  fails, Howdah prints a note and writes the line to stderr. In a container,
  mount the host's socket: `-v /dev/log:/dev/log`.
- Datagram only. glibc falls back to a stream socket when `/dev/log` is one
  (some syslog-ng configurations); Howdah does not, because a stream connect
  or send can block the request. Against a stream socket every line goes to
  stderr with a note. journald and rsyslog use a datagram socket.
- rsyslog truncates messages longer than its `$MaxMessageSize` (8 KiB by
  default). Event lines are rarely over 1 KiB; the request path is the field
  that can make one longer.
- Tested by `lab/integration/log_contract.sh` against a stand-in daemon on
  `/dev/log`, on PHP 7.4 and 8.3, under the built-in server, php-fpm and
  Apache mod_php (prefork). A run against a real journald (PHP 7.4 and 8.3,
  the host's socket mounted into the container) was done by hand; the lab
  images have no journald, so it is not part of the script.

### `exec`: a program per event

Off unless `exec` is set. For every event line, after the line is written,
Howdah starts the program and does not wait for it:

- **stdin:** the JSON line and a newline, then end of file.
- **argv:** the program path only. No arguments.
- **environment:** only `HOWDAH_RULE` and `HOWDAH_ACTION` (from the line;
  always `[a-z0-9_]`), and `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`.
  Nothing from the PHP process or the request is inherited.
- **stdout:** `/dev/null` (under CGI, PHP's stdout is the HTTP response).
  **stderr:** inherited, so the program's errors reach the web server or FPM
  error log.
- **Descriptors:** stdin, stdout and stderr, plus a descriptor for the
  program itself (see below). Open sockets, database connections and files of
  the PHP worker are not inherited.
- It runs in its own session (`setsid`), in `/`, as the PHP worker user.
- It is not a child of the PHP worker. Howdah forks twice: the middle process
  exits at once and Howdah reaps it, so the hook is re-parented to init (or
  the nearest subreaper, such as php-fpm's master when that runs as PID 1 in
  a container) and is never left as a zombie in a long-lived worker. A
  userland `pcntl` `SIGCHLD` handler in the application can see that short
  middle process exit; if it reaps it first, nothing breaks.

**Checks, on every event.** Before each start Howdah opens the program
without following a symlink and checks the open file: it must be a regular,
executable file, not group- or world-writable, owned by root or by the user
PHP runs as, and its directory must not be group- or world-writable (whoever
can write the directory can swap the file). Then Howdah runs that same open
file through `/proc/self/fd/N`, so the file that passed the checks is the
file that runs, even if the path is replaced in between. If a check fails the
hook is skipped and a note goes to stderr (again only when the reason
changes); a fix takes effect at the next event. Two consequences: `/proc`
must be mounted, and a script sees `$0` as `/proc/self/fd/N`, so use absolute
paths inside it rather than `dirname "$0"`. The program path must name the
real file, not a symlink.

**Limits,** per PHP process (each FPM worker or Apache child counts on its
own): at most `exec_rate_limit` starts in any one-second window (default
10). Over it the hook is skipped for that event (the event is still logged)
and one note goes to stderr. The checks above count toward the same limit, so
they run at most that often. A line that does not fit in the pipe buffer
(64 KiB by default) is not passed to the hook.

An example that forwards blocks to a chat webhook, passing the line as data
and never through a shell:

```sh
#!/bin/sh
# /usr/local/sbin/howdah-alert (root:root, mode 0755)
[ "$HOWDAH_ACTION" = block ] || exit 0
exec curl -fsS -m 5 -H 'Content-Type: application/json' --data-binary @- https://hooks.example.com/howdah
```

**Security caveats.**

- The program runs as the PHP worker user, on events that attackers trigger
  at will. The rate limit bounds how often; keep the program quick.
- The line contains attacker-influenced text (`uri`, and names in `reason`).
  Treat stdin as untrusted input: do not `eval` it or paste fields into a
  shell command.
- Keep the program and its directory owned by root and not writable by the
  PHP user. Howdah refuses a program that is group- or world-writable or in
  such a directory, but it accepts one owned by the PHP user itself (for CLI
  use), and a compromised application could rewrite that one.
- Each start costs the request one `fork` and `exec` of the PHP worker (the
  request waits for the `exec`, not for the program). The cost grows with the
  worker's memory size; it has not been benchmarked.

**SAPIs.** Starting a process from inside PHP is safe on the SAPIs Howdah
supports, all of them single-threaded (NTS): php-fpm, Apache mod_php with the
prefork MPM, CGI and the CLI. Between `fork` and `exec` the children only
call `close_range`/`fcntl`, `fork`, `_exit` and `setsid`. Howdah does not
support threaded (ZTS) builds such as mod_php under the worker or event MPM
or FrankenPHP, so neither does the hook. Tested by
`lab/integration/log_contract.sh` on PHP 7.4 and 8.3, under the built-in
server, php-fpm and Apache mod_php prefork. Not tested: SELinux-enforcing
hosts, where the policy may stop the web server domain from executing the
program until it is labelled for that.

### Shipping events to a SIEM

[integrations/](integrations/README.md) has a Wazuh decoder and rules and a
Promtail pipeline for Loki, tested against the real tools by
`lab/integration/siem_snippets.sh`.

## `[[exceptions]]` — scoped exceptions

An exception turns **one rule off for one scope**: the executing script, a
request parameter, a URI prefix, a client network, or a combination. Every
entry needs a `reason`; it is the decision record. The method, from a log
line to an entry, is in [docs/exceptions.md](exceptions.md); the shipped
starting points for WordPress, Drupal 7, Magento 1 and 2, Joomla and
PrestaShop 1.6 are in [`profiles/`](../profiles/README.md).

```toml
exceptions_log = false   # optional, top-level. true -> log each match as action "excepted"

[[exceptions]]
rule   = "sinks.command_exec"            # required: rule id | layer | layer.rule
script = "/var/www/html/cron.php"        # absolute path or glob (* within a segment, ** across, ? one char)
reason = "DECISION 2026-10-24 jdoe: cron.php shells out to the mailer with per-run temp paths."

[[exceptions]]
rule       = "inspect.sql_injection"
param      = "content"                   # request variable name, exact; or param_prefix = "jform["
uri_prefix = "/wp-admin/"                # request path prefix (query string removed), raw bytes
reason     = "Editors paste SQL into posts. Layer 2 is detect-only here."

[[exceptions]]
rule        = "max_request_headers"
client_cidr = "10.0.0.0/8"               # IPv4/IPv6 CIDR or a bare address; REMOTE_ADDR as the SAPI sees it
reason      = "The internal SSO proxy adds ~40 headers."

[[exceptions]]
rule          = "behavior.php_write"
script_sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"   # sha256sum of the file
reason        = "Vendor template compiler, pinned by content because the docroot differs per tenant."
```

Rules:

- **Facets are ANDed.** Every facet an entry sets must match; unset facets
  match anything. At least one facet is required, and a facet that matches
  every request (`script = "/**"`, `uri_prefix = "/"`, a `/0` CIDR) is
  refused. The first matching entry wins.
- **`uri_prefix` is never satisfied by a path with a `.`/`..` segment, `//`,
  `\` or `%`** (fail toward protection: nginx passes `$request_uri`
  unnormalized, and `/wp-admin/../index.php` executes `/index.php`).
- **`param`/`param_prefix` may not name or prefix `REQUEST_URI`/`PATH_INFO`**,
  the Layer 2 path pseudo-parameters.
- **`rule`** is a rule id as spelled in the log (`sql_injection`,
  `command_exec`, `php_write`, `max_request_headers`, ...), a layer name
  (`limits`, `inspect`, `sinks`, `behavior`; `inspect.*` is the same as
  `inspect`), or `layer.rule`. `*` on its own is refused.
- **Critical rules take no exception**: `max_parts`, `max_files`,
  `max_part_headers`, `max_part_header_bytes`, `max_field_name_len`,
  `max_filename_len`, `parse_memory_budget`, `max_input_vars`,
  `max_input_nesting_depth`. `rule = "limits"` covers only the Standard
  Layer 1 rules. An entry naming a Critical rule makes the file invalid.
- **Facets per layer.** Layer 1 Standard rules: `uri_prefix`, `client_cidr`
  only. Layer 2: `param`, `param_prefix`, `uri_prefix`, `client_cidr`; `script`
  is refused because Layer 2 values are inspected while PHP registers request
  variables, before any script runs. Layers 3 and 4: `script`,
  `script_sha256`, `uri_prefix`, `client_cidr`; `param` is refused. `param`
  and `param_prefix` are mutually exclusive.
- **`script`** is compared with the path PHP reports for the executing file
  (`__FILE__`): the file that contains the call (a framework's filesystem
  class, a `require`d file), not the page the request hit; absolute and
  realpath'd by PHP (`require`d files through `zend_resolve_path`, the main
  script through the stream layer's `opened_path`), so symlinks are followed;
  matched byte-for-byte. The exception: Layer 4's `upload_exec` check of the
  main script sees `SCRIPT_FILENAME` as the SAPI passed it. Code inside
  `eval()` reports as `<file>(<line>) : eval()'d code`, which a `**` glob on
  the directory also covers; a literal path or hash does not. Patterns must
  start with `/`; paths over 4096 bytes never match.
- **Effect.** A match sets the rule to `off` for that event, decided after the
  rule found something and before the mode applies. It never arms anything
  and never widens an allowlist: **an exception on `sinks.command_exec` means
  that sink is not checked for that script.**
- **Validation errors name the entry and key** (`exceptions[1].reason:
  required ...`). An invalid entry makes the whole file invalid and takes the
  `on_invalid_config` path: a startup line in the SAPI error log, an INVALID
  row in `php --ri howdah`, fallback mode.
- **Observability.** `php --ri howdah` shows `Exceptions ([[exceptions]]) => N
  configured, M rejected`; the SAPI error log gets one summary line per
  process when N > 0; `exceptions_log = true` writes each match as an event
  with `action: "excepted"` (schema 2 adds that one action value; see
  [log-schema.md](log-schema.md)). Layers 1 and 2 write at most one excepted
  line per request, Layers 3 and 4 one per excepted call.

### Verification

`lab/integration/exceptions.sh` (21 checks) passed on PHP 5.6, 7.4 and 8.3:
a sink exception by exact script, glob, SHA-256, through a symlinked CLI
main script and a symlinked `require` (both report the realpath); that an
exception on one sink leaves `eval` from the same script logged; that
`/wp-admin/../index.php` and its `/./`, `//` and `%2e%2e` spellings never
satisfy `uri_prefix = "/wp-admin/"`; a `param` exception silencing one Layer 2 rule for one parameter
while the same payload in another parameter and another rule in the same
parameter are still logged; `client_cidr` on Layer 1 Standard rules under
php-fpm (header count and input-key rules); `exceptions_log`; the `php --ri`
counts; a Critical-rule entry refused at startup with the loud error, the
INVALID row and the `on_invalid_config` fallback; and a `behavior.php_write`
exception by script.

### Known limitations

- `client_cidr` is `REMOTE_ADDR`: behind a proxy or CDN it is the proxy's
  address, and `X-Forwarded-For` is not read. The client must be known when
  the rule fires: php-fpm and Apache provide it before any variable is parsed;
  the CLI built-in server (`php -S`) does not, so under `php -S` a
  `client_cidr` exception does not match Layer 1 or Layer 2 events.
- `uri_prefix` is a raw byte prefix (not decoded, not case-folded). Prefer
  `script` where the layer offers it.
- `script` follows symlinks because PHP does; pin the target, not the link
  (copy `__FILE__`).
- The hash facet reads the file once per path per process (re-read when
  device, inode, size, mtime or ctime changes; 256-path cache; files over
  4 MiB and unreadable files never match).
- Layer 2 has no `script` facet (above). On a front-controller application
  every path may be `/index.php`.
- An exception is a recorded hole with the same threat model as setting the
  rule to `off`, narrowed to its scope.

## Enforcement timing (honest caveat)

Howdah refuses a request by sending the 403/413 (status, headers and the
"Howdah blocked" body with the request id) and keeping the script from
running. It never terminates the PHP worker. A refusal decided while PHP is
still starting the request is delivered at the end of Howdah's RINIT, the
first point where a response is legal. Releases up to 1.4.0 unwound out of
request startup instead, which made php-fpm exit the worker with code 70 and
drop the body; the mechanism and the per-SAPI evidence are in
`docs/superpowers/specs/2026-10-24-howdah-refusal-path-design.md` and
`lab/integration/refusal.sh`.

**Refused before the script runs.** php-fpm, Apache mod_php, php-cgi and the
CLI server all build `$_GET`, `$_POST` and `$_COOKIE` during request startup,
before any extension's RINIT, so these refusals happen before the
application's first line:

- the multipart limits: the body is parsed at startup, over-limit parts are
  never allocated, and the refusal follows at RINIT;
- the input-shape limits (`max_input_vars`, `max_input_nesting_depth`,
  `max_input_key_bytes`) on GET, POST and cookie variables; the offending
  variables are also dropped, which bounds the symbol table;
- an armed Layer 2 class (`[inspect] mode = "block"` or a `rule_modes` entry)
  on GET, POST and cookie values, and on the request path (`REQUEST_URI`,
  `PATH_INFO`): with Layer 2 armed, Howdah builds `$_SERVER` at RINIT itself,
  so the `auto_globals_jit` deferral no longer hides the path from the scan.
  Header values are not a Layer 2 input; what the forced `$_SERVER` buys for
  headers is that the Layer 1 count and size limits (next list) move in front
  of the script. The cost is one `$_SERVER` build per request on applications
  that never read it (the same work every framework triggers on its first
  line). The default, log-only install does not pay it;
- the Layer 2 `cgi_arg_injection` rule (on by default): it reads the SAPI's raw
  query string, not `$_SERVER`, so it needs no forced `$_SERVER` build and is
  refused before the script on every install, armed Layer 2 or not;
- the Layer 4 `deny_exec_dirs` check on the requested script.

For cron and other command-line users: a CLI main script refused by
`deny_exec_dirs` prints the "Howdah blocked" notice with the request id on
stdout, does not run, and **exits 0** (PHP treats "nothing compiled" as a
normal end; lab-measured on 5.6, 7.4 and 8.3). A job that checks the exit
status will not see the refusal; the event line in the log is the signal.

**Post-hoc refuse.** The response is set at request shutdown, after the
script ran and may have produced output, so the HTTP status can already be
committed; the log line is the reliable signal:

- the request-header limits (`max_request_headers`,
  `max_request_header_bytes`) when `$_SERVER` is built lazily by the script
  (`auto_globals_jit=On`, the default, and Layer 2 not armed). Headers are
  counted exactly once the variables exist; an application that never reads
  `$_SERVER` leaves the limit unexercised.

**Not a refusal.** An armed Layer 3 sink makes the call return `false` and the
script continues. Only the variables PHP itself registers are counted and
scanned: a raw body the application reads through `php://input` (JSON or XML
APIs) and variables past PHP's own `max_input_vars` never reach Howdah. A
superglobal PHP never builds (`variables_order` without `G`, `P` or `C`;
`enable_post_data_reading = Off` for POST) has nothing to inspect before or
after the script. See `docs/coverage.md` for the per-SAPI lab status.
