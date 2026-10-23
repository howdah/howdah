# Configuration

Howdah is configured by a TOML file whose path is given to PHP as an ini
setting. Two more ini settings pick the global mode and the log destination:

```ini
; php.ini (or a conf.d/*.ini, or -d on the CLI)
extension=howdah.so
howdah.config=/etc/howdah/howdah.toml   ; path to the TOML below (optional)
howdah.mode=block                       ; block | detect | off (TOML can override)
howdah.log=/var/log/howdah.log          ; where JSON event lines are written
```

If `howdah.config` is unset, or the file is missing or malformed, Howdah falls
back to its **safe defaults** (block mode, the limits below) and keeps serving —
a bad config never takes PHP down.

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
path = "/var/log/howdah.log"         # same as the howdah.log ini; TOML wins if both set

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

## `[rules]` — per-rule mode and severity

Each `[rules]` key is a **rule name**; the value is `block`, `detect`, or `off`.
Rule names: `max_parts`, `max_files`, `max_part_headers`, `max_part_header_bytes`,
`max_field_name_len`, `max_filename_len`, `parse_memory_budget`,
`malformed_multipart`, `upload_progress_abuse`, `self_test`, `max_input_vars`,
`max_input_nesting_depth`, `max_input_key_bytes`, `max_request_headers`,
`max_request_header_bytes`. (A few byte-limit **rule**
names end `_len` where the matching `[limits]` **directive** ends `_bytes`.)

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

**These rules only LOG; they do not block any request.** Layer 2 looks at
decoded request values for SQL-injection, path-traversal and
command-injection shapes and writes an event when it sees one. A global
`howdah.mode = block` does **not** arm them. To block, set `inspect.mode` (or
one class via `[inspect.rule_modes]`) to `block` explicitly.

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

[inspect.limits]
max_value_bytes = 16384   # scan at most this many bytes of one value
max_total_bytes = 2097152 # per-request aggregate scan budget
max_values = 2000         # per-request value count budget

[inspect.rule_modes]      # optional per-class mode override; keys are the rule names
# sql_injection = "block" # example only: opt ONE class into blocking (default is log-only). Also: path_traversal, command_injection
```

The rule names are `sql_injection`, `path_traversal` and `command_injection`.
A `[inspect.rule_modes]` entry overrides `inspect.mode` for that class only.
The `[inspect.limits]` budgets bound the scanning work per value and per
request; values past a budget are not scanned.

## `[sinks]` — Layer 3 sink hardening (log-only by default)

**Sinks log by default; they do not block.** Layer 3 watches dangerous PHP
functions ("sinks") and writes an event when one is called with something your
allowlist does not cover. In 1.2 it **actively guards two sinks**:

- `command_exec` — `system`, `exec`, `shell_exec`, `passthru`, `popen` and
  `proc_open`.
- `unserialize` — object unserialization.

`sinks.mode` defaults to `detect` (log only) and is **independent of the global
`howdah.mode`**: a global `howdah.mode = block` does **not** arm any sink. To
block, set a sink's mode to `block` explicitly, and **set its allowlist first**
— with an empty allowlist every call is "not allowlisted". Only `command_exec`
and `unserialize` can block in 1.2.

**The sink argument is never logged.** An event records only the sink and the
function name (plus the class name for `unserialize`) — never the command line
or the serialized payload.

Like `[inspect]`, `[sinks]` lives in the TOML file named by the `howdah.config`
php.ini setting. It adds **no new php.ini directives**.

```toml
[sinks]
enabled = true            # master on/off for Layer 3
mode = "detect"           # detect = log only (default); block; off. INDEPENDENT of the global howdah.mode.

[sinks.command_exec]      # system/exec/shell_exec/passthru/popen/proc_open
# mode = "block"          # optional per-sink override; unset inherits sinks.mode. Set allow FIRST.
allow = []                # commands that are fine; anything else is logged (or blocked in block mode)

[sinks.unserialize]       # OFF by default: object unserialize is high-volume
# mode = "detect"         # opt in (log only). "block" refuses non-allowlisted classes.
allow_classes = []        # class names that may be unserialized

# Reserved -- NOT ACTIVE in 1.2. Nothing is hooked, so setting these has NO effect.
# The keys exist so a config written now keeps working when they arrive in a later release.
[sinks.include]           # reserved: arriving in a later release
[sinks.eval]              # reserved: arriving in a later release
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

### Reserved: `include` and `eval` (not active in 1.2)

`[sinks.include]` and `[sinks.eval]` are **reserved and not active in 1.2**.
Their config keys are accepted so your file stays forward-compatible, but no
hook is installed, so they log nothing and block nothing. They arrive in a later
release; do not rely on them as guards today.

### Known limitations

- `proc_open` with an **array** command (PHP 7.4+) is **not inspected** — it
  fails open. Only the string form is guarded.
- As with `[inspect]`, this is best-effort hardening, not a substitute for
  fixing the application. phar:// and SSRF coverage are on the roadmap.

## Enforcement timing (honest caveat)

The multipart limits refuse the request *while the body is parsed*, before PHP
allocates per-part memory, and emit a 403/413 before the script runs.

The **input-shape and request-header limits** are enforced on the request-variable
and `$_SERVER` stream: Howdah **drops** offending variables (bounding the symbol
table — the real DoS mitigation) and writes the event, but the 403 response is
**best-effort** and may be emitted at request shutdown, after the script has
already produced output, on SAPIs that populate superglobals lazily
(`auto_globals_jit=On`). Request-header counting in particular depends on the
application (or PHP) materializing `$_SERVER`. Treat the var-drop + log as the
guarantee and the 403 as best-effort. See `docs/coverage.md` for the per-SAPI
lab status.
