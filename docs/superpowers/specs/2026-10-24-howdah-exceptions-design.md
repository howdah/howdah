# Howdah scoped `[[exceptions]]` — Design

**Date:** 2026-10-24
**Status:** design, approved to build (gap analysis item #2, "the keystone operability gap")
**Target release:** the next minor after 1.4.0 (version number is the owner's call; the crate stays 1.4.0 in this PR)
**Builds on:** the per-rule `[rules]` modes (1.0), the Layer 2 class toggles
(1.1), the Layer 3 allowlists (1.2/1.3), and the Layer 4 execution-origin
primitive (`zend_get_executed_filename()`, 1.4, `crates/howdah-sys/sink_hook.c`
and `ssrf_hook.c`). Reads: the gap analysis report §"Operability is the widest
gap", `php_extension_competitors.md` (Snuffleupagus `.filename()`, `.hash()`,
`.cidr()`, `.param()`; Imunify's "script path × rule" ignore list),
`general_waf_table_stakes.md` (CRS's four exclusion primitives and shipped
application exclusion packs), and the decision-record section of
`docs/compliance.md`.

## 1. Intent and why

Today the only way to make Howdah quiet about one legitimate behaviour is to
turn the whole rule off: a `[rules]` mode, a Layer 2 class toggle, or a sink
allowlist entry. Nothing is scoped. A WordPress editor saving a post that
contains `' OR 1=1 --` in its body, Magento's cron spawning `php`, Drupal 7's
`update.php` including every module's `.install` file, PrestaShop compiling
Smarty templates to `.php`: each one is a per-script or per-parameter fact, and
each one today forces an operator to choose between noise and `off` for the
entire site. On a shared host, where one PHP pool runs dozens of applications
and the config is process-global, that choice is made for every tenant at once.

Every comparator has scoped exceptions, and the CRS false-positive discipline
is built on nothing else: remove a rule for a target, conditioned on a URI,
and ship starting packs per application. Howdah's version keys on the one
thing an in-process extension knows and a network WAF cannot: **which PHP file
is running**. Layer 4 already captures it at every sink; this design reuses
that capture and adds nothing new at the hook level.

The second reason is the audit trail. PCI DSS reviewers look for "documented
rationales for rule removals". `docs/compliance.md` §5 asks operators to keep
a decision record by hand, in comments. An exception with a mandatory `reason`
makes the record part of the config itself: `grep -n reason howdah.toml` is
the register, and the version history of the file is its change log.

## 2. Goals, non-goals, anti-goals

**Goals**

- Downgrade one rule (or one sink, one class, one layer) to `off` for one
  script, one request parameter, one URI prefix, one client network, or a
  combination, without touching the rule for anything else.
- Make every exception carry a written reason, validated as mandatory.
- Reuse Layer 4's execution-origin capture: the `script` facet matches the same
  path Layer 4 attributes a finding to.
- Keep the default identical: no `[[exceptions]]` means exactly today's
  behaviour, byte for byte in the log.
- Ship starting points for six common legacy applications as documented
  snippets an operator copies, reads and edits.

**Non-goals**

- Not per-vhost or per-pool configuration. Config stays process-global; this
  is the per-script scoping mechanism that makes a process-global config
  usable on a shared box. No `include` mechanism for config files in 1.x.
- Not a learning mode. Exceptions are written by a person. The detect log is
  the input; `docs/exceptions.md` shows how to go from a log line to an entry.
  (Gap item #3, a `propose` workflow, is separate.)
- Not value matching. Snuffleupagus can except on `.value_r("^ping")`.
  Howdah never logs values and will not match on them either: an exception
  that depends on the payload is a rule, and rules are the core's job.
- Not a request dump (`.dump()`). Out of scope and against the privacy rule.

**Anti-goals** (would make this a failure even if it works)

- **Excepting a Critical rule.** The Layer 1 multipart and input-flood limits
  exist because PHP can be exhausted before any script runs. An exception on
  them is a self-inflicted DoS hole; the validator refuses it, and the matcher
  refuses it again even if a hand-built config reaches it.
- **Silent exceptions.** An exception that matches and leaves no trace is
  indistinguishable from a bug. Loaded exceptions are announced once per
  process at startup, counted in `php --ri howdah`, and can be logged per
  match with `exceptions_log = true`.
- **Widening an allowlist by accident.** An exception on `sinks.command_exec`
  for a script does not add that script's commands to `allow`; it means **that
  sink is not checked for that script**. The documentation says it in those
  words, every time.
- **Breaking the log contract.** No existing field changes. The only schema
  addition is one new `action` value, `excepted`, written only when the
  operator turns `exceptions_log` on.

## 3. The model

An **exception** is a set of **facets** plus a **rule selector** plus a
**reason**. An event matches an exception when **every facet the exception
specifies matches the event** (facets are ANDed; unspecified facets are
wildcards). Exceptions are tried in file order; the first match wins (only the
index matters, for the log). A match downgrades the selected rule to `off` for
**that event only**: no enforcement, no `log`/`block` line.

| Facet | Type | Matches against | Layers |
|---|---|---|---|
| `script` | absolute path or glob | the executing PHP file (see §5.1) | 3, 4 |
| `script_sha256` | 64 lowercase hex | SHA-256 of the executing file's bytes | 3, 4 |
| `param` | string | the request variable name, exact (`q`, `jform[articletext]`) | 2 |
| `param_prefix` | string | the request variable name, byte prefix (`jform[`) | 2 |
| `uri_prefix` | string starting `/` | the request path (query string removed), byte prefix | 1 (Standard), 2, 3, 4 |
| `client_cidr` | IPv4/IPv6 CIDR or bare IP | `REMOTE_ADDR` as the SAPI reports it | 1 (Standard), 2, 3, 4 |

At least one facet must be set. `rule` and `reason` are mandatory.

The **rule selector** is one of:

- a rule id as it appears in the log: `sql_injection`, `command_exec`,
  `php_write`, `max_request_headers`, ...
- a layer name, which is the config section name: `limits` (Layer 1),
  `inspect` (Layer 2), `sinks` (Layer 3), `behavior` (Layer 4); `inspect.*`
  is accepted as a spelling of `inspect`;
- a dotted family: `sinks.command_exec`, `inspect.sql_injection`,
  `behavior.php_write`, `limits.max_request_headers`. The part after the dot
  must be a rule of that layer.

`*` on its own (all layers) is **not** accepted. Imunify offers "ignore all
rules for this file"; Howdah does not, because an exception must name what it
turns off to be an audit record. Three entries, three reasons.

**Facet applicability is enforced by the validator**, because the facts are
not all available at every layer:

- **Layer 1 Standard rules** (`malformed_multipart`, `upload_progress_abuse`,
  `self_test`, `max_input_key_bytes`, `max_request_headers`,
  `max_request_header_bytes`) accept **only** `uri_prefix` and `client_cidr`.
  They fire while PHP registers request variables, before any script runs, so
  there is no script and no single parameter to name.
- **Layer 1 Critical rules** (`max_parts`, `max_files`, `max_part_headers`,
  `max_part_header_bytes`, `max_field_name_len`, `max_filename_len`,
  `parse_memory_budget`, `max_input_vars`, `max_input_nesting_depth`) accept
  **no exception at all**. `rule = "limits"` covers the Standard ones only.
- **Layer 2** accepts `param`, `param_prefix`, `uri_prefix`, `client_cidr`.
  `script` and `script_sha256` are **rejected** for Layer 2 with the message
  that Layer 2 events are raised while PHP registers request variables, before
  the script is known, and that `uri_prefix` is the facet to use. This is
  the "if Layer 2 needs the script before it is available" case the brief
  anticipated: it does, on every SAPI, for every source (GET, POST, cookie,
  path), so the facet is not offered rather than offered and silently never
  matching. (The main-script path from `SG(request_info).path_translated` is
  available at that point and could serve Layer 2 later; it is a second
  capture path and is deliberately not added in this change.)
- **Layers 3 and 4** accept `script`, `script_sha256`, `uri_prefix`,
  `client_cidr`. `param`/`param_prefix` are rejected: a sink call is not tied
  to one request variable.

`param` and `param_prefix` are mutually exclusive in one entry. `script` and
`script_sha256` may be combined (both must match).

## 4. Configuration

```toml
# Optional. Default false. When true, every matched exception is written to
# the event log as a line with action "excepted" (see §6). Off by default so
# that adding an exception never adds log volume by itself.
exceptions_log = false

# Zero or more. Each is an array-of-tables entry. Order matters only for which
# index is reported when several would match.
[[exceptions]]
rule   = "sinks.command_exec"          # required: rule id, layer, or layer.rule
script = "/var/www/html/cron.php"      # absolute path or glob (see §5.1)
reason = "DECISION 2026-10-24 jdoe: cron.php shells out to the mailer. Allowlisting the exact command line is impossible (per-run temp paths). Reviewed quarterly."

[[exceptions]]
rule         = "inspect.sql_injection"
param        = "content"
uri_prefix   = "/wp-admin/"
reason       = "Editors paste SQL into tutorial posts. Layer 2 is detect-only here; the finding is noise."

[[exceptions]]
rule        = "max_request_headers"
client_cidr = "10.0.0.0/8"
reason      = "The internal SSO proxy adds ~40 headers. Clients outside 10/8 are still limited."

[[exceptions]]
rule          = "behavior.php_write"
script_sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
reason        = "Vendor-pinned template compiler on a host where the docroot path differs per tenant."
```

Validation errors name the entry index and the key, in the core's usual
"invalid howdah config:" form, for example:

```
exceptions[0].rule: "max_parts" is a Critical rule and cannot be excepted
exceptions[1].reason: required (write why this exception exists; it is the audit record)
exceptions[2].script: not allowed for Layer 2 rule "sql_injection" (Layer 2 events are raised before any script runs; use uri_prefix)
exceptions[3]: at least one of script, script_sha256, param, param_prefix, uri_prefix, client_cidr is required
exceptions[4].client_cidr: "10.0.0.0/33" is not an IPv4/IPv6 CIDR or address
exceptions[5].rule: unknown rule "sqli" (rule ids are the names in the log; layers are limits, inspect, sinks, behavior)
```

Every error makes the **whole file invalid**, which takes the existing
`on_invalid_config` path from #36: one line in the SAPI error log naming the
file and the error, `Config status => INVALID (fell back to block): ...` in
`php --ri howdah`, and the fallback mode (`block`, or `off` with
`on_invalid_config = "off"`). A Critical-rule exception therefore cannot be
loaded quietly; the lab asserts the loud path.

No new php.ini directive. `exceptions_log` and `[[exceptions]]` live in the
TOML file named by `howdah.config`.

## 5. Mechanics

### 5.1 The `script` facet: what path is matched, exactly

The value compared is **the path PHP itself reports for the file that is
executing**, the same string Layer 4 puts in its findings:
`zend_get_executed_filename()`, which is the compiled op_array's filename,
which is the path PHP opened the file by. That means:

- It is **absolute** and already **resolved**: PHP runs the path through its
  realpath (and realpath cache) when it opens the file, so `.` and `..` are
  gone and **symlinks are followed**. A docroot that is a symlink to
  `/srv/releases/42` shows up as `/srv/releases/42/...`, not as the symlink.
  `__FILE__` in that script prints the same string; use it to see what to
  match. The lab asserts this with a symlinked script.
- For a `require`/`include`d file it is the included file, not the includer
  (Layer 4's origin attribution). For the main script it is the main script.
- For Layer 4 `upload_exec` the executing file is the denied file itself
  (the main script at RINIT, or the file being compiled for an include).
- Matching is **lexical, byte-wise, case-sensitive**. No normalization is
  applied by Howdah; the string PHP hands over is compared as is.
- On the CLI the main script path is whatever was passed on the command line,
  resolved the same way.

Glob syntax (the only metacharacters): `*` matches any run of characters
**except** `/`; `**` matches any run **including** `/`; `?` matches one
character except `/`. Everything else is literal. A pattern must start with
`/`. `/var/www/html/wp-admin/*.php` matches the admin scripts but not
`/var/www/html/wp-admin/includes/x.php`; `/var/www/html/wp-admin/**` matches
both. No brace expansion, no character classes.

### 5.1a Rails added after review

- **`uri_prefix` cannot be stepped into.** nginx passes `$request_uri`
  unnormalized, so `/wp-admin/../index.php` executes `/index.php` while
  starting with `/wp-admin/`. The matcher fails toward protection: a URI with
  a `.` or `..` segment, an empty segment (`//`), a backslash or any `%`
  never satisfies a `uri_prefix` facet (`exceptions::uri_is_plain`). A
  legitimate request spelled that way is not excepted either, which is the
  right way round. Unit tests cover each shape; the lab sends
  `/wp-admin/../index.php`, `/wp-admin/./../index.php`, `//` and `%2e%2e`
  with `--path-as-is` and asserts the `q` finding is still logged.
- **Wildcard facets do not satisfy the facet rail.** `script = "/**"`,
  `"/*"` (any pattern with no literal byte besides `/`), `uri_prefix = "/"`
  and a CIDR with prefix length 0 are refused at validation, mirroring `*`.
- **`param`/`param_prefix` may not name or prefix `REQUEST_URI`/`PATH_INFO`**,
  the Layer 2 path pseudo-parameters (`param_prefix = "R"` would otherwise
  silence the whole path scan).
- **Hash cache revalidation** keys on device, inode, size, mtime and ctime
  (`cp -p`, `touch -r`, `rsync -t` and `tar` keep mtime). Files over 4 MiB
  are not hashed; the digest streams 64-byte blocks without copying.
- **Glob matching** is O(tokens × path) via per-row suffix-ORs; paths over
  4096 bytes never match.
- **Zero cost without exceptions:** the glue latches
  `howdah_exceptions_count(CTX) > 0` at MINIT and skips the origin lookup and
  the hash path entirely when it is 0; `want_hash` checks emptiness before
  copying the path.
- **Which path, exactly (symlinks):** `require`d files are realpath'd by
  `zend_resolve_path`; the main script is opened through the stream layer,
  whose `opened_path` is realpath'd too, so `__FILE__` is the target on the
  CLI, php-fpm and the built-in server (lab-asserted for a symlinked CLI main
  script and a symlinked `require` on 5.6/7.4/8.3). The one unresolved
  spelling is Layer 4's `upload_exec` check of the main script, which
  compares `SCRIPT_FILENAME` as the SAPI passed it. Code inside `eval()`
  reports as `<file>(<line>) : eval()'d code`: a `**` glob on the directory
  covers it, a literal path or hash does not.

### 5.2 The `script_sha256` facet

The hash is SHA-256 of the file's bytes as they are on disk, lowercase hex
(`sha256sum file.php`). It exists for hosts where paths cannot be pinned
(per-tenant docroots, blue/green releases) and for operators who want the
exception to die when the file changes, Snuffleupagus-style.

The core is filesystem-free, so the **glue** hashes. To keep the cost
bounded: the glue first asks the core whether any exception with a hash facet
*could* apply to this script path (`howdah_exceptions_want_hash`): one whose
other script-independent facets allow it and whose `script` glob, if any,
matches. Only then is the file read and hashed, once per path per PHP
process, with a per-call `stat` revalidating size and mtime (an edited file is
re-hashed). The cache is bounded (256 paths; cleared when full). A config
with no `script_sha256` entry never reads a file. If the file cannot be read,
the hash facet does not match (the rule stays armed: fail toward protection
for an exception, which is the opposite of the fail-open rule for the engine,
and intentional).

### 5.3 Per-layer wiring

All decisions stay in `howdah-core`. The matcher is a pure `Exceptions` value
compiled once from the parsed config in `howdah_ctx::new`; every check passes
it an `EventFacts { rule, script, script_sha256, param, uri, client_ip }`.

- **Layer 1 Standard** (`apply()` in `ffi.rs`): before `decide`, a Standard
  hit whose facts match an exception becomes `Allow`. Critical hits never
  consult the matcher. Facts: `meta.uri`, `meta.client_ip`.
- **Layer 2** (`inspect_value()`): after the scan classified the value and
  the class is enabled and the layer is not off, the matcher is consulted
  with the variable name (as the input filter sees it, i.e. the raw submitted
  name such as `jform[articletext]`), the URI and the client IP.
- **Layer 3** (`sink_check`, `sink_check_ssrf`, `sink_ssrf_oversize`): new
  `_at` entry points carry the executing script and an optional hash; the
  existing entry points stay and behave as before (no script, so `script`
  facets cannot match through them). The glue (`sink_filter`, `ssrf_filter`)
  obtains the script from one exported C function,
  `howdah_sys_current_script()`, which is the existing
  `howdah_current_script()` helper in `sink_hook.c` made visible: the same
  capture Layer 4 uses, called from Rust instead of from a second place in C.
  No trampoline signature changes.
- **Layer 4** (`behavior_check`): the C trampolines already pass the caller
  (binary, egress, php-write) or the path (exec-dir); those are the script.
  New `_at` entry points add the optional hash; the originals stay.
- **Client IP on the CLI built-in server.** `maybe_begin` reads `REMOTE_ADDR`
  through `sapi_getenv`, which the built-in server does not implement, so
  event lines from `php -S` carry an empty `client_ip`. The input filter now
  also hands a `REMOTE_ADDR` `PARSE_SERVER` variable to a new
  `howdah_request_client_ip` entry point, which fills `client_ip` when it is
  still empty. **Found in the lab:** this helps less than hoped. PHP 8.x's
  built-in server registers its known variables (`REMOTE_ADDR` included)
  without the input filter (`sapi_cli_server_register_known_var_*` in
  `sapi/cli/php_cli_server.c`), and on every version `$_SERVER` is built
  after the GET/POST/COOKIE variables, so under `php -S` the client is not
  known when Layer 1 and Layer 2 events fire and `client_cidr` cannot match
  them there. php-fpm and Apache answer `sapi_getenv` before any variable is
  parsed, which is where the lab proves the facet (real php-fpm via
  cgi-fcgi, header-count and input-key rules). The entry point stays: it is
  harmless, and it fills the IP for Layer 3/4 events on older `php -S`.
- **Which file is "the script".** Layers 3 and 4 attribute an event to the
  file that contains the call (the Layer 4 origin), so for frameworks the
  executing script is the filesystem class or vendored library, not the
  request's entry page: WordPress updates write from
  `wp-admin/includes/class-wp-filesystem-direct.php`, Magento 2 from
  `vendor/magento/framework/Filesystem/Driver/File.php`, PrestaShop's Smarty
  from `tools/smarty/sysplugins/smarty_internal_write_file.php`. The profiles
  and `docs/exceptions.md` are written around this.

### 5.4 Effect and precedence

A matching exception is checked **after** the rule has decided it has a
finding and **before** the mode is applied. It therefore never changes what
counts as a finding, only whether this finding is acted on. Order of
precedence for a given event: layer off (global `off`, section `enabled =
false`, section/sink mode `off`, class toggle) → **exception** → mode
(`detect`/`block`, per-rule override). An exception cannot arm anything.

An exception on a sink is not an allowlist entry. **An exception on
`sinks.command_exec` means that sink is not checked for that script.** The
same sentence appears in `docs/config.md`, `docs/exceptions.md` and the site.

## 6. Rule ids and log semantics

- **No new `RuleId`.** The excepted event keeps the rule it would have had.
- **One new `Action` value, `Excepted`**, serialized as `"excepted"`, mapped
  to `HOWDAH_ALLOW` (0) over the ABI. It is written **only** when
  `exceptions_log = true`. The schema-2 contract from #39 lists the allowed
  `action` values; `excepted` is added to that enum, to
  `docs/log-schema.md` and to `docs/howdah-event.schema.json` (if #39 has
  merged by then; otherwise to `log.rs` and `docs/log-schema.md` here).
- The `reason` of an excepted line is `exception #<index> (<rule selector>):
  <reason text, truncated to 160 bytes>`. The reason is operator-written
  config text, not request data, so it may be logged. Nothing else changes:
  no body, cookie, value or argument.
- Layers 3 and 4 log one excepted line per excepted call. Layers 1 and 2 use
  the per-request single-line slot and log **at most one** excepted line per
  request, and only when nothing of higher rank is pending; a real finding
  later in the same request replaces it. This mirrors the existing
  `self_test` behaviour and keeps "Layers 1 and 2 write at most one line per
  request" true.
- **Startup summary.** When the config loads with N > 0 exceptions, MINIT
  writes one line to the SAPI error log: `Howdah: N exception(s) active from
  <path>; exceptions_log = off|on`. This is the "logged once per process at
  startup as a config summary" from the brief; it goes to the error log, not
  the event log, so the event log keeps its schema and stays event-only.
- `php --ri howdah` / `phpinfo()` gains a row `Exceptions => N configured, M
  rejected`. M is counted by a lenient second pass over the file
  (`Config::exceptions_report`), so a file refused because of two bad entries
  shows `0 configured, 2 rejected` next to the INVALID status row. When the
  TOML itself does not parse the row reads `n/a (config does not parse)`.

## 7. Application profiles

`profiles/wordpress.toml`, `drupal7.toml`, `magento1.toml`, `magento2.toml`,
`joomla.toml`, `prestashop16.toml`. Each is a complete, loadable TOML file in
`detect` mode that contains:

- `[[exceptions]]` entries for the application's known legitimate behaviours
  (compiled-template directories for `deny_php_writes`, the cron loopback and
  pingback shapes, Magento's `shell_exec` of `php` for cron, Drupal 7's
  `update.php`, admin editors whose parameters carry SQL-like or path-like
  text), every one with a `reason` that cites where the behaviour comes from;
- `[sinks.*]` allowlist **suggestions** and `[behavior]` `deny_exec_dirs`
  suggestions in comments, with the docroot as a placeholder the operator
  must replace;
- a header stating that the file is a starting point, is never applied
  automatically, assumes a vanilla install (plugins, modules and themes add
  behaviours), and that every entry should be read before use.

Paths come from the applications' own documentation and source, each cited
in the comment next to the entry; anything that could not be verified is
**commented out with a note saying so**. A core test parses every profile with
`Config::from_toml`, checks that every exception has a non-empty reason, and
that no profile arms a block.

Packaging: the release tarball, the deb and the rpm would each need their own
install lines (three packagers, not one line), so the profiles ship **in the
repository and on the site** (`howdah.org/profiles/<app>.toml`, copied at
site build) and are linked from the docs. Not packaged in this change.

## 8. Observability and the config editor

- `php --ri howdah`: the `Exceptions` row (§6). `howdah-check` gains nothing
  in this change.
- The config editor's `loadFromCanonical` must not drop `[[exceptions]]` or
  `exceptions_log`. They are **preserved and re-emitted verbatim**: the state
  carries the parsed entries, `emitToml` writes `exceptions_log` with the
  other top-level keys and the `[[exceptions]]` tables last, and a
  load-then-download round trip is byte-equivalent in meaning (the core parses
  both to the same config; the editor test asserts it).
- A plain exceptions table on the editor page (columns: rule, script, param,
  uri_prefix, client_cidr, reason; `script_sha256` and `param_prefix` are
  editable as text too) with add/remove, validated like everything else by
  handing the whole TOML to the wasm core. The validator's `exceptions[i].key`
  messages point at the row.
- A "Start from an application profile" selector that loads a profile file
  through the same load path, if the profile copy to the site is in place;
  otherwise the page links the profiles.

## 9. Honest limitations (stated in the docs; never claimed away)

- **Layer 2 has no `script` facet** (§3). Use `uri_prefix`; on an app with
  a front controller every request path may be `/index.php`, so Layer 2
  scoping there is by `param` and client.
- **`client_cidr` is `REMOTE_ADDR`.** Behind a reverse proxy or CDN that is
  the proxy's address. Howdah does not read `X-Forwarded-For` (it is
  client-controlled), so a `client_cidr` exception behind a proxy applies to
  everything the proxy forwards.
- **`uri_prefix` is a raw byte prefix of the request path.** It is not
  percent-decoded or case-folded. `/wp-admin/` does not match `/WP-ADMIN/`
  or `/wp%2Dadmin/`; a web server that would serve those as the same resource
  can be asked for them to slip past a URI-scoped exception, so prefer
  `script` (which is the file actually run) whenever the layer offers it.
- **`script` follows symlinks** because PHP does (§5.1). An operator who
  pins a symlink path gets no match. The docs say to use `__FILE__`.
- **A hash exception reads the file** once per process per path and stats it
  per call. Fine for a handful of scripts; not a mechanism for hundreds.
- **An exception is a hole by design.** It is scoped and recorded, but a
  request that matches it is not checked by that rule. The threat model is
  the same as a per-rule `off`, narrowed. Review the register.
- **Not a per-vhost config.** Two tenants that both need `sinks.command_exec`
  off for `/cron.php` under different docroots write two entries (or one
  glob `/home/*/public_html/cron.php`, with the reason saying so).
- **Layer 1 Standard rules on SAPIs with lazy superglobals** keep their
  existing caveat (var-drop is the guarantee, the 403 is best-effort); an
  exception simply removes the drop and the line.

## 10. Lab plan

`lab/integration/exceptions.sh` (host driver, same shape as `behavior.sh`)
and `exceptions_container.sh`, run on PHP 5.6, 7.4 and 8.3 (19 checks each,
all passing at the time of this PR):

(a) `sinks.command_exec` in `block`: an exception by exact `script` lets the
    matching script run `system('true')` (no event, not blocked) while the
    same call from another script is blocked and logged; the same by glob,
    by `script_sha256`, and through a symlinked docroot (asserting the
    resolved path is what matches).
(b) a `param` exception on `inspect.sql_injection` silences that one finding:
    POST `q=' OR 1=1 --` writes nothing, `other=' OR 1=1 --` writes
    `sql_injection`, and `q=../../etc/passwd` still writes `path_traversal`.
    **Found in the lab:** the same payload as GET `?q=` is also part of the
    request path, which Layer 2 scans as the pseudo-parameter `REQUEST_URI`
    on SAPIs that register it through the input filter (php-fpm, Apache,
    `php -S` before 8.0), so the `q` finding is excepted and a path-source
    finding may remain. Documented in `docs/exceptions.md`; `param`
    exceptions are at their best on POST fields and cookies.
(c) `client_cidr` on Layer 1 Standard rules under real php-fpm
    (`max_request_headers` and `max_input_key_bytes` in `block`): a matching
    CIDR gives 200 and no event; a non-matching CIDR gives the event with the
    client IP in the line (the 403 stays best-effort, as documented for the
    input path). The `php -S` case is recorded as information (§5.3).
(d) a Critical-rule exception is rejected at startup: the SAPI error log line
    names `exceptions[0].rule`, `php --ri howdah` shows `Config status =>
    INVALID` and `Exceptions => 0 configured, 1 rejected`, and the process
    runs in the fallback mode.
(e) `exceptions_log = true` writes `"action":"excepted"` for an excepted sink
    call; with it off the same call writes nothing.
(f) `php --ri howdah` shows the configured count.
(g) Layer 4: `deny_php_writes` with a `behavior.php_write` exception for the
    compiling script writes the file with no event; another script is logged.
(h) the privacy guard: no payload byte and no sink argument in the log.

## 11. What is decided here vs left to the builder

**Decided:** the config shape and every facet name; the rule-selector
grammar and the layer names (`limits`, `inspect`, `sinks`, `behavior`); facet
applicability per layer and the Layer 2 `script` rejection; Critical rules
never excepted; first match wins; exception checked after the finding and
before the mode; no allowlist widening; the `excepted` action value and when
it is written; the startup error-log line and the `php --ri` row; reuse of
the existing origin capture via one exported C function; `REMOTE_ADDR` from
the input filter for the built-in server; glob syntax; hash semantics and the
want-hash gate; profiles as repo + site files, not packages; editor
preserve-and-re-emit as the minimum.

**Left to the builder:** module layout in `howdah-core` (an `exceptions`
module with the matcher, the glob, the selector parser and a dependency-free
SHA-256); the exact `_at` entry-point signatures (append-only in `ffi.rs`
and `howdah_core.h`); the glue's hash cache; how much of the editor table
UI lands in this change versus a follow-up; the exact profile contents, which
depend on what the application research verifies.
