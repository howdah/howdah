# Howdah policy pack — signed, versioned, opt-in rule bundles (design)

**Date:** 2026-10-24
**Status:** design, pending owner approval. Nothing is built until this is approved. Design only: no product code ships with this document.
**Target release:** Howdah 1.6.0 (after 1.5 = scoped `[[exceptions]]`, PR #43). Pack format 1.
**Gap analysis:** recommendation 12 ("Signed, versioned opt-in policy pack separate from the binary") and the trust section of the competitive gap report.
**Builds on:** Layer 2 (`crates/howdah-core/src/inspect.rs`, the input-filter position), Layer 3 (`sinks.rs`, `sink_hook.c`, neutralize-on-block), Layer 4 (the RINIT main-script check and its proven `emit_and_bail`, `module.rs`), the log contract (`docs/log-schema.md`, schema 2), and the pending exceptions design (`docs/superpowers/specs/2026-10-24-howdah-exceptions-design.md`: facet vocabulary, glob grammar, rule selectors).
**Reads:** `general_waf_table_stakes.md` (CRS signed monthly releases, LTS line, exclusion packs, go-ftw test vectors), `legacy_php_threat_landscape.md` (the scanner noise paths and the per-CVE detectability notes), `php_userland_wafs.md` (Wordfence 30-day-delayed free feed, Patchstack 48-hour paid early warning, MalCare 7-days-vs-5-minutes).

Markers: **(owner)** = decided by the owner. **(call)** = a default chosen here; the builder may revisit it with a reason.

---

## 1. Intent and why

Every WAF the market trusts has a feed. Wordfence sells it as the Threat Defense Feed (free users get it 30 days late), Patchstack as 12,000 vPatch rules with 48-hour early warning, MalCare as "every 5 minutes on the paid tier", CrowdSec as a community blocklist paid for with telemetry. CRS does it without any of that: GPG-signed monthly git releases, an LTS line with a published backport policy, and a test vector for every rule. The gap report's reading is that "a WAF without a feed story is judged on brand alone", and Howdah's anti-goals forbid the two ways most vendors build one: phoning home and paywalling.

A **policy pack** is Howdah's feed story in the CRS shape. It is a TOML file of rules, signed with the project key, versioned, published at `pkg.howdah.org/packs/`, fetched and installed by a one-line `howdah-check pack install` that an operator runs on purpose, loaded by the extension at startup like the main config, and **log-only by default**. It carries two things the binary should not have to carry: scanner-noise rules that change month to month, and virtual patches for named CVEs that need to ship in days, not with the next extension release.

Two facts about Howdah's position make a pack worth more than a proxy rule set and shape every rule in it:

1. **Howdah knows the request reached PHP, and which file PHP resolved it to.** A proxy sees `GET /vendor/phpunit/.../eval-stdin.php` and does not know whether the file exists. Howdah at RINIT knows the main script path PHP is about to run. A rule that says "the main script is `eval-stdin.php` under `vendor/phpunit`" is not a guess about a URL; it is the vulnerable file about to execute.
2. **Howdah can correlate the request with the sink inside the same request.** "A request to `/wp-json/bricks/v1/render_element` in which `eval` is reached from a file under `themes/bricks/`" is the Bricks exploit, not a Bricks page view. No userland plugin and no proxy can say that.

The honest frame carries over from Layers 2 to 4. A pack rule matches a **shape**. A pack is not a patch: the vulnerable code is still there and a variant the rule does not describe still works. That is why packs ship in `detect`, why every rule names what it does not see, and why the site may say "detects" or "blocks the exploit's request shape as the lab shows" and never "protects against CVE-X".

## 2. Goals

1. **A rule model Howdah can evaluate with its existing hook points**, in linear time, with no regex: request facets (method, URI, main script, parameter name, header presence), bounded value tests on decoded input at the Layer 2 position, and sink facets (sink, executing script, argument shape class) at the Layer 3 position, with request-to-sink correlation inside one request.
2. **Every rule carries** a stable name, a severity label, a recommended action, at least one CVE or campaign reference, a one-line summary, a review date, and **test vectors** (at least one positive and one negative) that CI runs against the real core.
3. **Signed, versioned, opt-in delivery**: detached GPG signature with a dedicated pack signing subkey of the existing project key; published at `pkg.howdah.org/packs/<id>/<version>/` with `latest` and `lts` pointers; installed to `/etc/howdah/packs/` by a POSIX-sh `howdah-check pack` flow that verifies the signature and the Howdah version range; **never auto-updates**.
4. **Configured in the TOML file only**: `[packs] enabled = [...]`, a pack mode independent of `howdah.mode`, per-pack and per-rule overrides. No new php.ini directive (stays at three).
5. **Loaded at MINIT** like the main config, with the same loudness on failure: an error-log line and a `php --ri howdah` row.
6. **Log-first.** Installing or enabling a pack arms nothing. Blocking is an explicit per-pack or per-rule choice.
7. **Two initial packs**, `noise` and `virtual-patch`, with rule drafts in this document and the detectability of each stated.
8. **CRS-style cadence**: monthly signed `pack-v*` tags from this repository, out-of-band releases for new CVEs, an LTS pointer and a written backport policy.
9. **Shares the facet vocabulary with `[[exceptions]]`** (`script`, `param`, `uri_prefix`, `client_cidr`, `rule`), so an operator learns one set of words.

## 3. Non-goals and anti-goals

**Non-goals**

- Not a general rule language. The facets and value tests are a fixed, enumerated set (§5.2). A rule that cannot be expressed with them is a feature request for the core, not a reason to add a DSL.
- Not Layer 4 facets in format 1 (`php_write`, egress, `exec_dir`). The sink position covers `eval`, `include`, `command_exec`, `unserialize` and `phar`. `ssrf` is excluded from format 1 because its check is two-phase and resolves DNS; a URL-string rule on the egress sinks is a format 2 candidate.
- Not application exclusion packs. Those are the `profiles/` of PR #43 (exceptions, per application). A policy pack adds findings; a profile removes them. Keeping the two separate keeps "what this file can do to me" obvious.
- Not a replacement for web-server rules. A probe for a path that does not exist is answered by the web server with a 404 and never reaches PHP. The noise pack documents this in its first paragraph.

**Anti-goals** (would make this a failure even if it works)

- **Telemetry or phoning home.** The extension never opens a socket for packs. Nothing is fetched unless the operator runs `howdah-check pack install`. There is no update check, no usage counter, no "rule hit" report. The `pkg.howdah.org` access log is Cloudflare's and is not read by the project for anything but abuse.
- **An IP reputation feed.** Howdah does not ship, fetch or build IP lists. Operators who want one are pointed at CrowdSec, which does it well and whose bouncers work in front of PHP.
- **A paid tier or early access.** Every pack release is public for everyone at the same moment. There is no delayed free feed and no "real-time" tier. This is the one place Howdah deliberately does the opposite of Wordfence and Patchstack.
- **Auto-arming.** No pack, pack version or pack update ever starts blocking on its own. `[packs] mode` defaults to `detect`; the `recommended` mode is an explicit opt-in and `pack install` prints every recommendation that changed between the installed and the new version.
- **A pack that relaxes protection.** A pack can only add findings. No pack key can turn a built-in rule off, widen an allowlist, change a limit, or change the mode of anything outside the pack. This is a validator-enforced invariant and bounds the blast radius of a tampered or malicious pack file to "more log lines, or, under `block`, refused requests".
- **Reading more of the request than Layer 2 already sees.** Pack rules see what the input filter sees (decoded GET, POST, cookie and path values, variable names, `HTTP_*` header names) and what the sink hooks see (the sink argument). No raw body, no JSON body parsing, no file contents, no header values, no response.
- **Dynamic code.** No regex, no scripting, no bytecode, no Lua. A pack is data.
- **Logging a value.** A pack event carries the rule, the pack and the usual fields. Never the matched value or the sink argument (project privacy rule).

## 4. Constraints (inherited, project-wide)

- Defensive tool only; test vectors are static shapes, never runnable exploits or gadget chains.
- No overclaiming: every public claim about a rule is backed by its vectors in CI and, for `block`, by the lab.
- Log-first by default; nothing new blocks on install.
- No new php.ini directives (three: `howdah.mode`, `howdah.config`, `howdah.log`).
- Fail-open: a pack bug must never crash PHP. Every pack evaluation runs inside the existing `catch_unwind` guards.
- Pure-Rust, dependency-free, regex-free, filesystem-free `howdah-core`; the core receives pack bytes from the glue and never opens a file or a socket.
- Privacy: no bodies, cookies, Authorization headers, matched values or sink arguments in the log.
- The offline primary GPG key never touches CI. Signing in CI uses a subkey.
- Shared files (`ffi.rs`, `limits.rs`, `config.rs`, `howdah_core.h`) are append-only while parallel sessions are active: new fields, functions and variants only; nothing reordered, renamed or removed.

## 5. The how

### 5.1 Where pack rules run: inside Layers 2 and 3, not a new layer **(call)**

Two options were weighed.

- **A new Layer 5 ("policy").** Clean on paper, but it would need its own hook points, and there are none: a pack rule can only see what the input filter, RINIT and the sink trampolines already deliver. A fifth `layer` number in the log would also claim a vantage point that does not exist.
- **Ride inside the existing positions.** A rule is evaluated at the Layer 2 position (per decoded value, before RINIT), at RINIT (request facets, main script), or at the Layer 3 position (a sink trampoline). The log's `layer` field says where the evidence came from: `2` for request and value rules, `3` for sink rules.

The second is chosen. Pack rules are **not** a layer; they are extra rules at known positions, owned by a pack instead of the binary. Two new built-in rule ids make this concrete without touching the enum's existing variants: `RuleId::PackRequest` (layer 2) and `RuleId::PackSink` (layer 3), both `Severity::Standard`, appended to `RuleId` and `rule_catalog()`. They are the *class*; the event line carries the pack rule's own name (§5.6).

### 5.2 The rule model

A pack is one TOML file: a `format` number, a `[pack]` manifest, and `[[rules]]`. The complete grammar follows; everything not listed is rejected (`deny_unknown_fields`, as for the main config).

```toml
format = 1

[pack]
id          = "noise"            # [a-z][a-z0-9-]{0,31}; not "enabled", "mode" or "dir" (they are [packs] keys)
version     = "2026.11.0"        # CalVer YYYY.MM.N, shared by every official pack in one release
name        = "Scanner noise"
created     = "2026-11-03"
min_howdah  = "1.6.0"            # inclusive; the extension refuses to load a pack outside the range
max_howdah  = "1.99.99"          # optional, inclusive
rule_count  = 14                 # must equal the number of [[rules]] (a cheap truncation check)
retired     = ["old_rule_name"]  # names that once existed; they stay reserved and are never reused
homepage    = "https://howdah.org/packs/noise/"
signing_key = "ABCDEF0123456789" # informational: the subkey id that signs this pack series

[[rules]]
name      = "phpunit_eval_stdin" # [a-z][a-z0-9_]{0,63}; unique in the pack, unique across official packs,
                                 # never equal to a built-in rule name (max_parts, sql_injection, eval, ...)
severity  = "high"               # info | low | medium | high | critical. A LABEL for operators and SIEMs.
                                 # It never maps to Severity::Critical: no pack rule blocks in detect.
action    = "block"              # the pack's recommendation: log | block. Honoured only under mode = "recommended".
enabled   = true                 # false = shipped off; the operator turns it on per rule
refs      = ["CVE-2017-9841"]    # at least one CVE id or a named campaign ("RondoDox", "libredtail-http")
summary   = "POST to PHPUnit's eval-stdin.php, which evaluates the request body as PHP."
review_by = "2027-05-01"         # after this date the rule still runs; `pack list` and --ri mark it stale
position  = "request"            # request | sink

[rules.request]                  # request facets. ANDed across keys; a list is any-of within one key (at most 16 entries).
method           = ["POST"]                       # ASCII case-insensitive
uri_prefix       = ["/vendor/phpunit/"]           # request path, query removed (a string or a list, here and below)
uri_suffix       = ["/eval-stdin.php"]
uri_glob         = ["**/vendor/phpunit/**/eval-stdin.php"]   # the [[exceptions]] glob: * ** ?
main_script_glob = ["**/vendor/phpunit/**/eval-stdin.php"]   # the resolved main script (RINIT, path_translated)
param            = "s"                            # a variable of exactly this name was registered (in `source`);
param_prefix     = "--"                           #   or one whose name starts with this. With [rules.value], its value is tested.
source           = ["get"]                        # get | post | cookie | path; default: all four
param_present    = ["give_title"]                 # any-of: a variable of this name was registered in this request (any source)
header_present   = ["x-forwarded-host"]           # any-of; HTTP_* names only, lowercased, dashes; best-effort (§7)

[rules.value]                    # request rules only; requires param or param_prefix. Tests are ANDed.
view            = "lower"        # raw | lower (ASCII-lowercased prefix) | decoded (percent-decoded, then lowercased)
equals          = "true"
prefix          = "/bricks/v1/"
contains_any    = ["invokefunction", "call_user_func_array"]   # at most 32 needles of at most 128 bytes
tokens_in_order = ["o:", ":\"", "\":"]                          # at most 8 tokens, each found after the previous
max_gap         = 64             # for tokens_in_order: most bytes between consecutive tokens (default: no limit)
serialized_object = true         # the value names at least one class (the unserialize O:/C: scanner)
classes_any     = ["Crypt_GPG_Engine"]  # with serialized_object: one of these class names appears
length_min      = 2048

[rules.sink]                     # sink rules only. Tests are ANDed; [rules.request] facets, if present, must also hold.
sink                   = "eval"  # eval | include | command_exec | unserialize | phar
script_glob            = "**/wp-content/themes/bricks/**"   # the executing file (the Layer 4 origin)
arg_contains_traversal = true    # ../ or ..\ in the argument
arg_scheme             = ["phar", "ftp", "data", "http", "https"]   # scheme before "://", case-insensitive
arg_prefix             = "/tmp/"
arg_contains_any       = ["<?php"]                          # same bounds as the value test
classes_any            = ["Crypt_GPG_Engine"]               # unserialize: a named class in the payload
binary_in              = ["curl", "wget", "nc", "python"]  # command_exec: basename of the first token

[[rules.tests]]                  # at least one expect = "match" and one expect = "no_match" per rule
request = { method = "POST", uri = "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            main_script = "/var/www/html/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" }
expect  = "match"
[[rules.tests]]
request = { method = "GET", uri = "/index.php", main_script = "/var/www/html/index.php" }
expect  = "no_match"
# A vector's `request` table may also carry `params` (a list of {source, name, value} inline tables, registered
# in that order) and `headers` (a list of lowercased header names). A sink rule's vector adds a `sink` table:
# sink = { sink = "eval", arg = "<?php echo 1;", script = "/var/www/html/wp-content/themes/bricks/x.php" }.
# A vector is evaluated exactly as a request would be: params first (value rules latch), then the request
# rules, then the sink call if present; `expect` refers to this rule only.
```

How the facets compare, exactly:

- `uri_prefix`, `uri_suffix` and `uri_glob` match the request path (query removed) **either raw or percent-decoded and ASCII-lowercased**; one view matching is enough. Scanners vary case and encoding; a false positive from a benign path that decodes to a probe path is accepted and the vectors must include a benign near miss. `main_script_glob` and `script_glob` match the resolved filesystem path **raw, case-sensitive, symlinks already followed by PHP**, exactly as `[[exceptions]] script` does. When the SAPI reports no main script (`path_translated` is NULL or empty) a `main_script_glob` facet does not match.
- `param` and `param_prefix` compare the variable name as the input filter sees it (`jform[articletext]`), bytewise. `param_present` is remembered from the names Layer 1 already counts (`howdah_input_var`), so it needs no new hook.
- `header_present` names come from the `HTTP_*` `$_SERVER` keys the input filter sees: `HTTP_X_FORWARDED_HOST` becomes `x-forwarded-host` (strip `HTTP_`, lowercase, `_` to `-`). Only the name crosses into the core; the value never does.
- `method` compares ASCII case-insensitively against the SAPI's request method.
- There is no client-address facet in a rule. Scoping by client is `[[exceptions]] client_cidr`, so there is one way to say it.
- `min_howdah`/`max_howdah` and the running version compare as three numeric components; a pre-release suffix on the running version (`1.6.0-rc1`) is ignored for the comparison.
- Two loaded packs that both define a rule name is a load error for the **later** pack in `enabled` order (the first keeps its rule; the second is skipped and the message names both packs). Official packs can never collide (CI); this rule is for third-party files.

Rules for the grammar, enforced by the validator with an error that names `rules[<i>].<key>`:

- `position = "request"` requires at least one `[rules.request]` facet; `[rules.value]` requires `param` or `param_prefix`; `[rules.sink]` is forbidden.
- `position = "sink"` requires `[rules.sink].sink`; `[rules.value]` is forbidden; `[rules.request]` may add `method`, `uri_*`, `main_script_glob`, `param_present`, `header_present` (not `param`, `param_prefix`, `source`).
- `script_glob` belongs to `[rules.sink]` (the executing file); `main_script_glob` to `[rules.request]` (the requested script). The names differ because the files differ: a WordPress request's main script is `index.php` while the `eval` executes in a plugin file.
- `classes_any` and `binary_in` are only valid for the sink they describe; `arg_scheme` is valid for `include`, `phar` and `command_exec` (where it catches `curl http://` only in the argument, not the binary).
- Bounds: at most 256 rules per pack, 8 packs loaded, 32 needles of 128 bytes, 8 tokens, 64 tests per rule, globs of 256 bytes, a pack file of 1 MiB. Exceeding any is a load error.
- `refs`, `summary`, `review_by` and `tests` are mandatory. A rule with no negative vector is rejected: a rule nobody tried to make quiet is not ready.
- A rule name equal to any built-in rule name (`rule_catalog()` spelling) is rejected. CI additionally rejects a name used by another official pack or listed in any official pack's `retired` list.

**Why these tests and not a regex subset.** The brief allowed "a restricted regex subset evaluated linearly". It is not added. A regex subset still needs a compiler, an automaton and a story about which operators are safe, all of which are a dependency Howdah has avoided through four layers (`howdah-core` has no `regex` crate; every scanner is a hand-written forward walk). `contains_any` with a bounded needle set, `tokens_in_order` with a gap bound, `prefix`, `equals`, and the reuse of the existing `unserialize_classes` scanner cover every rule in both initial packs (§6). The first rule that genuinely needs more is the moment to revisit, with a concrete case.

**How the value test is matched, in bounded time.** The value is cut to `inspect.limits.max_value_bytes` (16 KiB default) before any view is built, and the existing per-request `max_total_bytes` / `max_values` budgets apply to pack value tests as they do to Layer 2 scanning. `contains_any` runs in time linear in the value length times at most the needle count (a first-byte bucket over the needles, then `memcmp`; the builder may use a hand-written Aho–Corasick automaton built at load if measured faster). `tokens_in_order` is one forward pass. `serialized_object` reuses `sinks::unserialize_classes`, already bounded.

### 5.3 Evaluation points, and what "block" means at each

| Rule kind | Evaluated | Facts available | `block` means |
|---|---|---|---|
| **Value rule** (request position with `[rules.value]`) | In the input filter, per registered GET/POST/cookie/path value, before RINIT — exactly where Layer 2 scans. The hit is **latched** on the request, not acted on yet. | variable name, source, decoded value, method, URI, client IP | Decided at RINIT (next row). GET, POST and cookie variables are always registered before RINIT (`php_hash_environment` runs before `RINIT` on every supported SAPI; multipart fields arrive through the rfc1867 callback, also before RINIT), so a latched hit on those sources is **refused before the script runs**. A hit whose source is `path` (`REQUEST_URI`/`PATH_INFO` arrive through `$_SERVER`, which `auto_globals_jit` materialises lazily) may be latched after RINIT and is then refused post-hoc at RSHUTDOWN, like Layer 2 `block` today. |
| **Request rule** (request position, no value test) | Once per request at RINIT, after the main script path is known (`SG(request_info).path_translated`, the same read the Layer 4 exec-dir check does). | method, URI, main script, client IP, the names of variables registered so far, header names seen so far | **Refused before the script runs**: `emit_and_bail` from RINIT, the proven Layer 4 path (403 plus request id, log line written, `zend_bailout` outside the panic guard). |
| **Sink rule** | In the sink trampoline, after the built-in sink policy, with the same argument bytes and the executing script the `_at` entry points of PR #43 already carry. | sink, argument, executing script, everything in the request record (method, URI, main script, variables seen, header names seen) | **Neutralized**: the call does not run; the return value is `false`/NULL and the script continues, exactly as Layer 3 `block` does today. |

Three consequences the builder must keep:

- **Pack value rules run whether or not `[inspect]` is on.** Today the glue calls `howdah_inspect_value` only while Layer 2 is active. With packs loaded it calls it whenever Layer 2 is active **or** a loaded pack has a value rule (`howdah_packs_want_values(ctx)`), and the core evaluates pack value rules against the `[packs]` mode, not the `[inspect]` mode. `[inspect] enabled = false` or `mode = "off"` silences the three built-in classes and nothing else. The Layer 2 byte and value budgets (`[inspect.limits]`) still bound the work, and the same per-value prefix cut applies.
- **Order at RINIT.** Pack request rules and latched value rules are evaluated in `rinit` after the Layer 4 exec-dir check and before anything else. A `block` from either refuses the request with the pack rule's line; under `detect` every matched rule writes its line and the request proceeds.
- **The request record is per request and bounded.** It holds the set of variable names that some loaded sink rule lists in `param_present` (only those; a request cannot grow it past the number of such names across all packs), the set of `HTTP_*` names some rule lists in `header_present`, the latched value hits, and a "fired" bit per rule so one rule writes at most one line per request. It is reset in `request_begin`, as the Layer 2 budgets are.

**Sink hook arming.** The `unserialize`, `phar` and (on PHP 5.x) include/eval hooks are installed only when their sink is armed, because installing them costs something. A loaded, enabled pack rule on sink X counts as arming X's **hook**, not X's built-in policy: `howdah_sink_armed(ctx, X)` returns 1, the trampoline installs, the built-in `[sinks.X]` policy still evaluates as `off` if that is what the operator set, and only the pack rule produces findings. The DNS-resolving `ssrf` hook is deliberately not in format 1 (§3), so a pack can never turn DNS resolution on.

### 5.4 Configuration

```toml
[packs]
enabled = ["noise", "virtual-patch"]   # pack ids to load from `dir`; default [] (nothing loads)
mode    = "detect"                     # off | detect | block | recommended. INDEPENDENT of howdah.mode.
dir     = "/etc/howdah/packs"          # where `howdah-check pack install` puts <id>.toml

[packs.noise]                          # optional per-pack override
mode = "recommended"                   # follow each rule's own `action` (log or block)

[packs.noise.rules]                    # optional per-rule override; keys are the pack's rule names
wp_login_post = "detect"               # off | detect | block; "detect"/"block" also turn on a rule shipped enabled = false

[packs.virtual-patch.rules]
cve_2017_9841_phpunit_eval = "block"
```

Resolution for one hit, in order: global `howdah.mode = off` → off. Otherwise take the per-rule override if present; else the per-pack `mode` if present; else `[packs] mode`. `recommended` resolves to the rule's own `action` (`log` → detect, `block` → block). A rule shipped `enabled = false` is off unless a per-rule override names it with `detect` or `block`. A global `howdah.mode = block` never arms a pack rule, exactly as it never arms `[inspect]`, `[sinks]` or `[behavior]`.

Validation of the main config:

- `dir` must be an absolute path. `enabled` entries must be valid pack ids; duplicates are an error. An id that is enabled but has no file in `dir` is **not** a config error (§5.5): the config editor can emit `enabled` before the operator has run `pack install`.
- A `[packs.<id>]` table for an id not in `enabled` is a warning (error-log line, `--ri`), not an error, so an operator can keep overrides for a pack they switched off.
- A `[packs.<id>.rules]` key that names no rule in the loaded pack is a **warning, not an error** **(call)**. Reason: a pack release may retire a rule, and an operator's stale override must not turn the whole config INVALID (which falls back to `block` for every built-in rule). This is the one lenient key in the config, and the warning says which key and which pack version it did not find.
- `[packs]` keys are fixed (`enabled`, `mode`, `dir`); per-pack tables are the only free-form keys, so a typo such as `enabeld = [...]` is rejected because an array is not a per-pack table.

Why per-rule overrides live in `[packs.<id>.rules]` and not in the existing `[rules]` table: `[rules]` is typed on the fixed `RuleId` enum and lives in an append-only file; a pack rule name is data from a file that is not loaded yet when `[rules]` is parsed; and keeping the overrides under the pack makes "what disappears when I remove this pack" visible. `[rules] pack_request = ...` and `[rules] pack_sink = ...` parse (the class ids exist) but are inert, like the Layer 2 to 4 names under `[rules]` today, and the config editor labels them so.

### 5.5 Loading at MINIT, and failure behaviour

The core is filesystem-free, so the **glue** reads pack files and hands bytes to the core, after `howdah_init` has parsed the main config:

1. For each id in `[packs] enabled`, in order: read `<dir>/<id>.toml` (at most 1 MiB); call `howdah_pack_load(ctx, id, bytes)`. The core parses the pack, checks `format == 1`, checks that `[pack].id` equals the requested id, checks `min_howdah <= HOWDAH_VERSION <= max_howdah`, validates every rule (§5.2), and runs no vectors (vectors run in CI and in the browser, not in production MINIT).
2. `howdah_pack_finish(ctx)` compiles the loaded packs into the matcher (per-parameter index, per-sink index, needle tables) and returns the count.
3. Warnings and errors are queued as strings; the glue drains `howdah_take_pack_message` and writes each to the SAPI error log once per process, in the form `Howdah: pack "virtual-patch" not loaded from /etc/howdah/packs/virtual-patch.toml: min_howdah 1.7.0 is above this Howdah (1.6.0)`.
4. `php --ri howdah` / `phpinfo()` gains a row: `Packs => noise 2026.11.0 (14 rules, 2 shipped off, mode recommended); virtual-patch NOT LOADED (min_howdah 1.7.0 > 1.6.0)`, and `Pack rules past review_by => 1 (noise.thinkphp_invokefunction, 2027-03-01)`.

**A pack that fails to load is skipped; the main config stays valid.** **(call)** This differs from a malformed `howdah.toml`, which makes the whole file INVALID and falls back to `block`. Reason: a pack is fetched content on a cadence of its own; the ordinary failure is "this pack release needs a newer Howdah" or "the file is not installed yet", and neither should put every built-in rule into `block` or `off`. The loudness is the same (error-log line, `--ri` row, and `howdah-check pack list` showing `enabled, not installed`); only the fallback differs, and the row says so. The owner may veto this.

The extension does **not** verify the GPG signature at load. Verification is `howdah-check pack install|verify`'s job at install time; once a pack sits root-owned in `/etc/howdah/packs/` it is configuration, trusted the way `howdah.toml` is. The invariant that a pack can only add findings (§3) is what makes this acceptable: the worst a tampered pack can do is log noise, or refuse requests if the operator had switched that pack to `block`.

Packs are read once per process at MINIT. **Installing or updating a pack takes effect at the next PHP restart or reload** (`systemctl reload php8.3-fpm` re-executes the FPM master and reruns MINIT; `apachectl graceful` likewise). `pack install` says so on every run.

### 5.6 Rule ids, log line and the `[[exceptions]]` vocabulary

**Event line.** A pack event is a schema-2 line with the existing fields and two added ones:

| field | content |
|---|---|
| `rule` | the pack rule's `name` (`phpunit_eval_stdin`). Same character set as built-in names (`^[a-z0-9_]+$`), so every decoder, `HOWDAH_RULE` consumer and the JSON Schema keep working unchanged. |
| `layer` | `2` for request and value rules, `3` for sink rules. |
| `pack` | the pack id (`noise`). Present only on pack events. |
| `pack_version` | the pack version (`2026.11.0`). Present only on pack events. |
| `action` | `log`, `block`, or (with `exceptions_log`) `excepted`. |
| `reason` | `pack rule <summary truncated to 160 bytes>; <position detail>` where the detail names the sink and function, or the source and variable name, never the value or the argument. |

Adding `pack` and `pack_version` is a compatible addition (schema stays 2; `docs/log-schema.md`'s compatibility rules say consumers ignore unknown keys). `docs/howdah-event.schema.json` gains the two optional properties. The sentence "Layers 1 and 2 write at most one line per request" in `log-schema.md` is amended: pack lines are per hit like Layer 3 lines, at most one per rule per request.

Why `rule` is the bare rule name and not `pack.noise.phpunit_eval_stdin`: a dotted name violates the published `rule` pattern and the documented `HOWDAH_RULE` character set, and a dotted bare key in TOML is a nested table. Uniqueness across **official** packs is enforced in CI (the repository holds all of them and the built-in catalog, so the check is one test). For a third-party pack the operator owns collisions; the `pack` field disambiguates in the log either way.

**Exceptions** (PR #43) gain one selector family and nothing else:

- `rule = "packs"` (every pack rule), `rule = "packs.noise"` (one pack), `rule = "packs.noise.phpunit_eval_stdin"` (one rule). The bare rule name is also accepted when it is unambiguous, for symmetry with built-in names.
- The whole-layer selectors `inspect` and `sinks` do **not** cover pack rules. An exception that says "Layer 2 off for this URI" means the three built-in classes; silencing a pack needs `packs`. (A whole-layer exception that silently also removed a CVE rule would be a surprise in the wrong direction.)
- Facet applicability follows the position: request and value rules accept `param`, `param_prefix` (value rules only), `uri_prefix`, `client_cidr`; sink rules accept `script`, `script_sha256`, `uri_prefix`, `client_cidr`. Checked after the finding and before the mode, as for every other rule. An exception can never arm a pack rule.

### 5.7 Format and delivery

**Files.** One pack is `pack.toml` plus a detached, armored signature `pack.toml.asc` over exactly those bytes. There is no tarball and no manifest file apart from the `[pack]` table, so `sha256sum`, `gpg --verify` and `cat` are the whole toolchain on the oldest supported box.

**Publication layout** on `pkg.howdah.org` (the existing R2 bucket, same cache rules as the apt tree: version-named paths immutable, pointers short-TTL):

```
packs/index.toml            # every official pack: id, name, summary, latest, lts, homepage
packs/index.toml.asc
packs/<id>/<version>/pack.toml
packs/<id>/<version>/pack.toml.asc
packs/<id>/latest           # one line: the newest version string
packs/<id>/latest.asc
packs/<id>/lts              # one line: the LTS version string (§5.9)
packs/<id>/lts.asc
```

The same files are attached to the GitHub Release for the `pack-v*` tag, so a mirror or an air-gapped operator can fetch from either.

**Signing key: a dedicated pack signing subkey of the existing primary key.** **(call)** Three options were weighed:

1. *Reuse the release signing subkey* (`1E8D725D31BD5DC9`). Zero new key material, but the pack pipeline runs monthly from a different workflow, may later be run by a second maintainer, and a compromise or rotation of the key that signs packs should not force every apt and yum client to re-import a key for the package repos.
2. *A separate primary key for packs.* Clean separation, but a second key for users to fetch, pin, and understand, and a second offline backup for the owner. The trust story gets worse to make the operational story slightly better.
3. *A new signing subkey under the existing primary* `11521035C600F63831F825512087B8720997807B`. Users already have this key (`howdah.org/key.asc`, `/etc/apt/keyrings/howdah.asc`, the rpm keyring). `gpg --verify` accepts any signing subkey the primary certifies, so a refreshed `key.asc` is the only thing a rotation changes. The CI secret is distinct (`HOWDAH_GPG_PACK_SIGNING_KEY`), stored in its own GitHub Environment (`pack-publish`) with its own reviewer gate, and revocable without touching releases.

Option 3 is chosen. `howdah-check pack verify` pins the **primary** fingerprint (hard-coded in the script, as the docs already print it) and requires `gpg`'s `VALIDSIG` status line to name it; it does not pin the subkey id, so rotation needs no script change. The manifest's `signing_key` is informational.

**`howdah-check pack`** (POSIX sh, in the existing script; `curl` and `gpg` are the only tools; `gpg` 1.4 on CentOS 7 is enough):

```
howdah-check pack list                       # installed packs: id, version, rules, shipped-off count, stale review_by count;
                                             # whether each is in [packs] enabled; `--remote` adds the latest/lts available
howdah-check pack install <id>... [--version V | --latest] [--dir DIR] [--quiet]
                                             # default channel is lts; --latest opts into the newest
howdah-check pack verify <id> | <file>       # signature against the pinned primary; format; version range against every
                                             # Howdah `detect` finds on the box; exits non-zero on any failure
howdah-check pack show <id>                  # rule table: name, severity, recommended action, refs, review_by, enabled
howdah-check pack remove <id>
```

`install` takes official pack ids only and fetches from `pkg.howdah.org`. A third-party pack is copied into `dir` by hand; `verify <file>` checks its format and version range but reports "not signed by the Howdah key" for its signature, and 1.6 offers no way to trust another key (a `--key` option is a later addition, if anyone asks). `list` reads `[packs] enabled` and `dir` from the TOML file that the first detected install's `howdah.config` names, with a lenient line scan of the `[packs]` table (the same discipline as the core's `on_invalid_config` scan), labelled "from <path>, best effort"; the core at MINIT remains the parser of record.

`install` flow, in order: download `pack.toml` and `pack.toml.asc` into a fresh temporary directory; import the public key into a throwaway `GNUPGHOME` (from the keyring already on the box if present, else from `https://howdah.org/key.asc`), check its fingerprint is the pinned primary; `gpg --status-fd --verify`, require `VALIDSIG <primary fingerprint>`; read `format`, `[pack] id`, `version`, `min_howdah`, `max_howdah`, `rule_count` with `sed` (only the manifest; the core is the TOML parser of record and runs at MINIT); refuse if `id` differs from the requested id; compare the version range against every PHP install `detect` reports with Howdah loaded and refuse if any is outside it (`--force` installs anyway and says which install will skip the pack); write `<dir>/<id>.toml.tmp` then `mv` over `<dir>/<id>.toml`, keep the previous file as `<id>.toml.prev`, install `<id>.toml.asc` beside it, mode 0644, owner root; print what changed since the previous version (rules added, retired, and every rule whose recommended `action` changed) and the restart reminder. Exit status: `0` installed or updated, `3` already at that version and unchanged, `1` verification or download failure, `2` usage. Nothing is ever executed from the downloaded content.

**No auto-update.** Nothing is installed in cron, a timer or a package hook. The documentation shows one opt-in example and explains the trade:

```
# /etc/cron.weekly/howdah-packs  (opt-in; you chose to fetch rules unattended)
#!/bin/sh
howdah-check pack install noise virtual-patch --quiet
case $? in
  0) systemctl reload php8.3-fpm ;;   # a new version was installed: reload so MINIT re-reads it
  3) ;;                               # unchanged
  *) logger -t howdah-packs "pack update failed" ;;
esac
```

Signature verification is unconditional, so an unattended update can at worst install a newer *signed* pack; with the default `detect` that means new log lines, never new blocks. An operator who runs `recommended` or `block` on a pack is told, in the same paragraph, that an unattended update can then change what is blocked, and that the manual path prints the recommendation diff.

### 5.8 Config editor and `--ri`

- The config editor gains a `[packs]` section: the `enabled` list from `packs/index.toml` (fetched by the browser from `pkg.howdah.org`, or typed), `mode`, per-pack mode, and a per-rule override table filled from the pack's rule list when the browser can fetch and validate the pack with the wasm core. Pack validation in the browser is the same core (`howdah_wasm_pack_validate`), which also runs the pack's own vectors and reports pass/fail per rule, so the pack page on the site can say "N rules, all vectors pass, checked by the core in your browser".
- `php --ri howdah`: the `Packs` row and the `Pack rules past review_by` row (§5.5).
- `howdah-check pack list` is the operator's cross-check: installed vs enabled vs loaded.

### 5.9 Release cadence and the LTS line

Modelled on CRS, scaled to this project:

- **Sources live in this repository** under `packs/<id>/pack.toml`, next to the core that evaluates them, so one `cargo test` runs every vector against the exact engine and the rule-name uniqueness check sees the built-in catalog.
- **Monthly release**, tag `pack-vYYYY.MM.N` (`N` from 0; an out-of-band release for a new CVE increments `N`). Every official pack is released together and carries the same version string. The release notes list per pack: rules added, retired, recommendation changes, vector count.
- **Signed tags and signed artefacts.** The tag is signed by the owner; `pack-release.yml` (a new workflow, triggered by `pack-v*` tags, environment `pack-publish` with a required reviewer) runs the vector tests and the pack lab subset, signs with the pack subkey, verifies against the committed public key in a clean keyring (as `release.yml` does), uploads to R2 in dependency order (`<version>/` files first, pointers last), and attaches the files to a GitHub Release.
- **`latest` and `lts` pointers.** `latest` always moves. `lts` tracks the newest pack release whose `min_howdah` is satisfied by the Howdah minor the `stable` package repositories ship. In practice both point at the same release until a pack needs a core feature newer than stable (a new facet, a new sink); then `latest` moves ahead with a higher `min_howdah` and `lts` stays, receiving backports.
- **Backport policy for `lts`**, copied from CRS v4.25: bypass fixes to an existing rule, false-positive fixes, rule retirements, metadata (`review_by`, `refs`). Never a new facet and never a new rule that needs a newer core. One LTS line at a time; it ends when the stable packages move to the minor `latest` requires, announced one release ahead.
- **Rule names are permanent.** A removed rule goes to `retired` and the name is never reused, so an operator's override or exception that names it keeps meaning the same thing (and produces the stale-key warning rather than silently attaching to something new).
- **`review_by`** is mandatory and at most 12 months out at release time (CI enforces). A rule past its date is still evaluated; `--ri` and `pack list` flag it so stale rules are visible rather than quietly accumulating.
- **Changelog** at `packs/CHANGELOG.md`, Keep-a-Changelog form, one section per pack release.

### 5.10 Testing story

1. **Vectors in the pack, run by CI against the real core.** `crates/howdah-core/tests/packs.rs` loads every `packs/*/pack.toml`, parses it with the production parser, compiles it, runs every `[[rules.tests]]` vector through the same `eval_request` / `eval_value` / `eval_sink` functions the FFI uses, and fails on any mismatch. The same test asserts: name uniqueness across packs and against `rule_catalog()`, no reuse of a `retired` name, every rule has a positive and a negative vector, `rule_count` matches, `review_by` is within 12 months of `created`, and `refs` is non-empty.
2. **Benign corpus.** The same test runs the Layer 2 benign strings (`inspect.rs` `benign_corpus_is_clean`) and the lab's false-positive corpus request shapes through every value and request rule and requires zero matches.
3. **In the browser.** `howdah_wasm_pack_validate(toml) -> {ok, pack, failures}` runs the vectors in the wasm core; the site's pack page and the config editor call it. What the site says about a pack is what the core said a minute ago in the visitor's browser.
4. **Lab** (`lab/integration/packs.sh` + container half, PHP 5.6, 7.4, 8.3; the RINIT refusal additionally under real php-fpm and Apache mod_php, because that is where `emit_and_bail` has to be proven again): install both packs from the repo tree (no network), enable them, and assert: a request rule under `block` is refused before the script runs (the script's output marker is absent, 403, request id in body and line); the same under default `detect` returns 200 with a line carrying `pack`, `pack_version`, `rule`, `layer: 2`; a sink rule with a request facet fires only when both hold (the `eval` from a non-matching URI writes nothing); `block` on a sink rule neutralizes (`eval` returns NULL, script continues); a benign request matches nothing; a pack with `min_howdah` above the build is skipped with the error-log line and the `--ri` row while the main config stays `ok`; a per-rule `off` override and a `packs.<id>.<rule>` exception each silence one rule; no value and no argument byte appears in the log; `howdah-check pack verify|install|list` against a `file://` URL signed with a throwaway key (`packaging/repo/gen-throwaway-key.sh`), including a tampered byte, a wrong `id`, and a `min_howdah` above the installed version.
5. **Shell tests** in `tools/howdah-check.test.sh` for the `pack` subcommand's parsing, exit codes and the no-network paths.
6. **Fuzz target** `pack_toml` (pack parser on arbitrary bytes; must never panic) added to the existing `cargo fuzz` smoke job.

## 6. The two initial packs (rule drafts)

These are drafts for the spec, not the shipped files; the plan's pack task writes the real files with full vectors. Severities are labels; every rule ships `enabled = true` unless noted; `action` is the recommendation honoured only under `recommended`.

### 6.1 `noise`: scanner and campaign noise

**The caveat first, in the pack's own header:** a rule here fires only when the request reaches PHP. A probe for a file that does not exist is answered by the web server with a 404 and never reaches Howdah, so **404-class noise belongs at the web server** (`nginx` `location` rules, `mod_rewrite`, fail2ban on the access log). Two things still make the pack useful: on a **front-controller application** (Laravel, Symfony, WordPress with pretty permalinks, Drupal, Magento) the rewrite sends *every* unmatched path to `index.php`, so `/.env` and `/.git/config` do reach PHP and the pack sees them; and when a probed path **does** exist (`eval-stdin.php` really is in `vendor/`, `adminer.php` really was left in the docroot) the request is no longer noise but the thing itself, and the `main_script_glob` facet says so with certainty a proxy cannot have.

| name | severity | action | position | facets (summary) | refs | what is and is not seen |
|---|---|---|---|---|---|---|
| `phpunit_eval_stdin_uri`, `phpunit_eval_stdin_script` | medium, high | log, block | request | `uri_glob **/eval-stdin.php` (the `_uri` rule) and `main_script_glob **/vendor/phpunit/**/eval-stdin.php` with `method POST` (the `_script` rule) | CVE-2017-9841, "libredtail-http", RondoDox, Kinsing | `_script` is certain: the file exists and is about to run; refusing at RINIT stops it before the body is evaluated. `_uri` fires on front controllers for the probe alone. Not seen: a copy of the file under a renamed path. |
| `dotenv_probe` | low | log | request | `uri_suffix /.env`, `method GET` (also `/api/.env`, `/backend/.env` via `uri_suffix`) | F5 Labs 2025 scanner study (80% of one scanner's traffic) | Only reaches PHP via a front controller, where the app answers 404 itself; the `.env` file is never served by PHP. Pure early warning. |
| `git_config_probe` | low | log | request | `uri_glob **/.git/*` | AbuseIPDB 2026 community reports | Same as above. |
| `vendor_phpunit_probe` | medium | log | request | `uri_prefix /vendor/phpunit/`, `uri_glob **/vendor/phpunit/**` | CVE-2017-9841 sweeps (VulnCheck: ~30 path prefixes per sweep) | Broader than `eval-stdin`; catches the sweep's other paths when they reach PHP. |
| `thinkphp_invokefunction` | high | block | request (value) | `source get`, `param s`, `value.contains_any ["invokefunction", "call_user_func_array", "\\think\\"]`, view `decoded`; sibling rule on `param function`, `value.equals call_user_func_array` with `param_present vars[0]` | CVE-2018-20062, CVE-2019-9082, Akamai 2023 attribution | The route string is a GET value: seen before RINIT, refused before the script on all SAPIs. Not seen: the `s` route carried in `PATH_INFO` (`/index.php/index/\think\app/invokefunction`) is `source = path`, materialised lazily; a second rule on `uri_glob` covers it log-first. |
| `joomla_api_config_probe` | high | log | request (value) | `uri_prefix /api/index.php/v1/config/application`, `param public`, `value.equals true` | CVE-2023-23752 | The exact exploit shape, seen before the script. The pack ships it `log` here and `block` in `virtual-patch`; the two packs share the vector set. |
| `xmlrpc_post` | info | log | request | `uri_suffix /xmlrpc.php`, `method POST`; **`enabled = false`** | ISC/DShield top paths; pingback and multicall abuse | Legitimate for Jetpack and mobile apps, so shipped off. An operator who has disabled XML-RPC in the app turns it on as a confirmation signal. |
| `wp_login_post` | info | log | request | `uri_suffix /wp-login.php`, `method POST`; **`enabled = false`** | ISC/DShield (`/wp-login.php` the most-hit honeypot path) | Every real login matches; it is brute-force *volume* a SIEM counts, not a finding. Shipped off for that reason. |
| `wp_install_probe` | medium | log | request | `uri_suffix` in `/wp-admin/install.php`, `/wp-admin/setup-config.php`; `main_script_glob **/wp-admin/install.php` | ISC/DShield | On an installed site the script exists and shows "already installed": harmless but a reliable scanner marker. |
| `phpinfo_probe` | medium | log | request | `uri_suffix` in `/phpinfo.php`, `/info.php`, `/php_info.php`, `/test.php`, `/i.php` | F5 Labs (11.45% of one scanner's traffic) | Reaches PHP only if the file exists, in which case `main_script_glob` in a sibling rule marks it `high`: a forgotten `phpinfo.php` is a disclosure, not noise. |
| `adminer_probe` | medium | log | request | `uri_glob **/adminer*.php`, `**/phpmyadmin/**`, `**/pma/**` | ISC/DShield | Same split: probe (front controller) vs present (`main_script_glob`). |
| `known_webshell_names` | high | log | request | `main_script_glob` with basenames `wso*.php`, `c99*.php`, `r57*.php`, `alfa*.php`, `shell.php`, `cmd.php`, `up.php` | Sucuri/Sansec webshell naming, 2024–2025 | Fires only when such a file **exists and runs**: that is a breach indicator, and it is the one place a noise rule says `high`. Not seen: a shell with an innocuous name (Layer 4 is for that). |
| `argv_style_param` | medium | log | request (value) | `source get`, `param_prefix --` | CVE-2024-56145 (Craft), CVE-2024-52301 (Laravel) | A GET variable named `--anything` is the argument-injection shape that needs `register_argc_argv = On`; `howdah-check ini` reports that setting. Seen before RINIT. Not seen: whether the setting is on in this process (the rule logs regardless). |
| `cgi_bin_php_probe` | info | log | request | `uri_prefix /cgi-bin/php` | CVE-2012-1823, CVE-2024-4577 | Reaches PHP only under CGI, and the argument injection itself happens before any extension runs (`docs/coverage.md` caveat 7). The rule confirms a probe arrived; it protects nothing, and its summary says exactly that. |

### 6.2 `virtual-patch`: named CVEs where Howdah's position sees the exploit

Each entry says what is detectable at which position and what is not. "Blocks" below always means "under an explicit `block`, as the lab proves", never "protects against the CVE".

1. **`cve_2017_9841_phpunit_eval`** (critical, block, sink). `sink = eval`, `script_glob **/vendor/phpunit/**/eval-stdin.php`. Request sibling: `main_script_glob` the same, `method POST`. *Seen:* both ends. The request rule refuses at RINIT before the body is evaluated; the sink rule neutralizes the `eval` if the request rule is in `detect`. *Not seen:* nothing of consequence; if the file is absent there is nothing to protect.
2. **`cve_2024_25600_bricks_eval`** (critical, block, sink). `sink = eval`, `script_glob **/wp-content/themes/bricks/**`, request facets `uri_glob **/wp-json/bricks/v1/render_element` **or** `param_present rest_route` (the non-pretty-permalink form `?rest_route=/bricks/v1/render_element`; a value rule `param rest_route`, `value.prefix /bricks/v1/render_element` covers it). *Seen:* the `eval` reached from the theme during a render_element request, which is the exploit and not a normal page. *Not seen:* the nonce check the bug skipped (authorization logic); a fixed Bricks that never evals during render_element produces nothing, which is the correct outcome.
3. **`cve_2024_5932_givewp_object_injection`** (critical, block, request value + sink). Value rule: `source post`, `param` in `give_title`, `give_company_name`, `value.serialized_object = true`. Sink rule: `sink = unserialize`, `script_glob **/plugins/give/**`, `param_present give_title`. *Seen:* a serialized object arriving in a donation-form field (before the script, refusable at RINIT), and the `unserialize` of it inside the plugin. *Not seen:* which gadget chain; the pack does not name classes here because the public chain's class names should be verified against the advisory before shipping (`classes_any` is left empty in the draft). `[sinks.unserialize]` is off by default; this rule arms the hook (§5.3), not the built-in policy.
4. **`cve_2018_20062_thinkphp_rce`** (critical, block, sink). `sink = command_exec`, `script_glob **/thinkphp/**`, request facet `param_present s` **or** `function`. Plus the `noise` value rule promoted to `block`. *Seen:* the route string in the request and the `system`/`call_user_func_array → system` call from the framework during that request. *Not seen:* a payload that ends in a non-exec sink (file write; Layer 4's `php_write` is the net for that, outside the pack).
5. **`cve_2022_47945_thinkphp_lang_include`** (high, block, sink). `sink = include`, `script_glob **/thinkphp/**`, `arg_contains_traversal = true` **or** `arg_scheme ["php", "phar", "data"]`; request facet `param_present lang` or `header_present think-lang`. *Seen:* the include of a traversal or wrapper path from the framework (PHP 7.0+: runtime opcode handler, opcache-independent; PHP 5.x: first compile only, the documented 5.x caveat). *Not seen:* a traversal into a file that is a legitimate language file; an attacker who puts PHP into a log file and includes it with a clean relative path.
6. **`cve_2024_56145_craft_argv_template_path`** (high, block, request value + sink). Value rule: `source get`, `param --templatesPath`, any value. Sink rule: `sink = include`, `arg_scheme ["ftp", "ftps", "http", "https", "data"]`, `script_glob **/craftcms/**` **or** `**/vendor/twig/**`. *Seen:* the argv-shaped parameter (before the script) and a remote-scheme include. *Not seen:* the precondition `register_argc_argv = On` (reported by `howdah-check ini` and the `--ri` risky-ini table, not by a request rule); a variant through a wrapper the include guard does not classify.
7. **`cve_2025_49113_roundcube_from_deserialization`** (critical, block, request value + sink). Value rule: `source get`, `param _from`, `value.contains_any ["!"]`, with `uri_glob **/?*` left open and `param_present _task`. Sink rule: `sink = unserialize`, `script_glob **/roundcube*/**` **or** `**/program/**`, `classes_any` to be filled from the public write-up's gadget after verification. *Seen:* the malformed `_from` (the write-up's corruption primitive) before the script, and the session unserialize in Roundcube's own files. *Not seen:* the session-file write that carries the object between requests (not a hooked sink); authenticated-only means the first request already has a valid session, which the rule does not and cannot check.
8. **`cve_2023_23752_joomla_api_config`** (high, block, request value). `uri_prefix /api/index.php/v1/config/application`, `param public`, `value.equals true`. *Seen:* the exact request, refused at RINIT before Joomla answers with its database credentials. *Not seen:* the same information reached by an authenticated client (legitimate), or any other endpoint the same access-control bug exposed (`v1/users` with `public=true` is a second rule with the same shape). This is the one rule in the pack that stops the bug's effect outright, because the effect is a response to this one request; the summary still says "the application is unpatched".

Considered and **left out**, with the reason stated in the pack's documentation: **CVE-2024-4577** (php-cgi argument injection happens before any extension code runs; nothing to see but the second stage, which the built-in `command_exec` and `eval` sinks already log); **LiteSpeed Cache CVE-2024-28000, Really Simple Security CVE-2024-10924, WP Freeio CVE-2025-11533** (privilege escalation and auth bypass with no sink and no distinctive request shape Howdah can see without the body semantics); **Magento SessionReaper CVE-2025-54236** (the nested deserialization reaches `unserialize` and the built-in off-by-default sink already covers it; a `script_glob` rule adds little and a wrong one adds false confidence).

## 7. Honest limitations (stated in the docs, on the site, and in each pack's header)

1. **Only what reaches PHP.** A 404 at the web server is invisible. On front-controller apps most probes do reach PHP; on a plain docroot most do not.
2. **A pack is not a patch.** A rule matches a shape the known exploit has. A variant, a different parameter name, a different encoding the view does not normalise, or a different gadget walks past it. The vulnerable code is still there. The docs say "apply the vendor fix; use the pack when you cannot, or until you can", the project's standing sentence.
3. **Request-position `block` is before the script for GET, POST and cookie facts; `path` and header facts may arrive after the script started** (`auto_globals_jit`), so rules on those are log-first and refuse post-hoc at best. Each such rule's summary says which it is.
4. **Sink rules see the call, not the chain.** A different sink (a file write, `mail()`, a callback) is a different rule or a different layer.
5. **`main_script_glob` and `script_glob` follow symlinks and depend on the SAPI reporting the path.** php-fpm, Apache, CGI and the CLI do; the path is the resolved one, as for `[[exceptions]] script`.
6. **The extension does not verify signatures at load.** Verification is at install time, by `howdah-check`. A pack file in `/etc/howdah/packs/` is trusted like `howdah.toml`.
7. **A pack update needs a PHP reload.** Until then the previous version runs; `pack list` shows installed vs loaded versions.
8. **`header_present` sees names only, and only when `$_SERVER` is materialised.** It is a weak facet and the packs use it only as an additional condition, never alone.
9. **A pack rule on `unserialize` or `phar` installs that hook**, with the documented costs and limitations of that sink (`docs/config.md`).
10. **Rule names are unique only across official packs.** A third-party pack may collide; the `pack` field in the line is the disambiguator.
11. **Correlation is within one request.** A two-request exploit (write, then trigger) is two rules or two layers.
12. **No per-vhost packs.** The config is process-global; a pack is on for every site the pool serves. Scope with `[[exceptions]]` (`uri_prefix`, `client_cidr`, `script`).

## 8. What the site may claim

- "Howdah publishes **signed, opt-in rule packs**: a scanner-noise pack and a virtual-patch pack for named PHP CVEs. Every rule ships with its own test vectors, run in CI and in your browser by the same core that runs on your server. Packs **log by default**. Howdah never phones home: you install a pack with one command, and nothing is fetched unless you run it. There is no paid tier and no delayed feed; every release is public for everyone at once."
- Per rule, from the coverage data the lab produces: "detects (request shape)", "refuses before the script runs (php-fpm, Apache, lab-verified)", "neutralizes the `eval` the exploit reaches (lab-verified)". Never "protects against CVE-X", never "virtual patch = patched".
- A pack release post names what was added and retired and links the vectors. No "blocked per day" numbers: there is no telemetry to produce them, and the site says so as a feature.

## 9. Decided here vs left to the builder

**Decided:** pack rules ride inside Layers 2 and 3 (`RuleId::PackRequest`, `RuleId::PackSink`, appended); the full rule grammar, bounds and validator rules of §5.2; no regex subset; three evaluation points and what `block` means at each (§5.3); a pack arms a sink's hook, never its built-in policy; `ssrf` and Layer 4 facets excluded from format 1; the `[packs]` config shape, resolution order and the warning-not-error rule for stale overrides; packs loaded by the glue after `howdah_init`, a failed pack skipped with the loud path and the main config kept; no signature verification in the extension; `rule` = bare rule name, `pack` and `pack_version` fields, `layer` 2 or 3; the `packs.*` exception selectors and that whole-layer selectors do not cover packs; file layout on `pkg.howdah.org`, `latest` and `lts`; a dedicated pack **subkey** under the existing primary, pinned by primary fingerprint; the `howdah-check pack` subcommands, flow and exit codes; no auto-update, with the opt-in cron example; monthly `pack-v*` cadence, LTS backport policy, permanent rule names, 12-month `review_by`; the testing story of §5.10; the two packs' rule sets and the excluded CVEs with reasons.

**Left to the builder (resolved in the plan):** module layout under `howdah-core/src/packs/`; the exact FFI signatures (append-only); whether `contains_any` is first-byte-bucketed literal matching or a hand-written Aho–Corasick (measure; either is acceptable); the per-request record's data structures; the exact `reason` wording per position; the `--ri` row formatting; the site page layout; the exact vectors and the final class names for the GiveWP and Roundcube sink rules (verify against the advisories before shipping; ship with `classes_any` empty if unverified, as the drafts do).

## 10. Builder-check resolutions

The design was read as a builder who has never seen the repository would read it, using the brainstorming skill's builder-check prompt. The questions a builder would still have to guess at, and how each is settled here (the owner may veto any):

1. **Does this depend on PR #43 merging first?** Yes. The glob matcher, the `RuleSelector` grammar and the facet-applicability table are #43's. The plan's first task states the dependency and stops if #43 is not on `main`; it does not fork a second glob. **(answered)**
2. **Where do request rules fire when a request never registers a variable (a bare `GET /` with no query)?** `maybe_begin` is called from RINIT itself for the Layer 4 check, so the request record always exists at RINIT; request rules evaluate on every request, variables or not. Stated in §5.3. **(answered)**
3. **Is the RINIT refusal safe when a value hit was latched during the rfc1867 callback (multipart) and Layer 1 has already decided?** Layer 1's verdict is applied first by the existing code path; a Layer 1 `block` has already bailed before RINIT. If Layer 1 logged only, the pack verdict follows at RINIT with its own line. One request can therefore carry a Layer 1 `log` line and a pack `block` line; that is correct and the lab asserts it. **(minor; settled)**
4. **What if two pack rules match one request and one says `block`, the other `log`?** All matching rules write their lines under their own resolved modes; if any resolves to `block`, the request is refused once, naming the first blocking rule in the response's request id line. Same for sinks. **(minor; settled)**
5. **Does a value rule with `source` unset also scan `path`?** Yes, default is all four sources; the two packs set `source` explicitly on every value rule, and the docs recommend it. **(minor; settled)**
6. **How does `pack install` know which Howdah version is installed without PHP on `PATH`?** It reuses `cmd_detect`'s discovery (every PHP binary, panel prefixes included) and reads the version from `php --ri howdah` of each install that loads Howdah. With `--php <binary>` it checks one. **(answered in §5.7)**
7. **Who writes `/etc/howdah/packs` on a cPanel box with several PHPs?** The same file serves every PHP on the box; `dir` is the same default for all, and the version-range check runs against every install. If one install is too old, `install` refuses unless `--force`, and then that install's `--ri` row shows the pack as not loaded. **(answered)**
8. **Does the wasm demo need the packs?** No. `howdah_wasm_pack_validate` is a validator export for the site; the multipart demo is unchanged. **(minor; settled)**
9. **What happens to a pack event under `[behavior] observe`?** Nothing; observe is a Layer 4 facet. Pack rules have no observe mode in format 1; `detect` is their observe. **(minor; settled)**
10. **Should the extension refuse a pack file writable by the PHP user, as the `[log] exec` hook refuses a writable program?** Not in 1.6: `howdah.toml` has no such check and a pack can only add findings. Left as a documented recommendation (`root:root 0644`, which `pack install` sets). The owner may ask for parity with the exec hook later. **(call)**
11. **Do pack value rules still run when the operator has turned `[inspect]` off?** They must, or a pack would be silently dead on the many installs that disable Layer 2 for noise. Settled in §5.3: the glue calls the value entry point when either is active and the core resolves pack hits against `[packs]`. **(answered; was missing)**
12. **"Any value" for `--templatesPath`: is that a value rule with an empty test?** No. `param` / `param_prefix` without `[rules.value]` is presence; `[rules.value]` is optional. Grammar text corrected. **(answered; was ambiguous)**
13. **Are URI facets case-sensitive, and do they see `%2e%2e`?** Both views are tried (raw, and decoded-then-lowercased); script globs are raw and case-sensitive like exceptions. Added to §5.2. **(answered; was missing)**
14. **How is `x-forwarded-host` derived from what PHP exposes?** `HTTP_X_FORWARDED_HOST` → strip, lowercase, underscores to dashes. Added. **(answered; was missing)**
15. **Lists or single strings for `uri_suffix` when the draft tables say "in [...]"?** Lists, any-of within a key, at most 16. Grammar corrected. **(answered; was inconsistent)**
16. **What does a vector look like for a value or sink rule?** `params`, `headers` and `sink` tables, evaluated in request order. Added to the grammar. **(answered; was missing)**
17. **Two loaded packs with the same rule name?** The later pack in `enabled` order is skipped with a message naming both. Added. **(answered; was missing)**

Everything in this section is folded into §5 above where it belongs; this list is the record of why those sentences are there.
