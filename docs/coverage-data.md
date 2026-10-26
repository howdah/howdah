# Howdah 0.1 coverage data (Task 12)

Machine-backed results that Task 14's coverage table consumes. Everything here
is reproduced by committed scripts; no payload or exploit is used — all fixtures
reproduce only the harmless *structure* of a PHP2Shell-shaped upload (part/field
counts and sizes).

**Headline coverage claim:** Howdah blocks abusive multipart part/file floods
(the PHP2Shell attack *shape*) before memory exhaustion, at default limits, on
every PHP version and SAPI run. This is NOT a claim that "Howdah blocks
CVE-2026-109618 on stock config."

**Scope caveat (read before STEP 1).** Our fixtures reproduce the harmless
part/field-flood *structure* only, counted via the rfc1867 callback. We did NOT
reproduce CVE-2026-109618's `session.upload_progress` header-parsing memory path,
which the advisory says exhausts memory on DEFAULT config. So every "stock is not
a threat" statement below is a statement about the flood *shape we built*, not
about the actual CVE — we make NO claim about whether the real CVE is contained
on a stock PHP box. What we DID measure: (a) stock PHP's own
`max_input_vars`/`max_file_uploads` bound the flood shape we built (peak ≤33 MB);
(b) on a box with those caps raised, the same shape reaches 127–173 MB and
Howdah's count-based limits block it at defaults with a ~45× margin; (c) Howdah
protects EOL PHP (5.x/7.x) that will never receive the official fix. The exact
CVE mechanism should be re-verified against the official advisory (design §1).

- STEP 1 gate (defaults vs memory): `lab/integration/step1_memory_container.sh`,
  `lab/integration/step1_raised_container.sh`; raw numbers in
  `lab/integration/step1-results/*.tsv`.
- Cross-version matrix: `lab/integration/matrix.sh` → `lab/integration/matrix-results.tsv`.
- False-positive corpus: `lab/integration/corpus/` (+ `README.md`).

## The exact defense (and a known caveat)

The precise, version-independent defense is the **count-based critical rules**
`max_parts` (2000) and `max_files` (200), plus the **length rules**
`max_filename_bytes` (512) and `max_field_name_bytes` (1024). These are exact:
the rfc1867 callback hands the glue one event per part (`FORMDATA` /
`FILE_START`) with the real name/filename, so Howdah counts every part and sees
every name length precisely.

Caveat (documented, by design): the glue-level `max_part_header_bytes` /
`max_part_headers` are a best-effort **lower bound**. PHP's callback surfaces
only the `Content-Disposition` name/filename — not a part's other headers
(`Content-Type`, etc.) nor their raw bytes — so Howdah records one
`Content-Disposition` header per part (from the name and filename lengths)
and under-counts header bytes versus what PHP actually parsed.
`max_part_header_bytes`/`max_part_headers` therefore back up, but do not drive,
the defense; the count + length rules above are the real gate.

## STEP 1 — the decisive default-tuning gate

Measured peak worker RSS (`/proc/<pid>/status:VmHWM`, which survives the block's
`zend_bailout`) for a shaped request on PHP 5.6 / 7.3 / 8.4, NTS.

### On a STOCK box the reproduced part/field-FLOOD SHAPE is contained by PHP's own caps

(Scope: this is about the part/field-flood *structure* we built — NOT the
CVE-2026-109618 `session.upload_progress` header-parsing path, which we did not
reproduce. See the scope caveat above.)

Stock config (`memory_limit=128M`, `post_max_size=8M`, `max_input_vars=1000`,
`max_file_uploads=20`): for our flood shape, PHP's own caps hold peak RSS flat
regardless of N, and on PHP 8.x additionally gate the rfc1867 callback:

| PHP | shape | parts sent | $_FILES/$_POST seen | peak RSS | Howdah (defaults) |
|---|---|---|---|---|---|
| 7.3 | file  | 50000 | 20   | 27 MB | not blocked (callback gated at 20) — no threat |
| 7.3 | field | 50000 | 1000 | 26 MB | **403 max_parts** (FORMDATA fires past 1000) |
| 5.6 | field | 50000 | 1000 | 23 MB | **403 max_parts** |
| 8.4 | field | 50000 | 1000 | 32 MB | not blocked (FORMDATA gated at 1000) — no threat |
| 8.4 | file  | 50000 | 20   | 32 MB | not blocked (gated at 20) — no threat |

So for our flood shape on stock config, peak RSS never exceeds ~33 MB (vs the
128M limit) whether or not Howdah blocks: PHP's `max_input_vars`/`max_file_uploads`
contain both the memory AND (on 8.x) the callback for *this structure*. There is
nothing for Howdah to add on this shape at stock caps. (This says nothing about
the CVE's header-parsing path, which we did not reproduce.) **The defense does
not depend on these PHP caps** — see next.

### On a RAISED-cap box the flood IS a DoS, and Howdah blocks it

The real exposure: an admin raises `max_input_vars` / `max_file_uploads` (common
for large forms / galleries). The callback then fires unbounded and, within the
*same stock 8 MiB* body budget, the undefended flood exhausts memory:

| PHP | shape | parts | undefended peak RSS | Howdah @ defaults | defended peak RSS |
|---|---|---|---|---|---|
| 5.6 | file  | 90000 | **173 MB** (> 128M: OOM) | **403 max_files** | 27 MB |
| 5.6 | field | 90000 | 55 MB | **403 max_parts** | 55 MB |
| 8.4 | file  | 90000 | **127 MB** (≈ 128M)      | **403 max_files** | 36 MB |
| 8.4 | field | 90000 | 52 MB | **403 max_parts** | 52 MB |

The undefended file-flood reaches 127–173 MB inside an 8 MiB request — a genuine
memory-exhaustion DoS. At DEFAULT limits Howdah blocks every flood, holding the
defended peak to 27–55 MB, well under 128M.

### Verdict: defaults block the reproduced flood shape; no lowering required

For the reproduced part/field-flood shape, reaching 128M needs ~90000 parts;
`max_parts=2000` / `max_files=200` fire ~45× earlier, so the memory never climbs.
Per the gate's own lowering criterion ("if the attack drives memory toward 128M
with FEWER parts than max_parts"), the answer is NO on every version, so
`Limits::defaults()` is kept unchanged and the justification is recorded in
`crates/howdah-core/src/limits.rs`. (This verdict is scoped to the flood shape we
built; it is not a verdict on CVE-2026-109618's header-parsing path, which was not
reproduced here and should be re-verified against the advisory — design §1.)

Callback-vs-PHP-caps confirmation (brief requirement):
- `FORMDATA` fires **past** `max_input_vars` on 5.6/7.3 even at stock; on 8.x it
  is gated at `max_input_vars`, but raising the cap makes it fire past → blocked.
- `FILE_START` is gated at `max_file_uploads` on all versions, but raising the
  cap makes it fire past → blocked at `max_files`.
- For this flood shape, the gating cap also caps memory, so the no-block cases
  are (for this shape) no-threat cases; Howdah's limits engage exactly when those
  caps are raised. (Again, scoped to the reproduced shape, not the CVE's
  header-parsing path.)

## STEP 2/3 — cross-version matrix & false-positive corpus

`lab/integration/matrix.sh` builds the extension for each PHP minor and runs, per
SAPI, 14 scenarios (7 fixed + the 7-item false-positive corpus):

- `shaped_block_files` → 403 + `max_files` + block log (client_ip checked under fpm/apache)
- `shaped_block_fields` → 403 + `max_parts` + block log
- `selftest` → 200 + `self_test` action=log (never blocks)
- `up_progress_on` / `up_progress_off` → both 403 (callback chaining intact with
  `session.upload_progress` both enabled and disabled — Review Focus #3)
- `detect_standard` → 200 + action=log (a downgraded `max_files` logs, never blocks)
- `detect_critical` → 403 (a critical rule blocks even when global mode = detect)
- `corpus_*` (×7) → 200, zero block lines

Each shaped request is sent on a raised-cap config so the rfc1867 callback fires
on every version (the real-exposure config; see STEP 1).

### Results (this pass)

| PHP (minor) | cli-server | php-fpm | apache mod_php |
|---|---|---|---|
| 5.4.16 (CentOS 7 stock) | 14/14 PASS | — (note 1) | — (note 1) |
| 5.6.40 | 14/14 PASS | 14/14 PASS | not-run (note 2) |
| 7.3.33 | 14/14 PASS | 14/14 PASS | not-run (note 2) |
| 7.4.33 | 14/14 PASS | 14/14 PASS | 14/14 PASS |
| 8.1.34 | 14/14 PASS | 14/14 PASS | 14/14 PASS |
| 8.4.27 | 14/14 PASS | 14/14 PASS | not-run (note 2) |

Total this pass: 182 PASS / 0 FAIL / 7 SKIP (the 5.4 fpm row) — 154 cli+fpm plus
28 apache (7.4 and 8.1, 14 each).

- **client_ip**: populated and asserted exactly (`203.0.113.9` under fpm, `127.0.0.1`
  under apache). The PHP CLI built-in server does not expose `REMOTE_ADDR` via
  `sapi_getenv`, so client_ip is validated on the production SAPIs, not on cli.
- **Note 1 (5.4)**: CentOS 7's stock packages ship no `cgi-fcgi` to drive php-fpm
  in the lab (fpm row SKIP), and PHP 5.4 predates official Docker images so there
  is no `php:5.4-apache` (apache not run). Real-world 5.4 on CentOS 7 is mod_php
  under httpd. 5.4's hook is the same SAPI-independent `main/rfc1867.c` path proven
  on cli-server here and on fpm for the adjacent 5.6; the full block/corpus suite
  passes on 5.4 cli-server.
- **Note 2**: apache mod_php (prefork, apache2handler SAPI) is confirmed real and
  passing on 7.4 and 8.1 — bail → clean 403, client_ip populated, corpus clean.
  5.6/7.3/8.4 apache were not run this pass; fpm already exercises the non-CLI SAPI
  on them and apache is a mechanical repeat of the 7.4/8.1 runs.
- **Not-yet-run minors** (no committed lab base image): 5.5 (upstream image pull
  broken, milestone-0 finding), 7.0/7.1/7.2, 8.0, 8.2/8.3, 8.5. Recorded as
  `## NOT-RUN` in the TSV. The bindings are per-generation (php5/php7/php8), so each
  of these is a repeat of an already-passing generation pending its base image —
  NOT claimed as passing here.

## CVE-shape × PHP version coverage (for Task 14)

Shapes: **F** = file-part flood (→ `max_files`), **P** = form-field/part flood
(→ `max_parts`). BLOCKED = refused 403 + logged at default limits on a
raised-cap box (the threat config); on stock config PHP's own caps contain the
same flood (no threat), as measured in STEP 1.

| PHP version | F — file flood (`max_files`) | P — field/part flood (`max_parts`) | SAPIs validated |
|---|---|---|---|
| 5.4.16 | BLOCKED | BLOCKED | cli |
| 5.6.40 | BLOCKED | BLOCKED | cli, fpm |
| 7.3.33 | BLOCKED | BLOCKED | cli, fpm |
| 7.4.33 | BLOCKED | BLOCKED | cli, fpm, apache |
| 8.1.34 | BLOCKED | BLOCKED | cli, fpm, apache |
| 8.4.27 | BLOCKED | BLOCKED | cli, fpm |
| 5.5, 7.0, 7.1, 7.2, 8.0, 8.2, 8.3, 8.5 | NOT-RUN | NOT-RUN | — (no lab base image yet) |

Every version actually run BLOCKS both shapes on every SAPI run, with zero
false positives across the 7-item benign corpus. No run produced PARTIAL or
NOT-COVERED; the only gaps are the NOT-RUN minors above, which lack a committed
base image and are honestly not claimed as passing.

---

# Howdah 1.0 Layer-1 coverage data (Task 9)

Validation of the new input-shape, request-header, and CGI rules across the same
version/SAPI matrix, plus the extended false-positive corpus. Reproduced by
`lab/integration/matrix.sh` (cli+fpm) and `SAPIS=apache ... APPEND=1` (apache);
raw rows in `lab/integration/matrix-results.tsv`.

**Full-matrix totals this pass: 358 rows — 339 PASS / 0 FAIL / 19 SKIP.** (The
7 former CGI rows were dropped — see "CVE-2012-1823" below — so this pass is 7
rows fewer than the previous one.) The 19 SKIPs are all expected and documented
(not failures): the 5.4 php-fpm column (no `cgi-fcgi` in the 5.4 image, 7 rows)
and the CLI header scenarios (2 per version × 6 = 12, deliberately asserted only
under fpm/apache).

## New scenarios (per SAPI)

- `input_vars_flood` → 60 urlencoded POST vars at `max_input_vars=50`: block +
  `max_input_vars` log. **Critical**, so `input_vars_flood_detect` (global
  `mode=detect`) still blocks.
- `nesting_depth` → `a[b][c][d][e]=1` at `max_input_nesting_depth=3`: block +
  `max_input_nesting_depth`. Critical.
- `request_headers_flood` → 15 real `HTTP_*` headers at `max_request_headers=5`:
  block (block mode) / log (`request_headers_flood_detect`, detect mode) +
  `max_request_headers`. **Standard.** Driven over REAL headers on php-fpm (via
  the fcgi `HTTP_*` env) and Apache (via `curl -H`) — closing the Task-8 gap.

## Enforcement timing — best-effort response (measured)

The input-shape and header rules run on the GET/POST/cookie/`$_SERVER` variable
stream through the chained `sapi_module.input_filter`. The **guaranteed**
mitigation is the **variable DROP** (the filter returns 0 for the offending var,
bounding the symbol table) plus the event log. The 403 **response** is
best-effort and SAPI/timing-dependent:

- A urlencoded POST flood (`input_vars`/`nesting`) typically yields a clean 403
  on cli-server, php-fpm and Apache (measured).
- A GET header flood commonly yields HTTP 200 with the block notice appended to
  the body (the script's output had already committed the headers) while the log
  line still records `action:block` — e.g. php-fpm 8.4 returns `H=…` then
  `Howdah blocked this request. status: 403`. The matrix therefore asserts the
  **log line**, not the HTTP code, for these rules and records the observed code
  in the detail column.

This is the "var-drop + best-effort 403 on JIT-globals SAPIs" lifecycle recorded
in the plan (Ruling 7c), now observed in the lab.

### Request-header counting depends on `$_SERVER` materialization

With `auto_globals_jit=On` (PHP default), the `HTTP_*` server vars are built only
when the app first touches `$_SERVER`; the chained `input_filter` can only count
what PHP registers. The lab app reads `$_SERVER` (as every real framework does),
and then header counting fires on fpm/Apache (and on php8 cli-server). An app
that never reads `$_SERVER` on a JIT-globals SAPI leaves the header limit
unexercised. This is why the CLI header scenarios are SKIP (not asserted) and the
header rules are validated on fpm + Apache.

## CVE-2012-1823 (php-cgi argument injection) — out of reach; NOT protected

Howdah does **not** protect against CVE-2012-1823, and no rule for it ships. Lab
testing proved the defense **cannot** work from inside a PHP extension:

- For every argv-injection query shape (no literal `=`, leading `-`), php-cgi
  consumes the query string as command-line arguments **during its own SAPI
  startup, before any PHP extension, module, or request-startup (RINIT) hook
  loads** — so any check from inside an extension is **never reached** (confirmed
  by instrumentation: RINIT fired for a benign `?x=1` query but not for `?-s`).
- The only php-cgi in the lab images, PHP **5.4.16**, is itself **already
  patched** against the CVE, so no vulnerable build was available to test a fire
  path against in any case.

Because a configurable rule that can never fire is a false promise (Howdah's
no-overclaim rule), the earlier RINIT virtual patch was **removed**. CVE-2012-1823
belongs with CVE-2019-11043: both are triggered before any extension code runs
and are outside what Howdah, as a PHP extension, can defend. Cover this CVE at
the web server / front proxy, or run a patched php-cgi.

## Regression caught by the matrix: CLI-server block-state leak (fixed)

The full matrix surfaced a HEAD regression from the Task 7/8 unified lifecycle:
on the persistent CLI built-in server, once any request blocked, **every
subsequent request on that worker returned a stale 403 with no new log line**.
Root cause: `module::BEGUN` was reset only in RSHUTDOWN, but the block path's
`zend_bailout` (longjmp) skips RSHUTDOWN on the cli-server SAPI, so `BEGUN`
stayed set, `maybe_begin` no-op'd, and the core request was never re-opened.
php-fpm/Apache run RSHUTDOWN after the bailout and did not leak. Fix:
`emit_and_bail` now clears the per-request lifecycle (`BEGUN`/`ENDED`/
`MULTIPART`/`INPUT_BLOCKED`, and the rfc1867 `BLOCKED`/`SELFTEST_SEEN` flags)
immediately before the longjmp, so a skipped RSHUTDOWN cannot poison the next
request. After the fix the matrix is green and the Ruling-8 gate
(`shaped_block_fields` → `max_parts`) holds across sequential requests.

## Extended false-positive corpus — zero blocks at shipped defaults

Added under `lab/integration/corpus/input/` and driven on every SAPI at the
DEFAULT limits:

| fixture | shape | under default |
|---|---|---|
| `large_form.urlencoded` | 1500 urlencoded fields | `max_input_vars=2000` |
| `nested_form.urlencoded` | survey/matrix fields, max depth 5 | `max_input_nesting_depth=64` |
| `ordinary_headers.txt` | 50 normal request headers | `max_request_headers=200` |
| `safe_queries.txt` | `sort=-price`, `q=a-b-c`, `filter=a-b&order=-date`, … | ordinary queries; no query-string rule exists |

All produced HTTP 200 with zero `action:block` lines on every SAPI run. The
defaults in `crates/howdah-core/src/limits.rs` are therefore **kept unchanged**;
no default blocked a legitimate request, so none was raised.

## Ruling-8 gate result

`shaped_block_fields` → **403 `max_parts`** on every SAPI/version actually run:
cli-server (5.4, 5.6, 7.3, 7.4, 8.1, 8.4), php-fpm (5.6, 7.3, 7.4, 8.1, 8.4), and
Apache mod_php (7.4, 8.1). 5.4 php-fpm is SKIP (no `cgi-fcgi` in the image, as in
0.1). The START-ordering dependence (MULTIPART set before the first PARSE_POST)
is confirmed sound; the contingency (Content-Type-based detection) was not needed.

# Howdah 1.0 Layer-2 (input inspection) coverage data (Task 8)

Layer 2 inspects the *values* of GET, POST, cookie and path variables for
three attack classes and logs what it finds. It is a different kind of control
from the Layer-1 structural limits above, so it is reported here as prose and
is deliberately **not** part of `matrix-results.tsv` / `coverage.json`.

## What it is, and what it is not

- **Log-only. It does not block by default.** `inspect.mode` is independent of
  the global `mode` and defaults to `detect`: a hit writes a JSON event with
  `"action":"log"` and the request continues. A global `mode = "block"` does
  not arm Layer 2.
- **Best-effort and bypassable.** These are small hand-written signatures, not
  a parser for SQL, shell or filesystem semantics. A determined attacker can
  encode, split or reshape a payload so that nothing flags. A clean log does
  **not** mean a request was safe. Do not rely on Layer 2 as a defense; it is a
  detection signal.
- **The logged event omits the value.** Only the rule, source and variable
  name are recorded, never the payload bytes (checked in the lab run below).
  This covers the matched GET, POST and cookie value. For the PATH source, the
  request path appears in the event's `uri` field exactly as it does for every
  Howdah event: the request target is always logged, and it is not decoded
  form, body or cookie input.

## What each class looks for

| Rule | Looks for (shapes, not an exhaustive list) |
|---|---|
| `sql_injection` | a quote followed by a comment marker or an `or`/`and` comparison (`' OR 1=1 --`); `UNION SELECT`; a `;` followed by a recognisable stacked statement (`DROP TABLE`, `DELETE FROM`, `INSERT INTO`, `UPDATE x SET`, `SELECT` of `*`/a number/`@@var`/columns `FROM`) |
| `path_traversal` | `../` or `..\` sequences; sensitive targets such as `/etc/passwd`, `/proc/self/`, `php://`, `file://`, `boot.ini`; percent-encoded forms in path values |
| `command_injection` | `$(...)`; a closed backtick pair that starts with a common binary; `;`, `\|`, `&&`, `\|\|` followed by a common binary (`cat`, `id`, `curl`, ...); a PHP exec sink name immediately followed by `(` (`system(`, `eval(`) |
| `cgi_arg_injection` | the raw query string, not a decoded value: no literal `=` and a php-cgi option word (`-s`, `-n`, `-d`/`-c`/`-z` with an argument, `--define`, ...), a php-cgi directive name (`auto_prepend_file`, `allow_url_include`, ...), or a soft-hyphen byte (`0xAD`) standing in for the dash (CVE-2012-1823, CVE-2024-4577). Enforcing by default; see `docs/config.md` |

## Signal quality: benign-corpus tuning

Run against realistic near-miss free text. These must not flag, and are pinned
in the `benign_corpus_is_clean` unit test: `operating system (Linux)`,
`file system (ext4)`, ``use `foo` here``, `#fff`, `#main`,
`Thanks; update your profile`, `fine; select one option`, `union of two sets`,
`name=O'Brien`, `reports/2024/q1.pdf`, `./theme/style.css`. Three signatures
were tightened to get there (no attack pin was weakened): the exec-sink rule no
longer allows whitespace before `(`; a backtick pair counts only if it starts
with a known binary; and a stacked statement after `;` needs a SQL-shaped
second token instead of just a verb.

## Where it was verified

End-to-end in a real SAPI (PHP built-in server, extension loaded, default
config) by `lab/integration/inspect.sh`: SQLi, traversal and command-injection
values sent as both GET and POST each returned HTTP 200 (not blocked) with an
`"action":"log"` event and the matching `rule`; the log did not contain the
payload bytes; and benign GET and POST requests produced zero events.

| PHP | Result |
|---|---|
| 8.3.36 (cli-server) | PASS, 7/7 checks |
| 7.4.33 (cli-server) | PASS, 7/7 checks |

Other versions and SAPIs were **not** run for Layer 2. The scanners are
version-independent pure Rust in `howdah-core`, with no PHP calls inside them,
so matching behavior should be identical across PHP 5.4-8.5 (an inference, not a per-version lab result). The version-dependent
part is only the input-filter hook wiring, which was exercised on the two
versions above.

# Howdah Layer-3 XXE flag-awareness coverage data (after 1.6.1)

The `xxe` rule (the `xml` legacy sink) is **on and enforcing by default**. It
acts only when a dangerous libxml parse flag (`LIBXML_NOENT` 2, `DTDLOAD` 4,
`DTDATTR` 8, `DTDVALID` 16) is passed together with an XML string that
declares an external entity or an entity-expansion bomb. It removes the flags and
lets the parse continue (logged as `block`). See `docs/config.md` (Legacy-era
sinks) for behaviour and limits.

## What it looks for

| shape | needs a dangerous flag | action in the default mode |
|---|---|---|
| `<!ENTITY ... SYSTEM\|PUBLIC ...>` in the internal subset (general or parameter entity) | yes | strip the flags, log `block` |
| internal entities whose nested references expand past 1 MiB (billion laughs and variants, any declaration order) | yes | strip the flags, log `block` |
| a document the scan cannot read: UTF-7 or EBCDIC text, a UTF-16/32 encoding declared on an ASCII-looking document, a prolog still open after 1 MiB | yes | strip the flags, log `block` |
| a bare `<!DOCTYPE>`, internal entities of ordinary size | n/a | silent |
| a bare external DTD reference (`SYSTEM`/`PUBLIC` on the DOCTYPE: SAML, SVG, XHTML, RSS, plist, ODF) | only `DTDLOAD`/`DTDATTR` fetch it | log `log` only, never blocked |

## Lab: `lab/integration/legacy_sinks.sh` (no config, shipped `howdah.mode = detect`)

Per PHP minor: (1) a control run **without Howdah** proves the vector is live
(an external entity parsed with `LIBXML_NOENT` leaks a canary file through every
entry point present); (2) the same parse through Howdah, with no configuration,
has the flag removed on every entry point (`simplexml_load_string`,
`new SimpleXMLElement`, `DOMDocument::loadXML`, `XMLReader::XML`, and on 8.4+
`Dom\XMLDocument::createFromString`), reads nothing, and writes one `xxe` /
`block` line that never contains the document or the path; (3) a benign corpus
(14 documents: plain, SOAP, SAML, Office XML, bare DOCTYPE, DOCTYPE with
declarations, nested internal entities, character-reference entities, XHTML, SVG,
RSS, plist, ODF, a local-DTD document with an internal entity) is parsed through
every entry point under 10 flag sets, with and without Howdah: zero blocks and
byte-identical results; (4) 15 disguised payloads (a `>` or `[` inside the DOCTYPE's system literal, a parameter entity whose literal declares the entity with plain, decimal, hex and split-keyword character references, UTF-7, UTF-32 BE and LE, UTF-16 with and without BOM, EBCDIC, a megabyte of comment or whitespace before the DOCTYPE, newlines inside the declaration) must each leak without Howdah where libxml still reads them (14 of 15 are live; libxml rejects the UTF-32LE-with-BOM one) and leave nothing readable with it.

| PHP | libxml2 | control leaks (no Howdah) | stripped by Howdah | disguised payloads stopped / live | benign parses | benign blocks | results identical |
|---|---|---|---|---|---|---|---|
| 5.4 | 2.9.1 | 2/2 | 2/2 | 14/14 | 280 | 0 | yes |
| 5.6 | 2.9.4 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 7.0 | 2.9.4 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 7.1 | 2.9.4 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 7.2 | 2.9.4 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 7.3 | 2.9.10 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 7.4 | 2.9.10 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 8.0 | 2.9.10 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 8.1 | 2.9.14 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 8.2 | 2.9.14 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 8.3 | 2.9.14 | 4/4 | 4/4 | 14/14 | 560 | 0 | yes |
| 8.4 | 2.9.14 | 5/5 | 5/5 | 14/14 | 560 | 0 | yes |
| 8.5 | 2.9.14 | 5/5 | 5/5 | 14/14 | 560 | 0 | yes |

The 5.4 image has no DOM or XMLReader extension, so only the two SimpleXML entry
points exist there (and 5.5 has no lab image). Of the 560 benign parses per
minor, 96 are the detect-only `log` line for a bare external DTD parsed with
`DTDLOAD`/`DTDATTR` (XHTML, SVG, RSS, plist, ODF); none is a block.

## Caveats, stated plainly

- **libxml2 before 2.9.0** resolves external entities whatever the flags say, so
  on such an engine the rule cannot rely on the flags: it checks the document
  alone and refuses the call (it cannot strip). No lab image carries a libxml2
  that old (5.4 has 2.9.1), so that branch is covered by unit tests of the
  decision (`cargo test -p howdah-core`) and by a check that the version probe
  reads the real libxml2 version on 5.4, 7.4, 8.3 and 8.5, not by an end-to-end
  run.
- **PHP 8's `$reader->XML()`** (an instance call to the static `XMLReader::XML`)
  runs a private non-static copy of the function that a swap of the class's
  function-table entry never sees; the hook patches that copy too. The lab pins
  both call forms.
- **By-path loaders are not hooked** (`simplexml_load_file`, `DOMDocument::load`,
  `XMLReader::open`, `SimpleXMLElement` with `$dataIsURL`): Howdah cannot see
  their content. The lab asserts they raise no event, so the gap is documented,
  not accidental. `[sinks.xml] external_entities = "deny"` covers them.
- A quadratic blow-up (one large entity referenced many times in the body, past
  the scanned prologue) and `LIBXML_XINCLUDE` file reads are not matched.
