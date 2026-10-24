// Generates docs/coverage.md and src/data/coverage.json FROM
// lab/integration/matrix-results.tsv, so no cell can claim a block the tests
// did not show. Lines starting with "##" are comments / NOT-RUN records.
//
//   node scripts/gen-coverage.mjs
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '../..');
const raw = readFileSync(resolve(repo, 'lab/integration/matrix-results.tsv'), 'utf8').split('\n');

const ALL_MINORS = ['5.4','5.5','5.6','7.0','7.1','7.2','7.3','7.4','8.0','8.1','8.2','8.3','8.4','8.5'];
const SAPIS = ['cli', 'fpm', 'apache'];
const SAPI_LABEL = { cli: 'cli-server', fpm: 'php-fpm', apache: 'Apache mod_php' };

const cells = {};
const notRun = [];
let generated = '';
for (const line of raw) {
  if (!line.trim()) continue;
  if (line.startsWith('##')) {
    const g = line.match(/generated (\S+)/);
    if (g && !generated) generated = g[1];
    const nr = line.match(/^## NOT-RUN (\S+) ([^:]+): (.*)$/);
    if (nr) notRun.push({ minor: nr[1], sapis: nr[2].trim(), why: nr[3].trim() });
    continue;
  }
  const [ver, sapi, scenario, result, detail = ''] = line.split('\t');
  ((cells[ver] ??= {})[sapi] ??= {})[scenario] = { result, detail };
}

const minorOf = (v) => v.split('.').slice(0, 2).join('.');
// Merge all version rows that share a minor so a split patch level still counts
// as one minor — e.g. an 8.5 fpm image tagged 8.5.12RC1 and an 8.5 apache image
// tagged 8.5.12 both belong to "8.5" (each contributes its own SAPIs).
const rc = (v) => /rc|beta|alpha|dev|snapshot/i.test(v);
const cellsByMinor = {}; // minor -> sapi -> scenario -> {result, detail}
const verOfMinor = {};   // minor -> representative version string to display
for (const v of Object.keys(cells)) {
  const m = minorOf(v);
  const bucket = (cellsByMinor[m] ??= {});
  for (const [sp, scs] of Object.entries(cells[v])) {
    const sb = (bucket[sp] ??= {});
    for (const [sc, val] of Object.entries(scs)) sb[sc] = val;
  }
  // prefer a final (non-RC) version string for display
  if (!verOfMinor[m] || (rc(verOfMinor[m]) && !rc(v))) verOfMinor[m] = v;
}

function sapiSummary(minor, sapi) {
  const s = cellsByMinor[minor]?.[sapi];
  if (!s) return { state: 'none', pass: 0, fail: 0, skip: 0, total: 0 };
  const all = Object.values(s);
  const pass = all.filter((c) => c.result === 'PASS').length;
  const fail = all.filter((c) => c.result === 'FAIL').length;
  const skip = all.filter((c) => c.result === 'SKIP').length;
  const total = all.length;
  const files = s.shaped_block_files?.result;
  const fields = s.shaped_block_fields?.result;
  let state;
  if (skip === total) state = 'skip';
  else if (fail > 0) state = 'fail';
  else if (files === 'PASS' && fields === 'PASS') state = 'pass';
  else state = 'partial';
  return { state, pass, fail, skip, total, files, fields };
}

const rows = [];
for (const minor of ALL_MINORS) {
  const ver = verOfMinor[minor];
  if (!ver) {
    const nr = notRun.find((n) => n.minor === minor);
    const why = minor === '5.5'
      ? 'The upstream php:5.5 Docker image is broken (corrupt layers on Docker Hub), so no test environment can be built. PHP 5.5 shares the PHP 5 code path with 5.4 and 5.6, which pass.'
      : 'Not tested yet: no test environment built.';
    rows.push({ minor, version: null, status: 'not-run', why, sapis: {}, tested: [] });
    continue;
  }
  const sapis = {};
  for (const sp of SAPIS) {
    const sum = sapiSummary(minor, sp);
    let note = '';
    if (sum.state === 'none') {
      const nr = notRun.find((n) => n.minor === minor && n.sapis.split(/\s+/).includes(sp));
      note = nr ? nr.why : '';
    }
    if (sum.state === 'skip') note = cellsByMinor[minor][sp].selftest?.detail || 'skipped';
    sapis[sp] = { ...sum, note };
  }
  const tested = SAPIS.filter((s) => sapis[s].state === 'pass');
  rows.push({ minor, version: ver, status: tested.length ? 'run' : 'not-run', sapis, tested });
}

let P = 0, F = 0, S = 0;
for (const v of Object.values(cells)) for (const sp of Object.values(v)) for (const c of Object.values(sp)) {
  if (c.result === 'PASS') P++; else if (c.result === 'FAIL') F++; else S++;
}
let corpusBad = 0;
for (const sp of Object.values(cells)) for (const sc of Object.values(sp)) for (const [k, c] of Object.entries(sc)) {
  if (k.startsWith('corpus_') && c.result === 'FAIL') corpusBad++;
}
// Minors with no test rows at all (whether or not the run emitted a NOT-RUN
// comment for them): these repeat a tested generation but were not run.
const notRunMinors = ALL_MINORS.filter((m) => !cellsByMinor[m]);

// ---- runtimes and SAPIs outside the matrix --------------------------------
// lab/integration/runtime-results.tsv: one row per run of a named script
// (LSAPI, the Docker images, Alpine, arm64, ZTS). Runs that differ only in the
// PHP version are shown as one row listing every version.
const runtimeRuns = [];
for (const line of readFileSync(resolve(repo, 'lab/integration/runtime-results.tsv'), 'utf8').split('\n')) {
  if (!line.trim() || line.startsWith('##')) continue;
  const [date, runtime, sapi, php, arch, script, result, detail = ''] = line.split('\t');
  if (!['PASS', 'FAIL'].includes(result)) throw new Error(`runtime-results.tsv: result must be PASS or FAIL: ${line}`);
  runtimeRuns.push({ date, runtime, sapi, php, arch, script, result, detail });
}
const runtimes = [];
for (const r of runtimeRuns) {
  const same = runtimes.find((g) => ['runtime', 'sapi', 'arch', 'script', 'result', 'detail'].every((k) => g[k] === r[k]));
  if (same) {
    same.php.push(r.php);
    if (r.date > same.date) same.date = r.date;
  } else {
    runtimes.push({ ...r, php: [r.php] });
  }
}

const data = {
  generated, source: 'lab/integration/matrix-results.tsv',
  totals: { pass: P, fail: F, skip: S }, corpusFalsePositives: corpusBad,
  rows, notRunMinors,
  runtimeSource: 'lab/integration/runtime-results.tsv', runtimes,
};
mkdirSync(resolve(here, '../src/data'), { recursive: true });
writeFileSync(resolve(here, '../src/data/coverage.json'), JSON.stringify(data, null, 2) + '\n');

// ---- Markdown ----
const shapeCell = (r, shape) => {
  if (!r.version) return 'Not run';
  const ok = SAPIS.filter((s) => r.sapis[s].state === 'pass' && r.sapis[s][shape] === 'PASS').map((s) => SAPI_LABEL[s]);
  return ok.length ? 'Blocked, 403 (' + ok.join(', ') + ')' : 'Not run';
};
const sapiCell = (r, sp) => {
  if (!r.version) return 'not run';
  const s = r.sapis[sp];
  if (s.state === 'pass') return `${s.pass}/${s.total} pass`;
  if (s.state === 'skip') return 'skipped (' + s.note + ')';
  if (s.state === 'fail') return `FAIL (${s.pass}/${s.total})`;
  return 'not run';
};

// --- Layer-1 (1.0) per-rule status, straight from the matrix rows ----------
// For a version + scenario, list the SAPIs whose row has the wanted result.
const sapisWith = (ver, scenario, want = 'PASS') =>
  SAPIS.filter((sp) => cells[ver]?.[sp]?.[scenario]?.result === want).map((sp) => SAPI_LABEL[sp]);
// A cell for a Layer-1 rule scenario: "Enforced (sapi list)" or honest absence.
const ruleCell = (ver, scenario) => {
  if (!ver) return 'Not run';
  const ok = sapisWith(ver, scenario);
  if (ok.length) return 'Enforced (' + ok.join(', ') + ')';
  const anyFail = SAPIS.some((sp) => cells[ver]?.[sp]?.[scenario]?.result === 'FAIL');
  return anyFail ? 'FAIL' : 'Not run';
};
let md = `# Howdah coverage table

> Generated by \`site/scripts/gen-coverage.mjs\` from
> [\`lab/integration/matrix-results.tsv\`](../lab/integration/matrix-results.tsv)
> (matrix run ${generated || 'n/a'}). Do not edit by hand: re-run the script. A cell says
> "Blocked" only if the matrix recorded a PASS for that exact version, SAPI and
> scenario. Everything else says "Not run".

## What is claimed

Howdah blocks abusive multipart part/file floods (the PHP2Shell attack
*shape*) before they exhaust memory, and the matrix below shows it on every
PHP version and SAPI that was actually run. That includes end-of-life PHP (the 5.x,
7.x and 8.1 versions in the table) that, according to public reports, will not get
the official fix. 8.2 to 8.5 are not described as end-of-life here.

The 1.0 **Layer-1** rules extend this to request *inputs* (variable count, array
nesting depth, key length) and request *headers* (count, size). Tables 3 and 4
report their per-version/SAPI status from the same matrix. Read the per-rule
caveats below: the input/header rules mitigate by **dropping** offending
variables and logging; the input-shape rules refuse before the script runs,
while the request-header rules' 403 is **post-hoc** (set at request shutdown,
after the script) when the script builds \`$_SERVER\` lazily. The refusal
itself (status, body, request id, worker survival) is covered by the
separate refusal-path lab below. php-cgi
argument injection (CVE-2012-1823) is **out of reach** from inside PHP — the
exploit is consumed before any extension hook runs — so it is **not** protected
(see Table 4 and caveat 7).

## What is NOT claimed

- **Not "blocks CVE-2026-109618 on a stock config".** The test fixtures reproduce
  only the harmless *structure* of a flood (part and field counts and sizes). The
  CVE's \`session.upload_progress\` header-parsing memory path was **not
  reproduced**, so we make no claim about whether the real CVE is contained on
  a default PHP box.
- On a **stock** PHP config, PHP's own \`max_input_vars\` and
  \`max_file_uploads\` already bound the flood shape we built (measured peak about
  33 MB or less). Howdah's value on that shape is strongest where an admin has
  **raised those caps** (undefended peak 127-173 MB for a file flood against a
  128 MB limit; Howdah's defaults fire about 45 times earlier than memory would
  run out), and on **end-of-life PHP** with no official fix.
- Re-verify the exact CVE mechanism against the official advisories
  (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp, php.net).

## Shapes

- **File flood**: very many small file parts. Defense: \`max_files\` (default 200).
- **Field/part flood**: very many form-field parts. Defense: \`max_parts\` (default 2000).

Every shaped request is sent on a **raised-cap config** (the exposed
configuration) so PHP's multipart callback fires on every version.

## Table 1: attack shape by PHP version

| PHP | File flood (\`max_files\`) | Field/part flood (\`max_parts\`) | Status |
|---|---|---|---|
`;
for (const r of rows) {
  let status;
  if (!r.version) status = r.why;
  else {
    status = 'Run on ' + r.tested.map((s) => SAPI_LABEL[s]).join(', ');
    const missing = SAPIS.filter((s) => !r.tested.includes(s));
    if (missing.length) status += '; not validated on ' + missing.map((s) => SAPI_LABEL[s]).join(', ');
  }
  md += `| ${r.version || r.minor} | ${shapeCell(r, 'files')} | ${shapeCell(r, 'fields')} | ${status} |\n`;
}

md += `
## Table 2: test results by SAPI

Each run exercises the multipart scenarios (file flood, field flood, self-test,
upload-progress on/off, detect-mode logs-not-blocks, a critical rule still
blocking in detect), the Layer-1 input/header scenarios (Table 3), and the full
benign corpus (multipart + input-path; must not block). The cell counts every
scenario on that SAPI.

| PHP | cli-server | php-fpm | Apache mod_php |
|---|---|---|---|
`;
for (const r of rows) md += `| ${r.version || r.minor} | ${sapiCell(r, 'cli')} | ${sapiCell(r, 'fpm')} | ${sapiCell(r, 'apache')} |\n`;

md += `
Totals in the matrix file: **${P} PASS / ${F} FAIL / ${S} SKIP**. Failures on the
benign corpus (false positives): **${corpusBad}**.

## Table 3: Layer-1 input-shape & request-header rules (1.0)

"Enforced" means the matrix recorded a block (or, for a Standard rule in detect
mode, a log) with the right rule name on that SAPI. The request-header rule is
driven over **real HTTP headers** on php-fpm and Apache; on the CLI built-in
server it is intentionally not asserted (its \`$_SERVER\` HTTP_* population is
version-dependent), shown as "Not run" there but covered by the other SAPIs.

| PHP | \`max_input_vars\` (var flood) | \`max_input_nesting_depth\` | \`max_request_headers\` |
|---|---|---|---|
`;
for (const r of rows) {
  const v = r.version;
  md += `| ${v || r.minor} | ${ruleCell(v, 'input_vars_flood')} | ${ruleCell(v, 'nesting_depth')} | ${ruleCell(v, 'request_headers_flood')} |\n`;
}

md += `
*Enforcement:* these rules **drop** the offending variable(s) (bounding the
symbol table — the actual DoS mitigation) and write the event. The input-shape
rules (\`max_input_vars\`, nesting depth) then refuse before the script runs; the
request-header rules' 403 is post-hoc (set at request shutdown, after the
script) when the script builds \`$_SERVER\` lazily. See caveats 5–7.

## Table 4: known-CVE & DoS coverage

| threat | defense (rule) | status |
|---|---|---|
| **CVE-2023-0662** — too-many-parts memory DoS | \`max_parts\` (2000) | Blocked wherever Table 1's field/part-flood column is green; same scenario, cross-referenced. |
| **Hash-collision / variable flood** (symbol-table DoS) | \`max_input_vars\` (2000) | Var-dropped + logged, then best-effort 403; Enforced on the SAPIs in Table 3's \`max_input_vars\` column. |
| **Array-nesting DoS** (deep \`a[b][c]…\`) | \`max_input_nesting_depth\` (64) | Var-dropped + logged, then best-effort 403; Enforced on the SAPIs in Table 3's nesting column. |
| **CVE-2012-1823** — php-cgi argument injection | *(none — out of reach)* | **NOT protected.** The exploit works only under the php-cgi SAPI, where php-cgi consumes the argv-injection query string during its **own startup — before any PHP extension, module, or request (RINIT) hook loads** — so no in-PHP check can ever fire for the attack shape. Like CVE-2019-11043, this happens before extension code runs and is outside what a PHP extension can defend. See caveat 7. |

## Table 5: other SAPIs and runtimes

From [\`lab/integration/runtime-results.tsv\`](../lab/integration/runtime-results.tsv),
one row per run of the named script, **not** from the matrix above. These runs
are one scenario each (the self-test: a marker request, a request one part
over \`max_parts\`, a normal form; the lab rows add the block-shaped script),
not the matrix's 27, so a PASS here says the extension loads and refuses the
over-limit shape on that runtime and nothing more. A FAIL is a run that went
wrong and is why that runtime is not supported.

| Runtime / SAPI | Arch | PHP | Result | Script | What ran |
|---|---|---|---|---|---|
`;
for (const r of runtimes) {
  md += `| ${r.runtime} (\`${r.sapi}\`) | ${r.arch} | ${r.php.join(', ')} | ${r.result === 'PASS' ? 'PASS' : '**FAIL**'} (${r.date}) | \`${r.script}\` | ${r.detail} |\n`;
}
md += `
Not covered by any row: LiteSpeed Enterprise, lsphp other than 8.3 and lsphp
from LiteSpeed's rpm repository, Apache \`mod_php\` with the event or worker
MPM, any ZTS build (see [zts.md](zts.md)), and aarch64 musl (there is no
aarch64 musl build). The Alpine rows ran a musl build of the 1.4.0 source
made locally; no release carried musl tarballs when they ran.

## Honest caveats

1. **The exact defense is the count and length rules**: \`max_parts\` (2000),
   \`max_files\` (200), \`max_filename_bytes\` (512) and \`max_field_name_bytes\`
   (1024). PHP's multipart callback gives Howdah one event per part with its real
   name and filename, so these are counted exactly.
2. **\`max_part_header_bytes\` and \`max_part_headers\` under-count.** At the glue
   level only the \`Content-Disposition\` name and filename reach the callback, not
   a part's other headers or their raw bytes. Those two limits are a best-effort
   lower bound that backs up, but does not drive, the defense.
3. **Apache mod_php was validated on 7.4 and 8.1.** On 5.6, 7.3 and 8.4 it
   was not run (php-fpm covers the non-CLI SAPI there). PHP 5.4 was run on
   cli-server only: there is no official 5.4 Docker image for Apache and no
   \`cgi-fcgi\` in the 5.4 lab image for php-fpm (its whole php-fpm column is SKIP).
4. **Eight minors were not independently run**: ${notRunMinors.join(', ')}. Howdah's
   PHP bindings are per generation (php5, php7, php8) and each of these repeats a
   generation that did pass, but that is an expectation, not a test result, and
   is **not claimed as passing**. They have no lab base image yet.
5. **The input-shape rules refuse before the script; the request-header
   rules' 403 is post-hoc.** For both, the guaranteed mitigation is that Howdah
   **drops** the offending variable(s) (bounding the symbol table) and writes
   the event. \`$_GET\`, \`$_POST\` and \`$_COOKIE\` are built during request
   startup on every SAPI, so a block they latch is refused at the end of
   Howdah's RINIT, before the script (the refusal-path lab asserts the 403,
   the body and that the script did not run). \`$_SERVER\` is built lazily by
   default, so a header-count block is usually first seen while the script
   runs and its 403 is set at request shutdown, *after* the script may have
   produced output. The matrix asserts the **log line** for these rules, not
   the HTTP code, and records the observed code in the detail.
6. **Request-header counting depends on \`$_SERVER\` being materialized.** With
   PHP's \`auto_globals_jit=On\` (the default), the HTTP_* server vars our chained
   \`input_filter\` counts are built only when the application accesses
   \`$_SERVER\` — which every real framework does, and the lab app does so
   explicitly. An app that never touches \`$_SERVER\` on a JIT-globals SAPI can
   leave the header limit unexercised. The limit is counted exactly once the
   vars exist. With Layer 2 armed, Howdah builds \`$_SERVER\` at RINIT itself,
   which also makes the header rules pre-execution on that install.
7. **CVE-2012-1823 (php-cgi argument injection) is out of reach and NOT
   protected.** Lab testing proved the argv-injection query shape ("\`-s\`",
   "\`-d…\`") is consumed by php-cgi during its **own startup — before any PHP
   extension, module, or request (RINIT) hook loads** — so a check from inside a
   PHP extension can never fire for the attack. A configurable rule that can
   never fire would be a false promise, so the virtual patch was removed. This
   CVE belongs with CVE-2019-11043: both happen before extension code runs and
   are outside what Howdah, as a PHP extension, can defend. Use a web-server or
   front-proxy rule (or a patched php-cgi) to cover it.
8. **Platforms: Linux x86_64 and aarch64, NTS builds only.** Release tarballs
   are built on a glibc-2.17 baseline for both architectures. x86_64 covers all
   14 PHP minors (5.4 to 8.5). aarch64 builds every minor from PHP source on
   native arm64 CI runners (Remi has no aarch64 EL7 packages); PHP 5.4's 2008
   \`config.guess\` cannot identify an aarch64 host, so the build passes an
   explicit \`--build\` triple (releases before 1.2.2 shipped no 5.4 arm64
   tarball for that reason). The release assets are the definitive per-arch
   list. The core is arch-agnostic pure Rust. Every matrix result in the
   tables above was recorded on x86_64; the scenario matrix has not been run
   on arm64. On arm64 only the lab's block-shaped and self-test scripts have
   run, for 7.4 and 8.3, under QEMU and on native arm64 CI runners (Table 5;
   the non-blocking \`lab-aarch64\` job runs them on every pull request).
   A musl (Alpine) build exists for x86_64 only, from the release after 1.4.0.
   ZTS PHP has no build: [zts.md](zts.md).

## Reproduce

\`\`\`
lab/integration/matrix.sh 5.4 5.6 7.3 7.4 8.1 8.4     # cli + fpm
SAPIS=apache APPEND=1 lab/integration/matrix.sh 7.4 8.1  # append Apache mod_php
node site/scripts/gen-coverage.mjs                       # regenerate this file
\`\`\`

Memory measurements and the reasoning behind the default limits are in
[\`docs/coverage-data.md\`](coverage-data.md).

## Layer 2 (input inspection)

Layer 2 **detects and logs** SQLi, path-traversal and command-injection
*shapes* in GET/POST/cookie/path values; it does **not** block by default and
is best-effort, so it can be bypassed. Lab-verified end to end (GET and POST only) on PHP 8.3 and
7.4 (cli-server); the scanners are version-independent, so matching should be the
same on 5.4-8.5. Details: [coverage-data.md](coverage-data.md#howdah-10-layer-2-input-inspection-coverage-data-task-8). It is not part of the
tables above.

When a class is **armed** (\`[inspect] mode = "block"\` or a \`rule_modes\`
entry), the request is refused **before the script runs**: GET, POST and
cookie values are scanned while PHP builds the superglobals at request
startup, and Howdah builds \`$_SERVER\` at RINIT so the request path
(\`REQUEST_URI\`, \`PATH_INFO\`) is scanned there too. Header values are not a
Layer 2 input; the forced \`$_SERVER\` also moves the Layer 1 header count and
size limits in front of the script. The refusal-path lab (next section)
asserts, for a SQLi-, traversal- and command-injection-shaped \`q\` in GET, POST
and a cookie, and for a traversal shape in the raw request path, that the
answer is 403 with the Howdah body and that the script's side effect (a marker
file) did not happen, on PHP 5.6, 7.4 and 8.3 under php-fpm behind nginx and
under Apache mod_php prefork. Not claimed: other minors (expected to match by
generation, not run), php-cgi, header values, a raw body read through
\`php://input\`, variables past PHP's \`max_input_vars\`, and a superglobal PHP
never builds (\`variables_order\` without \`G\`/\`P\`/\`C\`,
\`enable_post_data_reading = Off\`).

## Refusal path (worker survival)

Releases up to 1.4.0 refused a request by unwinding (\`zend_bailout\`) out of
PHP's request startup. Under php-fpm that made the worker exit with code 70
(FPM respawned it per blocked request), nginx logged \`readv() failed (104:
Connection reset by peer)\`, the body with the request id was lost, and
\`howdah-check web\` reported "refused (HTTP 403) but not by Howdah". The matrix
above never saw it because it drives php-fpm with \`cgi-fcgi\` and reads only
the \`Status:\` header. The refusal is now delivered at the end of Howdah's
RINIT with the script kept from compiling; no longjmp. Design note:
\`docs/superpowers/specs/2026-10-24-howdah-refusal-path-design.md\`.

\`lab/integration/refusal.sh\` runs php-fpm with one static worker behind a real
nginx (a sidecar container sharing its network namespace) and Apache mod_php
prefork, and checks for every refusal: HTTP 403/413, the "Howdah blocked" body
with \`request_id\`, the script's marker file absent, the php-fpm worker pid
unchanged, no \`exited with code\` / \`exited on signal\` in the php-fpm log, no
\`readv()\`/\`Connection reset\` in nginx's error log, and \`tools/howdah-check web\`
through nginx reporting BLOCKED.

| scenario | php-fpm + nginx (5.6, 7.4, 8.3) | php-fpm via cgi-fcgi (7.4, 8.3) | Apache mod_php prefork (5.6, 7.4, 8.3) |
|---|---|---|---|
| Layer 1 multipart flood (\`max_parts\`), twice on one worker | refused before the script, worker alive | refused, worker alive | refused before the script, no child exit |
| the same flood under \`output_handler = ob_gzhandler\` | refused, no "headers already sent" warning | not run | not run |
| Layer 1 \`max_input_vars\` flood | refused before the script | not run | refused before the script |
| Layer 1 header flood (\`max_request_headers = 5\`) with Layer 2 armed | refused before the script (\`$_SERVER\` forced at RINIT) | not run | refused before the script |
| the same header flood, Layer 2 not armed, app never reads \`$_SERVER\` | 200, no event (limit unexercised: documented caveat 6) | not run | not run |
| armed Layer 2: SQLi in GET, POST, cookie; traversal; command injection | refused before the script | not run | refused before the script |
| armed Layer 2: traversal shape in the raw request path (\`REQUEST_URI\`) | refused before the script | not run | refused before the script |
| Layer 2 default (detect) | logged, script ran | not run | logged, script ran |
| Layer 4 \`deny_exec_dirs\` on the requested script | refused before the script, worker alive | not run | refused before the script |
| Layer 4 \`deny_exec_dirs\` on a CLI main script | "Howdah blocked" on stdout, script not run (CLI, not fpm) | n/a | n/a |
| armed Layer 3 \`command_exec\` sink | call returns false, script continues, worker alive | not run | not run |
| \`howdah-check web\` through the front | BLOCKED with request id | n/a | BLOCKED with request id |

Run on 2026-10-24: 116 checks passed, 0 failed, 1 skipped (no \`cgi-fcgi\` in
the 5.6 image; the nginx path covers php-fpm there). nginx's error log is
checked after every scenario, not only after the floods. The refused CLI main
script exits 0 on all three minors (see \`docs/config.md\`, "Enforcement timing"). The same lab against the
1.4.0 tree reproduces the bug on 8.3: five \`child N exited with code 70\`
lines, four nginx \`readv() failed (104)\` lines, an empty body on the Layer 4
refusal, and "refused (HTTP 403) but not by Howdah" from \`howdah-check web\`.
Not claimed: php-cgi (same startup code as php-fpm, not run), the CLI server
(covered by the other labs, which still pass), other minors.

## Layer 3 (sink hardening, 1.3 additions)

Layer 3 guards dangerous PHP functions. It detects and logs by default and does
not block unless a sink is explicitly armed. 1.3 adds the \`phar\` and \`ssrf\`
sinks (both **off by default**, armed only by an explicit per-sink mode) and
makes \`include\`/\`eval\` **active on PHP 5.x**. These results come from
\`lab/integration/sinks_fastfollow.sh\`, not from the matrix tables above.

| sink / mechanism | PHP 5.4-5.6 | PHP 7.0-7.4 | PHP 8.0-8.5 |
|---|---|---|---|
| \`phar://\` (wrapper proxy; off by default) | detect/deny + **deserialization** | detect/deny + **deserialization** | detect/deny **only**; no deserialization claim |
| SSRF (function swap + curl handle map; off by default) | yes, opt-in | yes, opt-in | yes, opt-in |
| \`include\` / \`eval\` | **now active** (include: opcache caveat; eval: full) | active | active |

Verified on PHP 5.4, 5.6, 7.4, 8.3 and 8.5. Other minors build and are expected
to work but are **not independently verified**. A debug-build leak review is
still pending.

### Legacy-era sinks (1.5 additions)

Seven cheaper sinks for functions and behaviours that mostly matter on the PHP
5.x/7.x third of the web; each is a no-op where the function no longer exists.
All inherit \`sinks.mode\` (log by default, block only when armed) and never log
the argument. From \`lab/integration/legacy_sinks.sh\`.

| sink (rule) | PHP 5.x | PHP 7.x | PHP 8.x |
|---|---|---|---|
| \`mail\` (\`mail_injection\`) | detect + block | detect + block | detect + block |
| \`preg_eval\` (\`preg_eval\`) | detect + block | **not covered** (/e removed in 7.0) | **not covered** |
| \`create_function\` (\`create_function\`) | detect + block | detect + block | **not covered** (removed in 8.0) |
| \`assert\` (\`assert_string\`) | detect + block | detect + block | **not covered** (8.0 stopped evaluating strings) |
| \`callback\` (\`dangerous_callback\`) | detect + block | detect + block | detect + block |
| \`xml\` (\`xxe\`) | detect + block | detect + block | detect + block |
| \`tls\` (\`tls_verify\`) | detect only | detect only | detect only |

Verified on PHP 5.4, 5.6, 7.4 and 8.3. Limitations, stated plainly:

- **\`preg_eval\`, \`create_function\` and string \`assert\` fire nothing** on the
  PHP versions where the function or modifier is gone (7.0+ for \`/e\`, 8.0+ for
  \`create_function\` and string \`assert\`). The \`Layer-3 legacy sinks\` row of
  \`php --ri howdah\` names what installed on a given PHP.
- **The \`callback\` sink matches a string callback name only.** An array,
  closure, first-class callable or variable function callback is not matched,
  and a callback reached through a function Howdah does not hook is not seen.
  **On PHP 7.0+ a literal, unqualified \`call_user_func\` /
  \`call_user_func_array\` in the global namespace is compiled to
  \`ZEND_INIT_USER_CALL\` and never calls the function, so that shape is not
  seen there** (a namespaced or dynamic call, and the other hooked functions,
  are); PHP 5.x sees every form. Pinned per version by the lab.
- **The \`xml\` sink sees \`simplexml_load_string\` and \`DOMDocument::loadXML\`
  only**, and only the first 64 KiB of a document; \`new SimpleXMLElement\`,
  \`simplexml_import_dom\`, \`XMLReader\`, ext/xml (\`xml_parse\`),
  \`DOMDocument::loadHTML\` and the by-path readers (\`simplexml_load_file\`,
  \`DOMDocument::load\`, \`XMLReader::open\`) are not hooked. A hit is the
  *declaration*, not proof the entity was fetched; a bare external DTD
  reference (the XHTML/SVG doctypes) is detect only and never blocked.
  \`[sinks.xml] external_entities = "deny"\` is a libxml-level toggle (off by
  default) that also disables loading documents by path through libxml; PHP 8
  already defaults to not substituting external entities.
- **\`tls\` cannot block in this release** (detect only): a block mode is logged,
  the call proceeds. Only the option name is logged, never the URL.
- **\`mail\`** matches the one-string first/4th/5th arguments only; an array of
  headers (PHP 7.2+) is left to PHP, and extra \`Bcc:\`-style headers that look
  like headers are not flagged.

Limitations, stated plainly:

- **phar on 8.x is detection and denial, not deserialization coverage.** On
  5.x/7.x the claim is phar metadata deserialization via the stream wrapper
  (filesystem functions and \`include\`).
- **The direct Phar API is a gap:** \`new Phar\`, \`PharData\`, \`Phar::loadPhar\`,
  \`Phar::mapPhar\` and \`Phar::getMetadata\` unserialize before any wrapper
  operation. \`stream_wrapper_unregister\` then \`stream_wrapper_restore\` of
  \`phar\` is untested; another extension re-registering \`phar\`, or a static phar
  build, fails open.
- **SSRF is best-effort, resolve-at-check-time detection, not a connection-time
  boundary.** Bypasses: DNS rebinding, redirects to a new host, \`curl_multi_*\`,
  \`CURLOPT_RESOLVE\`/\`CONNECT_TO\`, and a non-string or absent \`CURLOPT_URL\`.
- **Not hooked:** \`copy\`, \`file\`, \`readfile\`, \`SoapClient\`,
  \`DOMDocument::load*\`, \`simplexml_load_file\`.
- A blocked \`fsockopen\`/\`stream_socket_client\` leaves \`$errno\`/\`$errstr\` unset;
  a blocked \`curl_exec\` returns false with \`curl_errno\` 0.
- Enabling SSRF adds a \`getaddrinfo\` per distinct outbound host with **no
  timeout**. More than 32 resolved addresses are capped; a host over 256 bytes
  is treated as suspicious.
- **PHP 5.x \`include\` is checked at compile time only:** a file served from a
  **warm opcache** is not re-inspected. \`eval\` is never cached and is fully
  covered. On 7.0+ the default opcode handler is not affected by opcache; with
  \`[sinks] hook = "compile"\` the 5.x caveat applies there too.
- **OPcache JIT (PHP 8.0+).** PHP turns its JIT off while any user opcode
  handler is installed, and one of the two include/eval mechanisms is one.
  Nothing is installed unless the \`eval\` sink is on, the \`include\` sink has
  \`allow_paths\`, or \`[behavior] deny_exec_dirs\` is set. The default
  \`[sinks] hook = "auto"\` uses the compile pointer when only \`eval\` needs the
  hook (the shipped default), so **a default install keeps the JIT on**; it
  uses the opcode handler when \`include\` has \`allow_paths\` or
  \`deny_exec_dirs\` is set (where warm-opcache includes matter), and
  \`hook = "compile"\` keeps the JIT on even then. \`lab/integration/jit.sh\`
  asserts \`opcache_get_status()['jit']['on']\` in each state on PHP 8.1 and
  8.3 (default config: on, with eval detect still logging; include
  \`allow_paths\`: off; \`hook = "compile"\`: on) and shows the warm-opcache
  caveat (two includes of one file: two events in \`opcode\` mode, one in
  \`compile\` mode); compile-mode include/eval behaviour is also checked on 7.4
  and 5.6.

## Performance and the OPcache JIT

Measured request latency with and without Howdah, the OPcache JIT result and
what Layer 2 flags of the GoTestWAF corpus are in
[docs/performance.md](performance.md) (on the site: /docs/performance/).

- The published JIT run (\`lab/bench/jit.sh\`, Howdah 1.3.0 at commit
  \`2e3109e\`, before [#42](https://github.com/howdah/howdah/pull/42))
  measured \`opcache_get_status()['jit']['on']\` false with Howdah loaded on
  PHP 8.1, 8.3 and 8.5 (CLI and php-fpm, \`opcache.jit=tracing\`), with PHP's
  startup warning "JIT is incompatible with third party extensions that setup
  user opcode handlers. JIT disabled."; the integration suite passed the same
  scenarios with the JIT configured only because the JIT was off. The current
  behaviour is the OPcache JIT item above (#42); \`lab/bench/jit.sh\` has **not**
  been re-run against it yet.
`;
// The Layer 2 section above was first added to docs/coverage.md by hand (PR
// #18) without this generator knowing about it; it lives here now so a
// regeneration keeps it.
writeFileSync(resolve(repo, 'docs/coverage.md'), md);
console.log(`coverage: ${rows.length} rows, ${P} pass / ${F} fail / ${S} skip; not-run minors: ${notRunMinors.join(',')}`);
