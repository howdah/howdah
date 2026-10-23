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
const verByMinor = {};
for (const v of Object.keys(cells)) verByMinor[minorOf(v)] = v;

function sapiSummary(ver, sapi) {
  const s = cells[ver]?.[sapi];
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
  const ver = verByMinor[minor];
  if (!ver) {
    const nr = notRun.find((n) => n.minor === minor);
    const why = minor === '5.5'
      ? 'Not tested yet: no test image could be built for 5.5.'
      : 'Not tested yet: no test environment built.';
    rows.push({ minor, version: null, status: 'not-run', why, sapis: {}, tested: [] });
    continue;
  }
  const sapis = {};
  for (const sp of SAPIS) {
    const sum = sapiSummary(ver, sp);
    let note = '';
    if (sum.state === 'none') {
      const nr = notRun.find((n) => n.minor === minor && n.sapis.split(/\s+/).includes(sp));
      note = nr ? nr.why : '';
    }
    if (sum.state === 'skip') note = cells[ver][sp].selftest?.detail || 'skipped';
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
const notRunMinors = ALL_MINORS.filter((m) => !verByMinor[m]);

const data = {
  generated, source: 'lab/integration/matrix-results.tsv',
  totals: { pass: P, fail: F, skip: S }, corpusFalsePositives: corpusBad,
  rows, notRunMinors,
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
// CGI (CVE-2012-1823) fire-path status, read from the dedicated cgi rows.
const cgiStatus = (() => {
  const row = Object.keys(cells).map((v) => cells[v]?.cgi).find((c) => c && (c.cgi_arg_safe || c.cgi_arg_injection));
  if (!row) return { tested: false };
  return {
    tested: true,
    safe: row.cgi_arg_safe?.result, // PASS = legit '-' query not false-blocked
    fire: row.cgi_arg_injection?.result, // SKIP = fire-path not reproducible
    detail: row.cgi_arg_injection?.detail || '',
  };
})();

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
variables and logging, and their 403 response is **best-effort** (it may land at
request shutdown, after the script, on JIT-globals SAPIs). The php-cgi
argument-injection virtual patch (CVE-2012-1823) is **not** claimed as working
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
blocking in detect), the Layer-1 input/header scenarios (Table 3), the CGI
virtual-patch checks where a php-cgi binary exists (Table 4), and the full
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
*Enforcement is best-effort on the response:* these rules **drop** the offending
variable(s) (bounding the symbol table — the actual DoS mitigation) and write the
event; the 403 may be emitted at request shutdown, after the script, on SAPIs
that populate superglobals lazily. See caveats 5–7.

## Table 4: known-CVE & DoS coverage

| threat | defense (rule) | status |
|---|---|---|
| **CVE-2023-0662** — too-many-parts memory DoS | \`max_parts\` (2000) | Blocked wherever Table 1's field/part-flood column is green; same scenario, cross-referenced. |
| **Hash-collision / variable flood** (symbol-table DoS) | \`max_input_vars\` (2000) | Var-dropped + logged, then best-effort 403; Enforced on the SAPIs in Table 3's \`max_input_vars\` column. |
| **Array-nesting DoS** (deep \`a[b][c]…\`) | \`max_input_nesting_depth\` (64) | Var-dropped + logged, then best-effort 403; Enforced on the SAPIs in Table 3's nesting column. |
| **CVE-2012-1823** — php-cgi argument injection | \`cgi_arg_injection\` (virtual patch) | ${cgiStatus.tested
    ? `Detection is unit-tested in the core (\`cgi_arg_injection\`), and the legitimate-\`-\`-in-query guard **passes** under the real CGI SAPI (${cgiStatus.safe || 'n/a'}). The **fire path is NOT verified** and the patch does **not** block the attack on the only php-cgi available (5.4.16): that build is itself already patched, and the argv-injection query shape is consumed by php-cgi during its own startup **before** our module's RINIT runs, so the virtual patch never fires. No vulnerable php-cgi was available to test against. **Not claimed as blocking CVE-2012-1823.** See caveat 7.`
    : 'No php-cgi binary was present in any lab image, so the fire path is lab-unverified (detection is core-unit-tested only). **Not claimed as blocking CVE-2012-1823.** See caveat 7.'} |

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
5. **The input-shape and request-header rules are enforced on the response as
   best-effort.** The guaranteed mitigation is that Howdah **drops** the
   offending variable(s) (bounding the symbol table) and writes the event; the
   403 may be emitted at request shutdown, *after* the script has produced
   output, so the HTTP status can be 200 with the block notice appended. The
   matrix asserts the **log line** for these rules, not the HTTP code, and
   records the observed code in the detail.
6. **Request-header counting depends on \`$_SERVER\` being materialized.** With
   PHP's \`auto_globals_jit=On\` (the default), the HTTP_* server vars our chained
   \`input_filter\` counts are built only when the application accesses
   \`$_SERVER\` — which every real framework does, and the lab app does so
   explicitly. An app that never touches \`$_SERVER\` on a JIT-globals SAPI can
   leave the header limit unexercised. The limit is counted exactly once the
   vars exist.
7. **The php-cgi virtual patch (CVE-2012-1823) is NOT verified to block the
   attack, and on the tested build does not.** The \`cgi_arg_injection\` detection
   is unit-tested in the core and the legitimate-\`-\`-in-query false-positive
   guard passes under the real CGI SAPI, but the only php-cgi in the lab
   (5.4.16) is itself already patched *and* consumes an argv-injection query
   ("\`-s\`", "\`-d…\`") during its own startup **before** any module request hook
   runs — so our RINIT-based patch is never reached. We make **no claim** that
   Howdah blocks CVE-2012-1823 via this path; a vulnerable php-cgi would be
   needed to settle whether the \`-d…\`-RCE variant (which does continue to the
   request) can be caught in RINIT, and none was available.
8. Linux x86_64, NTS builds only.

## Reproduce

\`\`\`
lab/integration/matrix.sh 5.4 5.6 7.3 7.4 8.1 8.4     # cli + fpm
SAPIS=apache APPEND=1 lab/integration/matrix.sh 7.4 8.1  # append Apache mod_php
node site/scripts/gen-coverage.mjs                       # regenerate this file
\`\`\`

Memory measurements and the reasoning behind the default limits are in
[\`docs/coverage-data.md\`](coverage-data.md).
`;
writeFileSync(resolve(repo, 'docs/coverage.md'), md);
console.log(`coverage: ${rows.length} rows, ${P} pass / ${F} fail / ${S} skip; not-run minors: ${notRunMinors.join(',')}`);
