// Coverage outside the matrix: every run recorded in
// lab/integration/runtime-results.tsv (LSAPI, Docker images, Alpine, arm64,
// ZTS) reaches docs/coverage.md's Table 5 and the site's coverage page, with
// its own result, and nothing else does. Builds the site once if
// dist/coverage/index.html is older than its sources.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ensureBuilt, site } from './build-site.mjs';

const repo = resolve(site, '..');
const out = resolve(site, 'dist/coverage/index.html');
ensureBuilt(out, ['src/pages/coverage.astro', 'scripts/gen-coverage.mjs', '../lab/integration/runtime-results.tsv']
  .map((p) => resolve(site, p)));
const html = existsSync(out) ? readFileSync(out, 'utf8') : '';
const md = readFileSync(resolve(repo, 'docs/coverage.md'), 'utf8');
const table5 = md.slice(md.indexOf('## Table 5'), md.indexOf('## Honest caveats'));
const runs = readFileSync(resolve(repo, 'lab/integration/runtime-results.tsv'), 'utf8').split('\n')
  .filter((l) => l.trim() && !l.startsWith('##'))
  .map((l) => { const [date, runtime, sapi, php, arch, script, result] = l.split('\t'); return { date, runtime, sapi, php, arch, script, result }; });
const decode = (s) => s.replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>');

test('runtime-results.tsv has the runs this change recorded', () => {
  assert.ok(runs.length >= 5, `rows: ${runs.length}`);
  for (const r of runs) assert.match(r.result, /^(PASS|FAIL)$/, `result of ${r.runtime}`);
  assert.ok(runs.some((r) => r.sapi === 'litespeed' && r.result === 'PASS'), 'an LSAPI run');
  assert.ok(runs.some((r) => r.sapi === 'frankenphp' && r.result === 'FAIL'), 'the failed ZTS run');
});

test('docs/coverage.md Table 5 lists every run, its arch and its result', () => {
  assert.ok(table5.includes('| Runtime / SAPI |'), 'Table 5 missing from docs/coverage.md');
  for (const r of runs) {
    const line = table5.split('\n').find((l) => l.startsWith(`| ${r.runtime} (\`${r.sapi}\`) | ${r.arch} |`) && l.includes(r.php));
    assert.ok(line, `no Table 5 row for ${r.runtime} / ${r.arch} / PHP ${r.php}`);
    assert.ok(line.includes(r.result === 'PASS' ? '| PASS (' : '| **FAIL** ('), `wrong result for ${r.runtime} ${r.php}`);
  }
});

test('the coverage page shows the same runs, failures as failed', () => {
  assert.ok(existsSync(out), 'dist/coverage/index.html missing');
  const page = decode(html);
  assert.ok(page.includes('Other server types and runtimes'), 'section heading');
  const sect = page.slice(page.indexOf('id="runtimes"'));
  for (const r of runs) {
    assert.ok(sect.includes(r.runtime), `page has no row for ${r.runtime}`);
    assert.ok(sect.includes(r.php), `page has no PHP ${r.php} for ${r.runtime}`);
  }
  // One card per run: the ZTS card carries the "failed" pill, and every card's
  // pill matches its recorded result.
  const cards = sect.split(/<li class="run /).slice(1).map((c) => c.slice(0, c.indexOf('</li>')));
  assert.equal(cards.length, new Set(runs.map((r) => `${r.runtime}|${r.arch}|${r.script}|${r.result}`)).size, 'one card per distinct run');
  const zts = cards.find((c) => c.includes('FrankenPHP'));
  assert.match(zts ?? '', /class="pill no"[^>]*>failed</, 'the ZTS run is shown as failed');
  for (const c of cards) {
    assert.match(c, c.startsWith('run-ok') ? /class="pill ok"[^>]*>passed</ : /class="pill no"[^>]*>failed</, 'card pill matches its result');
  }
  assert.ok(page.includes('docs/zts.md'), 'the page links the ZTS findings');
});
