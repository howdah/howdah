// Build-output checks for the performance page (/docs/performance/). Its
// numbers come from src/data/performance.json, which lab/bench/bench.mjs
// `publish` writes from a real benchmark run; docs/performance.md carries the
// same tables in the repository.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ensureBuilt, site } from './build-site.mjs';

const repo = resolve(site, '..');
const out = resolve(site, 'dist/docs/performance/index.html');
const dataPath = resolve(site, 'src/data/performance.json');
ensureBuilt(out, [
  'src/pages/docs/performance.astro',
  'src/pages/docs/index.astro',
  'src/pages/coverage.astro',
  'src/data/performance.json',
  'src/layouts/Layout.astro',
  'src/lib/site.ts',
].map((p) => resolve(site, p)));

const html = existsSync(out) ? readFileSync(out, 'utf8') : '';
const data = existsSync(dataPath) ? JSON.parse(readFileSync(dataPath, 'utf8')) : null;
// Text content with tags removed and whitespace collapsed, for phrase checks.
const text = html.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#39;|&apos;/g, "'")
  .replace(/&quot;/g, '"').replace(/\s+/g, ' ');

test('the performance page is built', () => {
  assert.ok(existsSync(out), 'dist/docs/performance/index.html missing');
});

test('the docs index and the coverage page link to it', () => {
  for (const p of ['docs/index.html', 'coverage/index.html']) {
    const f = resolve(site, 'dist', p);
    assert.ok(existsSync(f), p + ' missing');
    assert.ok(readFileSync(f, 'utf8').includes('href="/docs/performance/"'), p + ' has no link to /docs/performance/');
  }
});

test('the data covers PHP 5.6, 7.4 and 8.3 on php-fpm and Apache, every config and workload, all valid', () => {
  assert.ok(data, 'src/data/performance.json missing');
  const cells = data.latency.cells;
  for (const minor of ['5.6', '7.4', '8.3']) {
    for (const sapi of ['fpm', 'apache']) {
      for (const workload of ['get_nobody', 'post_form_1k', 'post_multipart_50k', 'sink_exec_include']) {
        for (const config of ['noext', 'l1', 'l12', 'l123']) {
          const c = cells.find((x) => x.minor === minor && x.sapi === sapi && x.workload === workload && x.config === config);
          assert.ok(c, `missing cell ${minor} ${sapi} ${workload} ${config}`);
          assert.equal(c.valid, true, `invalid cell ${minor} ${sapi} ${workload} ${config}`);
          assert.equal(c.events, 0, `benign traffic logged events in ${minor} ${sapi} ${workload} ${config}`);
        }
      }
    }
  }
});

test('the page shows the run date, machine spec, method and exact commands', () => {
  const m = data.latency.machine;
  assert.ok(text.includes(m.date_utc.slice(0, 10)), 'run date');
  assert.ok(text.includes(m.cpu_model), 'CPU model');
  assert.ok(text.includes(m.kernel), 'kernel');
  assert.ok(text.includes(`${m.nproc} CPUs`), 'nproc');
  for (const cmd of ['sh lab/bench/run.sh', 'sh lab/bench/corpus.sh', 'sh lab/bench/jit.sh']) {
    assert.ok(text.includes(cmd), `command ${cmd}`);
  }
  for (const label of ['GET, no body', 'POST, 1 KB form', 'POST, 50 KB multipart (10 parts)', "GET, system('true') + include"]) {
    assert.ok(text.includes(label), `workload ${label}`);
  }
  for (const php of new Set(data.latency.cells.map((c) => c.php))) {
    assert.ok(text.includes(php), `PHP ${php}`);
  }
});

test('the JIT result is stated as measured, with its cause', () => {
  assert.ok(text.includes('JIT is incompatible with third party extensions that setup user opcode handlers. JIT disabled.'));
  assert.ok(text.includes('sink_hook.c'));
  assert.ok(text.includes('opcache_get_status'));
  // The published run predates the fix; the page must point at it.
  assert.ok(html.includes('/pull/42'), 'link to the JIT fix');
  assert.ok(text.includes('hook = "opcode"'));
  for (const r of data.jit.results) assert.ok(text.includes(r.php), `JIT result for PHP ${r.php}`);
  // 8.x latency numbers are without the JIT; the page must say so.
  assert.match(text, /without the JIT/i);
});

test('the detection table is framed as what Layer 2 flags, not a WAF score', () => {
  assert.match(text, /not a WAF score/i);
  const b = data.corpus.totals.benign;
  assert.ok(text.includes(`${b.flagged}/${b.reached}`), 'false-positive count');
  assert.ok(text.includes(data.corpus.meta.gotestwaf_version), 'GoTestWAF version');
});

test('docs/performance.md exists and docs/coverage.md links to it', () => {
  const md = resolve(repo, 'docs/performance.md');
  assert.ok(existsSync(md), 'docs/performance.md missing');
  assert.ok(readFileSync(resolve(repo, 'docs/coverage.md'), 'utf8').includes('(performance.md)'), 'docs/coverage.md has no link to performance.md');
});

test('no third-party hosts on the page', () => {
  const hosts = [...html.matchAll(/https?:\/\/([^/"'\s<>)]+)/g)].map((m) => m[1]);
  const allowed = new Set(['howdah.org', 'pkg.howdah.org', 'cfg.howdah.org', 'github.com', 'www.w3.org']);
  for (const h of hosts) assert.ok(allowed.has(h), 'unexpected host ' + h);
});
