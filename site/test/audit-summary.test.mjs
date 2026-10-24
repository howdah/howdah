// scripts/audit-summary.mjs turns `npm audit --json` into the CI deps job's
// step summary and a ::warning:: annotation (ci.yml). No network: the reports
// below are trimmed copies of the real shape.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { site } from './build-site.mjs';

const script = resolve(site, 'scripts/audit-summary.mjs');

function run(input, { summary = true } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'audit-summary-'));
  const file = join(dir, 'summary.md');
  const env = { ...process.env };
  delete env.GITHUB_STEP_SUMMARY;
  if (summary) env.GITHUB_STEP_SUMMARY = file;
  const r = spawnSync(process.execPath, [script], { input, env, encoding: 'utf8' });
  let md = '';
  try { md = readFileSync(file, 'utf8'); } catch { /* no summary written */ }
  rmSync(dir, { recursive: true, force: true });
  return { status: r.status, stdout: r.stdout, md };
}

const adv = (name, severity, id, title, range) =>
  ({ source: 1, name, dependency: name, title, url: `https://github.com/advisories/${id}`, severity, range });

const findings = JSON.stringify({
  auditReportVersion: 2,
  vulnerabilities: {
    astro: {
      name: 'astro', severity: 'critical', isDirect: true, range: '<=7.3.1',
      via: [
        adv('astro', 'moderate', 'GHSA-376h-93r7-7g6f', 'Authorization bypass | base path', '<=7.2.3'),
        adv('astro', 'critical', 'GHSA-26w7-cxv4-gfx2', 'Remote code execution through AVIF image optimization', '<7.2.8'),
        adv('astro', 'high', 'GHSA-2pvr-wf23-7pc7', 'Host header SSRF in prerendered error page fetch', '<6.4.6'),
        adv('astro', 'low', 'GHSA-j687-52p2-xcff', 'XSS via incomplete </script> tag sanitization', '<6.1.6'),
        'sharp', 'zod',
      ],
      fixAvailable: { name: 'astro', version: '7.4.1', isSemVerMajor: true },
    },
    sharp: {
      name: 'sharp', severity: 'high', isDirect: false, range: '<=0.35.5-rc.1',
      via: [adv('sharp', 'high', 'GHSA-f88m-g3jw-g9cj', 'sharp inherited vulnerabilities in libvips', '<0.35.5')],
      fixAvailable: { name: 'astro', version: '7.4.1', isSemVerMajor: true },
    },
    zod: {
      name: 'zod', severity: 'high', isDirect: false, range: '<4.6.6',
      via: [adv('zod', 'high', 'GHSA-mrhx-c7xc-m3w5', 'Zod can exhaust memory', '<4.6.6')],
      fixAvailable: { name: 'astro', version: '7.4.1', isSemVerMajor: true },
    },
    esbuild: {
      name: 'esbuild', severity: 'low', isDirect: false, range: '0.27.3 - 0.28.0',
      via: [adv('esbuild', 'low', 'GHSA-g7r4-m6w7-qqqr', 'esbuild dev server file read on Windows', '0.27.3 - 0.28.0')],
      fixAvailable: true,
    },
  },
  metadata: { vulnerabilities: { info: 0, low: 1, moderate: 0, high: 2, critical: 1, total: 4 } },
});

const clean = JSON.stringify({
  auditReportVersion: 2, vulnerabilities: {},
  metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } },
});

// Findings exit 0: the ::warning:: annotation and the summary carry them. A
// non-zero exit would add a "Process completed with exit code 1" error
// annotation to every PR, which is the red-by-design noise this avoids.
test('findings: exit 0, counts by severity in the summary', () => {
  const r = run(findings);
  assert.equal(r.status, 0);
  assert.match(r.md, /4 vulnerable packages: 1 critical, 2 high, 1 low/);
});

test('findings: advisories listed most severe first, each linked, pipes escaped', () => {
  const r = run(findings);
  const rows = r.md.split('\n').filter((l) => l.startsWith('| ') && l.includes('GHSA-'));
  assert.equal(rows.length, 7);
  assert.match(rows[0], /critical .*astro .*\[GHSA-26w7-cxv4-gfx2\]\(https:\/\/github\.com\/advisories\/GHSA-26w7-cxv4-gfx2\)/);
  assert.match(rows.at(-1), /low .*esbuild/);
  assert.ok(r.md.includes('Authorization bypass \\| base path'), 'a | in a title breaks the table');
  assert.ok(r.md.includes('incomplete &lt;/script&gt; tag') && !r.md.includes('</script>'), 'raw HTML in a title');
  assert.ok(r.md.includes('| &lt;7.2.8 |'), 'ranges are escaped too');
});

test('findings: the fix that npm offers is named, with a major-version note', () => {
  assert.match(run(findings).md, /astro@7\.4\.1 \(major version\)/);
});

test('findings: one ::warning:: annotation with the counts and the top advisory ids', () => {
  const w = run(findings).stdout.split('\n').filter((l) => l.startsWith('::warning'));
  assert.equal(w.length, 1);
  assert.match(w[0], /^::warning title=npm audit::4 vulnerable packages \(1 critical, 2 high, 1 low\)/);
  assert.match(w[0], /GHSA-26w7-cxv4-gfx2, GHSA-2pvr-wf23-7pc7/);
});

test('a clean report: exit 0, says so, no annotation', () => {
  const r = run(clean);
  assert.equal(r.status, 0);
  assert.match(r.md, /No known vulnerabilities/);
  assert.ok(!r.stdout.includes('::warning'));
});

test('not an npm audit report: exit 2 with an error annotation', () => {
  for (const input of ['npm ERR! network', '{"error": {"code": "ENOAUDIT"}}']) {
    const r = run(input);
    assert.equal(r.status, 2, input);
    assert.match(r.stdout, /^::error title=npm audit::/m);
  }
});

test('without GITHUB_STEP_SUMMARY the Markdown goes to stdout', () => {
  const r = run(findings, { summary: false });
  assert.match(r.stdout, /### npm audit/);
});
