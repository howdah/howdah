// Build-output checks for the config editor page. Runs `astro build` once
// unless dist/config/index.html is newer than the page source.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = resolve(site, 'dist/config/index.html');
const src = resolve(site, 'src/pages/config.astro');

function fresh() {
  return existsSync(out) && existsSync(src) && statSync(out).mtimeMs >= statSync(src).mtimeMs;
}
if (!fresh()) {
  const r = spawnSync('npm', ['run', 'build'], { cwd: site, encoding: 'utf8' });
  if (r.status !== 0) console.error(r.stdout, r.stderr);
}
const html = existsSync(out) ? readFileSync(out, 'utf8') : '';

test('the config page is built', () => {
  assert.ok(existsSync(out), 'dist/config/index.html missing');
});

test('server-rendered defaults are present for no-JS readers', () => {
  assert.match(html, /mode = (&quot;|")detect(&quot;|")/);
  assert.ok(html.includes('extension=howdah.so'));
  assert.ok((html.match(/<fieldset/g) || []).length >= 4, 'fieldsets');
});

test('the docs, configuration and install pages link to the editor', () => {
  for (const p of ['docs/configuration/index.html', 'docs/index.html', 'install/index.html']) {
    const f = resolve(site, 'dist', p);
    assert.ok(existsSync(f), p + ' missing');
    assert.ok(readFileSync(f, 'utf8').includes('href="/config/"'), p + ' has no link to /config/');
  }
});

test('live region, scripts and no third-party hosts', () => {
  assert.ok(html.includes('aria-live="polite"'));
  assert.ok(html.includes('/config/editor.js'));
  assert.ok(html.includes('/config/schema.js'));
  assert.ok(html.includes('/demo/howdah-wasm.js'));
  const hosts = [...html.matchAll(/https?:\/\/([^/"'\s<>)]+)/g)].map((m) => m[1]);
  const allowed = new Set(['howdah.org', 'pkg.howdah.org', 'cfg.howdah.org', 'github.com', 'www.w3.org']);
  for (const h of hosts) assert.ok(allowed.has(h), 'unexpected host ' + h);
});
