// Build-output checks for the compliance evidence page (/docs/compliance/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ensureBuilt, site } from './build-site.mjs';

const out = resolve(site, 'dist/docs/compliance/index.html');
const srcs = [
  'src/pages/docs/compliance.astro',
  'src/pages/docs/index.astro',
  'src/components/Footer.astro',
  'src/lib/site.ts',
].map((p) => resolve(site, p));

ensureBuilt(out, srcs);
const html = existsSync(out) ? readFileSync(out, 'utf8') : '';
const read = (p) => readFileSync(resolve(site, 'dist', p), 'utf8');

test('the compliance page is built', () => {
  assert.ok(existsSync(out), 'dist/docs/compliance/index.html missing');
});

test('it covers PCI DSS requirement 6.4.2', () => {
  assert.ok(html.includes('6.4.2'), 'no "6.4.2" on the page');
});

test('the docs index and the footer link to it', () => {
  const docs = read('docs/index.html');
  const footer = docs.match(/<footer[\s\S]*<\/footer>/)?.[0] ?? '';
  assert.ok(docs.replace(footer, '').includes('href="/docs/compliance/"'), 'docs index body has no link');
  assert.ok(footer.includes('href="/docs/compliance/"'), 'footer has no link');
});

test('it says plainly what it is not', () => {
  assert.match(html, /not legal advice/i);
  assert.match(html, /no third-party (security )?audit/i);
});

test('every log field the core writes is documented', () => {
  // The field list is read from the core so the page cannot drift from it.
  const src = readFileSync(resolve(site, '../crates/howdah-core/src/log.rs'), 'utf8');
  const body = src.match(/serde_json::json!\(\{([\s\S]*?)\}\)/)?.[1] ?? '';
  const fields = [...body.matchAll(/"(\w+)":/g)].map((m) => m[1]);
  assert.equal(fields.length, 8, 'unexpected log_line shape in log.rs');
  // Scoped styles add data-astro-cid-* attributes, so allow attributes on <code>.
  for (const f of fields) assert.match(html, new RegExp(`<code[^>]*>${f}</code>`), `field ${f} not documented`);
});
