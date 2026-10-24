// Build-output checks for the release verification page (/docs/verify/), and
// that what it tells users to run matches docs/verify.md and the workflows
// that produce what it verifies.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ensureBuilt, site } from './build-site.mjs';

const out = resolve(site, 'dist/docs/verify/index.html');
const srcs = [
  'src/pages/docs/verify.astro',
  'src/pages/docs/index.astro',
  'src/pages/install.astro',
  'src/components/Footer.astro',
  'src/lib/site.ts',
].map((p) => resolve(site, p));

ensureBuilt(out, srcs);
const html = existsSync(out) ? readFileSync(out, 'utf8') : '';
const read = (p) => readFileSync(resolve(site, 'dist', p), 'utf8');
const repo = (p) => readFileSync(resolve(site, '..', p), 'utf8');
// The page as text: tags dropped, the entities Astro emits decoded.
const text = html
  .replace(/<[^>]+>/g, '')
  .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

// Commands users copy. Each must be on the page AND in docs/verify.md, the
// versioned source of truth, so the two cannot drift apart.
const commands = [
  'curl -fsSL https://howdah.org/key.asc | gpg --show-keys --with-fingerprint',
  'gpg --verify SHA256SUMS.asc SHA256SUMS',
  'sha256sum -c --ignore-missing SHA256SUMS',
  '--signer-workflow howdah/howdah/.github/workflows/release.yml',
  '--certificate-oidc-issuer https://token.actions.githubusercontent.com',
  '--certificate-identity "https://github.com/howdah/howdah/.github/workflows/release.yml@refs/tags/v$V"',
  '--type slsaprovenance1',
  '--predicate-type https://cyclonedx.org/bom',
  'packaging/verify-reproducible.sh v1.5.0 7.4',
];

test('the verify page is built', () => {
  assert.ok(existsSync(out), 'dist/docs/verify/index.html missing');
});

test('it shows the primary key fingerprint', () => {
  const fpr = repo('site/src/lib/site.ts').match(/KEY_FPR = '([^']+)'/)?.[1];
  assert.ok(fpr, 'KEY_FPR not found in site.ts');
  assert.ok(text.includes(fpr), 'fingerprint not on the page');
  assert.ok(repo('docs/verify.md').includes(fpr), 'fingerprint not in docs/verify.md');
});

test('every command is on the page and in docs/verify.md', () => {
  const md = repo('docs/verify.md');
  for (const c of commands) {
    assert.ok(text.includes(c), `page lacks: ${c}`);
    assert.ok(md.includes(c), `docs/verify.md lacks: ${c}`);
  }
});

test('what it verifies is produced: provenance and SBOM in release.yml, provenance in publish-repos.yml', () => {
  const rel = repo('.github/workflows/release.yml');
  assert.match(rel, /actions\/attest-build-provenance@/);
  assert.match(rel, /sbom-path:/);
  assert.match(rel, /\*\.sigstore\.json/);
  assert.match(repo('.github/workflows/publish-repos.yml'), /actions\/attest-build-provenance@/);
  assert.ok(existsSync(resolve(site, '../packaging/verify-reproducible.sh')), 'verify-reproducible.sh missing');
});

test('it says plainly what is not covered', () => {
  assert.match(text, /no third-party security audit/i);
  assert.match(text, /1\.4\.0 and earlier have no attestations/i);
  assert.match(text, /not byte-reproducible/i);
});

test('the docs index, the install page and the footer link to it', () => {
  const docs = read('docs/index.html');
  const footer = docs.match(/<footer[\s\S]*<\/footer>/)?.[0] ?? '';
  assert.ok(docs.replace(footer, '').includes('href="/docs/verify/"'), 'docs index body has no link');
  assert.ok(footer.includes('href="/docs/verify/"'), 'footer has no link');
  assert.ok(read('install/index.html').includes('href="/docs/verify/"'), 'install page has no link');
});
