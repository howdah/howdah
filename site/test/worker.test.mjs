// The cfg.howdah.org fetch handler, driven in Node with a locally instantiated
// wasm: a pure function of the URL, validated by the real core.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { handle } from '../worker/handle.js';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const H = require('../demo/howdah-wasm.js');
const E = require('../config-editor/editor.js');
const x = await H.loadFrom(readFileSync(resolve(here, '../demo/howdah_wasm.wasm')));
const VERSION = '1.2.1';
const req = (path, init) => new Request('https://cfg.howdah.org' + path, init);
const run = (path, init) => handle(req(path, init), x, VERSION);

test('valid payload returns the TOML with the pinned headers', async () => {
  const toml = 'mode = "detect"\n';
  const r = await run('/v1/' + await E.encodePayload(toml));
  assert.equal(r.status, 200);
  assert.equal(await r.text(), toml);
  assert.equal(r.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(r.headers.get('content-disposition'), 'inline; filename="howdah.toml"');
  assert.equal(r.headers.get('cache-control'), 'public, max-age=31536000, immutable');
  assert.equal(r.headers.get('x-howdah-validated'), VERSION);
});

test('compressed payload works', async () => {
  const toml = 'mode = "block"\n[sinks.include]\nallow_paths = [' + Array(60).fill('"/var/www/app/vendor"').join(', ') + ']\n';
  const p = await E.encodePayload(toml);
  assert.ok(p.startsWith('z.'));
  const r = await run('/v1/' + p);
  assert.equal(r.status, 200);
  assert.equal(await r.text(), toml);
});

test('invalid config returns 422 with the core error and not the config', async () => {
  const r = await run('/v1/' + await E.encodePayload('[limits]\nmax_files = 0\n'));
  assert.equal(r.status, 422);
  const body = await r.text();
  assert.match(body, /max_files must be greater than 0/);
  assert.ok(!body.includes('max_files = 0'));
  assert.equal(r.headers.get('cache-control'), 'no-store');
});

test('oversize payload returns 413', async () => {
  const r = await run('/v1/' + 'A'.repeat(12001));
  assert.equal(r.status, 413);
});

test('rejects_non_base64url_payload', async () => {
  for (const p of ['ab+/=', 'z.%%%', 'abc', 'z.']) {
    const r = await run('/v1/' + p);
    assert.ok(r.status === 404 || r.status === 422, p + ' -> ' + r.status);
  }
});

test('ignores_query_and_trailing_slash', async () => {
  const p = await E.encodePayload('mode = "detect"\n');
  assert.equal((await run('/v1/' + p + '/?x=1')).status, 404);
  assert.equal((await run('/v1/' + p + '?x=1')).status, 200);
});

test('other paths and methods', async () => {
  const root = await run('/');
  assert.equal(root.status, 200);
  assert.match(root.headers.get('content-type'), /^text\/plain/);
  assert.match(await root.text(), /howdah\.org\/config\//);
  assert.equal((await run('/v2/x')).status, 404);
  const post = await run('/v1/' + await E.encodePayload('mode = "detect"\n'), { method: 'POST' });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('allow'), 'GET, HEAD');
  const head = await run('/v1/' + await E.encodePayload('mode = "detect"\n'), { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');
});
