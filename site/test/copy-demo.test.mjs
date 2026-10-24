// The site build must fail loudly when the wasm is missing, never fall back to
// a stale copy (the demo shipped a 1.0 binary for two releases that way).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, renameSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const wasm = resolve(site, 'demo/howdah_wasm.wasm');
const hidden = wasm + '.hidden-by-test';

test('copy-demo exits 1 with a clear message when the wasm is missing', () => {
  const had = existsSync(wasm);
  if (had) renameSync(wasm, hidden);
  try {
    const r = spawnSync(process.execPath, ['scripts/copy-demo.mjs'], { cwd: site, encoding: 'utf8' });
    assert.equal(r.status, 1, `exit status (stderr: ${r.stderr})`);
    assert.match(r.stderr, /howdah_wasm\.wasm missing/);
  } finally {
    if (had) renameSync(hidden, wasm);
  }
});
