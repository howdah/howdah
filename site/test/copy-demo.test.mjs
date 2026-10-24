// The site build must fail loudly when the wasm is missing, never fall back to
// a stale copy (the demo shipped a 1.0 binary for two releases that way).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('copy-demo exits 1 with a clear message when the wasm is missing', () => {
  // An empty source dir stands in for a checkout where `npm run wasm` was not
  // run; the real site/demo is left alone so parallel tests can load it.
  const empty = mkdtempSync(join(tmpdir(), 'howdah-no-wasm-'));
  try {
    const r = spawnSync(process.execPath, ['scripts/copy-demo.mjs'], {
      cwd: site, encoding: 'utf8', env: { ...process.env, HOWDAH_DEMO_SRC: empty },
    });
    assert.equal(r.status, 1, `exit status (stderr: ${r.stderr})`);
    assert.match(r.stderr, /howdah_wasm\.wasm missing/);
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }
});
