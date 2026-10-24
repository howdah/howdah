// Shared by the build-output tests (not a test file itself: the runner only
// picks up *.test.mjs). `node --test` runs test files in parallel processes,
// so two files that each find dist/ stale would start `astro build` into the
// same directory at once. A lock directory serialises the builds; whoever gets
// the lock second re-checks freshness and usually finds nothing to do.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const lock = resolve(site, '.build.lock');
const STALE_MS = 10 * 60_000; // a lock older than this was left by a killed run

function fresh(out, srcs) {
  if (!existsSync(out)) return false;
  const built = statSync(out).mtimeMs;
  return srcs.every((s) => existsSync(s) && built >= statSync(s).mtimeMs);
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

function acquire() {
  const deadline = Date.now() + 2 * STALE_MS;
  for (;;) {
    try {
      mkdirSync(lock);
      return;
    } catch (e) {
      if (e.code !== 'EEXIST') throw e;
      try {
        if (Date.now() - statSync(lock).mtimeMs > STALE_MS) rmSync(lock, { recursive: true, force: true });
      } catch {
        // the holder released it between the two calls; just retry
      }
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${lock}`);
      sleep(200);
    }
  }
}

/** Run `npm run build` unless `out` is newer than every file in `srcs`. */
export function ensureBuilt(out, srcs) {
  if (fresh(out, srcs)) return;
  acquire();
  try {
    if (!fresh(out, srcs)) {
      const r = spawnSync('npm', ['run', 'build'], { cwd: site, encoding: 'utf8' });
      if (r.status !== 0) console.error(r.stdout, r.stderr);
    }
  } finally {
    rmSync(lock, { recursive: true, force: true });
  }
}
