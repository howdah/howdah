// Copies the demo's runtime assets (the prebuilt WASM and its vanilla-JS glue)
// from the canonical source `site/demo/` — the same files CI builds and
// verifies — into `site/public/demo/`, so Astro serves them same-origin at
// `/demo/…`. Generated, so `public/demo/` is git-ignored; the source of truth
// stays `site/demo/`.
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, '../demo');
const dst = resolve(here, '../public/demo');
mkdirSync(dst, { recursive: true });

const files = ['howdah_wasm.wasm', 'howdah-wasm.js', 'samples.js'];
for (const f of files) {
  copyFileSync(resolve(src, f), resolve(dst, f));
}
console.log(`demo assets copied: ${files.join(', ')} -> site/public/demo/`);
