// Copies generated public assets into `site/public/` at build time, each from
// its canonical source so there is no committed duplicate to drift:
//   * the demo runtime (prebuilt WASM + vanilla-JS glue) from `site/demo/` —
//     the same files CI builds and verifies — to `public/demo/`.
//   * the repository's public signing key from
//     `packaging/howdah-release-signing.asc` to `public/key.asc`, so
//     https://howdah.org/key.asc serves it. The apt `signed-by`, the yum
//     `gpgkey`, and the install picker all fetch that URL, so it MUST exist
//     before the package repos go live.
// Both outputs are git-ignored; the sources of truth stay where they are.
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

// Public signing key -> public/key.asc
copyFileSync(resolve(here, '../../packaging/howdah-release-signing.asc'), resolve(here, '../public/key.asc'));

console.log(`demo assets copied: ${files.join(', ')} -> site/public/demo/; key.asc -> site/public/`);
