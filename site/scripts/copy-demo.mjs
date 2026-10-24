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
//
// The wasm itself is NOT committed (it was, and went stale at 1.0 while the
// core gained two config sections). It is built from this checkout by
// `npm run wasm` (packaging/build-wasm.sh); pages.yml does that before the
// site build. A missing wasm is a hard error here, never a silent fallback.
import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// HOWDAH_DEMO_SRC lets the test point this at an empty directory instead of
// hiding the real wasm from the other tests running in parallel.
const src = process.env.HOWDAH_DEMO_SRC ? resolve(process.env.HOWDAH_DEMO_SRC) : resolve(here, '../demo');
const dst = resolve(here, '../public/demo');

if (!existsSync(resolve(src, 'howdah_wasm.wasm'))) {
  console.error('howdah_wasm.wasm missing: run `npm run wasm` (packaging/build-wasm.sh) before the site build');
  process.exit(1);
}
mkdirSync(dst, { recursive: true });

const files = ['howdah_wasm.wasm', 'howdah-wasm.js', 'samples.js'];
for (const f of files) {
  copyFileSync(resolve(src, f), resolve(dst, f));
}

// Config editor runtime (schema table + emitter/codec) -> public/config/
const cfgSrc = resolve(here, '../config-editor');
const cfgDst = resolve(here, '../public/config');
mkdirSync(cfgDst, { recursive: true });
const cfgFiles = ['schema.js', 'editor.js'];
for (const f of cfgFiles) {
  copyFileSync(resolve(cfgSrc, f), resolve(cfgDst, f));
}

// Public signing key -> public/key.asc
copyFileSync(resolve(here, '../../packaging/howdah-release-signing.asc'), resolve(here, '../public/key.asc'));

console.log(`demo assets copied: ${files.join(', ')} -> site/public/demo/; ${cfgFiles.join(', ')} -> site/public/config/; key.asc -> site/public/`);
