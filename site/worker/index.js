// Cloudflare Worker entry for cfg.howdah.org. The wasm is bundled as a module
// by wrangler (see wrangler.toml [[rules]]) from the build the deploy workflow
// makes from this same commit, so the service validates with exactly the core
// the site and the release were built from.
import wasm from '../demo/howdah_wasm.wasm';
import H from '../demo/howdah-wasm.js';
import { handle } from './handle.js';

let exportsPromise = null;

export default {
  async fetch(request) {
    if (!exportsPromise) {
      exportsPromise = H.loadFrom(wasm);
      // A failed instantiation must not poison every later request.
      exportsPromise.catch(() => { exportsPromise = null; });
    }
    const x = await exportsPromise;
    return handle(request, x, H.versionWith(x));
  },
};
