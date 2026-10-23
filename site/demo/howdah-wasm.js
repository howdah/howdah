// Howdah WebAssembly glue. Vanilla JS, no network beyond loading the .wasm
// from the same origin. Exposes window.HowdahWasm.{analyze, buildBody, BOUNDARY}
// (and CommonJS exports for Node-based checks).
(function (root) {
  'use strict';

  var BOUNDARY = 'HowdahDemoBoundary';
  var enc = new TextEncoder();
  var dec = new TextDecoder();
  var instancePromise = null;

  function load(url) {
    if (!instancePromise) {
      instancePromise = (async function () {
        var src = await fetch(url || 'howdah_wasm.wasm');
        if (!src.ok) throw new Error('could not load howdah_wasm.wasm (' + src.status + ')');
        var result;
        try {
          result = await WebAssembly.instantiateStreaming(src.clone(), {});
        } catch (e) {
          // Wrong MIME type or no streaming support: fall back to ArrayBuffer.
          result = await WebAssembly.instantiate(await src.arrayBuffer(), {});
        }
        return result.instance.exports;
      })();
      instancePromise.catch(function () { instancePromise = null; });
    }
    return instancePromise;
  }

  // Copy bytes into freshly allocated wasm memory. Returns the pointer.
  function put(x, bytes) {
    var ptr = x.howdah_wasm_alloc(bytes.length);
    // Re-read memory.buffer AFTER alloc: it may have grown (old buffer detaches).
    new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
    return ptr;
  }

  // Core marshalling, given instantiated exports.
  function analyzeWith(x, configToml, bodyBytes) {
    var cfg = enc.encode(configToml || '');
    var body = bodyBytes instanceof Uint8Array ? bodyBytes : enc.encode(String(bodyBytes));
    var cp = put(x, cfg);
    var bp = put(x, body);
    var rp = 0, rl = 0, out;
    try {
      rp = x.howdah_wasm_analyze(cp, cfg.length, bp, body.length);
      rl = x.howdah_wasm_result_len(); // immediately after analyze
      out = dec.decode(new Uint8Array(x.memory.buffer, rp, rl).slice());
    } finally {
      if (rp) x.howdah_wasm_free(rp, rl);
      x.howdah_wasm_free(bp, body.length);
      x.howdah_wasm_free(cp, cfg.length);
    }
    return JSON.parse(out);
  }

  async function analyze(configToml, bodyBytes) {
    return analyzeWith(await load(), configToml, bodyBytes);
  }

  // Build a multipart/form-data body from [{name, filename?, content?}] using
  // the fixed demo boundary. `raw` entries are emitted verbatim (for the
  // malformed sample). All content is benign filler.
  function buildBody(parts, opts) {
    var s = '';
    parts.forEach(function (p) {
      if (p.raw !== undefined) { s += p.raw; return; }
      s += '--' + BOUNDARY + '\r\nContent-Disposition: form-data; name="' + p.name + '"' +
        (p.filename !== undefined ? '; filename="' + p.filename + '"' : '') +
        '\r\n\r\n' + (p.content || '') + '\r\n';
    });
    if (!(opts && opts.noTerminator)) s += '--' + BOUNDARY + '--\r\n';
    return enc.encode(s);
  }

  var api = { analyze: analyze, analyzeWith: analyzeWith, load: load, buildBody: buildBody, BOUNDARY: BOUNDARY };
  root.HowdahWasm = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
