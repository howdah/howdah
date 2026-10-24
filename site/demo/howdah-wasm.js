// Howdah WebAssembly glue. Vanilla JS, no network beyond loading the .wasm
// from the same origin. Exposes window.HowdahWasm.{analyze, buildBody, BOUNDARY,
// validateConfig, ruleCatalogWith, versionWith, loadFrom} (and CommonJS exports
// for Node-based checks and the cfg.howdah.org Worker).
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

  // Instantiate from bytes already in hand (Node tests, the Worker's bundled
  // module). Becomes the instance later `load()`/`validateConfig()` calls use.
  function loadFrom(bytesOrModule) {
    instancePromise = (async function () {
      var result = bytesOrModule instanceof WebAssembly.Module
        ? { instance: await WebAssembly.instantiate(bytesOrModule, {}) }
        : await WebAssembly.instantiate(bytesOrModule, {});
      return result.instance.exports;
    })();
    instancePromise.catch(function () { instancePromise = null; });
    return instancePromise;
  }

  // Read and free the result buffer of the call that just ran (the length is
  // only valid until the next call that produces a result).
  function takeResult(x, rp) {
    var rl = x.howdah_wasm_result_len();
    try {
      return dec.decode(new Uint8Array(x.memory.buffer, rp, rl).slice());
    } finally {
      if (rp) x.howdah_wasm_free(rp, rl);
    }
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

  // ---- config editor: the real validator ---------------------------------

  // Config::from_toml through the core: {ok:true, config} | {ok:false, error}.
  function validateConfigWith(x, toml) {
    var bytes = enc.encode(String(toml == null ? '' : toml));
    var cp = put(x, bytes);
    try {
      return JSON.parse(takeResult(x, x.howdah_wasm_validate_config(cp, bytes.length)));
    } finally {
      x.howdah_wasm_free(cp, bytes.length);
    }
  }

  async function validateConfig(toml) {
    return validateConfigWith(await load(), toml);
  }

  // [{name, severity}] for every rule the core accepts under [rules].
  function ruleCatalogWith(x) {
    return JSON.parse(takeResult(x, x.howdah_wasm_rule_catalog()));
  }

  // The core version the wasm was built from, e.g. "1.2.1".
  function versionWith(x) {
    return takeResult(x, x.howdah_wasm_version());
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

  var api = {
    analyze: analyze, analyzeWith: analyzeWith, load: load, loadFrom: loadFrom,
    buildBody: buildBody, BOUNDARY: BOUNDARY,
    validateConfig: validateConfig, validateConfigWith: validateConfigWith,
    ruleCatalogWith: ruleCatalogWith, versionWith: versionWith
  };
  root.HowdahWasm = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
