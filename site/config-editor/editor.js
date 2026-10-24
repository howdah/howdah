// The config editor's pure functions: emit howdah.toml / howdah.ini from a
// flat state, load a state back from the core's canonical config JSON, and
// encode the TOML into the cfg.howdah.org URL payload (and back). No DOM, no
// network. Runs in the browser (window.HowdahConfigEditor), in Node tests and
// in the cfg.howdah.org Worker (CommonJS exports).
//
// Validation is NOT done here: the page and the Worker hand the emitted TOML
// to the real core (howdah-wasm.js validateConfig). This file only formats.
(function (root) {
  'use strict';

  var SCHEMA_API = (typeof module !== 'undefined' && module.exports)
    ? require('./schema.js')
    : root.HowdahConfigSchema;

  // Payload limits (spec §7). The Worker enforces the same numbers.
  var TOML_MAX = 16384;     // decoded TOML bytes
  var PAYLOAD_MAX = 12000;  // characters in the URL path segment
  var CFG_BASE = 'https://cfg.howdah.org/v1/';

  var enc = new TextEncoder();
  var dec = new TextDecoder();

  // ---- TOML formatting ------------------------------------------------------

  // TOML basic string: escape backslash, quote and control characters.
  function tomlString(s) {
    var out = '"';
    for (var i = 0; i < s.length; i++) {
      var c = s.charCodeAt(i), ch = s[i];
      if (ch === '"') out += '\\"';
      else if (ch === '\\') out += '\\\\';
      else if (ch === '\n') out += '\\n';
      else if (ch === '\r') out += '\\r';
      else if (ch === '\t') out += '\\t';
      else if (c < 0x20 || c === 0x7f) out += '\\u' + ('000' + c.toString(16).toUpperCase()).slice(-4);
      else out += ch;
    }
    return out + '"';
  }

  function tomlValue(type, v) {
    if (type === 'int') return String(Math.trunc(Number(v)));
    if (type === 'bool') return v ? 'true' : 'false';
    if (type === 'list') return '[' + v.map(tomlString).join(', ') + ']';
    return tomlString(String(v)); // enum, mode-or-inherit, path
  }

  function sameValue(a, b) {
    if (Array.isArray(a) || Array.isArray(b)) {
      if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
      for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
      return true;
    }
    return a === b;
  }

  // The TOML table a schema key lives in, and its key name inside it.
  // 'limits.max_parts' -> ['limits', 'max_parts'];
  // 'inspect.limits.max_values' -> ['inspect.limits', 'max_values'];
  // 'sinks.command_exec.allow' -> ['sinks.command_exec', 'allow'].
  function split(sectionId, key) {
    var i = key.lastIndexOf('.');
    return i < 0 ? [sectionId, key] : [sectionId + '.' + key.slice(0, i), key.slice(i + 1)];
  }

  // Emit the TOML for `state`. `mode` is always written (an omitted mode means
  // block to the core, while the shipped ini says detect). Every other key is
  // written only when it differs from the core default recorded in the schema,
  // or, with includeDefaults, as a comment line.
  function emitToml(state, opts) {
    var includeDefaults = !!(opts && opts.includeDefaults);
    var S = SCHEMA_API.SCHEMA;
    var tables = []; // [{name, lines:[{text, real}]}] in schema order
    var byName = {};
    function table(name) {
      if (!byName[name]) { byName[name] = { name: name, lines: [] }; tables.push(byName[name]); }
      return byName[name];
    }
    S.sections.forEach(function (sec) {
      sec.keys.forEach(function (k) {
        var v = state[sec.id + '.' + k.key];
        if (v === undefined) v = k.default;
        if (k.type === 'mode-or-inherit' && v === 'inherit') return; // never written
        var parts = split(sec.id, k.key);
        var isDefault = sameValue(v, k.default);
        if (isDefault && !includeDefaults) return;
        var line = parts[1] + ' = ' + tomlValue(k.type, v);
        table(parts[0]).lines.push({ text: isDefault ? '# ' + line : line, real: !isDefault });
      });
    });
    var out = 'mode = ' + tomlString(String(state['howdah.mode'] || 'detect')) + '\n';
    tables.forEach(function (t) {
      if (!t.lines.length) return;
      out += '\n[' + t.name + ']\n';
      t.lines.forEach(function (l) { out += l.text + '\n'; });
    });
    return out;
  }

  // The php.ini snippet; always carries all three directives.
  function emitIni(state) {
    return [
      '; Howdah: the .so is a plain PHP extension (not a Zend extension).',
      'extension=howdah.so',
      '',
      '; block | detect | off. Once howdah.config names a readable file, the',
      '; file’s mode is used and this value is ignored.',
      'howdah.mode = ' + state['howdah.mode'],
      '',
      '; The TOML file built on howdah.org/config/ (empty = built-in defaults).',
      'howdah.config = ' + state['howdah.config'],
      '',
      '; JSON-lines event log; the directory must be writable by the PHP worker.',
      'howdah.log = ' + state['howdah.log'],
      ''
    ].join('\n');
  }

  // ---- loading from the core's canonical JSON --------------------------------

  function getPath(obj, path) {
    var cur = obj;
    for (var i = 0; i < path.length; i++) {
      if (cur == null) return undefined;
      cur = cur[path[i]];
    }
    return cur;
  }

  // Build a state from the config the core parsed. Refuses (with the key
  // names) anything the form cannot represent, so a load-then-download round
  // trip never silently drops a setting. Today that is only [log].
  function loadFromCanonical(config, catalog) {
    var unsupported = [];
    if (config.log && config.log.path != null) unsupported.push('log');
    if (unsupported.length) return { unsupported: unsupported };
    var state = SCHEMA_API.defaultState(catalog);
    state['howdah.mode'] = config.mode;
    SCHEMA_API.SCHEMA.sections.forEach(function (sec) {
      sec.keys.forEach(function (k) {
        var path = [sec.id].concat(k.key.split('.'));
        var v = getPath(config, path);
        if (sec.id === 'rules') v = (config.rules || {})[k.key];
        if (k.type === 'mode-or-inherit') v = v == null ? 'inherit' : v;
        if (v === undefined) return;
        state[sec.id + '.' + k.key] = Array.isArray(v) ? v.slice() : v;
      });
    });
    return { state: state };
  }

  // ---- URL payload -----------------------------------------------------------

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  var B64REV = {};
  for (var bi = 0; bi < 64; bi++) B64REV[B64[bi]] = bi;

  function b64urlEncode(bytes) {
    var out = '', i;
    for (i = 0; i + 2 < bytes.length; i += 3) {
      var n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
      out += B64[(n >> 18) & 63] + B64[(n >> 12) & 63] + B64[(n >> 6) & 63] + B64[n & 63];
    }
    var rem = bytes.length - i;
    if (rem === 1) { var a = bytes[i] << 16; out += B64[(a >> 18) & 63] + B64[(a >> 12) & 63]; }
    else if (rem === 2) { var b = (bytes[i] << 16) | (bytes[i + 1] << 8); out += B64[(b >> 18) & 63] + B64[(b >> 12) & 63] + B64[(b >> 6) & 63]; }
    return out;
  }

  function b64urlDecode(s) {
    if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new Error('not base64url');
    var out = [], i = 0;
    while (i < s.length) {
      var c0 = B64REV[s[i++]], c1 = B64REV[s[i++]];
      var c2 = i < s.length ? B64REV[s[i++]] : undefined;
      var c3 = i < s.length ? B64REV[s[i++]] : undefined;
      out.push((c0 << 2) | (c1 >> 4));
      if (c2 !== undefined) out.push(((c1 & 15) << 4) | (c2 >> 2));
      if (c3 !== undefined) out.push(((c2 & 3) << 6) | c3);
    }
    return new Uint8Array(out);
  }

  // Run bytes through a Compression/DecompressionStream, giving up as soon as
  // the output passes `max` bytes (a deflate bomb is cancelled, not inflated).
  async function pipe(bytes, stream, max) {
    var reader = new Blob([bytes]).stream().pipeThrough(stream).getReader();
    var chunks = [], total = 0;
    for (;;) {
      var r = await reader.read();
      if (r.done) break;
      total += r.value.length;
      if (max !== undefined && total > max) {
        await reader.cancel();
        throw new Error('config too large');
      }
      chunks.push(r.value);
    }
    var out = new Uint8Array(total), off = 0;
    chunks.forEach(function (c) { out.set(c, off); off += c.length; });
    return out;
  }

  // TOML -> payload, or null when either limit is exceeded. Uses deflate-raw
  // (as 'z.' + base64url) when that is shorter and the runtime has it.
  async function encodePayload(toml) {
    var bytes = enc.encode(toml);
    if (bytes.length > TOML_MAX) return null;
    var plain = b64urlEncode(bytes);
    var best = plain;
    if (typeof CompressionStream !== 'undefined') {
      try {
        var z = 'z.' + b64urlEncode(await pipe(bytes, new CompressionStream('deflate-raw')));
        if (z.length < plain.length) best = z;
      } catch (e) { /* no deflate-raw here: plain is fine */ }
    }
    return best.length > PAYLOAD_MAX ? null : best;
  }

  // payload -> TOML. Throws on malformed or oversize input (the Worker maps
  // the throw to a 4xx).
  async function decodePayload(payload) {
    if (typeof payload !== 'string' || payload.length > PAYLOAD_MAX) throw new Error('payload too long');
    var compressed = payload.slice(0, 2) === 'z.';
    var bytes = b64urlDecode(compressed ? payload.slice(2) : payload);
    if (compressed) {
      if (typeof DecompressionStream === 'undefined') throw new Error('no deflate here');
      bytes = await pipe(bytes, new DecompressionStream('deflate-raw'), TOML_MAX);
    }
    if (bytes.length > TOML_MAX) throw new Error('config too large');
    return dec.decode(bytes);
  }

  function curlCommand(payload, configPath) {
    if (!payload) return null;
    var dir = configPath.replace(/\/[^/]*$/, '') || '/';
    return [
      'sudo mkdir -p ' + dir,
      "sudo curl -fsSL '" + CFG_BASE + payload + "' -o " + configPath,
      ''
    ].join('\n');
  }

  var api = {
    emitToml: emitToml, emitIni: emitIni, loadFromCanonical: loadFromCanonical,
    encodePayload: encodePayload, decodePayload: decodePayload, curlCommand: curlCommand,
    tomlString: tomlString, b64urlEncode: b64urlEncode,
    TOML_MAX: TOML_MAX, PAYLOAD_MAX: PAYLOAD_MAX, CFG_BASE: CFG_BASE
  };
  root.HowdahConfigEditor = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
