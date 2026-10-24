// The emitter, loader and payload codec, checked by meaning against the core:
// every emitted TOML goes through the real validator and the parsed config is
// compared with what the state asked for.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const H = require('../demo/howdah-wasm.js');
const { SCHEMA, defaultState } = require('../config-editor/schema.js');
const E = require('../config-editor/editor.js');

const x = await H.loadFrom(readFileSync(resolve(here, '../demo/howdah_wasm.wasm')));
const catalog = H.ruleCatalogWith(x);
const validate = (toml) => H.validateConfigWith(x, toml);
const fresh = () => defaultState(catalog);
const get = (obj, path) => path.split('.').reduce((o, k) => (o == null ? o : o[k]), obj);

test('shipped defaults emit only the mode line', () => {
  assert.equal(E.emitToml(fresh(), {}), 'mode = "detect"\n');
});

test('emitted presets validate and round-trip through the core', () => {
  for (const name of Object.keys(SCHEMA.presets)) {
    const s = Object.assign(fresh(), SCHEMA.presets[name]);
    const v = validate(E.emitToml(s, {}));
    assert.equal(v.ok, true, name + ': ' + v.error);
    assert.equal(v.config.mode, s['howdah.mode'], name);
  }
});

test('every key round-trips to the value set', () => {
  for (const sec of SCHEMA.sections) {
    for (const k of sec.keys) {
      const s = fresh();
      const sk = sec.id + '.' + k.key;
      let val;
      if (k.type === 'int') val = k.default + 1;
      else if (k.type === 'bool') val = !k.default;
      else if (k.type === 'list') val = ['a', 'b'];
      else val = k.values.find((v) => v !== k.default && v !== 'inherit');
      s[sk] = val;
      const toml = E.emitToml(s, {});
      const v = validate(toml);
      assert.equal(v.ok, true, sk + ': ' + v.error + '\n' + toml);
      const got = get(v.config, sk);
      assert.deepEqual(got, val, sk + '\n' + toml);
    }
  }
});

test('mode is always written even when it equals the core default', () => {
  const s = fresh();
  s['howdah.mode'] = 'block';
  assert.ok(E.emitToml(s, {}).startsWith('mode = "block"\n'));
});

test('includeDefaults writes defaults as comments and still validates', () => {
  const toml = E.emitToml(fresh(), { includeDefaults: true });
  assert.ok(toml.includes('# max_parts = 2000'), toml);
  assert.ok(toml.includes('[limits]'));
  assert.equal(validate(toml).ok, true);
});

test('escapes_quotes_and_backslashes_in_strings', () => {
  const s = fresh();
  s['sinks.command_exec.allow'] = ['echo "hi"', 'C:\\tools\\*', 'tab\there'];
  const v = validate(E.emitToml(s, {}));
  assert.equal(v.ok, true, v.error);
  assert.deepEqual(v.config.sinks.command_exec.allow, ['echo "hi"', 'C:\\tools\\*', 'tab\there']);
});

test('inherit rule modes are not written', () => {
  const s = fresh();
  s['rules.max_parts'] = 'detect';
  const toml = E.emitToml(s, {});
  assert.ok(toml.includes('[rules]\nmax_parts = "detect"'), toml);
  assert.ok(!toml.includes('inherit'));
  assert.ok(!toml.includes('max_files'));
});

test('load_accepts_every_rule_id', () => {
  for (const r of catalog) {
    const v = validate('[rules]\n' + r.name + ' = "block"');
    assert.equal(v.ok, true, r.name);
    const loaded = E.loadFromCanonical(v.config, catalog);
    assert.ok(loaded.state, r.name + ' refused: ' + JSON.stringify(loaded));
    assert.equal(loaded.state['rules.' + r.name], 'block');
  }
});

test('load refuses a config with [log]', () => {
  const v = validate('[log]\npath = "/tmp/x.log"');
  assert.equal(v.ok, true);
  assert.deepEqual(E.loadFromCanonical(v.config, catalog), { unsupported: ['log'] });
});

test('load then emit reproduces a non-trivial config', () => {
  const toml = [
    'mode = "detect"',
    '[limits]', 'max_files = 50', 'max_input_vars = 500',
    '[rules]', 'max_request_headers = "detect"', 'self_test = "off"',
    '[inspect]', 'mode = "block"', 'cmdi = false',
    '[inspect.rule_modes]', 'sql_injection = "detect"',
    '[sinks.command_exec]', 'mode = "block"', 'allow = ["id", "/usr/bin/convert *"]',
    '[sinks.unserialize]', 'mode = "detect"', 'allow_classes = ["App\\\\Job"]',
    '[sinks.include]', 'allow_paths = ["/var/www/app"]',
    '[sinks.eval]', 'mode = "block"'
  ].join('\n');
  const v = validate(toml);
  assert.equal(v.ok, true, v.error);
  const loaded = E.loadFromCanonical(v.config, catalog);
  assert.ok(loaded.state);
  const v2 = validate(E.emitToml(loaded.state, {}));
  assert.equal(v2.ok, true, v2.error);
  assert.deepEqual(v2.config, v.config);
});

test('1.3 phar and ssrf sinks round-trip through the core', () => {
  const s = fresh();
  s['sinks.phar.mode'] = 'detect';
  s['sinks.phar.allow_paths'] = ['/var/www/vendor'];
  s['sinks.ssrf.mode'] = 'block';
  s['sinks.ssrf.allow_hosts'] = ['10.0.0.0/8', 'api.internal', '192.168.1.5'];
  const toml = E.emitToml(s, {});
  assert.ok(toml.includes('[sinks.phar]') && toml.includes('[sinks.ssrf]'), toml);
  const v = validate(toml);
  assert.equal(v.ok, true, v.error);
  assert.equal(v.config.sinks.phar.mode, 'detect');
  assert.deepEqual(v.config.sinks.phar.allow_paths, ['/var/www/vendor']);
  assert.equal(v.config.sinks.ssrf.mode, 'block');
  assert.deepEqual(v.config.sinks.ssrf.allow_hosts, ['10.0.0.0/8', 'api.internal', '192.168.1.5']);
});

test('a wildcard ssrf host is rejected by the core, not by JavaScript', () => {
  const s = fresh();
  s['sinks.ssrf.allow_hosts'] = ['*.example.com'];
  const v = validate(E.emitToml(s, {}));
  assert.equal(v.ok, false);
  assert.match(v.error, /allow_hosts|wildcard|\*/i);
});

test('payload round-trips and uses z. when shorter', async () => {
  const small = 'mode = "detect"\n';
  const p = await E.encodePayload(small);
  assert.equal(await E.decodePayload(p), small);
  const big = 'mode = "block"\n[sinks.include]\nallow_paths = [' + Array(60).fill('"/var/www/app/vendor"').join(', ') + ']\n';
  const pz = await E.encodePayload(big);
  assert.ok(pz.startsWith('z.'), pz.slice(0, 10));
  assert.equal(await E.decodePayload(pz), big);
});

test('payload uses only base64url characters', async () => {
  const s = fresh();
  s['sinks.command_exec.allow'] = ['echo "hi" > /tmp/\u00e9', '???///+++'];
  const p = await E.encodePayload(E.emitToml(s, {}));
  assert.match(p, /^(z\.)?[A-Za-z0-9_-]+$/);
});

test('curl_command_is_null_when_payload_exceeds_limit', async () => {
  const s = fresh();
  s['sinks.include.allow_paths'] = Array.from({ length: 600 }, (_, i) => '/srv/' + Math.random().toString(36).slice(2) + '/app' + i + '/x'.repeat(20));
  const toml = E.emitToml(s, {});
  assert.ok(toml.length > E.TOML_MAX, 'fixture should exceed TOML_MAX');
  assert.equal(await E.encodePayload(toml), null);
  assert.equal(E.curlCommand(null, '/etc/howdah/howdah.toml'), null);
});

test('decodePayload stops inflating at TOML_MAX (decompression bomb)', async () => {
  const zeros = new Uint8Array(4 * 1024 * 1024);
  const buf = await new Response(new Blob([zeros]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer();
  const payload = 'z.' + E.b64urlEncode(new Uint8Array(buf));
  const t0 = Date.now();
  await assert.rejects(E.decodePayload(payload), /too large/);
  assert.ok(Date.now() - t0 < 300, 'took ' + (Date.now() - t0) + ' ms');
});

test('curl_command_is_null_when_payload_exceeds_PAYLOAD_MAX_with_toml_under_TOML_MAX', async () => {
  // Incompressible (deterministic pseudo-random base64url text), under 16 KiB
  // of TOML, but over 12000 URL characters even after deflate.
  let seed = 0x9e3779b9;
  const rnd = () => { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0); };
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const word = (n) => Array.from({ length: n }, () => alphabet[rnd() % 64]).join('');
  const s = fresh();
  s['sinks.include.allow_paths'] = Array.from({ length: 340 }, () => '/' + word(40));
  const toml = E.emitToml(s, {});
  assert.ok(toml.length < E.TOML_MAX, 'toml ' + toml.length);
  assert.equal(await E.encodePayload(toml), null);
});

test('curl command names the config path and the service', async () => {
  const p = await E.encodePayload('mode = "detect"\n');
  const c = E.curlCommand(p, '/etc/howdah/howdah.toml');
  assert.ok(c.includes("https://cfg.howdah.org/v1/" + p), c);
  assert.ok(c.includes('-o /etc/howdah/howdah.toml'), c);
  assert.ok(c.includes('mkdir -p /etc/howdah'), c);
});

test('emitIni carries the three directives', () => {
  const s = fresh();
  s['howdah.log'] = '/var/log/php/howdah.log';
  const ini = E.emitIni(s);
  assert.ok(ini.includes('extension=howdah.so'));
  assert.ok(ini.includes('howdah.mode = detect'));
  assert.ok(ini.includes('howdah.config = /etc/howdah/howdah.toml'));
  assert.ok(ini.includes('howdah.log = /var/log/php/howdah.log'));
});
