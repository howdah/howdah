// [[exceptions]] through the editor: preserved on load, re-emitted in full,
// validated by the real core, and every shipped application profile round-trips.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const H = require('../demo/howdah-wasm.js');
const { SCHEMA, defaultState, EXCEPTION_FIELDS, PROFILES } = require('../config-editor/schema.js');
const E = require('../config-editor/editor.js');

const x = await H.loadFrom(readFileSync(resolve(here, '../demo/howdah_wasm.wasm')));
const catalog = H.ruleCatalogWith(x);
const validate = (toml) => H.validateConfigWith(x, toml);
const fresh = () => defaultState(catalog);

const SAMPLE = `mode = "detect"
exceptions_log = true

[sinks]
mode = "block"

[[exceptions]]
rule = "sinks.command_exec"
script = "/var/www/html/cron.php"
reason = "cron mailer"

[[exceptions]]
rule = "inspect.sql_injection"
param = "content"
uri_prefix = "/wp-admin/"
client_cidr = "10.0.0.0/8"
reason = "editors paste SQL"
`;

test('default state has no exceptions and exceptions_log off, and emits neither', () => {
  const s = fresh();
  assert.deepEqual(s.exceptions, []);
  assert.equal(s.exceptions_log, false);
  assert.equal(E.emitToml(s, {}), 'mode = "detect"\n');
  assert.equal(validate('').config.exceptions_log, false);
  assert.deepEqual(validate('').config.exceptions, []);
});

test('loadFromCanonical keeps [[exceptions]] and exceptions_log; emitToml writes them back', () => {
  const v = validate(SAMPLE);
  assert.equal(v.ok, true, v.error);
  const r = E.loadFromCanonical(v.config, catalog);
  assert.ok(r.state, 'loaded');
  assert.equal(r.state.exceptions_log, true);
  assert.equal(r.state.exceptions.length, 2);
  assert.deepEqual(r.state.exceptions[1], {
    rule: 'inspect.sql_injection', param: 'content', uri_prefix: '/wp-admin/', client_cidr: '10.0.0.0/8', reason: 'editors paste SQL',
  });
  const toml = E.emitToml(r.state, {});
  assert.ok(toml.includes('exceptions_log = true'), toml);
  assert.ok(toml.indexOf('[[exceptions]]') > toml.indexOf('[sinks]'), 'exceptions are written after the tables\n' + toml);
  const again = validate(toml);
  assert.equal(again.ok, true, again.error + '\n' + toml);
  assert.deepEqual(again.config.exceptions, v.config.exceptions);
  assert.equal(again.config.exceptions_log, true);
  assert.equal(again.config.sinks.mode, 'block');
});

test('emitToml omits empty facets and quotes values', () => {
  const s = fresh();
  s.exceptions = [{ rule: 'behavior.php_write', script: '/srv/app/**', param: '', reason: 'a "quoted" reason\\path' }];
  const toml = E.emitToml(s, {});
  assert.ok(!toml.includes('param ='), toml);
  const v = validate(toml);
  assert.equal(v.ok, true, v.error + '\n' + toml);
  assert.equal(v.config.exceptions[0].reason, 'a "quoted" reason\\path');
  assert.equal(v.config.exceptions[0].script, '/srv/app/**');
});

test('the core names the row and key when an exception is wrong', () => {
  for (const [entry, want] of [
    [{ rule: 'max_parts', uri_prefix: '/', reason: 'x' }, /exceptions\[1\]\.rule.*Critical/],
    [{ rule: 'command_exec', script: '/a.php' }, /exceptions\[1\]\.reason/],
    [{ rule: 'sql_injection', script: '/a.php', reason: 'x' }, /exceptions\[1\]\.script.*uri_prefix/],
    [{ rule: 'command_exec', reason: 'x' }, /exceptions\[1\]: at least one of/],
    [{ rule: 'ssrf', client_cidr: '10/8', reason: 'x' }, /exceptions\[1\]\.client_cidr/],
  ]) {
    const s = fresh();
    s.exceptions = [{ rule: 'eval', script: '/ok.php', reason: 'fine' }, entry];
    const v = validate(E.emitToml(s, {}));
    assert.equal(v.ok, false, JSON.stringify(entry));
    assert.match(v.error, want);
  }
});

test('includeDefaults comments exceptions_log but never an exception', () => {
  const s = fresh();
  s.exceptions = [{ rule: 'eval', script: '/ok.php', reason: 'fine' }];
  const toml = E.emitToml(s, { includeDefaults: true });
  assert.ok(toml.includes('# exceptions_log = false'), toml);
  assert.ok(toml.includes('\n[[exceptions]]\nrule = "eval"\n'), toml);
  assert.equal(validate(toml).ok, true);
});

test('schema: exception fields and profiles are declared and exceptions_log is a top-level bool', () => {
  assert.deepEqual(EXCEPTION_FIELDS.map((f) => f.key),
    ['rule', 'script', 'script_sha256', 'param', 'param_prefix', 'uri_prefix', 'client_cidr', 'reason']);
  assert.ok(EXCEPTION_FIELDS.find((f) => f.key === 'rule').required);
  assert.ok(EXCEPTION_FIELDS.find((f) => f.key === 'reason').required);
  const top = SCHEMA.top.find((t) => t.key === 'exceptions_log');
  assert.equal(top.type, 'bool');
  assert.equal(top.default, false);
  assert.equal(SCHEMA.top[0].key, 'on_invalid_config');
  assert.deepEqual(PROFILES.map((p) => p.id), ['wordpress', 'drupal7', 'magento1', 'magento2', 'joomla', 'prestashop16']);
});

test('every shipped profile validates and round-trips through the editor', () => {
  const dir = resolve(here, '../../profiles');
  const files = readdirSync(dir).filter((f) => f.endsWith('.toml')).sort();
  assert.deepEqual(files, PROFILES.map((p) => p.id + '.toml').sort(), 'profiles/ and schema PROFILES differ');
  for (const f of files) {
    const text = readFileSync(resolve(dir, f), 'utf8');
    const v = validate(text);
    assert.equal(v.ok, true, f + ': ' + v.error);
    assert.ok(v.config.exceptions.length > 0, f + ' has no exceptions');
    assert.equal(v.config.mode, 'detect', f);
    const r = E.loadFromCanonical(v.config, catalog);
    assert.ok(r.state, f + ' refused: ' + JSON.stringify(r.unsupported));
    const again = validate(E.emitToml(r.state, {}));
    assert.equal(again.ok, true, f + ' re-emit: ' + again.error);
    assert.deepEqual(again.config.exceptions, v.config.exceptions, f + ' exceptions changed in the round trip');
    assert.deepEqual(again.config.sinks, v.config.sinks, f + ' sinks changed in the round trip');
    assert.deepEqual(again.config.behavior, v.config.behavior, f + ' behavior changed in the round trip');
    for (const e of v.config.exceptions) assert.ok(e.reason && e.reason.length > 10, f + ': reason');
  }
});
