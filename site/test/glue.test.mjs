// The wasm glue's config-editor entry points, driven in Node against the
// freshly built howdah_wasm.wasm (run `npm run wasm` first).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const H = require('../demo/howdah-wasm.js');
const wasmBytes = readFileSync(resolve(here, '../demo/howdah_wasm.wasm'));

const x = await H.loadFrom(wasmBytes);

test('validateConfigWith returns the parsed config for an empty file', () => {
  const v = H.validateConfigWith(x, '');
  assert.equal(v.ok, true);
  assert.equal(v.config.mode, 'block');
  assert.equal(v.config.limits.max_parts, 2000);
  assert.equal(v.config.sinks.unserialize.mode, 'off');
});

test('validateConfigWith returns the core error text', () => {
  const v = H.validateConfigWith(x, '[limits]\nmax_files = 0');
  assert.equal(v.ok, false);
  assert.match(v.error, /max_files/);
});

test('ruleCatalogWith lists every rule with severities', () => {
  const rules = H.ruleCatalogWith(x);
  assert.equal(rules.length, 44);
  assert.ok(rules.some((r) => r.name === 'phar') && rules.some((r) => r.name === 'ssrf'));
  assert.ok(rules.some((r) => r.name === 'include_wrapper') && rules.some((r) => r.name === 'file_open'));
  assert.ok(rules.some((r) => r.name === 'tls_verify') && rules.some((r) => r.name === 'dangerous_callback'));
  assert.ok(rules.some((r) => r.name === 'out_of_memory') && rules.some((r) => r.name === 'startup_fatal'));
  assert.ok(rules.some((r) => r.name === 'post_too_large') && rules.some((r) => r.name === 'nesting_budget') && rules.some((r) => r.name === 'parse_memory_estimate'));
  assert.ok(rules.some((r) => r.name === 'fatal_recycle') && rules.some((r) => r.name === 'cgi_arg_injection'));
  assert.equal(rules.find((r) => r.name === 'cgi_arg_injection').severity, 'standard');
  assert.deepEqual(rules[0], { name: 'max_parts', severity: 'critical' });
  assert.equal(rules.find((r) => r.name === 'malformed_multipart').severity, 'standard');
});

test('versionWith matches the Cargo.toml workspace version', () => {
  const cargo = readFileSync(resolve(here, '../../Cargo.toml'), 'utf8');
  const want = cargo.match(/^version = "([^"]+)"/m)[1];
  assert.equal(H.versionWith(x), want);
});

test('validateConfig (async, auto-loading) works when load() is given bytes first', async () => {
  const v = await H.validateConfig('mode = "detect"');
  assert.equal(v.ok, true);
  assert.equal(v.config.mode, 'detect');
});
