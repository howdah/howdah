// The schema table is the single source the editor's form, emitter and notes
// are built from. These tests pin it to the two authorities it must agree
// with: the core (through the wasm validator) and docs/config.md.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const H = require('../demo/howdah-wasm.js');
const { SCHEMA, defaultState, RULE_LAYER } = require('../config-editor/schema.js');

const x = await H.loadFrom(readFileSync(resolve(here, '../demo/howdah_wasm.wasm')));
const catalog = H.ruleCatalogWith(x);
const core = H.validateConfigWith(x, '').config;
const state = defaultState(catalog);

const sectionKeys = (id) => SCHEMA.sections.find((s) => s.id === id).keys;

test('every schema default equals the core default', () => {
  for (const k of sectionKeys('limits')) assert.equal(state['limits.' + k.key], core.limits[k.key], k.key);
  assert.equal(state['inspect.enabled'], core.inspect.enabled);
  assert.equal(state['inspect.mode'], core.inspect.mode);
  assert.equal(state['inspect.sqli'], core.inspect.sqli);
  assert.equal(state['inspect.traversal'], core.inspect.traversal);
  assert.equal(state['inspect.cmdi'], core.inspect.cmdi);
  for (const k of ['max_value_bytes', 'max_total_bytes', 'max_values']) {
    assert.equal(state['inspect.limits.' + k], core.inspect.limits[k], k);
  }
  assert.equal(state['sinks.enabled'], core.sinks.enabled);
  assert.equal(state['sinks.mode'], core.sinks.mode);
  assert.equal(state['sinks.unserialize.mode'], core.sinks.unserialize.mode);
  assert.equal(state['sinks.unserialize.mode'], 'off');
  assert.deepEqual(state['sinks.command_exec.allow'], []);
  // The ini default is the SHIPPED default (packaging/howdah.ini), deliberately
  // not the core's safe default, which is "block".
  assert.equal(state['howdah.mode'], 'detect');
  assert.equal(core.mode, 'block');
});

test('rules section covers the catalog with matching severities and a layer each', () => {
  const rules = sectionKeys('rules');
  assert.equal(rules.length, catalog.length);
  for (const c of catalog) {
    const r = rules.find((k) => k.key === c.name);
    assert.ok(r, c.name + ' missing from schema');
    assert.equal(r.severity, c.severity, c.name);
    assert.ok(RULE_LAYER[c.name], c.name + ' has no layer');
    assert.equal(state['rules.' + c.name], 'inherit');
  }
});

test('every [limits] key documented in docs/config.md is in the schema with the same default', () => {
  const md = readFileSync(resolve(here, '../../docs/config.md'), 'utf8');
  const rows = [...md.matchAll(/^\| `(max_[a-z_]+)` \| ([^|]+?) \|/gm)];
  assert.equal(rows.length, 12);
  const units = { '256 MiB': 268435456 };
  for (const [, key, def] of rows) {
    const want = units[def.trim()] ?? Number(def.trim());
    const k = sectionKeys('limits').find((s) => s.key === key);
    assert.ok(k, key + ' not in schema');
    assert.equal(k.default, want, key);
    assert.equal(k.type, 'int');
    assert.equal(k.min, 1);
    assert.ok(typeof k.note === 'string' && k.note.length > 10, key + ' note');
  }
});

test('no schema key is named log or starts with log.', () => {
  for (const k of Object.keys(state)) {
    assert.ok(k !== 'log' && !k.startsWith('log.'), k);
  }
  assert.ok(!SCHEMA.sections.some((s) => s.id === 'log'));
});

test('ini entries, presets and php7-only sinks are declared', () => {
  assert.deepEqual(SCHEMA.ini.map((i) => i.key), ['howdah.mode', 'howdah.log', 'howdah.config']);
  assert.equal(SCHEMA.ini[2].default, '/etc/howdah/howdah.toml');
  assert.deepEqual(Object.keys(SCHEMA.presets), ['defaults', 'enforcing']);
  assert.equal(SCHEMA.presets.enforcing['howdah.mode'], 'block');
  assert.deepEqual(SCHEMA.sections.find((s) => s.id === 'sinks').php7Only, ['include', 'eval']);
});
