// The event-log contract on the site and in docs/integrations: every sample
// event line the pages show must match what the core writes (schema 2, from
// crates/howdah-core/src/log.rs and docs/howdah-event.schema.json), and the
// SIEM snippets must parse and use only real fields. The snippets themselves
// are run in the real tools by lab/integration/siem_snippets.sh.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repo = resolve(site, '..');
const read = (p) => readFileSync(resolve(repo, p), 'utf8');

// The fields log_line writes, read from the core source.
const logRs = read('crates/howdah-core/src/log.rs');
const jsonBody = logRs.match(/serde_json::json!\(\{([\s\S]*?)\}\)/)?.[1] ?? '';
const FIELDS = [...jsonBody.matchAll(/"(\w+)":/g)].map((m) => m[1]).sort();
const schema = JSON.parse(read('docs/howdah-event.schema.json'));

function validate(s, v, path = '$') {
  const errs = [];
  if (s.type === 'object') {
    if (typeof v !== 'object' || v === null || Array.isArray(v)) return [`${path}: not an object`];
    for (const r of s.required ?? []) if (!(r in v)) errs.push(`${path}: missing ${r}`);
    for (const [k, ps] of Object.entries(s.properties ?? {})) if (k in v) errs.push(...validate(ps, v[k], `${path}.${k}`));
    return errs;
  }
  if (s.type === 'string' && typeof v !== 'string') return [`${path}: not a string`];
  if (s.type === 'integer' && !Number.isInteger(v)) return [`${path}: not an integer`];
  if ('const' in s && v !== s.const) errs.push(`${path}: ${v} != ${s.const}`);
  if (s.enum && !s.enum.includes(v)) errs.push(`${path}: ${v} not in enum`);
  if (s.pattern && !new RegExp(s.pattern).test(v)) errs.push(`${path}: ${v} !~ ${s.pattern}`);
  if (s.maxLength !== undefined && v.length > s.maxLength) errs.push(`${path}: too long`);
  if (s.minimum !== undefined && v < s.minimum) errs.push(`${path}: below minimum`);
  return errs;
}

function checkLine(line, where) {
  const v = JSON.parse(line);
  assert.deepEqual(Object.keys(v).sort(), FIELDS, `${where}: keys`);
  assert.deepEqual(validate(schema, v), [], `${where}: ${line}`);
}

test('the schema file lists exactly the fields log.rs writes', () => {
  assert.equal(FIELDS.length, 11);
  assert.deepEqual([...schema.required].sort(), FIELDS);
  assert.deepEqual(Object.keys(schema.properties).sort(), FIELDS);
  assert.equal(schema.properties.schema.const, 2);
});

test('sample event lines on the site match the core', () => {
  const pages = ['site/src/pages/docs/configuration.astro', 'site/src/pages/index.astro'];
  let n = 0;
  for (const p of pages) {
    const src = read(p);
    const blocks = [...src.matchAll(/data-sample="event"><code>\{`([\s\S]*?)`\}<\/code>/g)].map((m) => m[1]);
    assert.ok(blocks.length > 0, `${p}: no data-sample="event" block`);
    for (const b of blocks) for (const line of b.split('\n')) (checkLine(line, p), n++);
  }
  const compliance = read('site/src/pages/docs/compliance.astro').match(/const samples = String\.raw`([\s\S]*?)`;/)?.[1];
  assert.ok(compliance, 'compliance.astro: no samples');
  for (const line of compliance.split('\n')) (checkLine(line, 'compliance.astro'), n++);
  const md = read('docs/compliance.md').match(/```json\n([\s\S]*?)```/)?.[1] ?? '';
  for (const line of md.trim().split('\n')) (checkLine(line, 'docs/compliance.md'), n++);
  assert.ok(n >= 10, `only ${n} sample lines checked`);
});

test('the configuration page field table is the schema field list', () => {
  const src = read('site/src/pages/docs/configuration.astro');
  const table = src.match(/const logFields = \[([\s\S]*?)\];/)?.[1] ?? '';
  const names = [...table.matchAll(/^\s*\['(\w+)'/gm)].map((m) => m[1]).sort();
  assert.deepEqual(names, FIELDS);
});

test('the Promtail pipeline parses and uses real fields', () => {
  const text = read('docs/integrations/promtail-howdah.yaml');
  const cfg = yaml.load(text);
  const stages = cfg.scrape_configs[0].pipeline_stages;
  const json = stages.find((s) => s.json).json;
  for (const [k, v] of Object.entries(json.expressions)) {
    assert.ok(FIELDS.includes(v), `json expression ${k}: ${v} is not a field`);
  }
  const labels = Object.keys(stages.find((s) => s.labels).labels);
  assert.deepEqual(labels.sort(), ['action', 'layer', 'rule']);
  assert.deepEqual(stages.find((s) => s.timestamp).timestamp, { source: 'ts', format: 'UnixMs' });
  // The site shows this file's pipeline_stages verbatim.
  const page = read('site/src/pages/docs/configuration.astro');
  const excerpt = text.slice(text.indexOf('    pipeline_stages:')).trimEnd();
  assert.ok(page.includes(excerpt), 'configuration.astro Promtail excerpt differs from the tested file');
});

/** Minimal well-formedness: balanced tags, quoted attributes, no stray markup. */
function xmlWellFormed(text) {
  const body = text.replace(/<!--[\s\S]*?-->/g, '');
  const stack = [];
  for (const m of body.matchAll(/<(\/?)([A-Za-z_][\w.-]*)((?:\s+[\w.-]+="[^"<]*")*)\s*(\/?)>/g)) {
    const [, close, name, , self] = m;
    if (self) continue;
    if (close) assert.equal(stack.pop(), name, `unbalanced </${name}>`);
    else stack.push(name);
  }
  assert.deepEqual(stack, [], `unclosed ${stack.join(', ')}`);
  const stripped = body.replace(/<\/?[A-Za-z_][\w.-]*(?:\s+[\w.-]+="[^"<]*")*\s*\/?>/g, '');
  assert.ok(!/[<>]/.test(stripped.replace(/&lt;|&gt;/g, '')), 'stray < or > outside tags');
}

test('the Wazuh decoder and rules are well-formed and use real fields', () => {
  const dec = read('docs/integrations/wazuh/howdah_decoders.xml');
  const rules = read('docs/integrations/wazuh/howdah_rules.xml');
  xmlWellFormed(dec);
  xmlWellFormed(rules);
  for (const [, f] of rules.matchAll(/\$\((\w+)\)/g)) assert.ok(FIELDS.includes(f), `$(${f}) is not a field`);
  for (const [, f] of rules.matchAll(/<field name="(\w+)">/g)) assert.ok(FIELDS.includes(f), `field ${f} is not a field`);
  // `action` is static in Wazuh: <field name="action"> makes analysisd refuse the file.
  assert.ok(!/<field name="action">/.test(rules));
  const page = read('site/src/pages/docs/configuration.astro');
  const decoder = dec.slice(dec.indexOf('<decoder')).trimEnd();
  assert.ok(page.includes(decoder), 'configuration.astro Wazuh decoder differs from the tested file');
});
