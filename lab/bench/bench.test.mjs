// Unit tests for lab/bench/bench.mjs.   node --test lab/bench/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formBody, multipartBody, MULTIPART_BOUNDARY, median, aggregate, baselineOf, gate,
  groupEvents, splitByEncoder, howdahClass, inScope, summarizeCorpus, gotestwafSent, markdown,
} from './bench.mjs';

test('the 1 KB form body is exactly 1024 bytes of benign urlencoded fields', () => {
  const b = formBody().toString('latin1');
  assert.equal(b.length, 1024);
  assert.match(b, /^field_0=/);
  // Nothing Layer 2 looks for: quotes, comment dashes, statement separators,
  // traversal, command substitution.
  for (const bad of ["'", '--', '%27', ';', '%3B', '../', '%2F', '$(', '`', '|']) {
    assert.ok(!b.includes(bad), `form body contains ${bad}`);
  }
  assert.deepEqual(formBody(), formBody(), 'deterministic');
});

test('the multipart body is 51200 bytes with 10 parts, 2 of them files', () => {
  const buf = multipartBody();
  assert.equal(buf.length, 51200);
  const s = buf.toString('latin1');
  const opens = s.split(`--${MULTIPART_BOUNDARY}\r\n`).length - 1;
  assert.equal(opens, 10);
  assert.ok(s.endsWith(`--${MULTIPART_BOUNDARY}--\r\n`));
  assert.equal((s.match(/filename="/g) || []).length, 2);
  assert.deepEqual(multipartBody(), multipartBody(), 'deterministic');
});

test('median handles odd, even and empty inputs', () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 2, 3]), 2.5);
  assert.equal(median([]), null);
});

const wrk = (p50, p99, requests = 10000, extra = {}) => ({
  requests, duration_us: 10_000_000, bytes: 1,
  errors: { connect: 0, read: 0, write: 0, status: 0, timeout: 0, ...(extra.errors || {}) },
  latency_us: { min: 1, mean: p50, stdev: 1, p50, p90: p99, p99, max: p99 },
});
const row = (config, round, p50, p99, opts = {}) => ({
  php: '8.3.36', minor: '8.3', sapi: 'fpm', workload: opts.workload || 'get_nobody', config, round,
  events: opts.events || 0, events_warmup: 0,
  probe: { howdah: config !== 'noext', opcache: true, jit: false, ...(opts.probe || {}) },
  wrk: wrk(p50, p99, opts.requests, opts),
});

test('aggregate takes the median across rounds and computes added microseconds', () => {
  const cells = aggregate([
    row('noext', 1, 100, 300), row('noext', 2, 104, 320), row('noext', 3, 102, 310),
    row('l1', 1, 105, 330), row('l1', 2, 103, 300), row('l1', 3, 107, 340),
  ]);
  const base = cells.find((c) => c.config === 'noext');
  const l1 = cells.find((c) => c.config === 'l1');
  assert.equal(base.p50_us, 102);
  assert.equal(l1.p50_us, 105);
  assert.equal(l1.added_p50_us, 3);
  assert.equal(l1.added_p99_us, 20);
  assert.equal(l1.p50_spread_us, 4);
  assert.equal(l1.ratio_p50, Math.round((105 / 102) * 10000) / 10000);
  assert.equal(l1.valid, true);
  assert.equal(cells[0].config, 'noext', 'baseline sorts first');
});

test('a cell with non-2xx responses, socket errors or the wrong probe is invalid', () => {
  const cells = aggregate([
    row('noext', 1, 100, 300),
    row('l1', 1, 100, 300, { errors: { status: 3 } }),
    row('l12', 1, 100, 300, { errors: { timeout: 1 } }),
    row('l123', 1, 100, 300, { probe: { howdah: false } }),
  ]);
  for (const k of ['l1', 'l12', 'l123']) assert.equal(cells.find((c) => c.config === k).valid, false, k);
  assert.equal(cells.find((c) => c.config === 'noext').valid, true);
});

function resultsFor(rows) {
  return { machine: { date_utc: 'x', cpu_model: 'cpu', git_commit: 'abc', params: {} }, cells: aggregate(rows) };
}

test('the gate passes a run equal to its own baseline', () => {
  const r = resultsFor([row('noext', 1, 100, 300), row('l1', 1, 104, 310)]);
  const { fails } = gate(r, baselineOf(r));
  assert.deepEqual(fails, []);
});

test('the gate fails when GET-no-body added p50 exceeds 50 microseconds', () => {
  const r = resultsFor([row('noext', 1, 100, 300), row('l1', 1, 151, 310)]);
  const { fails } = gate(r, { cells: {} });
  assert.equal(fails.length, 1);
  assert.match(fails[0], /added p50 51/);
});

test('the gate fails a cell whose normalized p50 regressed by more than 25%', () => {
  const base = resultsFor([row('noext', 1, 1000, 3000, { workload: 'post_form_1k' }), row('l12', 1, 1000, 3000, { workload: 'post_form_1k' })]);
  const ok = resultsFor([row('noext', 1, 2000, 6000, { workload: 'post_form_1k' }), row('l12', 1, 2480, 6000, { workload: 'post_form_1k' })]);
  const bad = resultsFor([row('noext', 1, 2000, 6000, { workload: 'post_form_1k' }), row('l12', 1, 2520, 6000, { workload: 'post_form_1k' })]);
  // A slower machine (2x) with the same relative overhead passes; +26% fails.
  assert.deepEqual(gate(ok, baselineOf(base)).fails, []);
  const f = gate(bad, baselineOf(base)).fails;
  assert.equal(f.length, 1);
  assert.match(f[0], /normalized p50 1\.26/);
});

test('the gate fails on Howdah events from benign traffic and on missing cells', () => {
  const base = resultsFor([row('noext', 1, 100, 300), row('l1', 1, 100, 300), row('l12', 1, 100, 300)]);
  const run = resultsFor([row('noext', 1, 100, 300), row('l1', 1, 100, 300, { events: 2 })]);
  const f = gate(run, baselineOf(base)).fails;
  assert.ok(f.some((x) => /wrote 2 Howdah event/.test(x)));
  assert.ok(f.some((x) => /8\.3\/fpm\/get_nobody\/l12: cell missing/.test(x)));
});

test('markdown has a headline row per PHP and server, and flags invalid cells', () => {
  const r = resultsFor([row('noext', 1, 100, 300), row('l1', 1, 103, 300), row('l12', 1, 104, 300, { errors: { status: 1 } })]);
  r.machine = { ...r.machine, nproc: 16, kernel: 'k', os: 'os', pinning: 'none', params: { conns: 4, duration_s: 10, warmup_s: 3, rounds: 3 } };
  const md = markdown(r);
  assert.match(md, /\| 8\.3\.36 \| php-fpm behind nginx \| \+3 \| \+4 \| {2}\|/);
  assert.match(md, /\(INVALID\)/);
});

test('corpus events are attributed to the request whose marker precedes them', () => {
  const log = [
    '{"bench_marker":{"channel":"headers","method":"GET","test":false}}',
    '{"bench_marker":{"channel":"query string","method":"GET","test":true}}',
    '{"rule":"sql_injection","action":"log"}',
    '{"bench_marker":{"channel":"JSON body","method":"POST","test":true}}',
    '{"bench_marker":{"channel":"URL path","method":"GET","test":true}}',
    '{"rule":"command_exec","action":"log"}',
    '{"rule":"path_traversal","action":"log"}',
    'not json',
  ].join('\n');
  const reqs = groupEvents(log);
  assert.equal(reqs.length, 3, 'GoTestWAF start-up probes (test:false) are dropped');
  assert.deepEqual(reqs.map((r) => r.rules), [['sql_injection'], [], ['command_exec', 'path_traversal']]);
});

test('splitByEncoder writes one file per encoder and keeps everything else', () => {
  const y = 'payload:\n  - "a"\n  - b\nencoder:\n  - Base64Flat\n  - URL\nplaceholder:\n  - URLParam\ntype: SQL Injection\n';
  const parts = splitByEncoder(y);
  assert.deepEqual(parts.map((p) => p.encoder), ['Base64Flat', 'URL']);
  assert.equal(parts[1].text, 'payload:\n  - "a"\n  - b\nencoder:\n  - URL\nplaceholder:\n  - URLParam\ntype: SQL Injection\n');
});

test('GoTestWAF test cases map to Layer 2 classes only where they belong', () => {
  assert.equal(howdahClass('sql-injection'), 'sql_injection');
  assert.equal(howdahClass('community-8kb-sqli'), 'sql_injection');
  assert.equal(howdahClass('nosql-injection'), null);
  assert.equal(howdahClass('path-traversal'), 'path_traversal');
  assert.equal(howdahClass('community-lfi-multipart'), 'path_traversal');
  assert.equal(howdahClass('rce-urlpath'), 'command_injection');
  assert.equal(howdahClass('community-rce-rawrequests'), 'command_injection');
  assert.equal(howdahClass('shell-injection'), 'command_injection');
  assert.equal(howdahClass('ss-include'), null);
  assert.equal(howdahClass('community-xss'), null);
});

test('in scope means the raw payload reaches a value Layer 2 reads', () => {
  assert.equal(inScope('Plain', 'multipart form'), true);
  assert.equal(inScope('URL', 'multipart form'), false, 'PHP does not decode multipart fields');
  assert.equal(inScope('URL', 'query string'), true);
  assert.equal(inScope('URL', 'JSON body'), false);
  assert.equal(inScope('Plain', 'headers'), false);
  assert.equal(inScope('Base64Flat', 'query string'), false);
});

test('summarizeCorpus totals per class, in scope and false positives', () => {
  const index = [
    { set: 'owasp', case: 'sql-injection', encoder: 'URL', id: 'sql-injection~URL', id_key: 'owasp__sql-injection~URL' },
    { set: 'owasp', case: 'sql-injection', encoder: 'Base64Flat', id: 'sql-injection~Base64Flat', id_key: 'owasp__sql-injection~Base64Flat' },
    { set: 'false-pos', case: 'texts', encoder: 'URL', id: 'texts~URL', id_key: 'false-pos__texts~URL' },
  ];
  const m = (channel) => ({ channel, test: true });
  const ev = {
    'owasp__sql-injection~URL': [
      { marker: m('query string'), rules: ['sql_injection'] },
      { marker: m('JSON body'), rules: [] },
      { marker: m('urlencoded form'), rules: [] },
    ],
    'owasp__sql-injection~Base64Flat': [{ marker: m('query string'), rules: [] }],
    'false-pos__texts~URL': [{ marker: m('query string'), rules: [] }, { marker: m('urlencoded form'), rules: ['path_traversal'] }],
  };
  const s = summarizeCorpus(index, ev, { 'owasp__sql-injection~URL': 3, 'owasp__sql-injection~Base64Flat': 1, 'false-pos__texts~URL': 2 });
  const sqli = s.cases.find((c) => c.name === 'sql-injection');
  assert.equal(sqli.sent, 4);
  assert.equal(sqli.reached_php, 4);
  assert.equal(sqli.flagged, 1);
  assert.equal(sqli.in_scope_reached, 2);
  assert.equal(sqli.in_scope_flagged, 1);
  assert.equal(s.by_class.sql_injection.in_scope_rate_pct, 50);
  assert.equal(s.totals.benign.flagged, 1);
  assert.equal(s.totals.benign.rate_pct, 50);
  assert.deepEqual(s.by_encoder.Base64Flat, { reached: 1, flagged: 0, rate_pct: 0 });
});

test('gotestwafSent reads the per-test-case sent count from either summary', () => {
  const rep = { summary: { true_negative_tests: { test_sets: { 'false-pos': { 'texts~URL': { sent: 141 } } } } } };
  assert.equal(gotestwafSent(rep, 'false-pos', 'texts~URL'), 141);
  assert.equal(gotestwafSent(rep, 'owasp', 'x'), 0);
});
