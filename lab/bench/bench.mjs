#!/usr/bin/env node
// Reporting half of the Howdah benchmarks (no dependencies; Node 18+).
//
//   node lab/bench/bench.mjs bodies <dir>
//       Write the POST workload bodies (deterministic bytes, same every run).
//   node lab/bench/bench.mjs report <raw.jsonl> <machine.json> <outdir>
//       Aggregate wrk rounds into <outdir>/results.json and results.md.
//   node lab/bench/bench.mjs baseline <results.json>
//       Print a CI baseline (normalized p50 per cell) to stdout.
//   node lab/bench/bench.mjs gate <results.json> <baseline.json>
//       CI regression gate; exits 1 on a breach (see README.md for the rules).
//   node lab/bench/bench.mjs split <testcases> <outdir> <index.json>
//       Split GoTestWAF test cases into one file per encoder; prints the list.
//   node lab/bench/bench.mjs corpus <rundir>
//       Summarize a corpus.sh run into <rundir>/corpus.json and corpus.md.
//   node lab/bench/bench.mjs publish <results.json> <corpus.json> <jit.json> <out.json>
//       Merge the three result files into the site's data file.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export const CONFIGS = ['noext', 'l1', 'l12', 'l123'];
export const CONFIG_LABEL = {
  noext: 'No extension',
  l1: 'Layer 1',
  l12: 'Layers 1+2',
  l123: 'Layers 1+2+3',
};
export const WORKLOADS = ['get_nobody', 'post_form_1k', 'post_multipart_50k', 'sink_exec_include'];
export const WORKLOAD_LABEL = {
  get_nobody: 'GET, no body',
  post_form_1k: 'POST, 1 KB form',
  post_multipart_50k: 'POST, 50 KB multipart (10 parts)',
  sink_exec_include: "GET, system('true') + include",
};
export const SAPI_LABEL = {
  fpm: 'php-fpm behind nginx',
  apache: 'Apache mod_php (prefork)',
};

// The CI gate's thresholds. Deliberately loose: GitHub-hosted runners are
// shared VMs and their latency moves by tens of percent between runs.
export const GATE = { maxAddedGetP50Us: 50, maxRegress: 0.25 };

// ---- bodies ----------------------------------------------------------------

export const MULTIPART_BOUNDARY = '----HowdahBench0';

function lcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s >>> 24;
  };
}

const WORDS = ('order invoice customer address street city postal country phone ' +
  'note delivery morning evening garden kitchen window paper pencil table chair ' +
  'summer winter spring autumn river mountain coffee yellow purple orange green ' +
  'monday friday weekend project report budget meeting holiday travel ticket').split(' ');

function words(rand, n) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(WORDS[rand() % WORDS.length]);
  return out.join(' ');
}

/** 1024-byte application/x-www-form-urlencoded body of ordinary form fields. */
export function formBody() {
  const rand = lcg(1);
  const pairs = [];
  for (let i = 0; pairs.join('&').length < 900; i++) {
    pairs.push(`field_${i}=${encodeURIComponent(words(rand, 6)).replace(/%20/g, '+')}`);
  }
  let body = pairs.join('&') + '&pad=';
  while (body.length < 1024) body += 'x';
  return Buffer.from(body.slice(0, 1024), 'latin1');
}

/** 51200-byte multipart/form-data body: 8 text fields + 2 file parts. */
export function multipartBody() {
  const rand = lcg(2);
  const b = MULTIPART_BOUNDARY;
  const head = [];
  for (let i = 0; i < 8; i++) {
    head.push(Buffer.from(
      `--${b}\r\nContent-Disposition: form-data; name="text_${i}"\r\n\r\n${words(rand, 30)}\r\n`, 'latin1'));
  }
  const fileHead = (i) => Buffer.from(
    `--${b}\r\nContent-Disposition: form-data; name="upload_${i}"; filename="photo-${i}.jpg"\r\n` +
    'Content-Type: image/jpeg\r\n\r\n', 'latin1');
  const crlf = Buffer.from('\r\n', 'latin1');
  const tail = Buffer.from(`--${b}--\r\n`, 'latin1');
  const fixed = head.reduce((n, x) => n + x.length, 0) + fileHead(0).length + fileHead(1).length +
    2 * crlf.length + tail.length;
  const room = 51200 - fixed;
  const sizes = [Math.floor(room / 2), room - Math.floor(room / 2)];
  const files = sizes.map((n) => {
    const buf = Buffer.alloc(n);
    for (let i = 0; i < n; i++) buf[i] = rand();
    // keep the boundary marker out of the binary payload
    for (let i = 0; i + 1 < n; i++) if (buf[i] === 0x2d && buf[i + 1] === 0x2d) buf[i + 1] = 0x2e;
    return buf;
  });
  return Buffer.concat([...head, fileHead(0), files[0], crlf, fileHead(1), files[1], crlf, tail]);
}

function cmdBodies(dir) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'form-1k.txt'), formBody());
  writeFileSync(join(dir, 'multipart-50k.bin'), multipartBody());
}

// ---- report ----------------------------------------------------------------

export function median(xs) {
  const a = [...xs].sort((x, y) => x - y);
  if (!a.length) return null;
  const m = Math.floor(a.length / 2);
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}

const round1 = (x) => (x == null ? null : Math.round(x * 10) / 10);

export function parseRaw(text) {
  return text.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

/** Aggregate raw rounds into cells (median across rounds) with deltas vs noext. */
export function aggregate(rows) {
  const cells = new Map();
  for (const r of rows) {
    const key = [r.minor, r.sapi, r.workload, r.config].join('/');
    if (!cells.has(key)) {
      cells.set(key, { minor: r.minor, php: r.php, sapi: r.sapi, workload: r.workload, config: r.config, rounds: [] });
    }
    cells.get(key).rounds.push(r);
  }
  const out = [];
  for (const c of cells.values()) {
    const ok = c.rounds.filter((r) => r.wrk && r.wrk.latency_us);
    const p50s = ok.map((r) => r.wrk.latency_us.p50);
    const p99s = ok.map((r) => r.wrk.latency_us.p99);
    const rpss = ok.map((r) => r.wrk.requests / (r.wrk.duration_us / 1e6));
    const errs = ok.reduce((n, r) => n + r.wrk.errors.connect + r.wrk.errors.read + r.wrk.errors.write + r.wrk.errors.timeout, 0);
    const non2xx = ok.reduce((n, r) => n + r.wrk.errors.status, 0);
    const events = c.rounds.reduce((n, r) => n + (r.events || 0), 0);
    const wantHowdah = c.config !== 'noext';
    const probeOk = c.rounds.every((r) => r.probe && r.probe.howdah === wantHowdah && r.probe.opcache === true);
    out.push({
      minor: c.minor,
      php: c.php,
      sapi: c.sapi,
      workload: c.workload,
      config: c.config,
      rounds: c.rounds.length,
      requests: ok.reduce((n, r) => n + r.wrk.requests, 0),
      p50_us: median(p50s),
      p99_us: median(p99s),
      rps: round1(median(rpss)),
      p50_spread_us: p50s.length ? Math.max(...p50s) - Math.min(...p50s) : null,
      socket_errors: errs,
      non_2xx: non2xx,
      events,
      load1_max: c.rounds.some((r) => typeof r.load1 === 'number') ? Math.max(...c.rounds.map((r) => r.load1 ?? 0)) : null,
      jit: c.rounds[0]?.probe?.jit ?? null,
      valid: ok.length === c.rounds.length && errs === 0 && non2xx === 0 && probeOk,
    });
  }
  const base = new Map(out.filter((c) => c.config === 'noext').map((c) => [[c.minor, c.sapi, c.workload].join('/'), c]));
  for (const c of out) {
    const b = base.get([c.minor, c.sapi, c.workload].join('/'));
    if (!b || c.p50_us == null || b.p50_us == null) continue;
    c.added_p50_us = round1(c.p50_us - b.p50_us);
    c.added_p99_us = round1(c.p99_us - b.p99_us);
    c.rps_change_pct = b.rps ? round1((c.rps / b.rps - 1) * 100) : null;
    c.ratio_p50 = Math.round((c.p50_us / b.p50_us) * 10000) / 10000;
  }
  const order = (c) => [c.minor, c.sapi === 'fpm' ? 0 : 1, WORKLOADS.indexOf(c.workload), CONFIGS.indexOf(c.config)];
  out.sort((a, b) => {
    const x = order(a), y = order(b);
    for (let i = 0; i < x.length; i++) {
      if (x[i] < y[i]) return -1;
      if (x[i] > y[i]) return 1;
    }
    return 0;
  });
  return out;
}

const fmt = (x) => (x == null ? 'n/a' : Number.isInteger(x) ? String(x) : x.toFixed(1));
const signed = (x) => (x == null ? '' : (x > 0 ? '+' : x < 0 ? '−' : '±') + fmt(Math.abs(x)));

export function markdown(results) {
  const { machine, cells } = results;
  const L = [];
  const p = machine.params || {};
  L.push(`Run ${machine.date_utc} on ${machine.cpu_model} (${machine.nproc} CPUs), kernel ${machine.kernel}, ${machine.os}.`);
  L.push(`wrk ${p.conns} connection(s), ${p.duration_s} s per round after a ${p.warmup_s} s warmup, ${p.rounds} round(s) per cell, ` +
    `median across rounds. CPU pinning: ${machine.pinning}. OPcache on, JIT off.` +
    (machine.load1 ? ` Host 1-minute load average across rounds: ${machine.load1.min} to ${machine.load1.max} (median ${machine.load1.median}).` : ''));
  L.push('');
  L.push('Added p50 latency for "GET, no body" (microseconds, versus no extension):');
  L.push('');
  L.push('| PHP | Server | Layer 1 | Layers 1+2 | Layers 1+2+3 |');
  L.push('|---|---|---|---|---|');
  const groups = [...new Set(cells.map((c) => `${c.minor}/${c.sapi}`))];
  for (const g of groups) {
    const [minor, sapi] = g.split('/');
    const get = (cfg) => cells.find((c) => c.minor === minor && c.sapi === sapi && c.workload === 'get_nobody' && c.config === cfg);
    const php = get('noext')?.php ?? minor;
    L.push(`| ${php} | ${SAPI_LABEL[sapi] ?? sapi} | ${['l1', 'l12', 'l123'].map((k) => signed(get(k)?.added_p50_us)).join(' | ')} |`);
  }
  for (const g of groups) {
    const [minor, sapi] = g.split('/');
    const rows = cells.filter((c) => c.minor === minor && c.sapi === sapi);
    L.push('');
    L.push(`### PHP ${rows[0].php}, ${SAPI_LABEL[sapi] ?? sapi}`);
    L.push('');
    L.push('| Workload | Config | p50 µs | p99 µs | Requests/s | Added p50 µs | Added p99 µs | Requests/s change | Events |');
    L.push('|---|---|---|---|---|---|---|---|---|');
    for (const c of rows) {
      const isBase = c.config === 'noext';
      L.push(`| ${WORKLOAD_LABEL[c.workload] ?? c.workload} | ${CONFIG_LABEL[c.config] ?? c.config} | ${fmt(c.p50_us)} | ${fmt(c.p99_us)} | ` +
        `${fmt(c.rps)} | ${isBase ? '' : signed(c.added_p50_us)} | ${isBase ? '' : signed(c.added_p99_us)} | ` +
        `${isBase ? '' : (c.rps_change_pct == null ? '' : signed(c.rps_change_pct) + '%')} | ${c.events}${c.valid ? '' : ' (INVALID)'} |`);
    }
  }
  L.push('');
  return L.join('\n');
}

function cmdReport(rawPath, machinePath, outdir) {
  const rows = parseRaw(readFileSync(rawPath, 'utf8'));
  const machine = JSON.parse(readFileSync(machinePath, 'utf8'));
  const cells = aggregate(rows);
  const loads = rows.map((r) => r.load1).filter((x) => typeof x === 'number');
  // The host's 1-minute load average at the end of every round: how busy the
  // (shared) machine was while it was measured.
  const load1 = loads.length ? { min: Math.min(...loads), median: median(loads), max: Math.max(...loads) } : null;
  const results = { schema: 1, machine: { ...machine, load1 }, cells };
  mkdirSync(outdir, { recursive: true });
  writeFileSync(join(outdir, 'results.json'), JSON.stringify(results, null, 2) + '\n');
  const md = markdown(results);
  writeFileSync(join(outdir, 'results.md'), md);
  process.stdout.write(md);
  const bad = cells.filter((c) => !c.valid);
  if (bad.length) {
    console.error(`WARNING: ${bad.length} invalid cell(s) (socket errors, non-2xx, or wrong probe):`);
    for (const c of bad) console.error(`  ${c.minor} ${c.sapi} ${c.workload} ${c.config}`);
  }
}

// ---- CI baseline + gate ------------------------------------------------------

export function baselineOf(results) {
  const cells = {};
  for (const c of results.cells) {
    if (c.config === 'noext') continue;
    cells[[c.minor, c.sapi, c.workload, c.config].join('/')] = { ratio_p50: c.ratio_p50, added_p50_us: c.added_p50_us };
  }
  return {
    note: 'Normalized p50 (cell p50 / same-run no-extension p50) per cell. Generated by `node lab/bench/bench.mjs baseline` from a MODE=ci run; see lab/bench/README.md.',
    generated_from: { date_utc: results.machine.date_utc, cpu_model: results.machine.cpu_model, git_commit: results.machine.git_commit },
    thresholds: GATE,
    cells,
  };
}

/** Returns a list of human-readable failures (empty = pass). */
export function gate(results, baseline, t = GATE) {
  const fails = [];
  const notes = [];
  const byKey = new Map(results.cells.map((c) => [[c.minor, c.sapi, c.workload, c.config].join('/'), c]));
  for (const c of results.cells) {
    if (!c.valid) fails.push(`${c.minor} ${c.sapi} ${c.workload} ${c.config}: invalid cell (socket errors ${c.socket_errors}, non-2xx ${c.non_2xx}, or wrong probe)`);
    if (c.config !== 'noext' && c.events > 0) fails.push(`${c.minor} ${c.sapi} ${c.workload} ${c.config}: benign traffic wrote ${c.events} Howdah event(s)`);
    if (c.workload === 'get_nobody' && c.config !== 'noext' && c.added_p50_us != null) {
      const line = `${c.minor} ${c.sapi} get_nobody ${c.config}: added p50 ${c.added_p50_us} us (limit ${t.maxAddedGetP50Us})`;
      if (c.added_p50_us > t.maxAddedGetP50Us) fails.push(line); else notes.push(line);
    }
  }
  for (const [key, b] of Object.entries(baseline.cells)) {
    const c = byKey.get(key);
    if (!c) { fails.push(`${key}: cell missing from this run`); continue; }
    const limit = b.ratio_p50 * (1 + t.maxRegress);
    const line = `${key}: normalized p50 ${c.ratio_p50} vs baseline ${b.ratio_p50} (limit ${limit.toFixed(4)})`;
    if (c.ratio_p50 > limit) fails.push(line); else notes.push(line);
  }
  return { fails, notes };
}

function cmdGate(resultsPath, baselinePath) {
  const results = JSON.parse(readFileSync(resultsPath, 'utf8'));
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  const { fails, notes } = gate(results, baseline);
  for (const n of notes) console.log('ok   ' + n);
  for (const f of fails) console.log('FAIL ' + f);
  if (fails.length) {
    console.log(`bench gate: ${fails.length} failure(s)`);
    process.exit(1);
  }
  console.log('bench gate: pass');
}

// ---- corpus ------------------------------------------------------------------

/**
 * Split one GoTestWAF test-case YAML into one YAML per encoder, so every
 * GoTestWAF run has a single known encoder (the app cannot tell a
 * Base64-encoded payload from a plain one). The test-case files are simple:
 * top-level `payload:`, `encoder:`, `placeholder:` and `type:` keys, each a
 * list; only the `encoder:` list is rewritten.
 */
export function splitByEncoder(text) {
  const lines = text.split('\n');
  const ei = lines.findIndex((l) => /^encoder:\s*$/.test(l));
  if (ei < 0) return [{ encoder: 'none', text }];
  let pi = lines.findIndex((l, i) => i > ei && /^[A-Za-z_]+:/.test(l));
  if (pi < 0) pi = lines.length;
  const encs = lines.slice(ei + 1, pi).filter((l) => /^\s*-\s*\S/.test(l))
    .map((l) => l.replace(/^\s*-\s*/, '').trim().replace(/^["']|["']$/g, ''));
  return encs.map((encoder) => ({
    encoder,
    text: [...lines.slice(0, ei + 1), `  - ${encoder}`, ...lines.slice(pi)].join('\n'),
  }));
}

export function caseType(text) {
  const m = text.match(/^type:\s*(.*)$/m);
  return m ? m[1].trim().replace(/^["']|["']$/g, '') : null;
}

/** The Layer 2 class a GoTestWAF test case belongs to, or null if none. */
export function howdahClass(name) {
  if (name === 'sql-injection' || /(^|-)sqli$/.test(name)) return 'sql_injection';
  if (name === 'path-traversal' || /(^|-)lfi(-|$)/.test(name)) return 'path_traversal';
  if (/^(rce|shell-injection)(-|$)/.test(name) || /(^|-)rce(-|$)/.test(name)) return 'command_injection';
  return null;
}

export const L2_RULES = ['sql_injection', 'path_traversal', 'command_injection'];

/**
 * "In scope" = the request puts the raw payload where Layer 2 looks, i.e. the
 * value PHP hands the application is the attack string itself. Layer 2 reads
 * decoded GET, POST (urlencoded and multipart fields), cookie and URL-path
 * values; GoTestWAF has no cookie placement. Verified against what the app
 * received:
 *  - Plain: the raw payload, in every placement below.
 *  - URL: PHP decodes it in the query string and urlencoded form (the app sees
 *    the raw payload); in the URL path Layer 2 checks the encoded form; in a
 *    multipart field PHP does NOT decode it, so the app sees percent-encoded
 *    text, which is not an attack unless the app decodes it itself.
 *  - Base64Flat: only the application could decode it; never in scope.
 * Headers and JSON/XML bodies are not inspected (PHP does not parse those into
 * $_POST), so they are never in scope.
 */
export function inScope(encoder, placement) {
  if (encoder === 'Plain') return ['query string', 'urlencoded form', 'multipart form', 'URL path'].includes(placement);
  if (encoder === 'URL') return ['query string', 'urlencoded form', 'URL path'].includes(placement);
  return false;
}

/**
 * Split a corpus.sh event log into per-request groups. The corpus app writes a
 * marker line {"bench_marker":{...}} into the Howdah event log while the
 * script runs; Howdah's own lines for that request follow it (sink lines
 * during the script, the Layer 1/2 line at request shutdown), before the next
 * request's marker. Requests are strictly sequential (one GoTestWAF worker, one
 * php-fpm child), so the grouping is exact. Requests without GoTestWAF's debug
 * header (its start-up probes) are dropped.
 */
export function groupEvents(text) {
  const reqs = [];
  let cur = null;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    let j;
    try { j = JSON.parse(line); } catch { continue; }
    if (j.bench_marker) {
      cur = { marker: j.bench_marker, rules: [] };
      reqs.push(cur);
    } else if (j.rule && cur) {
      cur.rules.push(j.rule);
    }
  }
  return reqs.filter((r) => r.marker.test !== false);
}

const pct = (a, b) => (b ? Math.round((a / b) * 1000) / 10 : null);
const bump = (o, k, flagged) => {
  o[k] ??= { reached: 0, flagged: 0 };
  o[k].reached++;
  if (flagged) o[k].flagged++;
};

/** Summarize the grouped requests of every split run, per original test case. */
export function summarizeCorpus(index, eventsById, sentById = {}) {
  const cases = new Map();
  for (const e of index) {
    const key = `${e.set}/${e.case}`;
    if (!cases.has(key)) {
      cases.set(key, {
        set: e.set, name: e.case, type: e.type, howdah_class: howdahClass(e.case),
        benign: e.set === 'false-pos', sent: 0, reached_php: 0, flagged: 0, flagged_same_class: 0,
        in_scope_reached: 0, in_scope_flagged: 0, by_encoder: {}, by_placement: {}, by_rule: {},
      });
    }
    const c = cases.get(key);
    c.sent += sentById[e.id_key] ?? 0;
    for (const r of eventsById[e.id_key] ?? []) {
      const l2 = r.rules.filter((x) => L2_RULES.includes(x));
      const flagged = l2.length > 0;
      const place = r.marker.channel || 'other';
      c.reached_php++;
      if (flagged) c.flagged++;
      if (c.howdah_class && l2.includes(c.howdah_class)) c.flagged_same_class++;
      if (inScope(e.encoder, place)) {
        c.in_scope_reached++;
        if (flagged) c.in_scope_flagged++;
      }
      bump(c.by_encoder, e.encoder, flagged);
      bump(c.by_placement, place, flagged);
      for (const x of new Set(r.rules)) c.by_rule[x] = (c.by_rule[x] || 0) + 1;
    }
  }
  const list = [...cases.values()];
  for (const c of list) {
    c.rate_pct = pct(c.flagged, c.reached_php);
    c.in_scope_rate_pct = pct(c.in_scope_flagged, c.in_scope_reached);
  }
  const total = (xs) => {
    const t = { cases: xs.length, sent: 0, reached: 0, flagged: 0, in_scope_reached: 0, in_scope_flagged: 0 };
    for (const c of xs) {
      t.sent += c.sent; t.reached += c.reached_php; t.flagged += c.flagged;
      t.in_scope_reached += c.in_scope_reached; t.in_scope_flagged += c.in_scope_flagged;
    }
    t.rate_pct = pct(t.flagged, t.reached);
    t.in_scope_rate_pct = pct(t.in_scope_flagged, t.in_scope_reached);
    return t;
  };
  const attack = list.filter((c) => !c.benign);
  const byClass = {};
  for (const k of [...L2_RULES, null]) {
    byClass[k ?? 'other'] = total(attack.filter((c) => c.howdah_class === k));
  }
  const merge = (field, xs) => {
    const o = {};
    for (const c of xs) {
      for (const [k, v] of Object.entries(c[field])) {
        o[k] ??= { reached: 0, flagged: 0 };
        o[k].reached += v.reached;
        o[k].flagged += v.flagged;
      }
    }
    for (const v of Object.values(o)) v.rate_pct = pct(v.flagged, v.reached);
    return o;
  };
  const l2cases = attack.filter((c) => c.howdah_class);
  return {
    totals: { attack: total(attack), benign: total(list.filter((c) => c.benign)) },
    by_class: byClass,
    // Placement and encoder breakdowns cover the test cases in Layer 2's three
    // classes only, so out-of-class payloads (XSS, LDAP, ...) do not dilute them.
    by_placement: merge('by_placement', l2cases),
    by_encoder: merge('by_encoder', l2cases),
    cases: list,
  };
}

/** Requests GoTestWAF says it sent for one split run (true-positive or -negative). */
export function gotestwafSent(rep, set, id) {
  const s = rep?.summary ?? {};
  for (const k of ['true_positive_tests', 'true_negative_tests']) {
    const v = s[k]?.test_sets?.[set]?.[id]?.sent;
    if (typeof v === 'number') return v;
  }
  return 0;
}

function cmdSplit(orig, out, indexPath) {
  const index = [];
  for (const set of readdirSync(orig).sort()) {
    const sd = join(orig, set);
    let files;
    try { files = readdirSync(sd).filter((x) => x.endsWith('.yml')).sort(); } catch { continue; }
    for (const f of files) {
      const name = f.replace(/\.yml$/, '');
      const text = readFileSync(join(sd, f), 'utf8');
      mkdirSync(join(out, set), { recursive: true });
      for (const { encoder, text: t } of splitByEncoder(text)) {
        const id = `${name}~${encoder}`;
        writeFileSync(join(out, set, `${id}.yml`), t);
        index.push({ set, case: name, encoder, id, id_key: `${set}__${id}`, type: caseType(text) });
      }
    }
  }
  writeFileSync(indexPath, JSON.stringify(index, null, 2) + '\n');
  process.stdout.write(index.map((e) => `${e.set}/${e.id}`).join('\n') + '\n');
}

function cmdCorpus(dir) {
  const meta = JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8'));
  const index = JSON.parse(readFileSync(join(dir, 'cases-index.json'), 'utf8'));
  const eventsById = {};
  const sentById = {};
  for (const e of index) {
    const ev = join(dir, 'events', `${e.id_key}.log`);
    if (existsSync(ev)) eventsById[e.id_key] = groupEvents(readFileSync(ev, 'utf8'));
    const rep = join(dir, 'reports', `${e.id_key}.json`);
    if (existsSync(rep)) {
      try { sentById[e.id_key] = gotestwafSent(JSON.parse(readFileSync(rep, 'utf8')), e.set, e.id); } catch { /* no report */ }
    }
  }
  const out = { schema: 1, meta, ...summarizeCorpus(index, eventsById, sentById) };
  writeFileSync(join(dir, 'corpus.json'), JSON.stringify(out, null, 2) + '\n');
  const md = corpusMarkdown(out);
  writeFileSync(join(dir, 'corpus.md'), md);
  process.stdout.write(md);
}

export const CLASS_LABEL = {
  sql_injection: 'SQL injection',
  path_traversal: 'Path traversal / LFI',
  command_injection: 'Command injection / RCE',
  other: 'Not a Layer 2 class (XSS, LDAP, NoSQL, SSTI, XXE, ...)',
};

export function corpusMarkdown(out) {
  const L = [];
  const m = out.meta;
  const b = out.totals.benign;
  const r = (f, n) => `${f}/${n} (${n ? fmt(pct(f, n)) + '%' : 'n/a'})`;
  L.push(`GoTestWAF ${m.gotestwaf_version} payloads, PHP ${m.php} (${m.sapi}), Howdah ${m.howdah_version} at shipped defaults (Layer 2 in detect mode), run ${m.date_utc}.`);
  L.push('"Flagged" = Howdah logged a Layer 2 event (sql_injection, path_traversal or command_injection) for that request.');
  L.push('"In scope" = the raw payload arrives where Layer 2 looks: plain or URL-encoded in the query string, urlencoded form or URL path, or plain in a multipart field.');
  L.push('');
  L.push('| Payload class | GoTestWAF test cases | Flagged, all requests | Flagged, in scope |');
  L.push('|---|---|---|---|');
  for (const [k, t] of Object.entries(out.by_class)) {
    L.push(`| ${CLASS_LABEL[k] ?? k} | ${t.cases} | ${r(t.flagged, t.reached)} | ${r(t.in_scope_flagged, t.in_scope_reached)} |`);
  }
  L.push(`| Benign (GoTestWAF false-pos set): false positives | ${b.cases} | ${r(b.flagged, b.reached)} | ${r(b.in_scope_flagged, b.in_scope_reached)} |`);
  L.push('');
  L.push('Per GoTestWAF test case:');
  L.push('');
  L.push('| Test set | Test case | Layer 2 class | Sent | Reached PHP | Flagged | In scope flagged |');
  L.push('|---|---|---|---|---|---|---|');
  for (const c of out.cases) {
    const cls = c.benign ? 'benign' : (c.howdah_class ?? '-');
    if (!c.sent && !c.reached_php) {
      L.push(`| ${c.set} | ${c.name} | ${cls} | 0 | 0 | not sent (needs a GraphQL or gRPC endpoint, or not selected) | |`);
      continue;
    }
    L.push(`| ${c.set} | ${c.name} | ${cls} | ${c.sent} | ${c.reached_php} | ` +
      `${r(c.flagged, c.reached_php)} | ${r(c.in_scope_flagged, c.in_scope_reached)} |`);
  }
  L.push('');
  L.push('Layer 2 classes only, by where the payload was placed (all encodings):');
  L.push('');
  L.push('| Placement | Flagged |');
  L.push('|---|---|');
  for (const [k, v] of Object.entries(out.by_placement).sort()) L.push(`| ${k} | ${r(v.flagged, v.reached)} |`);
  L.push('');
  L.push('Layer 2 classes only, by GoTestWAF encoder (all placements):');
  L.push('');
  L.push('| Encoder | Flagged |');
  L.push('|---|---|');
  for (const [k, v] of Object.entries(out.by_encoder).sort()) L.push(`| ${k} | ${r(v.flagged, v.reached)} |`);
  L.push('');
  return L.join('\n');
}

// ---- publish -----------------------------------------------------------------

function cmdPublish(resultsPath, corpusPath, jitPath, outPath) {
  const results = JSON.parse(readFileSync(resultsPath, 'utf8'));
  const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'));
  const jit = JSON.parse(readFileSync(jitPath, 'utf8'));
  const data = {
    schema: 1,
    latency: {
      machine: results.machine,
      cells: results.cells.map((c) => ({
        minor: c.minor, php: c.php, sapi: c.sapi, workload: c.workload, config: c.config,
        p50_us: c.p50_us, p99_us: c.p99_us, rps: c.rps, p50_spread_us: c.p50_spread_us,
        added_p50_us: c.added_p50_us ?? null, added_p99_us: c.added_p99_us ?? null,
        rps_change_pct: c.rps_change_pct ?? null, events: c.events, valid: c.valid, jit: c.jit,
      })),
    },
    corpus: {
      meta: corpus.meta,
      totals: corpus.totals,
      by_class: corpus.by_class,
      by_placement: corpus.by_placement,
      by_encoder: corpus.by_encoder,
      cases: corpus.cases.map((c) => ({
        set: c.set, name: c.name, howdah_class: c.howdah_class, benign: c.benign, sent: c.sent,
        reached_php: c.reached_php, flagged: c.flagged, in_scope_reached: c.in_scope_reached,
        in_scope_flagged: c.in_scope_flagged,
      })),
    },
    jit,
  };
  writeFileSync(outPath, JSON.stringify(data, null, 2) + '\n');
}

// ---- main --------------------------------------------------------------------

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const [cmd, ...a] = process.argv.slice(2);
  switch (cmd) {
    case 'bodies': cmdBodies(a[0]); break;
    case 'report': cmdReport(a[0], a[1], a[2]); break;
    case 'baseline': process.stdout.write(JSON.stringify(baselineOf(JSON.parse(readFileSync(a[0], 'utf8'))), null, 2) + '\n'); break;
    case 'gate': cmdGate(a[0], a[1]); break;
    case 'split': cmdSplit(a[0], a[1], a[2]); break;
    case 'corpus': cmdCorpus(a[0]); break;
    case 'publish': cmdPublish(a[0], a[1], a[2], a[3]); break;
    default:
      console.error('usage: bench.mjs bodies|report|baseline|gate|split|corpus|publish ...');
      process.exit(2);
  }
}
