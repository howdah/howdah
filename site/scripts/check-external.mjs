#!/usr/bin/env node
// Fail if the built site would make a third-party request.
//
// A request is anything the browser loads or sends to: <script src>, <link
// href> (stylesheets, fonts, preconnects, icons), <img>/<source>/<video>/
// <audio>/<iframe>/<embed>/<object>/<track> sources, <form action>, CSS
// url()/@import, and any URL string inside JavaScript (inline or in a .js
// file). A plain hyperlink (<a href>) is a citation the reader may follow; it
// is not a request and is allowed.
//
// Usage: node scripts/check-external.mjs <dist dir>
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ALLOWED = [
  /^https:\/\/((pkg|cfg)\.)?howdah\.org(\/|$)/,
  /^https:\/\/github\.com\/howdah\/howdah(\/|$)/,
  /^http:\/\/www\.w3\.org\/2000\/svg$/,
  // Placeholder shown inside example commands on the install page; never fetched.
  /^https:\/\/your\.site\//,
];

const URL_RE = /https?:\/\/[^"'\s)<>\\]+/g;
// Tags whose URL-bearing attributes cause a load or a submission.
const LOADING_TAG_RE = /<(script|link|img|iframe|source|video|audio|embed|object|track|form)\b[^>]*>/gi;
const ATTR_RE = /\b(?:src|href|action|data|poster|srcset)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
const INLINE_STYLE_RE = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
const STYLE_BLOCK_RE = /<style\b[^>]*>([\s\S]*?)<\/style>/gi;
const SCRIPT_BLOCK_RE = /<script\b[^>]*>([\s\S]*?)<\/script>/gi;

const urls = (s) => (s.match(URL_RE) ?? []).map((u) => u.replace(/[.,;:]+$/, ''));
const external = (u) => !ALLOWED.some((re) => re.test(u));

/** URLs in `text` (of kind 'html' | 'css' | 'js') that would be requested from a third party. */
export function findExternal(kind, text) {
  let found = [];
  if (kind === 'html') {
    for (const tag of text.match(LOADING_TAG_RE) ?? []) {
      for (const m of tag.matchAll(ATTR_RE)) found.push(...urls(m[1] ?? m[2] ?? m[3] ?? ''));
    }
    for (const m of text.matchAll(INLINE_STYLE_RE)) found.push(...urls(m[1] ?? m[2] ?? ''));
    for (const m of text.matchAll(STYLE_BLOCK_RE)) found.push(...urls(m[1]));
    for (const m of text.matchAll(SCRIPT_BLOCK_RE)) found.push(...urls(m[1]));
  } else {
    found = urls(text);
  }
  return [...new Set(found.filter(external))];
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

const KIND = { '.html': 'html', '.css': 'css', '.js': 'js', '.mjs': 'js' };

export function checkDist(dist) {
  const problems = [];
  for (const file of walk(dist)) {
    const kind = KIND[extname(file)];
    if (!kind) continue;
    for (const u of findExternal(kind, readFileSync(file, 'utf8'))) problems.push(`${file}: ${u}`);
  }
  return problems;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const dist = process.argv[2];
  if (!dist) {
    console.error('usage: check-external.mjs <dist dir>');
    process.exit(2);
  }
  const problems = checkDist(dist);
  if (problems.length) {
    console.error('third-party requests in the build output:');
    for (const p of problems) console.error('  ' + p);
    process.exit(1);
  }
  console.log('check-external: no third-party requests');
}
