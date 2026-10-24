// The site must not make third-party requests: no external scripts, styles,
// fonts, images, frames or fetches. Hyperlinks to sources (<a href>) are
// allowed; a citation is not a request. This mirrors the guard pages.yml runs
// before deploying, so a PR that would break the deploy fails here first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { ensureBuilt, site } from './build-site.mjs';
import { findExternal } from '../scripts/check-external.mjs';

test('an <a href> to an external source is not a request', () => {
  const html = '<p>See <a href="https://www.pcisecuritystandards.org/document_library/">the standard</a>.</p>';
  assert.deepEqual(findExternal('html', html), []);
});

test('external script, stylesheet, image, frame and form targets are flagged', () => {
  const html = [
    '<script src="https://cdn.example/x.js"></script>',
    '<link rel="stylesheet" href="https://fonts.example/css">',
    '<img src="https://img.example/a.png">',
    '<iframe src="https://frame.example/"></iframe>',
    '<form action="https://form.example/post">',
    '<link rel="preconnect" href="https://fonts.gstatic.com">',
  ].join('\n');
  const found = findExternal('html', html);
  assert.deepEqual(found.sort(), [
    'https://cdn.example/x.js',
    'https://fonts.example/css',
    'https://fonts.gstatic.com',
    'https://form.example/post',
    'https://frame.example/',
    'https://img.example/a.png',
  ]);
});

test('inline styles, inline scripts, CSS and JS files are scanned for URLs', () => {
  assert.deepEqual(findExternal('html', '<style>@import url("https://fonts.example/a.css");</style>'), ['https://fonts.example/a.css']);
  assert.deepEqual(findExternal('html', '<div style="background:url(https://img.example/b.png)">'), ['https://img.example/b.png']);
  assert.deepEqual(findExternal('html', '<script>fetch("https://api.example/x")</script>'), ['https://api.example/x']);
  assert.deepEqual(findExternal('css', 'a{background:url(https://img.example/c.png)}'), ['https://img.example/c.png']);
  assert.deepEqual(findExternal('js', 'const u = "https://api.example/y";'), ['https://api.example/y']);
});

test('first-party hosts and the SVG namespace are allowed everywhere', () => {
  const html = [
    '<script src="https://howdah.org/demo/x.js"></script>',
    '<img src="https://pkg.howdah.org/a.png">',
    '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
    '<script>fetch("https://cfg.howdah.org/v1/abc")</script>',
  ].join('\n');
  assert.deepEqual(findExternal('html', html), []);
  assert.deepEqual(findExternal('js', 'fetch("https://github.com/howdah/howdah/releases")'), []);
});

test('the built site makes no third-party requests', () => {
  ensureBuilt(resolve(site, 'dist/index.html'), [resolve(site, 'src/pages/index.astro')]);
  const r = spawnSync(process.execPath, [resolve(site, 'scripts/check-external.mjs'), resolve(site, 'dist')], { encoding: 'utf8' });
  assert.equal(r.status, 0, `check-external failed:\n${r.stdout}${r.stderr}`);
});
