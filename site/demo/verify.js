// Headless check: loads howdah_wasm.wasm in Node and asserts each demo sample
// produces its expected verdict through the same glue the page uses.
// Usage: node site/demo/verify.js
'use strict';
const fs = require('fs');
const path = require('path');
const H = require('./howdah-wasm.js');
const samples = require('./samples.js');

(async () => {
  const { instance } = await WebAssembly.instantiate(
    fs.readFileSync(path.join(__dirname, 'howdah_wasm.wasm')), {});
  let bad = 0;
  for (const s of samples) {
    const v = H.analyzeWith(instance.exports, '', s.build());
    const ok = v.action === s.expect.action && v.rule === s.expect.rule;
    if (!ok) bad++;
    console.log(ok ? 'PASS' : 'FAIL', s.id, JSON.stringify(v));
  }
  process.exit(bad ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
