# Howdah Config Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A page at `howdah.org/config/` that builds `howdah.ini` + `howdah.toml` from form controls, validates the TOML with the real `howdah-core` (wasm), and hands it out as copy, download, or a `curl` URL served by a stateless Cloudflare Worker on `cfg.howdah.org`.

**Architecture:** One schema table (`site/config-editor/schema.js`) drives the form, the TOML emitter and the notes. The emitter and payload codec are pure, UMD-style JS (`site/config-editor/editor.js`) testable in Node and loaded by the Astro page as a plain script, like the demo. Validation is a new export on `howdah-wasm` that returns the core's error text or the parsed config as canonical JSON; the page and the Worker run the same wasm built from the same commit (no committed binary any more).

**Tech Stack:** Rust (`howdah-core`, `howdah-wasm`, serde), Astro 5 + vanilla JS (site), Node 22 `node --test`, Cloudflare Workers (ESM `fetch` handler, wasm module import), GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-24-howdah-config-editor-design.md`

## Global Constraints

- Validation comes only from `howdah_core::Config::from_toml` via wasm; no JavaScript validation logic beyond "is this a number" input hints (spec §4).
- `mode` is always written in the emitted TOML; other keys are omitted when equal to `Config::safe_defaults()` unless "include defaults as comments" is on (spec §5).
- `[log]` is never emitted or offered; a loaded file containing it is refused with a message naming the key (spec §5).
- `[rules]` offers every `RuleId` the core accepts (22 names today) (spec §5).
- Fetch URL format: `https://cfg.howdah.org/v1/<payload>`; payload is base64url (no padding) of the TOML bytes, or `z.` + base64url of `deflate-raw`(TOML) when shorter; decoded TOML ≤ 16384 bytes, payload ≤ 12000 characters; the page never emits a URL over those limits (spec §7).
- Worker responses: valid → `200`, `text/plain; charset=utf-8`, `Content-Disposition: inline; filename="howdah.toml"`, `Cache-Control: public, max-age=31536000, immutable`, `X-Howdah-Validated: <version>`; invalid → `422` with the core's error text; oversize → `413`; other path → `404`; other method → `405`; the Worker stores and logs nothing (spec §7).
- Site bar: WCAG 2.2 AA, light and dark via existing CSS tokens, no trackers/cookies/third-party requests, works without JS (defaults rendered server-side), phone width with 16px gutters (spec §3, design §10).
- Copy for notes is taken from `docs/config.md` wording; nothing on the page may claim more than that file does (spec §4).
- Commit messages follow the repo's `type(scope): subject` style; every commit ends with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Review Focus

1. A `[sinks.command_exec] allow` pattern containing `"` or `\` (e.g. `C:\tools\*`, `echo "hi"`): the emitted TOML must stay parseable and round-trip to the same string. Test in Task 5 (`escapes_quotes_and_backslashes_in_strings`).
2. A very long allow list (hundreds of paths) pushes the payload past 12000 characters: the `curl` block must be disabled with the reason, never truncated. Test in Task 5 (`curl_command_is_null_when_payload_exceeds_limit`).
3. Pasting a TOML that uses only `[rules] sql_injection = "block"` (a Layer 2 rule name) must load into the form, not be refused. Test in Task 5 (`load_accepts_every_rule_id`).
4. A payload with `+`, `/` or `=` (someone hand-built standard base64) or a trailing slash/query string: the Worker must answer 404/422 cleanly, never throw. Test in Task 7 (`rejects_non_base64url_payload`, `ignores_query_and_trailing_slash`).
5. Validation unavailable (wasm fails to load, e.g. CSP or old browser): the page must say so and keep copy working, never show "valid". Covered by the no-JS fallback markup and the `validation unavailable` branch in Task 6; manual check in Task 6 step 7.

---

### Task 1: Core: canonical config JSON and the wasm validator export

**Files:**
- Modify: `crates/howdah-core/src/config.rs` (derives on `Mode`, `LogConfig`, `InspectConfig`, `CommandExecConfig`, `IncludeConfig`, `EvalConfig`, `UnserializeConfig`, `SinkConfig`, `Config`)
- Modify: `crates/howdah-core/src/limits.rs` (`Limits`, `RuleId`, `Severity`), `crates/howdah-core/src/inspect.rs` (`InspectLimits`)
- Modify: `crates/howdah-wasm/src/lib.rs`
- Test: `crates/howdah-wasm/src/lib.rs` (`mod tests`)

**Interfaces:**
- Produces: `howdah_core::Config: serde::Serialize` (field order = declaration order; `rule_modes` serialises as `"rules"` via `#[serde(rename = "rules")]`; `RuleId` and `Mode` serialise to their snake_case / lowercase names).
- Produces: `pub fn rule_catalog() -> Vec<(&'static str, Severity)>` in `limits.rs`: every `RuleId` in declaration order with its severity, names as serde spells them.
- Produces wasm exports (same alloc/free/result_len protocol as `howdah_wasm_analyze`):
  - `howdah_wasm_validate_config(toml_ptr: *const u8, toml_len: usize) -> *mut u8` returning JSON `{"ok":true,"config":<Config as JSON>}` or `{"ok":false,"error":"<ConfigError Display>"}`.
  - `howdah_wasm_rule_catalog() -> *mut u8` returning JSON `[{"name":"max_parts","severity":"critical"},…]`.
  - `howdah_wasm_version() -> *mut u8` returning `CARGO_PKG_VERSION` as a UTF-8 string (not JSON).

- [ ] **Step 1: Write the failing tests** in `crates/howdah-wasm/src/lib.rs` `mod tests` (call the pure helpers directly, not the raw pointers):

```rust
#[test] fn validate_empty_is_defaults() {
    let v: serde_json::Value = serde_json::from_str(&validate_config(b"")).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["config"]["mode"], "block");
    assert_eq!(v["config"]["limits"]["max_parts"], 2000);
    assert_eq!(v["config"]["sinks"]["unserialize"]["mode"], "off");
    assert!(v["config"]["rules"].is_object());
}
#[test] fn validate_reports_unknown_key_text() {
    let v: serde_json::Value = serde_json::from_str(&validate_config(b"[limits]\nnope = 1")).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().unwrap().contains("nope"));
}
#[test] fn validate_reports_zero_limit() { /* "[limits]\nmax_files = 0" -> ok false, error contains "max_files" */ }
#[test] fn validate_reports_invalid_toml() { /* b"= = =" -> ok false */ }
#[test] fn validate_round_trips_detect_mode_and_rule_override() {
    let v: serde_json::Value = serde_json::from_str(&validate_config(b"mode = \"detect\"\n[rules]\nsql_injection = \"block\"")).unwrap();
    assert_eq!(v["config"]["mode"], "detect");
    assert_eq!(v["config"]["rules"]["sql_injection"], "block");
}
#[test] fn rule_catalog_has_every_rule_with_severity() {
    let v: serde_json::Value = serde_json::from_str(&rule_catalog_json()).unwrap();
    let names: Vec<&str> = v.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(names.len(), 22);
    assert!(names.contains(&"max_parts") && names.contains(&"unserialize"));
    assert_eq!(v[0]["severity"], "critical");
    assert_eq!(v.as_array().unwrap().iter().find(|r| r["name"] == "malformed_multipart").unwrap()["severity"], "standard");
}
#[test] fn version_is_cargo_version() { assert_eq!(version_str(), env!("CARGO_PKG_VERSION")); }
```

- [ ] **Step 2: Run to verify fail:** `cargo test -p howdah-wasm` → compile errors (`validate_config`, `rule_catalog_json`, `version_str` undefined).

- [ ] **Step 3: Implement.** In `howdah-core`: add `Serialize` to the derives listed above (`Config` is a plain struct today; derive `Serialize` with `#[serde(rename = "rules")]` on `rule_modes`); add `pub fn rule_catalog()` next to `RuleId::severity`, built from an explicit array of all variants (a unit test in `limits.rs`, `rule_catalog_covers_every_variant`, matches on a `RuleId` to force a compile error when a variant is added). In `howdah-wasm`: `fn validate_config(toml: &[u8]) -> String`, `fn rule_catalog_json() -> String`, `fn version_str() -> &'static str`, and the three `#[no_mangle] extern "C"` exports that wrap them with the existing `into_raw`/`RESULT_LEN` protocol (`howdah_wasm_version` stores its length too). Update the module doc comment's ABI list.

- [ ] **Step 4: Run to verify pass:** `cargo test -p howdah-wasm -p howdah-core` → all green; `cargo clippy -p howdah-core -p howdah-wasm --all-targets -- -D warnings` clean; `cargo build -p howdah-wasm --target wasm32-unknown-unknown --release` succeeds.

- [ ] **Step 5: Commit** — `feat(wasm): config validator export with canonical config JSON and rule catalog`.

### Task 2: Build pipeline: fresh wasm for the site, no committed binary

**Files:**
- Modify: `.gitignore` (add `/site/demo/howdah_wasm.wasm`), remove the tracked file with `git rm --cached site/demo/howdah_wasm.wasm`
- Modify: `site/scripts/copy-demo.mjs` (clear error when the wasm is missing)
- Modify: `.github/workflows/pages.yml` (Rust toolchain + `packaging/build-wasm.sh` before `npm run build`; allowlist `cfg.howdah.org`)
- Modify: `site/package.json` (`"wasm": "sh ../packaging/build-wasm.sh"` script; `"test": "node --test test/"`)
- Modify: `CHANGELOG.md` (`[Unreleased] / Fixed`: demo wasm was stale since 1.0; now built on every site deploy)

**Interfaces:**
- Produces: `npm run wasm` (in `site/`) builds `site/demo/howdah_wasm.wasm` from the checkout; `npm run build` fails with `howdah_wasm.wasm missing: run npm run wasm` if it is absent.

- [ ] **Step 1: Write the failing check:** `site/test/copy-demo.test.mjs` with `node --test`: temporarily rename `site/demo/howdah_wasm.wasm`, run `node scripts/copy-demo.mjs` as a child process, assert exit code 1 and stderr contains `howdah_wasm.wasm missing`; restore the file in `finally`.
- [ ] **Step 2: Run to verify fail:** `cd site && node --test test/` → FAIL (script throws ENOENT, different message, or copies a stale file).
- [ ] **Step 3: Implement:** in `copy-demo.mjs` check `existsSync(src wasm)` first and `console.error('howdah_wasm.wasm missing: run npm run wasm (packaging/build-wasm.sh)'); process.exit(1)`. Add the two package.json scripts. In `pages.yml` add before `npm ci`: `dtolnay/rust-toolchain@stable` with `targets: wasm32-unknown-unknown`, `actions/cache@v4` on `~/.cargo` and `target` keyed by `Cargo.lock`, then `run: packaging/build-wasm.sh`. Extend the external-URL allowlist regex with `|^https://cfg\.howdah\.org`. `git rm --cached` the binary and ignore it.
- [ ] **Step 4: Run to verify pass:** `cd site && npm run wasm && node --test test/ && npm ci && npm run build` → test passes, build succeeds, `site/dist/demo/howdah_wasm.wasm` exists and `strings` on it contains `allow_classes` (proves it is the fresh build, not the 1.0 one). `git status` shows the binary untracked and ignored.
- [ ] **Step 5: Commit** — `build(site): build the demo wasm on every deploy instead of committing a stale binary`.

### Task 3: JS glue: `validateConfig`, `ruleCatalog`, `version`

**Files:**
- Modify: `site/demo/howdah-wasm.js`
- Test: `site/test/glue.test.mjs`

**Interfaces:**
- Produces on `HowdahWasm` (window global and CommonJS export): `validateConfigWith(exports, toml: string) -> {ok:true, config:object} | {ok:false, error:string}`, `validateConfig(toml)` (loads first), `ruleCatalogWith(exports) -> Array<{name, severity}>`, `versionWith(exports) -> string`, plus `loadFrom(bytes: Uint8Array) -> exports` for Node callers.

- [ ] **Step 1: Write the failing tests** (`node --test`, loading `site/demo/howdah_wasm.wasm` via `fs` and `WebAssembly.instantiate`, requiring the glue with `createRequire`):

```js
test('validateConfigWith returns the parsed config', ...) // '' -> ok true, config.mode === 'block'
test('validateConfigWith returns the core error', ...)    // '[limits]\nmax_files = 0' -> ok false, /max_files/
test('ruleCatalogWith lists 22 rules with severities', ...)
test('versionWith matches Cargo.toml workspace version', ...) // read ../../Cargo.toml, compare
```

- [ ] **Step 2: Run to verify fail:** `cd site && node --test test/glue.test.mjs` → FAIL (`validateConfigWith is not a function`).
- [ ] **Step 3: Implement** the four functions in `howdah-wasm.js` following `analyzeWith` (alloc, call, read `howdah_wasm_result_len()` immediately, free). `versionWith` decodes raw UTF-8 (not JSON).
- [ ] **Step 4: Run to verify pass:** `node --test test/glue.test.mjs` → PASS; `node demo/verify.js` still PASS.
- [ ] **Step 5: Commit** — `feat(site): wasm glue exposes config validation, rule catalog and version`.

### Task 4: The schema table

**Files:**
- Create: `site/config-editor/schema.js` (UMD like the glue: `window.HowdahConfigSchema` + `module.exports`)
- Test: `site/test/schema.test.mjs`

**Interfaces:**
- Produces `SCHEMA`:
  ```js
  {
    ini: [ {key:'howdah.mode', type:'enum', values:['detect','block','off'], default:'detect', note}, {key:'howdah.log', type:'path', default:'/var/log/howdah.log', note}, {key:'howdah.config', type:'path', default:'/etc/howdah/howdah.toml', note} ],
    sections: [
      {id:'limits', title, group:'multipart'|'input'|'headers' per key, keys:[{key, type:'int', min:1, default, note}, …12]},
      {id:'rules', keys: /* filled from ruleCatalog at runtime: {key:<rule>, type:'mode-or-inherit', default:'inherit', severity, layer} */ },
      {id:'inspect', keys:[enabled:bool=true, mode:enum=detect, sqli/traversal/cmdi:bool=true, 'limits.max_value_bytes':int=16384, 'limits.max_total_bytes':int=2097152, 'limits.max_values':int=2000, 'rule_modes.sql_injection'|'path_traversal'|'command_injection': mode-or-inherit]},
      {id:'sinks', keys:[enabled:bool=true, mode:enum=detect, 'command_exec.mode':mode-or-inherit, 'command_exec.allow':list, 'unserialize.mode':enum=off, 'unserialize.allow_classes':list, 'include.mode':mode-or-inherit, 'include.allow_paths':list, 'eval.mode':mode-or-inherit], php7Only:['include','eval']}
    ],
    presets: { defaults: {'howdah.mode':'detect'}, enforcing: {'howdah.mode':'block'} }
  }
  ```
  Notes are strings taken from `docs/config.md`. `RULE_LAYER = {max_parts:'multipart', …, sql_injection:'inspect', …, command_exec:'sinks', …}`.
- Produces `defaultState(ruleCatalog) -> state`: a flat `Map`-like object `{ 'howdah.mode': 'detect', 'limits.max_parts': 2000, 'rules.max_parts': 'inherit', 'inspect.mode': 'detect', 'sinks.command_exec.allow': [], … }`.

- [ ] **Step 1: Write the failing tests** (`node --test`, using Task 3's glue against the built wasm):

```js
test('every schema default equals the core default', ...)
  // state = defaultState(catalog); core = validateConfigWith(x, '').config;
  // for each limits key: state['limits.'+k] === core.limits[k]; inspect.limits likewise;
  // inspect.mode/enabled/sqli/traversal/cmdi; sinks.mode/enabled; sinks.unserialize.mode === 'off';
  // 'howdah.mode' default is 'detect' (the SHIPPED ini default; deliberately not the core's 'block').
test('rules section covers the catalog with matching severities', ...) // 22 rules, severity from catalog, every rule has a layer
test('every [limits] key documented in docs/config.md is in the schema with the same default', ...)
  // parse the table rows "| `max_x` | 2000 |" from ../../docs/config.md (256 MiB -> 268435456 handled by a small map)
test('no schema key is named log or starts with log.', ...)
```

- [ ] **Step 2: Run to verify fail** → `schema.js` not found.
- [ ] **Step 3: Implement** `schema.js` with the table above and `defaultState`.
- [ ] **Step 4: Run to verify pass:** `node --test test/schema.test.mjs` → PASS.
- [ ] **Step 5: Commit** — `feat(site): config editor schema table checked against the core and docs/config.md`.

### Task 5: Emitter, loader and payload codec

**Files:**
- Create: `site/config-editor/editor.js` (UMD: `window.HowdahConfigEditor` + `module.exports`)
- Test: `site/test/editor.test.mjs`

**Interfaces:**
- Consumes: `SCHEMA`, `defaultState` (Task 4); `validateConfigWith` (Task 3) in tests only.
- Produces:
  - `emitToml(state, {includeDefaults:boolean}) -> string`. Always writes `mode = "<state['howdah.mode']>"` first. Sections in order `[limits]`, `[rules]`, `[inspect]`, `[inspect.limits]`, `[inspect.rule_modes]`, `[sinks]`, `[sinks.command_exec]`, `[sinks.unserialize]`, `[sinks.include]`, `[sinks.eval]`; a section is omitted when it has no non-default key (unless `includeDefaults`, where defaults appear as `# key = value` comment lines). `inherit` rule modes are never written. Strings are TOML basic strings with `\\`, `\"` and control characters escaped; lists one item per line.
  - `emitIni(state) -> string`: `extension=howdah.so`, `howdah.mode=…`, `howdah.config=…`, `howdah.log=…` with the short comments from `packaging/howdah.ini`.
  - `loadFromCanonical(config: object, catalog) -> {state} | {unsupported: string[]}`: builds state from the wasm's canonical JSON; returns `unsupported: ['log']` when `config.log.path` is non-null. Rule modes present in `config.rules` become the select values; everything else maps 1:1.
  - `encodePayload(toml: string) -> string | null` (base64url without padding of UTF-8 bytes; if `CompressionStream` exists and `'z.' + base64url(deflateRaw)` is shorter, that; `null` when the result exceeds `PAYLOAD_MAX = 12000` or the TOML exceeds `TOML_MAX = 16384` bytes). Async (returns a Promise) because `CompressionStream` is async.
  - `decodePayload(payload: string) -> Promise<string>` (inverse; throws on invalid base64url or oversize). Shared with the Worker.
  - `curlCommand(payload: string | null, configPath: string) -> string | null`: the three-line block from spec §5, or `null`.

- [ ] **Step 1: Write the failing tests:**

```js
test('shipped defaults emit only the mode line', ...)        // emitToml(defaultState) === 'mode = "detect"\n'
test('emitted presets validate and round-trip through the core', ...)
  // for preset in [defaults, enforcing]: v = validateConfigWith(x, emitToml(state)); v.ok; v.config.mode === state['howdah.mode']
test('every key round-trips to the value set', ...)
  // for each schema key: set a non-default value (int: default+1; bool: !default; enum: another value; list: ['a','b']); emit; validate ok; canonical value equals
test('mode is always written even when it equals the core default', ...) // state mode 'block' -> first line mode = "block"
test('includeDefaults writes defaults as comments', ...)      // contains '# max_parts = 2000'
test('escapes_quotes_and_backslashes_in_strings', ...)         // allow ['echo "hi"', 'C:\\tools\\*'] -> validate ok, canonical equals input
test('inherit rule modes are not written', ...)
test('load_accepts_every_rule_id', ...)                        // canonical of '[rules]\nsql_injection = "block"' loads; state['rules.sql_injection'] === 'block'
test('load refuses a config with [log]', ...)                  // unsupported deep-equals ['log']
test('load then emit reproduces a non-trivial config', ...)    // emit(load(validate(toml).config)) validates to the same canonical JSON
test('payload round-trips and uses z. when shorter', ...)      // decodePayload(await encodePayload(t)) === t; long repetitive toml -> startsWith('z.')
test('payload uses only base64url characters', ...)            // /^(z\.)?[A-Za-z0-9_-]+$/
test('curl_command_is_null_when_payload_exceeds_limit', ...)   // 600 allow paths of 40 chars -> encodePayload null, curlCommand null
test('curl command names the config path', ...)               // contains "-o /etc/howdah/howdah.toml" and 'https://cfg.howdah.org/v1/'
```

- [ ] **Step 2: Run to verify fail** → `editor.js` not found.
- [ ] **Step 3: Implement** `editor.js`. Base64url via `btoa`/`Buffer`-free code (manual table) so the same file runs in browser, Node and the Worker. Deflate via `CompressionStream('deflate-raw')`/`DecompressionStream`, both global in Node 22, browsers and Workers.
- [ ] **Step 4: Run to verify pass:** `node --test test/editor.test.mjs` → PASS.
- [ ] **Step 5: Commit** — `feat(site): config editor emitter, loader and payload codec`.

### Task 6: The page

**Files:**
- Create: `site/src/pages/config.astro`
- Modify: `site/scripts/copy-demo.mjs` (also copy `site/config-editor/{schema,editor}.js` → `public/config/`)
- Modify: `site/src/lib/site.ts` (export `CFG = 'https://cfg.howdah.org'`)

**Interfaces:**
- Consumes: `/demo/howdah-wasm.js` (Task 3), `/config/schema.js` (Task 4), `/config/editor.js` (Task 5), all loaded with `<script is:inline src>`; frontmatter imports `../../config-editor/schema.js` and `editor.js` (CommonJS exports work under Vite) to server-render the default outputs for no-JS.
- Page structure per spec §5: `pagehead` + `wrap` like `install.astro`; `<form id="cfg">` with the preset buttons, a "Load existing" `<details>` holding a `<textarea>` and `<input type="file" accept=".toml,text/plain">`, one `<fieldset>` per schema section (controls generated from `SCHEMA` at runtime; the no-JS markup is the server-rendered defaults in the same shape), each control with `<small>` note and "default: …"; output panel `<aside id="out">` with tabs (two `<button role="tab">` + `<pre tabindex="0">`), `#valid` line (`aria-live="polite"`), Copy and Download buttons, `#curl` block, the include-defaults toggle, and the footer notes. `php7Only` sinks carry the "PHP 7.0+ only" note; `inspect.mode = block` shows the enforcement-timing caveat.
- Behaviour: on any change, debounce 150 ms → `emitToml`/`emitIni` → `validateConfig` → update `#valid` ("Valid for Howdah <version>" or the error verbatim, with `class="ok|bad"`), enable/disable Download and the curl block (`disabled` + reason: invalid, or over the size limit); `#curl` text from `curlCommand(await encodePayload(toml), state['howdah.config'])`. Load existing: validate the pasted text; on `ok` call `loadFromCanonical`; on `unsupported` show "This file sets [log]…edit it by hand"; on error show the core's text; the form is untouched in both failure cases. If `HowdahWasm.load` rejects, `#valid` reads "Validation unavailable in this browser: copy is still available, the curl link is not" and the curl block stays disabled.

- [ ] **Step 1: Write the failing test:** `site/test/page.test.mjs`: run `astro build` once (skip if `dist/config/index.html` is already fresh), read `dist/config/index.html` and assert: it contains `mode = &quot;detect&quot;` (or the escaped equivalent) in the server-rendered TOML, contains `extension=howdah.so`, contains `<fieldset` × ≥ 4, contains `aria-live="polite"`, contains `/config/editor.js` and `/demo/howdah-wasm.js` script tags, and contains no `http(s)://` host other than `howdah.org`, `pkg.howdah.org`, `cfg.howdah.org`, `github.com/howdah/howdah`.
- [ ] **Step 2: Run to verify fail** → no `dist/config/index.html`.
- [ ] **Step 3: Implement** `config.astro`, the copy step, and `CFG`. Styles scoped in the page (`<style>`), reusing `--surface`, `--rule`, `--muted`, `--ok`, `--no`, `--hot`, `.btn`, `.note`, `.legend`; sticky `aside` at ≥ 960px, stacked below; focus rings visible; buttons ≥ 44px tall.
- [ ] **Step 4: Run to verify pass:** `cd site && npm run build && node --test test/page.test.mjs` → PASS.
- [ ] **Step 5: Manual browser check** with `npm run preview` (or the built `dist` served statically): defaults load; change `max_files` to 0 → error text from the core; set it back → valid; add an allow pattern with `*` in the middle → the core's "only allowed as the final character" error; Load existing with a `[log]` file → refused; Download produces the shown TOML; the curl block text matches `curlCommand`. Record what was seen.
- [ ] **Step 6: Accessibility pass:** run the local `ui-validator` agent on `http://localhost:4321/config/` at phone and desktop widths, light and dark; fix any axe violation or contrast failure in the page's own markup/styles; keep the evidence folder path for the PR.
- [ ] **Step 7: Verify the validation-unavailable branch:** in the preview, block `/demo/howdah_wasm.wasm` in devtools (or temporarily rename it in `dist/`) → `#valid` shows the unavailable text, Copy works, curl block disabled.
- [ ] **Step 8: Commit** — `feat(site): config editor page at /config/`.

### Task 7: The fetch Worker

**Files:**
- Create: `site/worker/index.js` (ESM: `export function handle(request, exports, version)`; `export default { async fetch(request, env, ctx) }` that instantiates the imported wasm module once)
- Create: `site/worker/wrangler.toml` (`name = "howdah-cfg"`, `main = "index.js"`, `compatibility_date` = a 2026 date, `[[rules]] type = "CompiledWasm" globs = ["**/*.wasm"]`, custom domain `cfg.howdah.org` via `routes = [{ pattern = "cfg.howdah.org", custom_domain = true }]`, `workers_dev = false`, `[observability] enabled = false`)
- Create: `site/worker/README.md` (what it is, that it stores nothing, how to deploy)
- Create: `.github/workflows/worker.yml` (on `push: tags: ['v*']` and `workflow_dispatch`: checkout, Rust toolchain + wasm target, `packaging/build-wasm.sh`, copy the wasm and `site/demo/howdah-wasm.js` + `site/config-editor/editor.js` next to the Worker, `npx wrangler@3 deploy` with `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` secrets)
- Test: `site/test/worker.test.mjs`

**Interfaces:**
- Consumes: `decodePayload` (Task 5), `validateConfigWith` / `versionWith` (Task 3), the wasm.
- Produces: HTTP behaviour exactly as Global Constraints state. `handle` builds a `Response`; the default export passes the instantiated exports so tests call `handle` with a Node-instantiated instance and a `new Request(url)`.

- [ ] **Step 1: Write the failing tests:**

```js
test('valid payload returns the TOML with the pinned headers', ...)
  // payload = await encodePayload('mode = "detect"\n'); r = await handle(new Request('https://cfg.howdah.org/v1/'+payload), x, '1.2.1')
  // status 200; text === 'mode = "detect"\n'; headers content-type, content-disposition, cache-control, x-howdah-validated as specified
test('compressed payload works', ...)                   // 'z.' form
test('invalid config returns 422 with the core error and not the config', ...) // '[limits]\nmax_files = 0' -> 422, body /max_files/, body not containing 'max_files = 0'
test('oversize payload returns 413', ...)                // 12001 'A's
test('rejects_non_base64url_payload', ...)               // 'ab+/=' -> 422 or 404, never throws
test('ignores_query_and_trailing_slash', ...)            // '/v1/<p>/?x=1' -> 404; '/v1/<p>?x=1' -> 200
test('other paths and methods', ...)                      // '/' -> 200 text/plain explanation; '/v2/x' -> 404; POST -> 405 with Allow: GET, HEAD; HEAD -> 200 empty body
```

- [ ] **Step 2: Run to verify fail** → `index.js` not found.
- [ ] **Step 3: Implement** `handle` and the default export; load the glue and editor as ESM-compatible imports (the UMD files set `module.exports` only when `module` exists; in the Worker bundle import them via `import './editor.js'` and read `globalThis.HowdahConfigEditor`, or split a tiny ESM shim). No `console.log` of request data anywhere.
- [ ] **Step 4: Run to verify pass:** `node --test test/worker.test.mjs` → PASS. `npx wrangler@3 deploy --dry-run --outdir /tmp/wr` from `site/worker` (after copying the wasm there) → bundle succeeds (no account needed for dry-run).
- [ ] **Step 5: Commit** — `feat(worker): cfg.howdah.org stateless config fetch service with deploy workflow`.

### Task 8: Docs, links and changelog

**Files:**
- Modify: `docs/config.md` (new section "Build a config in the browser" after the intro; fix the `[log] path` line: "accepted, not used by the extension; set `howdah.log`"), `site/src/pages/docs/configuration.astro` (link card/paragraph at top), `site/src/pages/docs/index.astro` (card), `site/src/pages/install.astro` (one sentence after the configure step linking `/config/`), `README.md` (one line under Documentation), `CHANGELOG.md` (`[Unreleased] / Added`: editor + Worker; `/ Fixed`: `[log]` docs claim), `docs/superpowers/specs/2026-10-24-howdah-config-editor-design.md` status line → built.

- [ ] **Step 1: Write the failing test:** extend `site/test/page.test.mjs`: `dist/docs/configuration/index.html` and `dist/docs/index.html` and `dist/install/index.html` each contain `href="/config/"`.
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Make the edits.** Copy for the `docs/config.md` section: three sentences: what the page does, that validation is the extension's own parser compiled to wasm, that the `curl` URL contains the whole config and the service stores nothing.
- [ ] **Step 4: Run to verify pass:** `npm run build && node --test test/` → all PASS.
- [ ] **Step 5: Commit** — `docs: link the config editor; correct the [log] path claim`.

### Task 9: Whole-branch verification and PR

- [ ] **Step 1:** `cargo test --locked -p howdah-core -p howdah-ext -p howdah-wasm`, `cargo clippy --locked -p howdah-core -p howdah-ext -p howdah-wasm --all-targets -- -D warnings`, `cd site && npm run wasm && npm ci && npm run build && node --test test/ && node demo/verify.js` → all green.
- [ ] **Step 2:** Lab check of the output: take the "Enforcing" preset's TOML from `dist` (or the emitter), run `php -d extension=howdah.so -d howdah.config=<file> --ri howdah` in `howdah-dev-php7.3` → `Mode => (set by howdah.config file: …)` and no stderr error; repeat with a deliberately broken file to see the fallback (documents the pre-existing silent-fallback behaviour; not fixed here).
- [ ] **Step 3:** Push `feat/config-editor`, open the PR with: what it does, the two bugs fixed on the way (stale demo wasm, `[log]` docs), the owner actions (Cloudflare token + account id secrets; `cfg.howdah.org` custom domain appears on first deploy), the accessibility evidence path, and a note that the Worker deploys on the next tag.

### Task 10 (gated on the 1.3 merge): `[sinks.phar]` and `[sinks.ssrf]`

Do not start until `feat/layer3-fast-follow` is on `main`; rebase first.

- [ ] **Step 1: Failing tests:** `schema.test.mjs` default checks for `sinks.phar.mode === 'off'`, `sinks.ssrf.mode === 'off'`; `editor.test.mjs` round-trip for `sinks.phar.allow_paths` and `sinks.ssrf.allow_hosts` (`['10.0.0.0/8','api.internal']`), and that `allow_hosts: ['*.x']` yields the core's error through validation (no JS check).
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Add the two schema rows** (notes: phar realpath prefixes, empty = every phar access is a hit in detect; ssrf hostname | IP | CIDR, no wildcards) and the two emitter sections `[sinks.phar]`, `[sinks.ssrf]` after `[sinks.eval]`. Rebuild the wasm (the core now serialises the new fields).
- [ ] **Step 4: Run to verify pass:** full `node --test test/` and `npm run build`.
- [ ] **Step 5: Commit** — `feat(site): config editor supports [sinks.phar] and [sinks.ssrf] (1.3)`.
