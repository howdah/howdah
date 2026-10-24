# Howdah config editor: design

**Status:** owner-approved direction (2026-10-24); builder-checked design.
**Owner asks:** a configuration editor and validator on howdah.org whose output a sysadmin can fetch with one `curl` command. Validation must come from Howdah's real validator, not a JavaScript copy of it.

Markers: **(owner)** = decided by the owner. **(call)** = a default chosen during design; the builder may revisit it with a reason.

## 1. Intent

Howdah is configured by three php.ini directives and a TOML file with five sections (`[limits]`, `[rules]`, `[inspect]`, `[sinks]`, `[log]`; see `docs/config.md`). Today an operator hand-writes that TOML from the docs. Two things go wrong:

- A typo or unknown key makes `Config::from_toml` fail, and the extension silently falls back to safe defaults (Block mode, default limits) while `phpinfo()` still names the file. The operator believes their config is in effect; it is not. (Review finding, 2026-10-23.)
- The defaults and their consequences (which rules block even in `detect`, which layers never block unless armed, which sinks need an allowlist first) are spread over a long reference page, so people either leave everything default or guess.

The editor fixes both: it builds the files from choices the operator understands, and it refuses to hand out a config the extension would reject, using the extension's own parser.

## 2. Who it is for

Sysadmins installing Howdah on servers they control (design §2), on a fresh install wanting a safe starting config, or on an existing install who have watched the `detect` log and want to turn specific things on. **(owner, via the install picker's audience)**

## 3. Goals

1. Build `howdah.ini` and `howdah.toml` from form controls, every control pre-filled with the shipped default, with a one-line note on what changing it does.
2. Validate the TOML with the real `howdah-core` validator compiled to WebAssembly, and show its exact error text. A config the extension rejects is never offered for download or fetch.
3. Offer the result three ways: copy, download, and a `curl` one-liner that fetches exactly that TOML from `https://cfg.howdah.org/…`.
4. Load an existing TOML (paste or file) into the form, so the page works as a validator for configs people already have. **(call)**
5. Work without JavaScript: the page renders the documented default files and the reference notes; only the interactivity needs JS.
6. Meet the site's bar (design §10): WCAG 2.2 AA, light and dark, no trackers, no cookies, self-hosted fonts, phone width.

## 4. Non-goals and anti-goals

- No stored configs, no accounts, no short links. The `curl` URL carries the whole config; the Worker keeps nothing. **(owner: option 1 of 3)**
- No JavaScript reimplementation of validation. If the wasm fails to load, the page says validation is unavailable and still lets the user copy; it never claims a config is valid without the core.
- Not a general TOML editor: only the keys `docs/config.md` documents.
- Anti-goal: the Worker becoming a control plane (design §7). It is a pure function of its URL: decode, validate, return text.
- Anti-goal: the page implying more than the extension does. Every note on a control must match `docs/config.md` and the coverage caveats (Layer 2 `block` is post-hoc; `include`/`eval` are PHP 7.0+; `proc_open` array form is unguarded).

## 5. The page: `howdah.org/config/`

Astro page in `site/src/pages/config.astro`, vanilla JS in the `install.astro` style, nav entry under Docs. **(call)**

Layout, top to bottom:

1. **Lead:** what the page does, in two sentences, and which Howdah version's validator it uses (`VERSION` from `site.ts`).
2. **Start from:** three buttons: *Shipped defaults* (detect mode, everything else default), *Enforcing* (block mode, Layers 2 and 3 still log-only), *Load existing* (paste or choose a TOML file; validates and fills the form, or shows the core's error and leaves the form untouched).
3. **Sections**, each a `<fieldset>` with the control, the default shown next to it, and the note:
   - **php.ini:** `howdah.mode` (block / detect / off), `howdah.log` path, `howdah.config` path (default `/etc/howdah/howdah.toml`). Two notes: these are read once per PHP process at startup, so per-pool or `.htaccess` values have no effect; and once `howdah.config` names a readable file, the file's `mode` is authoritative and `howdah.mode` is ignored (`module.rs` MINIT). The editor therefore keeps the two in step: changing either mode control changes both outputs.
   - **`[limits]`:** the twelve directives from `docs/config.md`, numeric inputs with min 1 (0 is rejected by the core and the control says so). Grouped as multipart, input-shape, request-header.
   - **`[rules]`:** per rule, a select: inherit / block / detect / off, for **every** rule name the core accepts (all `RuleId` variants, including the Layer 2 and 3 names), grouped by layer so a loaded file never has a rule the form cannot show. Rules marked Critical carry the note "blocks even when mode is detect"; Standard rules "logs in detect, blocks in block". Severity comes from the schema table, which is checked against `RuleId::severity`.
   - **`[inspect]`:** enabled, mode (detect default), the three class toggles, the three budgets, per-class mode overrides. Note: independent of the global mode; `block` here is enforced after the script has run (`docs/config.md` "Enforcement timing").
   - **`[sinks]`:** enabled, mode, then per sink: `command_exec` allow list (one pattern per line, with the trailing-`*` warning from the config reference), `unserialize` (off by default; mode + allow_classes), `include` (allow_paths; PHP 7.0+ only), `eval` (PHP 7.0+ only).
4. **Output panel** (sticky on wide screens, below the form on phones): tabs *howdah.toml* and *howdah.ini*, each with Copy; a **validation line** that reads "Valid for Howdah X.Y.Z" or the core's error verbatim; **Download** (`howdah.toml`, `howdah.ini`); the **`curl` block**:

   ```
   sudo mkdir -p /etc/howdah
   curl -fsSL 'https://cfg.howdah.org/v1/<payload>' -o /etc/howdah/howdah.toml
   ```

   followed by the ini lines to add, and a reminder to restart PHP-FPM/Apache. The `curl` block is disabled (greyed, with the reason) while the TOML is invalid or longer than the Worker's limit.
5. **Footer notes:** nothing leaves the browser except what is in the URL you copy; the URL contains your whole config, so treat it like the file (allow lists can name internal paths).

Generated TOML is deterministic: fixed section order, fixed key order (the order in `docs/config.md`). `mode` is **always** written, because an omitted `mode` means `block` to the core (`safe_defaults`) while the shipped ini says `detect`; omitting it would silently flip a detect install to block. Every other key is omitted when it equals the **core's** default (`Config::safe_defaults()`, not the editor preset), with a toggle "include defaults as comments" for a self-documenting file. **(call)** The ini snippet always includes all three directives.

**`[log]` is not offered.** The core parses `[log] path`, but the extension never reads it: the log destination comes only from the `howdah.log` ini (`module.rs`, `LOG_PATH`). Offering it would be a knob that does nothing (anti-goal). `docs/config.md` currently says "TOML wins if both set"; that claim is wrong and is corrected as part of this work (§9). A follow-up outside this project may make the extension honour it.

**Load existing:** a file the core accepts but the form cannot fully represent (today only `[log]`) is refused with a message naming the keys, rather than loaded and silently dropped on the next download. **(call)**

## 6. Validation: the real core in the browser

`crates/howdah-wasm` already builds `howdah-core` to wasm for the demo with plain C-ABI exports and no JS glue, and `site/scripts/copy-demo.mjs` ships it at `/demo/howdah_wasm.wasm`. Add one export:

```
howdah_wasm_validate_config(toml_ptr, toml_len) -> result_ptr   // JSON, length via howdah_wasm_result_len()
  {"ok": true, "config": <canonical JSON of the parsed Config>}
  {"ok": false, "error": "<Config::from_toml error text>"}
```

Implemented in the wasm crate by calling `howdah_core::Config::from_toml` directly (no ctx). The canonical JSON (a `Serialize` derive on `Config` and its parts, keys in declaration order) lets tests compare configs by meaning rather than bytes (§10) and lets "Load existing" fill the form from what the core parsed rather than from a second TOML parser in JS. **(call)** The JS glue (`site/demo/howdah-wasm.js`) gains a `validateConfig(toml)` wrapper. Validation runs on every change, debounced.

**The wasm must be fresh, and the page and the Worker must run the same bytes.** Today `site/demo/howdah_wasm.wasm` is a committed binary last built at 1.0; it predates `[sinks]` and `[inspect.rule_modes]`, and neither `pages.yml` nor `release.yml` rebuilds it (only `ci.yml` builds and discards it). That is a live bug in the demo and would be a worse one here. Decision **(call)**: stop committing the binary. `pages.yml` and the Worker deploy workflow each install the Rust toolchain with the `wasm32-unknown-unknown` target and build `howdah-wasm` from the same commit (`packaging/build-wasm.sh`, already used by `ci.yml`); `copy-demo.mjs` copies the fresh build. `ci.yml` keeps its wasm job as the build check. The site build fails loudly if the wasm is missing rather than falling back to a stale copy.

The page shows the core version it validated against (from `VERSION`), so an operator on an older Howdah knows the check may be stricter or looser than their binary.

## 7. The fetch service: `cfg.howdah.org`

A Cloudflare Worker on the `howdah.org` zone (already on Cloudflare), custom domain `cfg.howdah.org`, free plan. **(owner: option 1)**

- Route: `GET /v1/<payload>` where `<payload>` is base64url of the TOML, optionally compressed with deflate-raw first (the page compresses when it shortens the URL, and marks it with a leading `z.`). **(call)** Maximum decoded size 16 KiB; maximum URL length well under the 16 KB Cloudflare request-URL limit. Over the limit: `413` with a one-line explanation; the page never generates such a URL.
- The Worker decodes, then **validates with the same wasm module** (bundled as a module import; Workers run wasm natively). Invalid: `422 text/plain` with the core's error text, never the config. Valid: `200`, `Content-Type: text/plain; charset=utf-8`, `Content-Disposition: inline; filename="howdah.toml"`, `Cache-Control: public, max-age=31536000, immutable` (the URL is the content), `X-Howdah-Validated: <version>`.
- Anything else (`POST`, other paths, `/`): `404` or `405`; `/` returns a one-paragraph explanation pointing at `howdah.org/config/`.
- No storage, no logging of payloads (Workers logs off; no `console.log` of the body), no analytics, no cookies. The Worker's behaviour is a pure function of the URL.
- Abuse: the Worker only ever returns what the caller sent, re-encoded as TOML that the core accepted, so it cannot be used to host arbitrary files; the content type is fixed to `text/plain`. Cloudflare's free-plan rate limiting is enough.
- Source lives in the repo under `site/worker/` (one `index.js` or `index.ts`, `wrangler.toml`, a test that round-trips a config and rejects an invalid one). Deployed by a GitHub Actions workflow on tag, with `CLOUDFLARE_API_TOKEN` and account id as repository secrets; a `workflow_dispatch` path for manual deploys. **(call; the owner creates the token and the custom domain)**

## 8. Versioning and the config surface

The URL's `/v1/` names the payload encoding, not the Howdah version. A config produced today stays fetchable as long as `/v1/` is served. The Worker validates with the core version it was deployed with; its response header names that version. If a future config key is unknown to a deployed Worker, the fetch fails with the core's "unknown key" error, which is the right failure: that config would fail on an older extension too.

The config surface grows with releases, and `Config` uses `deny_unknown_fields`, so a validator built from 1.2.1 rejects a valid 1.3 config. Two rules follow:

- **One schema table drives everything.** The page's form, the TOML emitter, and the reference notes come from a single data table in the page's source (section → key → type, default, severity/mode semantics, note text). Adding a config section is a table entry plus a test, not new UI code. The table is checked against `docs/config.md` by a test, and the "shipped defaults" output is checked against the core (§10).
- **The Worker is redeployed on every release tag**, so its wasm is never older than the newest config keys a release documents. The page states the version it validates against.

Known upcoming entries, with the final field list from the 1.3 branch (`feat/layer3-fast-follow`, `crates/howdah-core/src/config.rs`, fields `phar` and `ssrf` on `SinkConfig`):

- `[sinks.phar]`: `mode` (`off | detect | block`, default off; only an explicit value arms it, as with `[sinks.unserialize]`), `allow_paths` (list of lexical realpath prefixes, matched component-wise up to and including the `.phar` segment; empty means every phar access is a hit in detect).
- `[sinks.ssrf]`: `mode` (same semantics, default off), `allow_hosts` (list; each entry a hostname matched exactly and ASCII-case-insensitively, a literal IP, or a CIDR `a.b.c.d/0..32` or IPv6 `/0..128`; the core rejects wildcards, out-of-range prefixes, empty or whitespace entries and shorthand networks such as `10/8` at load, so the editor's note should say so and the wasm validator surfaces the exact error).
- Rule and log names: `phar`, `ssrf`.

The editor is built against `main` as it stands and gains these two sections when 1.3 merges; the plan carries that as its last task, gated on the merge.

## 9. Documentation and site changes

- `docs/config.md`: a short section "Build a config in the browser" linking the page, and a note that the fetch service validates with the same core. Correct the `[log] path` claim: the TOML key is accepted but not used; set the log path with `howdah.log`.
- `pages.yml`: the "no third-party requests" check gains `cfg.howdah.org` (first-party) in its allowlist.
- `site/src/pages/docs/configuration.astro`: link to the editor at the top.
- The install page: after step "configure", a link "or build your config with the editor".
- README: one line.
- Review follow-up (not this project): make the extension itself log a loud error on an invalid `howdah.config` instead of falling back silently. The editor reduces how often that happens; it does not fix it.

## 10. Testing

- Rust: unit tests for `howdah_wasm_validate_config` (valid, unknown key, zero limit, invalid TOML, empty input = defaults = valid).
- Worker: tests with `wrangler`'s test runner or a plain Node harness against the fetch handler: valid round-trip; invalid returns 422 with the core's text; oversize returns 413; wrong method 405; headers as specified.
- Site: Astro build passes. A script test runs the page's TOML emitter in Node for each preset and for a round-trip of every schema key, validates each output through the wasm, and asserts the parsed `config` equals the expected values (shipped defaults = `safe_defaults()` with `mode = detect`; each key round-trips to the value set). The schema table is checked against `docs/config.md` (every documented key present, every default equal) and against `RuleId::severity`.
- Accessibility: there is no automated axe run in the site today. This page is checked with the local `ui-validator` pass (axe, contrast, two viewports, light and dark) before the PR, and the results are attached to the PR. Adding an automated axe step for the whole site is a separate follow-up.
- Manual: the generated `curl` line, run on a lab container, produces a file the extension loads with the chosen mode visible in `php --ri howdah`.

## 10a. Bugs found while designing (fix in this project unless noted)

- The committed demo wasm is stale (built at 1.0). Fixed by the fresh-build rule in §6.
- `docs/config.md` says `[log] path` overrides `howdah.log`; the extension never reads it. Docs corrected here (§9); making the extension honour it is a follow-up.

## 11. Left to the builder

- Exact form markup and the sticky output panel's responsive behaviour, within the site's existing styles.
- Whether `[rules]` shows all fifteen rules at once or groups them under their layer; the default view must not hide that Critical rules block in detect.
- Debounce timing, copy-button feedback, and the no-JS fallback markup.
- Worker implementation language (JS or TS) and the deflate choice if it does not shorten typical configs enough to matter.

## 12. Owner actions

- Create the `cfg.howdah.org` custom domain on the Worker in the Cloudflare dashboard, or let the deploy workflow do it with a token that has Workers Scripts and Workers Routes permissions.
- Add `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` as GitHub Actions secrets.
