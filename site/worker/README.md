# cfg.howdah.org

The fetch service behind the config editor's `curl` command
(https://howdah.org/config/). A Cloudflare Worker on the howdah.org zone.

**What it does.** `GET /v1/<payload>` decodes the payload the editor put in
the URL (base64url of the TOML, or `z.` + base64url of its deflate-raw
stream), validates it with the Howdah core compiled to WebAssembly (the same
`howdah_wasm.wasm` the page runs), and returns it as `text/plain` with
`Content-Disposition: inline; filename="howdah.toml"` and a one-year immutable
cache header (the URL *is* the content). A config the core rejects gets `422`
with the core's error text. Over 16 KiB of TOML or 12 000 URL characters gets
`413`. Anything else is `404`/`405`.

**What it keeps.** Nothing. There is no storage, no KV, no analytics, and
observability is off in `wrangler.toml`; the handler never logs a request.

**Code.** `handle.js` is the pure handler (tested in Node by
`site/test/worker.test.mjs`); `index.js` binds it to the bundled wasm.

**Deploy.** `.github/workflows/worker.yml` deploys on every release tag (and on
demand), so the Worker's validator is never older than the newest config keys
a release documents. It needs the repository secrets `CLOUDFLARE_API_TOKEN`
(Workers Scripts: Edit, Workers Routes: Edit, on the howdah.org zone) and
`CLOUDFLARE_ACCOUNT_ID`. The custom domain `cfg.howdah.org` is created by the
first deploy. Locally:

```sh
packaging/build-wasm.sh
cd site/worker && npx wrangler@4 deploy --dry-run --outdir /tmp/howdah-cfg   # bundle check, no account needed
```
