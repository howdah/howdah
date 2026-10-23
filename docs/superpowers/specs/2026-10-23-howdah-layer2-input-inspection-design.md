# Howdah Layer 2 — Input Inspection (design)

**Status:** design, pending owner approval. Nothing is built until this is approved.
**Date:** 2026-10-23
**Parent design:** `docs/superpowers/specs/2026-10-22-howdah-design.md` §3 (the four layers), §5.5 (modes).
**Ships:** after 1.0, as the first post-1.0 layer (layer order was Claude's call; the owner chose Layer 2 next).

---

## 1. Intent — the why

Layer 1 stops request **shapes** that exhaust resources: too many multipart parts,
too many input variables, over-deep arrays, oversized names (the PHP2Shell family).
It counts and measures; it never looks at what a value *says*.

So a perfectly well-shaped request — one form field, normal size — sails through
Layer 1 even when that field's value is `' OR 1=1 --`, or `../../etc/passwd`, or
`; cat /etc/passwd`. Layer 2 reads the **content** of each decoded request value
and flags three injection families, so an operator gets a JSON event the moment a
value looks like an attack, on PHP versions (5.4–8.1) that will never get upstream
help.

**The honest frame.** Signature inspection of request content is best-effort and
bypassable by construction — that is true of every WAF that does it, and pretending
otherwise is the overclaiming trap Howdah has stayed out of. So Layer 2 does not
block by default. It **logs**. An operator watches the events, confirms Howdah is
right on real attacks and quiet on their legitimate traffic, and *then* chooses to
block. Detect first; earn block.

## 2. Goals

1. **Inspect decoded values** of: **GET** query params, **POST** form fields,
   **cookies**, and the **URL path**. (Not request header values — see non-goals.)
2. **Three attack classes**, each a distinct rule: **SQL injection**,
   **path traversal**, **command/code injection**.
3. **Log-first, never block by default — and a global block flip does NOT arm it.**
   Layer 2 has its **own** mode, `inspect.mode`, default `detect` (= log). It is
   **not** governed by the global `howdah.mode`. Flipping `howdah.mode=block` — the
   parent design's recommended rollout step — leaves Layer-2 content scanning in
   log-only. Blocking is armed **only** by explicitly setting `inspect.mode` (or one
   class) to `block`. Layer-2 rules are `Severity::Standard` and never `Critical`.
   (See §5.3 — this is the one real departure from "it falls out for free": the
   handler resolves an inspect hit against `inspect.mode`, not the global mode.)
4. **Loud "does not block by default" messaging** at every point a person could
   assume otherwise (§6).
5. **DoS-safe matching:** linear-time, no backtracking, bounded work per value.
6. **Every signature backed by a test** that proves what it catches, and the public
   coverage page states plainly that this is best-effort and bypassable.
7. **Off-able and tunable** by config: disable Layer 2 entirely, or per class.
8. Runs on all supported PHP minors (5.4–8.5) and SAPIs, like Layer 1.

## 3. Non-goals and anti-goals

- **Not XSS. Not output inspection.** Watching what PHP *emits* (`<script>` and
  friends) is **Layer 3**. Layer 2 only reads what comes *in*.
- **Not header-value scanning** by default (high false-positive, low yield).
- **Not a comprehensive ruleset.** This is a small, documented, high-confidence set
  per class — not a CRS clone, not "paranoia levels", and never the claim
  "Howdah stops SQL injection." The claim is only: "Howdah flags these documented
  patterns; here is the test for each; it is bypassable, which is why it logs."
- **Never a payload generator or an attack cookbook.** Test fixtures contain
  representative malicious *strings* (the standard for any detection engine —
  Snort, CRS, ClamAV all ship them); the repo ships no runnable attack generator,
  consistent with every prior release.
- **No backtracking regex** on attacker-controlled input — that is a denial-of-service
  hole, and a security tool must not ship one.
- **Changes nothing about Layer 1** and adds **no new block-by-default behavior**.
- **Does not log raw values by default** — preserves the §7 privacy rule (bodies,
  cookies, auth never logged by default).

## 4. Constraints (inherited, project-wide)

- Defensive tool only; never a hacking tool.
- No overclaiming: every coverage claim backed by a test or stated honestly.
- Reproducers recreate only harmless request **shape**, never runnable payloads;
  detection fixtures are static strings, not a generator.
- Log-only by default (this layer).
- Pure-Rust core, chained PHP glue, PHP 5.4–8.5, NTS, FPM/Apache-prefork/CGI.

## 5. The how — decisions made in this conversation

### 5.1 Hook point — reuse the chained `input_filter`
PHP calls `sapi_module.input_filter` once per request variable (`PARSE_GET`,
`PARSE_POST`, `PARSE_COOKIE`, and `PARSE_SERVER`) with the variable **name and
value**, before `RINIT`. Layer 1 already chains this filter (`input_filter.rs`) and
uses the name for shape limits. The value is already in the signature it carries
(`val: *mut *mut c_char`, `val_len`) — today's code simply never dereferences it.
Layer 2 reads it. No new PHP hook; works on every supported minor.

- **Read the value binary-safe** via (`*val`, `val_len`) — never as a C string
  (values can contain NUL). Scanning runs inside the existing `catch_unwind`
  fail-open path, so a scanner bug never unwinds into PHP and never drops a var.
- **Independent of Layer 1's count/drop branch.** The handler's existing early
  returns (it skips `PARSE_POST` on multipart to avoid double-counting *names*, and
  returns before value work on some paths) mean value scanning must run on its **own
  path**, covering GET / POST (including multipart form fields) / COOKIE values and
  the `PARSE_SERVER` path keys — not appended after the Layer-1 branch, or multipart
  field values and the URL path would go unscanned. (`input_filter` *does* fire for
  multipart fields — Layer 1's "skip PARSE_POST on multipart" comment confirms it.)
- The **URL path** arrives through `PARSE_SERVER` as `REQUEST_URI` / `PATH_INFO`
  (scan whichever exist; `PATH_INFO` may be absent). Those are *not* URL-decoded by
  PHP, so the traversal scanner matches against a bounded, percent-decoded copy
  (`../` may arrive as `%2e%2e%2f`).
- The source label (`get` / `post` / `cookie` / `path`) comes from the `arg` the
  filter was called with. Only those four are scanned; other `PARSE_SERVER` keys and
  header values are skipped by default.
- **Timing caveat (inherited from Layer 1):** with `auto_globals_jit` on (PHP
  default), `input_filter` fires only when a script first touches the superglobal, so
  a script that never reads its input isn't scanned. Acceptable: a script vulnerable
  through an input reads that input.

### 5.2 Engine — a pure-Rust `inspect` module in `howdah-core`
A new `inspect` module, pure Rust, host-unit-testable through the C ABI exactly like
the existing core. Per-class matching uses a **guaranteed linear-time, non-backtracking**
matcher — Rust's `regex` / `aho-corasick` (both already linear-time, no catastrophic
backtracking) — so there is no ReDoS surface. Bounds:

- **Per-value byte cap:** above it, scan only the prefix (an enormous value cannot
  cost unbounded time).
- **Per-request aggregate budget:** a cap on total values and total bytes scanned per
  request, so multi-value arrays (`a[]=…`) and variable floods cannot multiply the
  per-value cost. Scanning also stops once Layer 1 latches `INPUT_BLOCKED` / passes
  `max_input_vars` (≈2000), so at most ~that many values are ever content-scanned.

Returns an optional hit `{ class, reason-token }` — never a `zend_bailout`, never a
copy of the value into the log (§5.4).

### 5.3 Severity + config — an INDEPENDENT inspect mode
- New `RuleId`s (e.g. `SqlInjection`, `PathTraversal`, `CommandInjection`), each
  `Severity::Standard`, never `Critical`.
- **`decide()` is unchanged, but the caller changes.** `decide()` resolves a Standard
  rule under global `Mode::Block` to `Action::Block` — so Layer 2 must NOT be resolved
  against the global mode, or the recommended `howdah.mode=block` rollout would silently
  arm content scanning with all its false positives (the "take sites down" anti-goal).
  Instead, the input-filter handler resolves an inspect hit against the **inspect
  layer's own mode**: `effective = Off if global==Off else inspect.mode`
  (default `detect` → `Log`). A global block flip never arms Layer 2; only an explicit
  `inspect.mode = block` (or a per-class override) does. Global `off` still disables
  everything.
- New `[inspect]` config section: on/off for the whole layer and per class, its own
  `mode`, plus a per-class `mode` override. Default: enabled, `mode = detect` (= log).
  Fully disable-able.

### 5.4 Logging — a hit, never the value
A Layer-2 event is one JSON line (same shape as Layer 1): timestamp, request id,
`rule`, `action: log`, source (`get`/`post`/`cookie`/`path`), and the **variable
name**. It **never** includes the raw value. The earlier "opt-in redacted snippet"
idea is **dropped**: a snippet logs the value that tripped a signature, which on a
*false positive* is exactly the private user input parent §7 promises never to log,
and "redact arbitrary free-form input" is not a solvable thing. Name + class + source
is enough to find the request; the operator has their own request logs for the value.
This keeps "Howdah never logs bodies/cookies/auth by default" absolutely true.

### 5.5 Rules — small, documented, high-confidence
Each class ships a handful of high-confidence signatures, each with a one-line
rationale and a test proving the catch. The aim is low false-positive *and* honest
about the ceiling — not breadth. The plan pins the exact set and its tests.

**Bypass honesty without an evasion cookbook.** The general truth — signature
inspection is best-effort and bypassable, which is *why* Layer 2 logs rather than
blocks — is stated plainly in the public coverage. But a *per-signature* "here is how
to slip past this exact rule" list is not published: it edges toward an evasion how-to,
against the defensive-only line. Per-signature bypass awareness stays in internal
development notes, not on the site.

## 6. The "does not block by default" guarantee — where it is stated
This is a hard requirement, stated plainly everywhere a person could assume otherwise:
- **Generated config file:** the `[inspect]` section opens with a plain-language
  comment — *these rules only log; they do not block any request; a global
  `howdah.mode = block` does NOT arm them; to block, set `inspect.mode` (or a class)
  to `block` explicitly.*
- **Repo `README`:** the release/feature summary states Layer 2 detects-and-logs and
  does not block by default.
- **CHANGELOG / release notes** for the version that introduces Layer 2.
- **Site:** the Layer-2 section, the coverage page, and the comparison framing all
  say "detects and logs; does not block by default."
- **`howdah-check`:** where it lists active rules, Layer-2 rules are shown as
  log-only.
- **The JSON events:** carry `action: log`, so the data itself shows it.

## 7. What is left to the builder (resolved in the plan)
- The exact signature set per class, and the test for each.
- The exact `[inspect]` config keys and defaults.
- The per-value byte cap value and the redacted-snippet format (if the opt-in is kept).
- The percent-decoding bound for the path source.
- Coverage-page and coverage-data wording for Layer 2.

## 8. Resolutions from the builder check (owner may veto)
The builder check surfaced three posture questions; all three resolve in the
direction the owner's stated constraints already point, and are now baked into the
design above:
- **Independent inspect mode (§5.3):** a global `howdah.mode = block` must NOT arm
  Layer 2 — resolved per the owner's repeated "does not block by default" requirement.
  This is the one real design change the builder check forced.
- **Value snippet dropped (§5.4):** no raw value is ever logged; the opt-in snippet is
  removed, because it would leak private input on a false positive.
- **No public per-signature bypass list (§5.5):** honest about the general ceiling,
  but no evasion cookbook on the site.
