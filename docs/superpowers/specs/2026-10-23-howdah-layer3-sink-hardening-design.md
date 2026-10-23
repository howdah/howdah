# Howdah Layer 3 — Sink Hardening (design)

**Status:** design, pending owner approval. Nothing is built until this is approved.
**Date:** 2026-10-23
**Parent design:** `docs/superpowers/specs/2026-10-22-howdah-design.md` §3 (the four layers), §5.5 (modes).
**Sibling:** `docs/superpowers/specs/2026-10-23-howdah-layer2-input-inspection-design.md` (Layer 2 — the posture, mode-independence and privacy rules below are carried from it deliberately).
**Ships:** after 1.1 (Layer 2), as Howdah 1.2 — the third layer.

---

## 1. Intent — the why

Layer 1 refuses abusive request **shapes**. Layer 2 reads the **content** of request
values and logs when it looks like SQLi / traversal / command injection — best-effort,
log-only, at the front door.

Both watch the request on the way *in*. Neither stands at the place where damage
actually happens: the moment PHP is about to **do** something dangerous — run a shell
command, include a file, unserialize attacker data. Layer 3 stands there. At the exact
instant `system($cmd)` or `include $path` or `unserialize($data)` is about to execute,
Howdah checks the call against a flat, operator-set policy and logs it; and, only when
an operator has explicitly armed that sink, refuses it.

This is **not** the taint-tracking fork (following user input through the program to the
sink). It is **flat policy at the sink**, in the lineage of Suhosin and Snuffleupagus:
the rule is about the *call itself* — "this `system()` call's command is not on the
allowlist", "this `include` resolves outside the app directory" — regardless of where
the argument came from. Flat policy is tractable, predictable, and honest; taint
tracking through arbitrary PHP is neither complete nor honestly claimable.

**Why this is the honest place to act.** Layer 2 inspects a *guess* about input and so
must stay log-only. Layer 3 stands at the sink itself: there is no guessing about
whether `system()` is being called — it is. That makes a sink decision far more
defensible than an input signature. But the project's rule still holds: a flat policy
can still be *wrong for an app* (an app that legitimately shells out, includes
computed paths, or unserializes objects), so Layer 3 still ships **detect-first** and
earns block per sink. Standing at the sink raises confidence; it does not license
blocking by default.

## 2. Goals

1. **Guard a small set of dangerous sinks** with flat, per-sink policy:
   - **Command / code execution:** `system`, `exec`, `shell_exec`, `passthru`,
     `popen`, `proc_open`.
   - **Include / require / eval:** the `include`/`require`(`_once`) and `eval`
     language constructs.
   - **`unserialize`:** object-injection payloads (serialized data carrying objects).
2. **Fixed-knob TOML config, NO new php.ini directives.** A new `[sinks]` section in
   the existing `howdah.config` TOML — the install surface stays at exactly three ini
   directives (`howdah.mode`, `howdah.config`, `howdah.log`), as it has since 1.0.
   This is a fixed set of knobs per sink (a mode plus a focused allowlist), **not** an
   ordered rule engine / DSL.
3. **Log-first, never block by default — and a global block flip does NOT arm it.**
   Layer 3 has its **own** mode, `sinks.mode`, default `detect` (= log), independent of
   the global `howdah.mode`, exactly as Layer 2's `inspect.mode` is. Flipping
   `howdah.mode = block` does **not** arm any sink. Blocking is armed only by explicitly
   setting `sinks.mode` (or one sink's mode) to `block`. Layer-3 rules are
   `Severity::Standard`, never `Critical`.
4. **Each sink has an allowlist escape hatch**, so `block` is usable without breaking
   apps that legitimately use the sink (allowed `system` commands; allowed include
   directories; allowed unserialize classes).
5. **The matched argument is NEVER logged** (a command line, an include path, or a
   serialized blob can all carry secrets) — only the sink, the function/construct, and,
   where it is a type and not user data, the offending class name. Carries Layer 2's
   privacy rule verbatim.
6. **Bounded, constant per-sink overhead.** The hook touches only calls to the guarded
   functions/constructs — not every PHP call — so there is no per-request scanning cost
   like Layer 2's. Argument policy checks are linear-time, no backtracking.
7. **Every guard backed by a test** proving what it catches and what it leaves alone,
   and the public coverage states plainly that this is flat-policy virtual patching,
   not a guarantee, and that it ships log-first.
8. **Off-able and tunable:** disable Layer 3 entirely, or per sink.
9. Runs on all supported PHP minors (5.4–8.5) and SAPIs — **proven feasible by the
   spike** (§5.1).

## 3. Non-goals and anti-goals

- **Not taint tracking.** Howdah does not claim to know whether a sink argument came
  from user input. Flat policy only. (Claiming taint awareness we don't have is the
  overclaiming trap.)
- **Not a blanket `disable_functions`.** The point is a *policy* (allowlist) at the
  sink, not turning functions off wholesale — and it is log-first, so it does not even
  turn them off until an operator arms a sink.
- **phar:// stream-wrapper deserialization and SSRF are OUT of 1.2** — deferred, with
  reasons, in §8. In short: both need a *third/fourth* hook mechanism (stream-wrapper
  control; outbound-destination resolution) that the spike did not cover and that does
  not fit the detect-first model as cleanly. Shipping them half-proven would be
  dishonest. They are the documented Layer-3 fast-follow.
- **Never a payload generator or an exploitation cookbook.** Tests use representative
  static strings (a serialized object, a traversal path) — never a runnable exploit,
  consistent with every prior release.
- **No new block-by-default behavior.** Layer 1's request-shape limits remain the only
  rules that block out of the box.
- **Does not log sink arguments** (command lines, paths, blobs) — preserves the
  project privacy rule.
- **Changes nothing about Layers 1 or 2.**

## 4. Constraints (inherited, project-wide)

- Defensive tool only; never a hacking tool.
- No overclaiming: every coverage claim backed by a test or stated honestly.
- Reproducers recreate only harmless request **shape**; detection fixtures are static
  strings, not a generator.
- Private GPG master key stays offline; nothing here touches signing.
- Log-first by default (this layer).
- Pure-Rust core, chained PHP glue, PHP 5.4–8.5, NTS, FPM/Apache-prefork/CGI.

## 5. The how — decisions made in this conversation

### 5.1 Hook mechanism — proven by a throwaway spike first

The owner asked for the hook mechanism to be **spiked before any design was committed**,
on PHP **5.6, 7.4 and 8.3** (the widest ABI spread: the PHP 5 internal ABI, the PHP 7
rewrite, and current PHP 8). That spike was built and run. **Result: both mechanisms
Layer 3 needs work, uniformly, on all three versions** (argument captured, original call
chained intact):

- **Mechanism A — function-table handler swap.** At MINIT, look up a function in
  `CG(function_table)`, save its `internal_function.handler`, install Howdah's
  trampoline. The PHP 5 ABI (`zend_hash_find`, NUL-inclusive keys,
  `zend_get_parameters_ex`, the 5-arg handler signature) and the PHP 7/8 ABI
  (`zend_hash_str_find_ptr`, `ZEND_CALL_ARG`, the 2-arg handler signature) differ, but
  both were proven. Covers: `system`, `exec`, `shell_exec`, `passthru`, `popen`,
  `proc_open`, `unserialize`.
- **Mechanism B — user opcode handler.** `include`/`require`/`eval` are **not**
  functions in the function table — they compile to the `ZEND_INCLUDE_OR_EVAL` opcode.
  The spike proved `zend_set_user_opcode_handler(ZEND_INCLUDE_OR_EVAL, …)` fires on
  include and chains via `ZEND_USER_OPCODE_DISPATCH`, on all three versions (under NTS
  the handler signature is identical across 5/7/8).

**Architectural ruling the spike validates:** keep the ABI-variant hooking in a small
**C shim** (as `howdah-sys` already does for `ZEND_MODULE_BUILD_ID` in `shim.c`), where
the real PHP macros handle each generation's layout, rather than reconstructing
`zend_function` / opcode internals through bindgen across 14 minors. The C trampoline
extracts the argument as a `(ptr, len)` pair and calls **into Rust** for the policy
decision; the brain stays in `howdah-core` (pure Rust), exactly as Layers 1–2 keep
decisions in the core and only framing/ABI in the glue.

### 5.2 Engine — a pure-Rust `sinks` module in `howdah-core`

A new `sinks` module, pure Rust, host-unit-testable through the C ABI like the rest of
the core. It owns:

- `SinkId { CommandExec, Include, Unserialize }` and the policy decision
  `check(sink, arg: &[u8], cfg: &SinkConfig) -> SinkOutcome` where `SinkOutcome` is
  `Allow` (on the allowlist / benign), `Log`, or `Block`.
- The **argument policy** per sink (all linear-time, bounded):
  - *CommandExec:* the command string is `Allow` iff it matches one of the operator's
    `allow` patterns; otherwise `Log`/`Block` per mode.
  - *Include:* the resolved path is `Allow` iff it lies under one of `allow_paths`;
    otherwise `Log`/`Block`. **Inert until `allow_paths` is set** (no safe default
    baseline exists without operator input — documented, not silent).
  - *Unserialize:* scan the serialized bytes for object/class tokens (`O:`/`C:`); a
    payload with none is `Allow` (plain data). A payload naming classes is `Allow` iff
    every class is in `allow_classes`; otherwise `Log`/`Block`. The scan is a bounded
    forward pass, never a deserializer.

The FFI entry `howdah_sink_check(ctx, sink_id, arg_ptr, arg_len) -> i32` mirrors Layer
2's `howdah_inspect_value`: it resolves the sink's effective mode, stashes a log line on
the ctx (sink + function/construct + offending class name where applicable, **never the
argument**), and returns an action code the glue acts on. On a scan panic it fails
open (allow + chain) inside `catch_unwind`, never into PHP — a Layer-3 bug must never
break a working call.

### 5.3 Severity + config — an INDEPENDENT sinks mode (mirrors Layer 2 §5.3)

- New `RuleId`s: `CommandExecSink`, `IncludeSink`, `UnserializeSink`, each
  `Severity::Standard`, never `Critical`.
- A new `SinkConfig` with the **same `effective_mode(global)` shape as
  `InspectConfig`**: `Off if global == Off or !enabled else self.mode`. The global
  `block` is deliberately ignored, so the recommended `howdah.mode = block` rollout step
  never arms a sink. Only an explicit `sinks.mode = block` (or one sink's mode) arms it.
- New `[sinks]` TOML section (fixed knobs, no DSL, no new ini directive):

  ```toml
  [sinks]
  enabled = true
  mode    = "detect"            # log-first; independent of howdah.mode

  [sinks.command_exec]           # system/exec/shell_exec/passthru/popen/proc_open
  mode  = "detect"
  allow = []                     # regexes; a matching command is Allow

  [sinks.include]                # include/require(_once)/eval
  mode        = "detect"
  allow_paths = []               # absolute dir prefixes; inert until set

  [sinks.unserialize]
  mode          = "detect"
  allow_classes = []             # class names permitted in a payload
  ```

  Parsed with `#[serde(deny_unknown_fields, default)]` like every other section, so an
  unknown key is a clear error and an absent key takes the safe default.

### 5.4 The block mechanism at a sink — neutralize, do not bail

**(Revised per the builder check — see §10.4.)** A sink fires deep inside the Zend VM,
mid internal-function call or mid-opcode, with arguments already pushed. A
`zend_bailout`/403 there (Layer 1's refuse path, which fires at request setup) is an
unproven longjmp in a very different context. So Layer 3 block does **not** bail:

- **Log / Allow:** the C trampoline chains to the original handler (for the opcode,
  returns `ZEND_USER_OPCODE_DISPATCH`). The call runs normally; a `Log` outcome has
  already emitted the event (§5.5).
- **Block:** the trampoline **neutralizes the call** — the PHP-native
  `disable_functions` model: it does **not** call the original, sets the return value to
  `false`/NULL, emits a PHP warning and the block log line, and lets execution continue.
  For the opcode, it sets the result and skips the include/eval. The dangerous operation
  never runs; no mid-VM longjmp is attempted. A **Task-0 refuse spike** confirms this
  (set return value + skip original) on 5.6/7.4/8.3 before the real build. This only
  happens when an operator has explicitly armed the sink.

### 5.5 Logging — a per-hit line emitted at the call site, never the argument

**(Revised per the builder check — see §10.1.)** Unlike Layers 1–2, which decide once at
a request boundary and stash a single sticky line, a sink fires **repeatedly during
script execution** (a page may call `system()` several times and also `include`). So
Layer 3 does **not** use the core's single-slot sticky `worst`/`log` model (which would
drop all but one event). Instead each sink hit is emitted **immediately at the call
site**: the C trampoline calls `howdah_sink_check`, which formats that hit's line into a
**dedicated sink slot**, and the glue takes and writes it right then via the existing
`response::write_log_line`. A sink hit does **not** participate in the Layer-1/2 sticky
verdict, so it never displaces their RSHUTDOWN line nor double-fires their 403.

A Layer-3 event is one JSON line, same shape as Layers 1–2: timestamp, request id,
`rule` (`command_exec` / `include` / `eval` / `unserialize`), `action` (`log`/`block`),
and the sink's **function or construct name**. For `unserialize`, the offending **class
name** may be included (a type identifier, not user data). The sink **argument** —
command line, include path, serialized blob — is **never** logged. This keeps "Howdah
never logs bodies/args/auth by default" absolutely true, as in Layer 2.

### 5.6 Rules — small, documented, high-confidence

Each sink ships the minimal policy above, each knob with a test proving both the catch
and a benign non-catch. The public coverage states the honest ceiling: flat-policy
virtual patching is bypassable (an app can reach a dangerous effect by a route Howdah
does not guard), which is *why* it logs first. As with Layer 2, the general ceiling is
stated plainly; no per-sink evasion how-to is published.

## 6. The "does not block by default" guarantee — where it is stated

Stated plainly everywhere a person could assume otherwise, mirroring Layer 2 §6:
- **Generated config file:** the `[sinks]` section opens with a plain-language comment —
  *these guards only log; they do not block any request; a global `howdah.mode = block`
  does NOT arm them; to block, set `sinks.mode` (or a sink) to `block` and set its
  allowlist first.*
- **Repo `README`**, **CHANGELOG / release notes** (1.2), and the **site** (a Layer-3
  section, the coverage page, the comparison framing): "guards dangerous sinks;
  detects and logs; does not block by default."
- **`howdah-check`:** shows Layer-3 sinks as log-only where it lists active rules.
- **The JSON events:** carry `action: log`.

## 7. What is left to the builder (resolved in the plan)

- The exact function list bound per sink and the per-generation argument extraction in
  the C shim (the spike proved the mechanism for `system` + the include opcode; the
  plan extends it to the full list and to `unserialize`).
- The `unserialize` object/class-token scan (bounded forward pass) and its tests.
- The include path-resolution/normalization used for the `allow_paths` check.
- The exact `[sinks]` keys, defaults, and validation.
- Coverage-page and coverage-data wording for Layer 3.
- The lab integration test (`lab/integration/sinks.sh` + container half), on the model
  of `inspect.sh`, asserting: a guarded call logs with the right rule in detect mode,
  the argument never appears in the log, an allowlisted call is silent, and a global
  `howdah.mode = block` does not block a sink.

## 8. Deferred to the Layer-3 fast-follow (documented non-goals for 1.2)

- **phar:// deserialization.** The attack reaches object injection through a filesystem
  function (`file_exists`, `fopen`, …) given a `phar://` path, not through
  `unserialize()`. Guarding it log-first means hooking those file-op functions (a wider
  function set) or controlling the stream wrapper — a mechanism the spike did not
  cover, and a blunt "unregister the phar wrapper" is block-only and does not fit the
  detect-first model. Deferred, not faked.
- **SSRF.** Honest SSRF guarding means resolving an outbound request's destination and
  checking it against private/link-local ranges at connect time, through redirects and
  DNS rebinding — a different machine from sink hooking. Even Snuffleupagus does not do
  it. Deferred to its own design.

Both are named on the site's roadmap as the Layer-3 fast-follow, so the public framing
never implies 1.2 covers them.

## 10. Resolutions from the builder check (owner may veto)

A fresh builder reviewed this design and surfaced five questions where a wrong guess
would matter. All five are resolved here in the direction the owner's stated constraints
already point (log-first, quiet-by-default, no overclaiming, defensive-only); they are
baked into §5 above and into the plan. The owner may veto any of them.

**10.1 One line per hit, emitted at the call site (reshapes §5.5 and the FFI).** The
core's single pending-line slot + escalation-only `fold` would drop every sink event but
one. Resolved: sinks use a dedicated per-hit emit path, written immediately at the call
site, outside the Layer-1/2 sticky verdict. See §5.5.

**10.2 Per-sink defaults — quiet by default wins.** On a no-config install, logging
*every* `unserialize` would flood (frameworks unserialize sessions/cache constantly).
Resolved:
- `command_exec`: default **detect, enabled** → logs every exec-family call (rare in a
  healthy app; the visibility is the point). Operators quiet known-good calls with
  `allow` patterns.
- `include`: default **detect but inert until `allow_paths` is set** (no safe baseline
  without operator input).
- `eval`: default **detect** (eval is rare and high-signal; logging every eval is cheap).
- `unserialize`: default **off** (opt-in) — legitimate object unserialize is
  high-volume, so logging it all by default would break quiet-by-default. An operator
  hunting object injection sets `[sinks.unserialize] mode = "detect"`.

**10.3 `eval` is its own sink.** `eval` rides the same `ZEND_INCLUDE_OR_EVAL` opcode as
include/require but `allow_paths` is meaningless for it. Resolved: a distinct
`[sinks.eval]` sink (its own mode + `RuleId::Eval`), served by the same opcode handler
branching on the opcode's type. `[sinks.include]`'s `allow_paths` governs file includes
only.

**10.4 Block = neutralize-and-continue, not bailout (reshapes §5.4).** The spike proved
install + chain, not the refuse path, and a `zend_bailout` deep in the VM mid-call is an
unproven longjmp. Resolved: block neutralizes the call the way PHP's own
`disable_functions` does (suppress, return false/NULL, warn + log), no bailout.
**Task-0 refuse spike result (2026-10-23, on 5.6/7.4/8.3):** the function-swap
neutralize (`RETVAL_FALSE` + return without calling the original) is **proven** — the
blocked call returns false, does not run, and the script continues, on all three ABIs.
So **`command_exec` and `unserialize` support `block` in 1.2.** The opcode-neutralize for
`include`/`eval` was **not** pursued (fiddly per-version result-operand handling, and a
clean fallback exists): **`include` and `eval` ship DETECT-ONLY in 1.2**, with their
block deferred to the Layer-3 fast-follow (§8). Their detect/log path is already proven
(§9).

**10.5 `command_exec` `allow` patterns are full-string anchored — and literal, not
regex.** A substring match would let an `allow` pattern `ls` also permit `ls; rm -rf /`,
gutting the one place Layer 3 actively blocks. Resolved: patterns match the **entire**
command string (implicit `^…$`). And — to keep the no-regex ethos Layer 2 established
(`howdah-core` has no `regex` dependency; its scanners are hand-rolled linear-time) — a
pattern is an **anchored literal string with an optional single trailing `*`** meaning
"any suffix": `id` matches only `id`; `/usr/bin/convert *` matches any command starting
with `/usr/bin/convert `. No regex, no mid-pattern wildcards, trivially linear, no new
dependency. (The design's earlier "regexes" wording is superseded by this.)

## 9. Spike record (evidence, 2026-10-23)

Throwaway spike (not merged): a C trampoline swapped `system()`'s handler in
`CG(function_table)` and installed a `ZEND_INCLUDE_OR_EVAL` user opcode handler, driven
from MINIT, built into `howdah-ext` and run under the lab images for 5.6 / 7.4 / 8.3.
All three: hook installed, `system()` argument captured verbatim, included file ran,
original calls chained intact. Conclusion: the fixed-knob sink-hardening design is
buildable across the full supported PHP range on the two mechanisms above. The spike
code was reverted; this section is its record.
