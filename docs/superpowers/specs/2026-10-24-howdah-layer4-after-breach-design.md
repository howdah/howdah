# Howdah Layer 4 — "After a breach" — Design

**Date:** 2026-10-24
**Status:** design, approved to build end-to-end (owner: "continue our workflow and get this to prod including the site updates and readme")
**Target release:** Howdah 1.4.0 (Layer 4; follows 1.0=L1, 1.1=L2, 1.2/1.3=L3)
**Builds on:** Layer 3 sink hardening (`crates/howdah-core/src/sinks/`, `crates/howdah-sys/sink_hook.c`, `ssrf_hook.c`). Reuses its hook mechanisms; adds one new primitive, proven by spike (below).

## 1. Intent and why

Layers 1–3 act *before and during* a request: they limit request shape, inspect
request content, and guard dangerous sinks against injection. Layer 4 is the last
line: it assumes the attacker already has a foothold — a webshell dropped in an
uploads directory, a `.php` file written into writable storage, an app coerced
into doing something it should never do — and it catches the breach **while PHP
itself is the thing doing the dirty work.**

The owner framed it in two concrete pictures:

1. **PHP running from a folder that should never hold executable PHP** — e.g. an
   uploads directory. A request to `/uploads/x.php` that executes PHP is almost
   always a dropped webshell.
2. **An app doing what it has no business doing** — "a simple Laravel app should
   not be running bitcoin miners." Concretely: a PHP process shelling out to an
   unknown binary, or opening outbound connections to a host the app never
   legitimately talks to.

The thing that makes Layer 4 worth building *inside PHP* — and not in a network
box or a PHP-level prepend — is **execution origin**: Howdah sits in the compiler
and on the internal-function handlers, so it knows *which PHP file is doing the
calling.* Only an in-PHP extension knows this cheaply.

## 2. Goals / non-goals / anti-goals

**Goals**
- Detect (and, when an operator opts in, block) PHP **executed from a directory
  that should not contain executable PHP** (uploads, tmp, cache, writable storage).
- Detect (and optionally block) a script **shelling out to a binary the app is
  not expected to run**, **connecting out to a host it is not expected to reach**,
  or **writing a `.php` file**, with the finding attributed to the *calling
  script's directory*.
- Let the policy come from **both**: an operator-declared allowlist **and** a
  Howdah **observe/discovery mode** that watches the running app and *proposes*
  additions.
- Stay faithful to the house rules: **log-first, never blocks by default**;
  Layer-4 mode independent of the global `howdah.mode`; no new php.ini directives
  (stays at 3); argument values never logged; honest coverage only.

**Non-goals**
- Not process monitoring. Howdah does not enumerate system processes, watch CPU,
  or inspect anything PHP did not itself initiate through a hooked path.
- Not antivirus / file-content scanning of uploads. Layer 4 reasons about
  *execution and behaviour*, not file bytes at rest.
- Not a replacement for filesystem permissions, `open_basedir`, or disabling PHP
  execution in upload dirs at the web-server level. Howdah is the backstop for
  servers that cannot do those (old PHP, shared hosting, can't-touch-the-app).

**Anti-goals (would make this a failure even if it "works")**
- **Auto-promoting discovered behaviour to a block.** Observe mode must *only
  propose*. If Howdah is first installed on a box that is *already breached*,
  silent auto-allow would bless the miner into the policy. Discovery writes
  proposals to the log / a suggested-config the operator reviews and commits;
  nothing it discovers ever arms a block on its own.
- **Breaking legitimate apps on install.** Shipping defaults must not block a
  working app. Everything arrives in detect/log-only.
- **Overclaiming.** We do not claim to stop miners in general — only to catch the
  phases where PHP is the actor. See §7.

## 3. The model: an application-behaviour policy, anchored on origin

A new config section, **`[behavior]`** (Layer 4), parallel to `[inspect]`
(Layer 2) and `[sinks]` (Layer 3). **It mirrors `InspectConfig` exactly** (builder
check #5): `enabled: bool` (default `true`) + `mode: Mode` (default `Detect`), with
`effective_mode(global) = if global == Off || !enabled { Off } else { self.mode }`.
No top-level `Option<Mode>` and no per-facet modes — per-facet gating is
list-driven (empty list = nothing expected), which matches the intent and keeps
one knob per layer. Four policy facets:

| Facet | Config | What it checks | Hook |
|---|---|---|---|
| **Execution origin** | `deny_exec_dirs` | A PHP file whose realpath is under one of these dirs runs **as the main script** (checked at RINIT from `SG(request_info).path_translated`, opcache-independent) **or** is `require`/`include`d (compile-file pointer) | RINIT main-script check **+** L3 compile-file pointer |
| **Expected binaries** | `allow_exec_binaries` | `exec`/`system`/`popen`/`proc_open`/`shell_exec`/`passthru` to a program **not** on the list | L3 command-exec sink fn-table swap (always calls decide) + call-time origin |
| **Expected egress** | `allow_egress_hosts` | outbound connect to a host **not** on the list (an allowlist axis, distinct from L3 SSRF's reserved-range axis) | L3 SSRF egress hooks + call-time origin — **requires the SSRF `armed` gate to become "ssrf OR behavior-egress active"** (see below) |
| **`.php` writes** | `deny_php_writes` | writing a PHP-extension file **into a writable/upload location** (origin-scoped, see below) via `file_put_contents`/`fopen`(write-mode)/`move_uploaded_file`/`rename` | fn-table swap, **per-function arg position** |

**Write-facet mechanics (builder check #1, #2).** The `.php`-write check is
**origin-scoped**, not "any `.php` write anywhere": it flags a write only when the
target path is under a `deny_exec_dirs` entry (or, if none set, under the script's
own writable upload/storage area) **or** the calling script is itself under a
`deny_exec_dirs` entry. This is deliberate — legitimate frameworks write compiled
`.php` constantly (Blade → `storage/framework/views/*.php`, Twig/Symfony compiled
templates, opcache-style caches), so an unscoped rule would break Laravel/Symfony
under `block`. The path argument differs per function: **arg 1** for
`file_put_contents`/`fopen`, **arg 2** (destination) for `move_uploaded_file`/
`rename` — the builder uses the `ssrf_hook.c`-style n-th-arg accessor, not
`sink_hook.c`'s arg-1-only macro. `fopen` must gate on its **mode arg (arg 2:
`w`/`a`/`x`/`c`)** so ordinary reads of `.php` config/templates are ignored. And
because `ssrf_hook.c` **already** fn-table-swaps `fopen`, Layer 4 must **not** add a
second independent swap: there is **one shared `fopen` trampoline** that runs both
the SSRF egress check and the php-write check and chains the saved original once.

**Egress-facet arming (builder check #3).** L3 SSRF defaults off, and its egress
trampolines short-circuit to the bare chain when `ssrf armed` is false. So the
`armed` predicate the SSRF hooks consult must become **"SSRF active OR
behavior-egress active"**, and the egress `decide` callback must be extended to
carry the **call-time origin** (the calling script path). Likewise the command-exec
`decide` path (which always fires) gains an origin parameter. These arming/
signature couplings are design-level, not left to the builder.

**Origin attribution (the new primitive):** at every sink hook, Howdah records the
realpath of the script that owns the current execution frame
(`zend_get_executed_filename()`), so a finding reads "`/var/www/uploads/x.php`
called `system`", attributing the act to the webshell even when a legitimate
entry script `require()`d it. Spike-proven on 5.4 / 5.6 / 7.4 / 8.1 / 8.4 (§6).

**Observe / discovery mode:** `behavior.observe = true` logs every *would-be
finding* as a `proposed` line — the binary that was exec'd, the host connected
to, the directory PHP ran from — tagged so an operator (or the config editor at
cfg.howdah.org) can roll the observed set into `allow_exec_binaries` /
`allow_egress_hosts`. Observe never blocks and never writes config itself.

## 4. Configuration (no new php.ini directives)

```toml
[behavior]
enabled = true              # mirrors [inspect]; false -> Layer 4 Off regardless of mode
mode = "detect"             # "off" | "detect" | "block"; default detect (log-only).
                            # Independent of howdah.mode: howdah.mode=block does NOT force block here.
observe = false             # true -> log observed behaviour as `proposed`, never block

deny_exec_dirs = []         # e.g. ["/var/www/uploads", "/var/www/storage", "/tmp"]
allow_exec_binaries = []    # e.g. ["/usr/bin/gs", "convert"]  (empty = none expected)
allow_egress_hosts = []     # e.g. ["api.stripe.com"]          (empty under detect = log all egress)
deny_php_writes = false     # true -> flag writing a *.php/.phar/.phtml file INTO a writable/
                            # upload location or from a script under deny_exec_dirs (origin-scoped;
                            # NOT any .php write — frameworks compile .php templates legitimately)
```

`effective_mode(global)` resolves exactly as `[inspect]`: `Off` if `global == Off`
or `!enabled`, else `mode`. The four facets are each gated by their own
list/bool being set; a facet whose list is empty expects nothing (logs under
detect, denies nothing until the operator fills it — the Layer-3 "allowlist must
be set before block" discipline).

**Default-safe stance.** Everything ships empty / `false` / detect so a fresh
install blocks nothing. The recommended starting values are documented, not
baked in. `allow_*` lists being empty means "nothing is expected" — under
detect that logs everything (useful for discovery); it only *denies* under
`block`, and only after the operator has set the lists, mirroring the Layer-3
rule that a sink blocks only after its allowlist is set.

Validation reuses Layer 3's `valid_allow_entry` discipline (reject empty,
whitespace, bad entries). Paths in `deny_exec_dirs` are canonicalised for prefix
comparison; non-absolute or non-existent entries are rejected at config load.

## 5. New RuleIds (log labels + severity)

Add to `RuleId` (and to `rule_catalog()` — the `rule_catalog_covers_every_variant`
test enforces this), all **`Severity::Standard`** (log-first, never auto-critical):

- `UploadExec` — PHP executed from a denied directory.
- `UnexpectedBinary` — exec of a program not on `allow_exec_binaries`.
- `UnexpectedEgress` — outbound connection to a host not on `allow_egress_hosts`.
- `PhpWrite` — writing a PHP-extension file when `deny_php_writes`.

Reuse the existing per-hit log slot and the `effective_mode` resolution. Action
resolves solely from `behavior.effective_mode` + per-facet gating, never from the
`[rules]` labels (which are inert, as established for phar/ssrf). **The config
editor must therefore mark all four new ids as no-op labels** — extend the
"no-op rule names labelled" set added in commit bdc5329 for phar/ssrf — so the
editor never offers `upload_exec = "block"` as if it did something (builder
check #6). Adding the variants is mechanical and compile-guarded: add to `RuleId`,
to the default-`Standard` arm of `severity()`, bump `rule_catalog()`'s `ALL`
24→28, and extend the exhaustive match in `rule_catalog_covers_every_variant`
(which fails to compile if any is missed).

## 6. Spike result (done 2026-10-24, throwaway, reverted)

`lab/spike/origin_probe.c`: fn-table swap on `system()`, then
`zend_get_executed_filename()` in the trampoline. Across **5.4, 5.6, 7.4, 8.1,
8.4** the caller path was reported correctly, and crucially, when a legit entry
script `require()`d an uploaded `shell.php`, the call-time origin was
`/var/www/uploads/shell.php` (the shell), **not** the entry script. This is the
load-bearing primitive and it holds on all three ABI families. The compile-time
origin (`fh->filename`) is already captured by the Layer-3 compile hook.

## 7. Honest limitations (stated on the site and coverage page; never claimed away)

- **Howdah only sees what PHP itself does through a hooked path.** A miner that
  PHP launches and then detaches, a reverse shell that forks away from PHP, or
  anything dropped by a non-PHP vector (an attacker's cron, a compromised binary)
  runs outside PHP and is invisible to Layer 4. Layer 4 catches the
  webshell/dropper phase — *while PHP is the actor* — not post-detachment.
- **Execution-origin denial: the main-script case is opcache-independent; the
  included-file case is first-compile, best-effort.** A direct request to
  `/uploads/x.php` (the headline webshell case) is checked at RINIT from the SAPI
  `path_translated`, every request, regardless of opcache. The secondary case —
  `require('/uploads/shell.php')` from another script — rides the compile-file
  pointer, and a file served from a warm opcache is not recompiled, so that check
  may not re-fire on repeat hits (same shape as the documented Layer-3 5.x include
  limitation). The call-time facets (binary/egress/php-write) fire on every call
  regardless of opcache, because they hook internal functions.
- **`deny_php_writes` is origin-scoped and still has false positives.** Even
  scoped to writable/upload locations, an app legitimately configured to compile
  templates or cache into such a directory will be flagged; this is why the facet
  is off by default and logs first. Frameworks that write compiled `.php`
  (Blade, Twig, Symfony) are the expected noise an operator tunes out via
  `deny_exec_dirs` scoping before ever enabling `block`.
- **Allowlists are best-effort, bypassable.** Binary matching is by program
  path/basename; an attacker who execs via a shell builtin, an absolute path
  variant, or an interpreter can evade. Egress matching resolves at check time
  and shares the Layer-3 SSRF bypasses (DNS rebinding, redirects, `curl_multi_*`,
  non-string URL). This is why Layer 4 logs rather than blocks by default.
- **`.php`-write detection is by target extension**, and does not catch a write
  to a non-`.php` path later executed via rename, nor `.htaccess`-based tricks.
- **Discovery can be poisoned on an already-breached box** — hence propose-only.

## 8. What's decided vs. left to the builder

**Decided here** (incl. builder-check rulings, owner away): the `[behavior]`
section mirroring `InspectConfig` (`enabled` + `mode`, one-arg `effective_mode`,
list-driven facets — no `Option<Mode>`, no per-facet modes); log-first /
independent-mode / off-safe-by-default; the four new `Standard` RuleIds + their
no-op config-editor labels; origin via `zend_get_executed_filename()`;
`deny_exec_dirs` checked at **RINIT (main script) AND compile-file (includes)**;
`.php`-write **origin-scoped**, per-function arg position (1 for
`file_put_contents`/`fopen`, 2 for `move_uploaded_file`/`rename`), `fopen` gated
on write-mode and sharing **one** trampoline with the SSRF `fopen` swap; egress
`armed` predicate widened to "SSRF OR behavior-egress"; `decide` callbacks
extended with a call-time-origin parameter; observe = propose only; version 1.4.0.

**Left to the builder (plan will pin exact signatures):** the Rust module layout
under `howdah-core` (a `behavior` module mirroring `sinks`); exact FFI entrypoints
(`howdah_behavior_*`) mirroring `howdah_sink_*`; the shared-`fopen`-trampoline C
glue and the RINIT main-script origin check; the site coverage-matrix rows; the
lab integration script (`lab/integration/behavior.sh`) across 5.4/5.6/7.4/8.3/8.5.
