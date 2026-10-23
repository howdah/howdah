# Howdah 0.1 coverage data (Task 12)

Machine-backed results that Task 14's coverage table consumes. Everything here
is reproduced by committed scripts; no payload or exploit is used — all fixtures
reproduce only the harmless *structure* of a PHP2Shell-shaped upload (part/field
counts and sizes).

- STEP 1 gate (defaults vs memory): `lab/integration/step1_memory_container.sh`,
  `lab/integration/step1_raised_container.sh`; raw numbers in
  `lab/integration/step1-results/*.tsv`.
- Cross-version matrix: `lab/integration/matrix.sh` → `lab/integration/matrix-results.tsv`.
- False-positive corpus: `lab/integration/corpus/` (+ `README.md`).

## The exact defense (and a known caveat)

The precise, version-independent defense is the **count-based critical rules**
`max_parts` (2000) and `max_files` (200), plus the **length rules**
`max_filename_bytes` (512) and `max_field_name_bytes` (1024). These are exact:
the rfc1867 callback hands the glue one event per part (`FORMDATA` /
`FILE_START`) with the real name/filename, so Howdah counts every part and sees
every name length precisely.

Caveat (documented, by design): the glue-level `max_part_header_bytes` /
`max_part_headers` are a best-effort **lower bound**. PHP's callback surfaces
only the `Content-Disposition` name/filename — not a part's other headers
(`Content-Type`, etc.) nor their raw bytes — so Howdah reconstructs a single
header per part and under-counts header bytes versus what PHP actually parsed.
`max_part_header_bytes`/`max_part_headers` therefore back up, but do not drive,
the defense; the count + length rules above are the real gate.

## STEP 1 — the decisive default-tuning gate

Measured peak worker RSS (`/proc/<pid>/status:VmHWM`, which survives the block's
`zend_bailout`) for a shaped request on PHP 5.6 / 7.3 / 8.4, NTS.

### On a STOCK box the shaped flood is NOT a memory threat

Stock config (`memory_limit=128M`, `post_max_size=8M`, `max_input_vars=1000`,
`max_file_uploads=20`): PHP's own caps hold peak RSS flat regardless of N, and
on PHP 8.x additionally gate the rfc1867 callback:

| PHP | shape | parts sent | $_FILES/$_POST seen | peak RSS | Howdah (defaults) |
|---|---|---|---|---|---|
| 7.3 | file  | 50000 | 20   | 27 MB | not blocked (callback gated at 20) — no threat |
| 7.3 | field | 50000 | 1000 | 26 MB | **403 max_parts** (FORMDATA fires past 1000) |
| 5.6 | field | 50000 | 1000 | 23 MB | **403 max_parts** |
| 8.4 | field | 50000 | 1000 | 32 MB | not blocked (FORMDATA gated at 1000) — no threat |
| 8.4 | file  | 50000 | 20   | 32 MB | not blocked (gated at 20) — no threat |

So on stock config peak RSS never exceeds ~33 MB (vs the 128M limit) whether or
not Howdah blocks: PHP's `max_input_vars`/`max_file_uploads` contain both the
memory AND (on 8.x) the callback. There is nothing to exhaust and nothing to
block. **The defense does not depend on these PHP caps** — see next.

### On a RAISED-cap box the flood IS a DoS, and Howdah blocks it

The real exposure: an admin raises `max_input_vars` / `max_file_uploads` (common
for large forms / galleries). The callback then fires unbounded and, within the
*same stock 8 MiB* body budget, the undefended flood exhausts memory:

| PHP | shape | parts | undefended peak RSS | Howdah @ defaults | defended peak RSS |
|---|---|---|---|---|---|
| 5.6 | file  | 90000 | **173 MB** (> 128M: OOM) | **403 max_files** | 27 MB |
| 5.6 | field | 90000 | 55 MB | **403 max_parts** | 55 MB |
| 8.4 | file  | 90000 | **127 MB** (≈ 128M)      | **403 max_files** | 36 MB |
| 8.4 | field | 90000 | 52 MB | **403 max_parts** | 52 MB |

The undefended file-flood reaches 127–173 MB inside an 8 MiB request — a genuine
memory-exhaustion DoS. At DEFAULT limits Howdah blocks every flood, holding the
defended peak to 27–55 MB, well under 128M.

### Verdict: defaults are correct, no lowering required

Reaching 128M needs ~90000 parts; `max_parts=2000` / `max_files=200` fire ~45×
earlier, so the memory never climbs. Per the gate's own lowering criterion
("if the attack drives memory toward 128M with FEWER parts than max_parts"),
the answer is NO on every version, so `Limits::defaults()` is kept unchanged and
the justification is recorded in `crates/howdah-core/src/limits.rs`.

Callback-vs-PHP-caps confirmation (brief requirement):
- `FORMDATA` fires **past** `max_input_vars` on 5.6/7.3 even at stock; on 8.x it
  is gated at `max_input_vars`, but raising the cap makes it fire past → blocked.
- `FILE_START` is gated at `max_file_uploads` on all versions, but raising the
  cap makes it fire past → blocked at `max_files`.
- In every case the gating cap also caps memory, so the no-block cases are
  no-threat cases; the defense engages exactly when the threat exists.

## STEP 2/3 — cross-version matrix & false-positive corpus

`lab/integration/matrix.sh` builds the extension for each PHP minor and runs, per
SAPI, 14 scenarios (7 fixed + the 7-item false-positive corpus):

- `shaped_block_files` → 403 + `max_files` + block log (client_ip checked under fpm/apache)
- `shaped_block_fields` → 403 + `max_parts` + block log
- `selftest` → 200 + `self_test` action=log (never blocks)
- `up_progress_on` / `up_progress_off` → both 403 (callback chaining intact with
  `session.upload_progress` both enabled and disabled — Review Focus #3)
- `detect_standard` → 200 + action=log (a downgraded `max_files` logs, never blocks)
- `detect_critical` → 403 (a critical rule blocks even when global mode = detect)
- `corpus_*` (×7) → 200, zero block lines

Each shaped request is sent on a raised-cap config so the rfc1867 callback fires
on every version (the real-exposure config; see STEP 1).

### Results (this pass)

| PHP (minor) | cli-server | php-fpm | apache mod_php |
|---|---|---|---|
| 5.4.16 (CentOS 7 stock) | 14/14 PASS | — (note 1) | — (note 1) |
| 5.6.40 | 14/14 PASS | 14/14 PASS | not-run (note 2) |
| 7.3.33 | 14/14 PASS | 14/14 PASS | not-run (note 2) |
| 7.4.33 | 14/14 PASS | 14/14 PASS | 14/14 PASS |
| 8.1.34 | 14/14 PASS | 14/14 PASS | 14/14 PASS |
| 8.4.27 | 14/14 PASS | 14/14 PASS | not-run (note 2) |

Total this pass: 154 PASS / 0 FAIL / 7 SKIP (the 5.4 fpm row).

- **client_ip**: populated and asserted exactly (`203.0.113.9` under fpm, `127.0.0.1`
  under apache). The PHP CLI built-in server does not expose `REMOTE_ADDR` via
  `sapi_getenv`, so client_ip is validated on the production SAPIs, not on cli.
- **Note 1 (5.4)**: CentOS 7's stock packages ship no `cgi-fcgi` to drive php-fpm
  in the lab (fpm row SKIP), and PHP 5.4 predates official Docker images so there
  is no `php:5.4-apache` (apache not run). Real-world 5.4 on CentOS 7 is mod_php
  under httpd. 5.4's hook is the same SAPI-independent `main/rfc1867.c` path proven
  on cli-server here and on fpm for the adjacent 5.6; the full block/corpus suite
  passes on 5.4 cli-server.
- **Note 2**: apache mod_php (prefork, apache2handler SAPI) is confirmed real and
  passing on 7.4 and 8.1 — bail → clean 403, client_ip populated, corpus clean.
  5.6/7.3/8.4 apache were not run this pass; fpm already exercises the non-CLI SAPI
  on them and apache is a mechanical repeat of the 7.4/8.1 runs.
- **Not-yet-run minors** (no committed lab base image): 5.5 (upstream image pull
  broken, milestone-0 finding), 7.0/7.1/7.2, 8.0, 8.2/8.3, 8.5. Recorded as
  `## NOT-RUN` in the TSV. The bindings are per-generation (php5/php7/php8), so each
  of these is a repeat of an already-passing generation pending its base image —
  NOT claimed as passing here.

## CVE-shape × PHP version coverage (for Task 14)

Shapes: **F** = file-part flood (→ `max_files`), **P** = form-field/part flood
(→ `max_parts`). BLOCKED = refused 403 + logged at default limits on a
raised-cap box (the threat config); on stock config PHP's own caps contain the
same flood (no threat), as measured in STEP 1.

| PHP version | F — file flood (`max_files`) | P — field/part flood (`max_parts`) | SAPIs validated |
|---|---|---|---|
| 5.4.16 | BLOCKED | BLOCKED | cli |
| 5.6.40 | BLOCKED | BLOCKED | cli, fpm |
| 7.3.33 | BLOCKED | BLOCKED | cli, fpm |
| 7.4.33 | BLOCKED | BLOCKED | cli, fpm, apache |
| 8.1.34 | BLOCKED | BLOCKED | cli, fpm, apache |
| 8.4.27 | BLOCKED | BLOCKED | cli, fpm |
| 5.5, 7.0, 7.1, 7.2, 8.0, 8.2, 8.3, 8.5 | NOT-RUN | NOT-RUN | — (no lab base image yet) |

Every version actually run BLOCKS both shapes on every SAPI run, with zero
false positives across the 7-item benign corpus. No run produced PARTIAL or
NOT-COVERED; the only gaps are the NOT-RUN minors above, which lack a committed
base image and are honestly not claimed as passing.
