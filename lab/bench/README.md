# Benchmarks: latency, Layer 2 detection, OPcache JIT

Three measurements, each one command from the repo root. They need Docker and
Node 18+, and reuse the lab images (`lab/images/`); missing images are built.
Published results live in [`results/`](results/) and on
[howdah.org/docs/performance/](https://howdah.org/docs/performance/)
(source: [`docs/performance.md`](../../docs/performance.md)).

| command | what it measures | time on the reference machine |
|---|---|---|
| `sh lab/bench/run.sh` | request latency with and without Howdah | about 80 minutes |
| `sh lab/bench/corpus.sh` | what Layer 2 flags of the GoTestWAF corpus, and false positives | about 5 minutes |
| `sh lab/bench/jit.sh` | whether the OPcache JIT stays on with Howdah, and the integration suite with the JIT configured | about 10 minutes |
| `MODE=ci sh lab/bench/run.sh` | the short run CI gates on | about 4 minutes after the images are built |

Unit tests for the reporting code: `node --test lab/bench/bench.test.mjs`.

## Latency (`run.sh`)

For every PHP version and server type, one lab dev container runs PHP and
builds the extension once; nginx (for php-fpm) and wrk run from
`tools.Dockerfile` in the same network namespace, so traffic is loopback.

- **PHP / servers:** 5.6, 7.4 and 8.3 (`VERSIONS`), each as php-fpm behind
  nginx (static pool of 4 children) and as Apache mod_php, prefork (`SAPIS`).
- **Configurations** (`configs/`): `noext` (extension not loaded), `l1`
  (Layer 1 only: `[inspect]` and `[sinks]` disabled), `l12` (Layer 2 in detect
  mode), `l123` (every Layer 3 sink in detect mode, including `unserialize`,
  `phar` and `ssrf`, which are off by default; allowlists cover the benchmark
  script). `[behavior]` (Layer 4) is off in all three. OPcache is on
  everywhere; the JIT is off (`opcache.jit_buffer_size=0` on 8.x), so every
  configuration, including `noext`, is compared without the JIT (see `jit.sh`
  for whether Howdah lets the JIT run).
- **Workloads** (`app/`, bodies from `bench.mjs bodies`): `get_nobody` (GET,
  no body), `post_form_1k` (1024-byte urlencoded form), `post_multipart_50k`
  (51200-byte multipart body: 8 text fields and 2 files), `sink_exec_include`
  (a script that calls `system('true')` and `include`s one file). The scripts
  read every superglobal, as real applications do, so PHP materializes them.
- **Load:** wrk with one connection (`CONNS=1`), so each latency is one
  request's own time with no queueing anywhere; requests per second is for that
  one connection. `WARMUP` seconds (2) are discarded, then `DURATION` seconds
  (6) are measured; `ROUNDS` (5) rounds per cell, and each reported number is
  the median across rounds (five short rounds rather than three long ones, so
  a burst of other work on a shared machine spoils a round or two that the
  median drops). The host's 1-minute load average is stored with every round. Workloads are the outer loop and configurations the
  inner loop, rotated every round, so a cell and its no-extension baseline are
  measured minutes apart.
- **Checks:** before each cell, `server.sh start` sends one probe request with
  an injection-shaped value, a non-allowlisted `exec()` and a `phar://` path,
  and requires exactly the events the configuration should produce (a TOML the
  core rejects silently falls back to defaults, so `php --ri` alone cannot prove
  the config took effect). The probe's answer (Howdah loaded, OPcache on, JIT
  state) is stored with every round. After each cell the Howdah log must be
  empty: benign traffic writes no events. A cell with socket errors, non-2xx
  responses, a wrong probe or events is marked invalid.
- **CPU pinning:** on a machine with 8 or more CPUs, PHP runs on CPUs 2-5, nginx
  on 6 and wrk on 1 (`SRV_CPUS`, `FE_CPUS`, `CL_CPUS`; `PIN=off` disables it).
  nginx runs one worker: with two, wrk's connections split between them at
  random per run and made p50 bimodal.

### Machine spec capture

`run.sh` writes `machine.json` next to the results, from the host it runs on:
`nproc`; the CPU model (`model name` in `/proc/cpuinfo`); the kernel
(`uname -r`); the OS (`PRETTY_NAME` in `/etc/os-release`); `MemTotal`; the
CPU frequency governor of cpu0; the Docker server version; the wrk and nginx
versions in the tools image; the git commit and Howdah version; the CPU pinning;
the load average at the start and the end (the reference machine is a shared
workstation, not an idle benchmark box); and every parameter above.

### Output

`$OUT` (default `lab/bench/out/<UTC timestamp>/`, ignored by git) holds
`raw.jsonl` (one line per round: wrk's numbers, event counts, the probe),
`machine.json`, `results.json` (per-cell medians, added microseconds and
requests-per-second change versus `noext`) and `results.md` (the same as
tables), plus `logs/` with every wrk output.

## CI gate (`MODE=ci`)

The `bench` job in `.github/workflows/ci.yml` runs `MODE=ci sh lab/bench/run.sh`
(PHP 8.3, php-fpm, every configuration and workload, one 10 s round per cell,
2 s warmup), uploads the results as an artifact, then runs
`node lab/bench/bench.mjs gate <results.json> lab/bench/baseline-ci.json`. It
fails if:

- Howdah adds more than **50 µs** to the median of "GET, no body" in any
  configuration;
- any cell's **normalized p50** (its p50 divided by the same run's `noext` p50
  for that workload) is more than **25%** above the baseline's; or
- any cell is invalid or benign traffic wrote a Howdah event.

Cells are compared normalized, not in absolute microseconds, because the
runner is not the machine the baseline came from. GitHub-hosted runners are
shared virtual machines and their timings move a lot between runs, so both
limits are deliberately loose: the gate catches a gross regression (a hook that
starts doing real work on every request), not a small one. In CI mode PHP,
nginx and wrk share 4 CPUs, as on a 4-vCPU runner; on a bigger machine all
three are pinned to CPUs 2-5 so a local CI-mode run is measured the same way.

To regenerate the baseline after an intended performance change:

```
MODE=ci OUT=lab/bench/out/ci sh lab/bench/run.sh
node lab/bench/bench.mjs baseline lab/bench/out/ci/results.json > lab/bench/baseline-ci.json
```

and say why in the commit.

## Layer 2 detection and false positives (`corpus.sh`)

Runs [GoTestWAF](https://github.com/wallarm/gotestwaf) (MIT licence) from its
Docker image, pinned by digest, against PHP 8.3 php-fpm behind nginx with
Howdah at the shipped defaults (`howdah.mode = detect`, no TOML: Layer 2 on,
log only). GoTestWAF's payloads ship inside its image; nothing is vendored here.

- The test cases are copied out of the image and each is split into one file
  per encoder (Plain, URL, Base64Flat), so every GoTestWAF run has one known
  encoder. Runs are strictly sequential (one GoTestWAF worker, one php-fpm
  child, `--sendDelay 0`).
- The target app (`corpus/app.php`) writes a marker line into the Howdah event
  log while each request runs, recording only where the payload was placed
  (inferred from the request: query string, urlencoded form, multipart form,
  URL path, JSON or XML body, headers) and whether the request carries
  GoTestWAF's `X-GoTestWAF-Test` header. Howdah's own lines for that request
  follow its marker, so `bench.mjs corpus` attributes every event exactly.
  GoTestWAF's own start-up probes are not counted.
- **Flagged** = Howdah logged a Layer 2 event (`sql_injection`,
  `path_traversal` or `command_injection`). **In scope** = the raw payload
  arrives where Layer 2 looks: plain or URL-encoded in the query string, a
  urlencoded form field or the URL path, or plain in a multipart field (PHP
  does not URL-decode multipart fields, so a URL-encoded payload there reaches
  the app as percent-encoded text). Headers, JSON/XML bodies and Base64
  payloads are never in scope.
- **Framing:** Layer 2 is deliberately narrow (three classes, linear-time,
  log-only by default). This is what it flags of a standard corpus, **not a WAF
  score**: GoTestWAF scores blocking, which a log-only layer never does.

Output: `corpus.json`, `corpus.md`, the per-run event logs and GoTestWAF's own
JSON reports. `--noEmailReport` keeps GoTestWAF's report local.

## OPcache JIT (`jit.sh`)

For each PHP 8.x minor given (default 8.1 and 8.3), `jit_container.sh`:

1. reads `opcache_get_status()['jit']['on']` from the CLI and from a php-fpm
   worker, with `opcache.jit=tracing` and `opcache.jit_buffer_size=64M`, in
   three cases: without Howdah, with Howdah at the shipped defaults (no TOML),
   and with `[sinks] hook = "opcode"` (the user opcode handler, which OPcache's
   JIT refuses to run with); it keeps PHP's startup warning if there is one;
2. runs the integration suite (`lab/integration/matrix_container.sh`, cli and
   fpm) with OPcache on and the JIT off, then again with the JIT configured.

It exits non-zero if the two suite runs differ in PASS/FAIL/SKIP counts or
either has a failure. Whether the JIT stayed on is **reported, not asserted**
(see docs/performance.md for the published run and which commit it measured).

## Publishing a run

```
D=lab/bench/results/<YYYY-MM-DD>
mkdir -p $D
cp <run>/results.json <run>/results.md <run>/machine.json $D/
cp <corpus run>/corpus.json <corpus run>/corpus.md $D/
cp <jit run>/jit.json $D/
node lab/bench/bench.mjs publish $D/results.json $D/corpus.json $D/jit.json site/src/data/performance.json
```

then copy the tables from `results.md` and `corpus.md` into
`docs/performance.md`. The site page reads `site/src/data/performance.json`
directly, so its numbers are never typed by hand.
