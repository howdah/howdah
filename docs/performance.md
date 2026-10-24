# Performance: what Howdah costs, and what Layer 2 flags

> Measured on 2026-10-24 on one machine. Every number below is copied from the
> result files in [`lab/bench/results/2026-10-24/`](../lab/bench/results/2026-10-24/),
> written by the harnesses in [`lab/bench/`](../lab/bench/). The site page,
> https://howdah.org/docs/performance/, reads the same data. How to rerun
> everything: [`lab/bench/README.md`](../lab/bench/README.md).

The design promised "no measurable overhead on requests without a body" and
benchmarks in CI. This page is the measurement, and the `bench` job in
`.github/workflows/ci.yml` is the CI part.

**What each run measured.** The latency run measured `main` at
`e0cde7114826` (Howdah 1.4.0), before #42 (the JIT-compatible
include/eval hook) and #44 (the php-fpm refusal fix). The GoTestWAF corpus
run and the JIT run measured `2e3109efc754` (Howdah 1.3.0).
None of them has been re-run on later commits yet.

## Summary

- **A GET with no body:** Howdah changed the median (p50) request time by
  −2 to +6 µs across every layer combination, PHP version and server tested,
  on requests that take 42 to 74 µs without it; most cells moved by +3 to
  +6 µs, and the same cell moved by about 2 µs between rounds. The design
  aimed for no measurable overhead here; a few microseconds is measurable, and
  small next to a real application's own time.
- **Layer 2 costs time in proportion to the values it scans.** With Layer 2
  on, the 1 KB form moved by +22 to +47 µs and the 50 KB multipart body
  (8 text fields of about 200 bytes each, 2 files) by +38 to +64 µs. With
  Layer 1 alone, the same bodies moved by +3 to +8 µs: counting parts costs
  little, scanning values costs more.
- **Layer 3 with every sink in detect mode:** the `system('true')` +
  `include` request moved by +8 to +56 µs on a request that takes 469 to
  1981 µs, most of it spent forking a shell; those cells moved by up to
  631 µs between rounds, so the Layer 3 difference is inside the noise.
- **OPcache JIT:** before #42, loading Howdah turned the JIT off on PHP 8.1,
  8.3 and 8.5 whatever the config said. Since #42 the default
  `[sinks] hook = "auto"` keeps it on; that is **not measured here yet**.
  The latency numbers on this page are without the JIT.
- **Layer 2 flagged 19 of 62** (30.6%) GoTestWAF payloads in its three
  classes that arrived where it looks, and **0 of 141** of GoTestWAF's benign
  requests. That is what a narrow, log-only layer catches of a standard
  corpus, **not a WAF score**.

## How it was measured

- **Machine:** AMD Ryzen 7 8845HS w/ Radeon 780M Graphics, 16 CPUs (`nproc`),
  27 GiB RAM, kernel 6.12.111+deb13-amd64, Debian GNU/Linux 13 (trixie),
  CPU governor `powersave`, Docker 29.9.2. It is a shared
  workstation, not an idle benchmark box: the 1-minute load average at the
  end of each round ranged from 0.89 to 13.14 (median 1.8).
  `run.sh` records all of this in `machine.json`.
- **Software:** PHP 5.6.40, 7.4.33 and 8.3.36 from the lab images; nginx/1.22.1;
  wrk debian/4.1.0-3+b2.
- **Servers:** php-fpm (static pool of 4 children) behind nginx
  over FastCGI, and Apache mod_php (prefork). nginx and wrk share the PHP
  container's network namespace, so all traffic is loopback. CPU pinning:
  php 2-5, nginx 6, wrk 1.
- **Configurations:** no extension; Layer 1 only (`[inspect]` and `[sinks]`
  disabled); Layers 1+2 (input inspection in detect mode); Layers 1+2+3 (every
  sink in detect mode, including `unserialize`, `phar` and `ssrf`, which
  are off by default, with allowlists covering the benchmark script). Layer 4
  is switched off in every configuration and was not measured. OPcache is on
  everywhere; the JIT is off (`opcache.jit_buffer_size=0`). The TOML files
  are in `lab/bench/configs/`.
- **Workloads:** a GET with no body; a POST of a 1024-byte urlencoded form; a
  POST of a 51200-byte multipart body with 10 parts (8 text fields, 2 files);
  a GET of a script that calls `system('true')` and `include`s one file. The
  scripts read every superglobal, as a real application does.
- **Load:** wrk with one connection, so each latency is one request's own
  time, with no queueing in nginx or PHP; requests per second is for that one
  connection. 2 s warmup, then 6 s measured, 5
  rounds per cell; each number is the median across rounds. Workloads are the
  outer loop and configurations the inner loop, rotated every round.
- **Checks:** before each cell a probe request proves which configuration is
  loaded (an injection-shaped value, a non-allowlisted command and a
  `phar://` path must log exactly for the layers that are on). After each
  cell the Howdah log must be empty; benign traffic wrote no events in any
  cell, and no cell had a socket error or a non-2xx response.

```
sh lab/bench/run.sh               # latency: PHP 5.6, 7.4, 8.3 x php-fpm, Apache (about 80 minutes)
sh lab/bench/jit.sh 8.1 8.3 8.5   # OPcache JIT check
sh lab/bench/corpus.sh            # GoTestWAF corpus against Layer 2
```

## Latency

Added p50 latency for "GET, no body" (microseconds, versus no extension):

Added p50 latency for "GET, no body" (microseconds, versus no extension):

| PHP | Server | Layer 1 | Layers 1+2 | Layers 1+2+3 |
|---|---|---|---|---|
| 5.6.40 | php-fpm behind nginx | +3 | +6 | +5 |
| 5.6.40 | Apache mod_php (prefork) | +3 | +5 | +5 |
| 7.4.33 | php-fpm behind nginx | −2 | −1 | ±0 |
| 7.4.33 | Apache mod_php (prefork) | +3 | +3 | +3 |
| 8.3.36 | php-fpm behind nginx | +5 | +6 | +6 |
| 8.3.36 | Apache mod_php (prefork) | +3 | +4 | +4 |

### PHP 5.6.40, php-fpm behind nginx

| Workload | Config | p50 µs | p99 µs | Requests/s | Added p50 µs | Added p99 µs | Requests/s change | Events |
|---|---|---|---|---|---|---|---|---|
| GET, no body | No extension | 72 | 193 | 12874.8 |  |  |  | 0 |
| GET, no body | Layer 1 | 75 | 165 | 12316 | +3 | −28 | −4.3% | 0 |
| GET, no body | Layers 1+2 | 78 | 575 | 11273.6 | +6 | +382 | −12.4% | 0 |
| GET, no body | Layers 1+2+3 | 77 | 161 | 12117.2 | +5 | −32 | −5.9% | 0 |
| POST, 1 KB form | No extension | 88 | 2125 | 10150.9 |  |  |  | 0 |
| POST, 1 KB form | Layer 1 | 95 | 2409 | 8774.3 | +7 | +284 | −13.6% | 0 |
| POST, 1 KB form | Layers 1+2 | 135 | 2961 | 6304.4 | +47 | +836 | −37.9% | 0 |
| POST, 1 KB form | Layers 1+2+3 | 118 | 772 | 7567.4 | +30 | −1353 | −25.5% | 0 |
| POST, 50 KB multipart (10 parts) | No extension | 237 | 458 | 4008.6 |  |  |  | 0 |
| POST, 50 KB multipart (10 parts) | Layer 1 | 243 | 518 | 3915.6 | +6 | +60 | −2.3% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2 | 301 | 734 | 3084.6 | +64 | +276 | −23.1% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2+3 | 297 | 725 | 3113.7 | +60 | +267 | −22.3% | 0 |
| GET, system('true') + include | No extension | 1640 | 2628 | 634.8 |  |  |  | 0 |
| GET, system('true') + include | Layer 1 | 1661 | 2429 | 623.5 | +21 | −199 | −1.8% | 0 |
| GET, system('true') + include | Layers 1+2 | 1673 | 2434 | 620.4 | +33 | −194 | −2.3% | 0 |
| GET, system('true') + include | Layers 1+2+3 | 1686 | 2302 | 617.4 | +46 | −326 | −2.7% | 0 |

### PHP 5.6.40, Apache mod_php (prefork)

| Workload | Config | p50 µs | p99 µs | Requests/s | Added p50 µs | Added p99 µs | Requests/s change | Events |
|---|---|---|---|---|---|---|---|---|
| GET, no body | No extension | 42 | 80 | 22631 |  |  |  | 0 |
| GET, no body | Layer 1 | 45 | 70 | 20967 | +3 | −10 | −7.4% | 0 |
| GET, no body | Layers 1+2 | 47 | 74 | 20372 | +5 | −6 | −10% | 0 |
| GET, no body | Layers 1+2+3 | 47 | 69 | 20480.1 | +5 | −11 | −9.5% | 0 |
| POST, 1 KB form | No extension | 49 | 79 | 19339.4 |  |  |  | 0 |
| POST, 1 KB form | Layer 1 | 55 | 112 | 16994.8 | +6 | +33 | −12.1% | 0 |
| POST, 1 KB form | Layers 1+2 | 84 | 122 | 11743.4 | +35 | +43 | −39.3% | 0 |
| POST, 1 KB form | Layers 1+2+3 | 86 | 203 | 11446.5 | +37 | +124 | −40.8% | 0 |
| POST, 50 KB multipart (10 parts) | No extension | 234 | 467 | 4095.5 |  |  |  | 0 |
| POST, 50 KB multipart (10 parts) | Layer 1 | 241 | 450 | 3997 | +7 | −17 | −2.4% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2 | 293 | 481 | 3299.2 | +59 | +14 | −19.4% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2+3 | 293 | 498 | 3278.9 | +59 | +31 | −19.9% | 0 |
| GET, system('true') + include | No extension | 1981 | 2626 | 514 |  |  |  | 0 |
| GET, system('true') + include | Layer 1 | 2023 | 2618 | 495.6 | +42 | −8 | −3.6% | 0 |
| GET, system('true') + include | Layers 1+2 | 2025 | 2646 | 501.5 | +44 | +20 | −2.4% | 0 |
| GET, system('true') + include | Layers 1+2+3 | 2037 | 2638 | 494.9 | +56 | +12 | −3.7% | 0 |

### PHP 7.4.33, php-fpm behind nginx

| Workload | Config | p50 µs | p99 µs | Requests/s | Added p50 µs | Added p99 µs | Requests/s change | Events |
|---|---|---|---|---|---|---|---|---|
| GET, no body | No extension | 74 | 460 | 11944 |  |  |  | 0 |
| GET, no body | Layer 1 | 72 | 162 | 12958.7 | −2 | −298 | +8.5% | 0 |
| GET, no body | Layers 1+2 | 73 | 147 | 12763.3 | −1 | −313 | +6.9% | 0 |
| GET, no body | Layers 1+2+3 | 74 | 159 | 12739.5 | ±0 | −301 | +6.7% | 0 |
| POST, 1 KB form | No extension | 83 | 213 | 11465.5 |  |  |  | 0 |
| POST, 1 KB form | Layer 1 | 86 | 167 | 10972.4 | +3 | −46 | −4.3% | 0 |
| POST, 1 KB form | Layers 1+2 | 105 | 186 | 8996.5 | +22 | −27 | −21.5% | 0 |
| POST, 1 KB form | Layers 1+2+3 | 106 | 290 | 8715 | +23 | +77 | −24% | 0 |
| POST, 50 KB multipart (10 parts) | No extension | 236 | 3954 | 3777 |  |  |  | 0 |
| POST, 50 KB multipart (10 parts) | Layer 1 | 244 | 4676 | 3379.4 | +8 | +722 | −10.5% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2 | 299 | 2503 | 2999.7 | +63 | −1451 | −20.6% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2+3 | 278 | 4237 | 3020.5 | +42 | +283 | −20% | 0 |
| GET, system('true') + include | No extension | 473 | 1750 | 1775.3 |  |  |  | 0 |
| GET, system('true') + include | Layer 1 | 509 | 3190 | 1631 | +36 | +1440 | −8.1% | 0 |
| GET, system('true') + include | Layers 1+2 | 480 | 1023 | 1857.3 | +7 | −727 | +4.6% | 0 |
| GET, system('true') + include | Layers 1+2+3 | 489 | 3080 | 1659.7 | +16 | +1330 | −6.5% | 0 |

### PHP 7.4.33, Apache mod_php (prefork)

| Workload | Config | p50 µs | p99 µs | Requests/s | Added p50 µs | Added p99 µs | Requests/s change | Events |
|---|---|---|---|---|---|---|---|---|
| GET, no body | No extension | 42 | 89 | 22621.3 |  |  |  | 0 |
| GET, no body | Layer 1 | 45 | 341 | 19749.7 | +3 | +252 | −12.7% | 0 |
| GET, no body | Layers 1+2 | 45 | 110 | 20184 | +3 | +21 | −10.8% | 0 |
| GET, no body | Layers 1+2+3 | 45 | 81 | 21167.3 | +3 | −8 | −6.4% | 0 |
| POST, 1 KB form | No extension | 48 | 264 | 18496.1 |  |  |  | 0 |
| POST, 1 KB form | Layer 1 | 53 | 198 | 16323.5 | +5 | −66 | −11.7% | 0 |
| POST, 1 KB form | Layers 1+2 | 72 | 105 | 13205.3 | +24 | −159 | −28.6% | 0 |
| POST, 1 KB form | Layers 1+2+3 | 74 | 300 | 12217.1 | +26 | +36 | −33.9% | 0 |
| POST, 50 KB multipart (10 parts) | No extension | 219 | 426 | 4409.2 |  |  |  | 0 |
| POST, 50 KB multipart (10 parts) | Layer 1 | 225 | 445 | 4260 | +6 | +19 | −3.4% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2 | 261 | 475 | 3688.7 | +42 | +49 | −16.3% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2+3 | 260 | 465 | 3702 | +41 | +39 | −16% | 0 |
| GET, system('true') + include | No extension | 469 | 969 | 1757.5 |  |  |  | 0 |
| GET, system('true') + include | Layer 1 | 479 | 985 | 1730.7 | +10 | +16 | −1.5% | 0 |
| GET, system('true') + include | Layers 1+2 | 499 | 983 | 1701.2 | +30 | +14 | −3.2% | 0 |
| GET, system('true') + include | Layers 1+2+3 | 497 | 973 | 1700.3 | +28 | +4 | −3.3% | 0 |

### PHP 8.3.36, php-fpm behind nginx

| Workload | Config | p50 µs | p99 µs | Requests/s | Added p50 µs | Added p99 µs | Requests/s change | Events |
|---|---|---|---|---|---|---|---|---|
| GET, no body | No extension | 69 | 119 | 13332.7 |  |  |  | 0 |
| GET, no body | Layer 1 | 74 | 124 | 12809.2 | +5 | +5 | −3.9% | 0 |
| GET, no body | Layers 1+2 | 75 | 133 | 12543.3 | +6 | +14 | −5.9% | 0 |
| GET, no body | Layers 1+2+3 | 75 | 137 | 12524.9 | +6 | +18 | −6.1% | 0 |
| POST, 1 KB form | No extension | 83 | 137 | 11527.2 |  |  |  | 0 |
| POST, 1 KB form | Layer 1 | 88 | 148 | 10903.4 | +5 | +11 | −5.4% | 0 |
| POST, 1 KB form | Layers 1+2 | 106 | 179 | 8880.9 | +23 | +42 | −23% | 0 |
| POST, 1 KB form | Layers 1+2+3 | 106 | 182 | 8996.2 | +23 | +45 | −22% | 0 |
| POST, 50 KB multipart (10 parts) | No extension | 217 | 427 | 4339.4 |  |  |  | 0 |
| POST, 50 KB multipart (10 parts) | Layer 1 | 223 | 475 | 4220.7 | +6 | +48 | −2.7% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2 | 258 | 504 | 3706.4 | +41 | +77 | −14.6% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2+3 | 256 | 405 | 3758.3 | +39 | −22 | −13.4% | 0 |
| GET, system('true') + include | No extension | 473 | 985 | 1888.1 |  |  |  | 0 |
| GET, system('true') + include | Layer 1 | 488 | 1000 | 1818.4 | +15 | +15 | −3.7% | 0 |
| GET, system('true') + include | Layers 1+2 | 482 | 994 | 1850.6 | +9 | +9 | −2% | 0 |
| GET, system('true') + include | Layers 1+2+3 | 487 | 994 | 1835.3 | +14 | +9 | −2.8% | 0 |

### PHP 8.3.36, Apache mod_php (prefork)

| Workload | Config | p50 µs | p99 µs | Requests/s | Added p50 µs | Added p99 µs | Requests/s change | Events |
|---|---|---|---|---|---|---|---|---|
| GET, no body | No extension | 42 | 72 | 22744.3 |  |  |  | 0 |
| GET, no body | Layer 1 | 45 | 73 | 21357.6 | +3 | +1 | −6.1% | 0 |
| GET, no body | Layers 1+2 | 46 | 64 | 20938.9 | +4 | −8 | −7.9% | 0 |
| GET, no body | Layers 1+2+3 | 46 | 66 | 20818.7 | +4 | −6 | −8.5% | 0 |
| POST, 1 KB form | No extension | 48 | 66 | 20147.4 |  |  |  | 0 |
| POST, 1 KB form | Layer 1 | 53 | 74 | 17827.1 | +5 | +8 | −11.5% | 0 |
| POST, 1 KB form | Layers 1+2 | 70 | 98 | 13567.5 | +22 | +32 | −32.7% | 0 |
| POST, 1 KB form | Layers 1+2+3 | 70 | 95 | 13615.5 | +22 | +29 | −32.4% | 0 |
| POST, 50 KB multipart (10 parts) | No extension | 209 | 420 | 4621.3 |  |  |  | 0 |
| POST, 50 KB multipart (10 parts) | Layer 1 | 215 | 412 | 4487.9 | +6 | −8 | −2.9% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2 | 247 | 420 | 3917.8 | +38 | ±0 | −15.2% | 0 |
| POST, 50 KB multipart (10 parts) | Layers 1+2+3 | 247 | 417 | 3918.9 | +38 | −3 | −15.2% | 0 |
| GET, system('true') + include | No extension | 517 | 996 | 1627.2 |  |  |  | 0 |
| GET, system('true') + include | Layer 1 | 547 | 998 | 1582.3 | +30 | +2 | −2.8% | 0 |
| GET, system('true') + include | Layers 1+2 | 491 | 1012 | 1695.1 | −26 | +16 | +4.2% | 0 |
| GET, system('true') + include | Layers 1+2+3 | 525 | 996 | 1620.7 | +8 | ±0 | −0.4% | 0 |

p99 moves between rounds on a shared machine (see the load average above);
read it as a rough bound, not a comparison.

## OPcache JIT

Measured on 2026-10-24 with Howdah 1.3.0
(commit `2e3109efc754`), **before #42 was merged**, with
`opcache.jit=tracing` and `opcache.jit_buffer_size=64M`. The values are
`opcache_get_status()['jit']['on']`, read from the CLI and from a php-fpm
worker (`lab/bench/jit.sh`).

| PHP | JIT without Howdah (CLI / php-fpm) | JIT with Howdah, shipped defaults (CLI / php-fpm) | Integration suite, JIT off | Integration suite, JIT configured |
|---|---|---|---|---|
| 8.1.34 | on / on | off / off | cli 25 pass, 0 fail; fpm 27 pass, 0 fail | cli 25 pass, 0 fail; fpm 27 pass, 0 fail |
| 8.3.36 | on / on | off / off | cli 25 pass, 0 fail; fpm 27 pass, 0 fail | cli 25 pass, 0 fail; fpm 27 pass, 0 fail |
| 8.5.12RC1 | on / on | off / off | cli 25 pass, 0 fail; fpm 27 pass, 0 fail | cli 25 pass, 0 fail; fpm 27 pass, 0 fail |

At startup PHP printed: "JIT is incompatible with third party extensions that setup user opcode handlers. JIT disabled."

- **Why, at that commit:** on PHP 7.0 and later, Layer 3 guarded
  `include`/`require` and `eval` with a user opcode handler for
  `ZEND_INCLUDE_OR_EVAL`, installed at startup by
  `howdah_install_sink_hooks()` in `crates/howdah-sys/sink_hook.c` whatever
  the config said. OPcache does not run its JIT while any user opcode handler
  is set, so even `[sinks] enabled = false` did not bring the JIT back. The
  integration suite passed the same number of scenarios with the JIT
  configured, but only because the JIT was off.
- **Since #42** (merged to `main` after this run, not yet in a release): the
  default `[sinks] hook = "auto"` keeps the JIT on. The JIT is off only when
  `[sinks.include] allow_paths` is set, when `[behavior] deny_exec_dirs` is
  set, or with `hook = "opcode"` (see [config.md](config.md) and
  [coverage.md](coverage.md)). `lab/bench/jit.sh` now measures the shipped
  defaults and an explicit `hook = "opcode"` case; **it has not been run
  against #42 yet**, so there is no measured result for the new behaviour
  here. (`lab/integration/jit.sh`, added by #42, asserts the hook states.)
- The latency numbers above were measured with the JIT off in every
  configuration, including no extension, so compare them with a JIT-off PHP.
- Other in-PHP tools have run into the same thing: Imunify360's Proactive
  Defense turns the JIT off unless its JIT-compatible mode is enabled, and
  Snuffleupagus issue #441 reports OPcache's JIT disabling itself.

## Layer 2 against a standard attack corpus

Layer 2 is deliberately narrow: three classes (SQL injection, path traversal,
command injection), linear-time signatures, log-only by default. This run
shows what it flags of a standard corpus. **It is not a WAF score:**
GoTestWAF scores blocking, and a log-only layer would score zero by its rules,
so the counts come from Howdah's own log.

- **Corpus:** GoTestWAF v0.5.8 (Wallarm, MIT licence), from its
  Docker image pinned by digest (`wallarm/gotestwaf@sha256:ff7184da90029a98c87bfdbadcee544c979b999593175d17b2d38f642ee29977`); its payloads ship in
  the image and nothing is vendored here. Each test case was split by encoder
  and sent one request at a time.
- **Target:** PHP 8.3.36, php-fpm behind nginx, Howdah 1.3.0 (commit
  `2e3109efc754`) at the shipped defaults (`howdah.mode = detect`, no TOML,
  so Layer 2 is on and only logs). The signature code
  (`crates/howdah-core/src/inspect.rs`) is unchanged on `main` since.
- **Flagged** means Howdah logged a Layer 2 event for that request. **In
  scope** means the raw payload arrived where Layer 2 looks: plain or
  URL-encoded in the query string, a urlencoded form field or the URL path, or
  plain in a multipart field. Headers, JSON and XML bodies and Base64-encoded
  payloads are never in scope; Layer 2 does not read them.
- Reading the table: Layer 2 scans only the first 16 KB of a value
  (`[inspect.limits] max_value_bytes`). The 16-128 KB community cases put
  their attack after that much padding, so they are not flagged (the 8 KB
  ones are): padding a value past 16 KB gets an attack past Layer 2. Many
  GoTestWAF SQL injection payloads are WAF-evasion variants (inline comments,
  double encoding, JSON functions) that Layer 2's signatures do not match.

| Payload class | GoTestWAF test cases | Flagged, all requests | Flagged, in scope |
|---|---|---|---|
| SQL injection | 7 | 1/65 (1.5%) | 1/23 (4.3%) |
| Path traversal / LFI | 3 | 5/30 (16.7%) | 5/12 (41.7%) |
| Command injection / RCE | 11 | 13/62 (21%) | 13/27 (48.1%) |
| Not a Layer 2 class (XSS, LDAP, NoSQL, SSTI, XXE, ...) | 22 | 7/517 (1.4%) | 7/195 (3.6%) |
| Benign (GoTestWAF false-pos set): false positives | 1 | 0/141 (0%) | 0/94 (0%) |

Per GoTestWAF test case:

| Test set | Test case | Layer 2 class | Sent | Reached PHP | Flagged | In scope flagged |
|---|---|---|---|---|---|---|
| community | community-128kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-128kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-128kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-16kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-16kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-16kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-32kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-32kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-32kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-64kb-rce | command_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-64kb-sqli | sql_injection | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-64kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-8kb-rce | command_injection | 1 | 1 | 1/1 (100%) | 1/1 (100%) |
| community | community-8kb-sqli | sql_injection | 1 | 1 | 1/1 (100%) | 1/1 (100%) |
| community | community-8kb-xss | - | 1 | 1 | 0/1 (0%) | 0/1 (0%) |
| community | community-lfi-multipart | path_traversal | 2 | 2 | 0/2 (0%) | 0/2 (0%) |
| community | community-lfi | path_traversal | 8 | 8 | 2/8 (25%) | 2/4 (50%) |
| community | community-rce-rawrequests | command_injection | 3 | 3 | 1/3 (33.3%) | 1/3 (33.3%) |
| community | community-rce | command_injection | 4 | 4 | 2/4 (50%) | 2/2 (100%) |
| community | community-sqli | sql_injection | 12 | 12 | 0/12 (0%) | 0/6 (0%) |
| community | community-user-agent | - | 9 | 9 | 0/9 (0%) | 0/0 (n/a) |
| community | community-xss | - | 104 | 104 | 4/104 (3.8%) | 4/52 (7.7%) |
| community | community-xxe | - | 2 | 2 | 0/2 (0%) | 0/0 (n/a) |
| false-pos | texts | benign | 141 | 141 | 0/141 (0%) | 0/94 (0%) |
| owasp | crlf | - | 7 | 7 | 0/7 (0%) | 0/7 (0%) |
| owasp | ldap-injection | - | 24 | 24 | 0/24 (0%) | 0/6 (0%) |
| owasp | mail-injection | - | 24 | 24 | 0/24 (0%) | 0/9 (0%) |
| owasp | nosql-injection | - | 50 | 50 | 0/50 (0%) | 0/15 (0%) |
| owasp | path-traversal | path_traversal | 20 | 20 | 3/20 (15%) | 3/6 (50%) |
| owasp | rce-urlparam | command_injection | 9 | 9 | 2/9 (22.2%) | 2/6 (33.3%) |
| owasp | rce-urlpath | command_injection | 3 | 3 | 3/3 (100%) | 3/3 (100%) |
| owasp | rce | command_injection | 6 | 6 | 0/6 (0%) | 0/0 (n/a) |
| owasp | shell-injection | command_injection | 32 | 32 | 4/32 (12.5%) | 4/8 (50%) |
| owasp | sql-injection | sql_injection | 48 | 48 | 0/48 (0%) | 0/12 (0%) |
| owasp | ss-include | - | 24 | 24 | 3/24 (12.5%) | 3/9 (33.3%) |
| owasp | sst-injection | - | 24 | 24 | 0/24 (0%) | 0/9 (0%) |
| owasp | xml-injection | - | 7 | 7 | 0/7 (0%) | 0/0 (n/a) |
| owasp | xss-scripting | - | 224 | 223 | 0/223 (0%) | 0/83 (0%) |
| owasp-api | graphql-post | - | 0 | 0 | not sent (needs a GraphQL or gRPC endpoint, or not selected) | |
| owasp-api | graphql | - | 0 | 0 | not sent (needs a GraphQL or gRPC endpoint, or not selected) | |
| owasp-api | grpc | - | 0 | 0 | not sent (needs a GraphQL or gRPC endpoint, or not selected) | |
| owasp-api | non-crud | - | 2 | 2 | 0/2 (0%) | 0/0 (n/a) |
| owasp-api | rest | - | 7 | 7 | 0/7 (0%) | 0/0 (n/a) |
| owasp-api | soap | - | 5 | 5 | 0/5 (0%) | 0/0 (n/a) |

Layer 2 classes only, by where the payload was placed (all encodings):

| Placement | Flagged |
|---|---|
| JSON body | 0/29 (0%) |
| URL path | 4/15 (26.7%) |
| headers | 0/11 (0%) |
| multipart form | 0/31 (0%) |
| query string | 6/29 (20.7%) |
| urlencoded form | 9/42 (21.4%) |

Layer 2 classes only, by GoTestWAF encoder (all placements):

| Encoder | Flagged |
|---|---|
| Base64Flat | 0/50 (0%) |
| Plain | 1/11 (9.1%) |
| URL | 18/96 (18.8%) |

## What these numbers do not show

- One machine, one day. Your hardware, PHP build and application will give
  different absolute numbers; the added microseconds are the part worth
  comparing.
- The benchmark scripts are tiny. A real application spends far longer in its
  own code, so the same added microseconds are a smaller share of its request
  time.
- Benign traffic only: no cell measures the cost of writing a log line or of
  blocking, and the SSRF sink's DNS lookup never runs because the script makes
  no outbound request.
- Memory use was not measured. Neither were Layer 4, ZTS builds, aarch64, PHP
  versions other than the three above, or php-cgi.
- wrk is a closed-loop load generator with one connection here: it measures
  each request's own time, not behaviour under an open arrival rate or under
  saturation.
- The detection run uses one corpus, on one PHP version and server. Layer 2's
  signatures are listed in [coverage-data.md](coverage-data.md).

## The check on every pull request

CI runs a short version of the latency benchmark (`MODE=ci`: PHP 8.3, php-fpm
behind nginx, every configuration and workload, one 10 s round per cell) and
fails if Howdah adds more than 50 µs to the median GET with no body, or if any
cell's median, taken relative to the same run's no-extension cell, grows by
more than 25% over [`lab/bench/baseline-ci.json`](../lab/bench/baseline-ci.json).
GitHub's runners are shared virtual machines and their timings move a lot, so
both limits are deliberately loose: the job catches a gross regression, not a
small one. It uploads its results as the `bench-results` artifact. The
baseline was generated from a local CI-mode run on commit `2e3109efc754`
(`lab/bench/results/2026-10-24/ci-mode-results.json`).
