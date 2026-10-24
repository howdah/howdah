Run 2026-10-24T21:58:49Z on AMD Ryzen 7 8845HS w/ Radeon 780M Graphics (16 CPUs), kernel 6.12.111+deb13-amd64, Debian GNU/Linux 13 (trixie).
wrk 1 connection(s), 6 s per round after a 2 s warmup, 5 round(s) per cell, median across rounds. CPU pinning: php 2-5, nginx 6, wrk 1. OPcache on, JIT off. Host 1-minute load average across rounds: 0.89 to 13.14 (median 1.8).

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
