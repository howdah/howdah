# Input-hook spike findings (1.0 Layer-1 protections, Task 1)

**Gate verdict: PASS for the input-shape and CGI-virtual-patch glue on all six
measured versions, with four precisions the glue must respect (below).**
Request-header enumeration is reachable on the CLI server but its
production-SAPI (FPM/Apache) confirmation is deferred, per the controller
ruling.

On PHP 5.4.16, 5.6.40, 7.3.33, 7.4.33, 8.1.34 and 8.4.27 (all NTS, non-debug,
CLI built-in server), saving `sapi_module.input_filter` at MINIT, installing a
counting filter, and always chaining the saved prior filter (returning ITS
verdict):

- **sees every GET / POST / COOKIE variable**, for both urlencoded and
  multipart bodies. Both body types arrive as `arg == PARSE_POST` (0).
  Counts matched the request exactly on every version (5 POST vars -> 5, 2 GET
  -> 2, 3 cookies -> 3).
- **preserves the prior filter.** `$_GET` / `$_POST` / `$_COOKIE` stayed fully
  populated with the right counts; the chain flag was set on every request.
- **exposes the raw query string** via `SG(request_info).query_string`
  (`x=1&y=2`, `g=1`; `NULL` when there is none) and **the SAPI name** via
  `sapi_module.name` (`cli-server`).

## Precisions the glue must respect

1. **`input_filter` also fires for `PARSE_SERVER` (5).** It is called for
   `$_SERVER` entries, including the `HTTP_*` request headers, so the filter
   must switch on `arg` and count only `PARSE_POST/GET/COOKIE` (0/1/2) for
   input-shape limits. Total call counts also differ by version (e.g. an empty
   GET: 15 calls on 5.4-8.1, 3 on 8.4), so never use the raw total.
2. **The filter fires BEFORE RINIT.** POST variables are filtered during
   `sapi_activate` and GET/COOKIE during `php_hash_environment`, both ahead of
   `PHP_RINIT`. The probe observed `rinit_seen` = 5 (POST), 2 (GET), 6
   (POST+GET+cookie) at RINIT time. Per-request state therefore must NOT be
   reset in RINIT (that erases the counts); reset in RSHUTDOWN (or on a
   request boundary the glue can see before the first variable). `$_SERVER`
   filtering happens after RINIT (`rinit_seen` = 0 for the header request).
3. **Signature differs in 8.1+: `var` is `const char *`.** Found by compile
   failure on 8.1 and 8.4 (first build used `char *var` per the brief; it
   does not compile there).
4. **`sapi_register_input_filter()` exists but does not chain** - it replaces
   the field. Chaining requires assigning `sapi_module.input_filter` directly
   as the probe does.

## Exact symbols and signatures to bind

Global `sapi_module` (type `sapi_module_struct`, `main/SAPI.h`):

| Field | Type |
|---|---|
| `sapi_module.input_filter` | function pointer, see below |
| `sapi_module.name` | `char *` (`"cli-server"` here; `"fpm-fcgi"`, `"apache2handler"` etc. expected elsewhere, unmeasured) |
| `SG(request_info).query_string` | `char *` (NULL if absent); also `.request_method`, `.content_length`, `.cookie_data` were readable |

`input_filter` return type is `unsigned int` on every version. Parameters:

```c
/* PHP_VERSION_ID <  70000 */
unsigned int f(int arg, char *var, char **val, unsigned int val_len, unsigned int *new_val_len TSRMLS_DC);
/* 70000 <= PHP_VERSION_ID < 80100 (7.0-7.4 measured; 8.0 inferred) */
unsigned int f(int arg, char *var, char **val, size_t val_len, size_t *new_val_len);
/* PHP_VERSION_ID >= 80100 (8.1, 8.4 measured) */
unsigned int f(int arg, const char *var, char **val, size_t val_len, size_t *new_val_len);
```

`arg` values seen: `PARSE_POST`=0, `PARSE_GET`=1, `PARSE_COOKIE`=2,
`PARSE_SERVER`=5. `TSRMLS_*` must be a local gated macro (removed in 8.x), as
in probe.c. The 8.1 gate is from compile evidence on 7.4 vs 8.1 only; 8.0 was
not built (not in compose), so the const boundary is inferred to be 8.1.

Chain recipe (see `lab/spike/input_probe.c`): `prior = sapi_module.input_filter;
sapi_module.input_filter = ours;` at MINIT; ours records, then calls
`prior` (if non-NULL) and returns its result; restore `prior` at MSHUTDOWN. If
`prior` is NULL, set `*new_val_len = val_len` and return 1.

## Request-header reach (best effort, CLI server only)

- Headers are NOT in `SG(request_info)`; there is no header list there.
- They are reachable two ways on the CLI server, on every version:
  (a) as `HTTP_*` keys in `$_SERVER`; (b) as `PARSE_SERVER` calls into the
  chained `input_filter` (the filter saw `HTTP_X_HOWDAH_THREE`, name length 19,
  as `last_name_len`). Path (b) means the same hook can count/size headers
  with no new hook. `getallheaders()` exists on CLI server from 5.6 (5 headers
  for the POST, 6 for the cookie request) and is absent on 5.4.16.
- **Not verified:** that FPM (`php_register_variable_safe` path) and Apache
  `mod_php` also route `HTTP_*` through `input_filter(PARSE_SERVER)`. That is
  inference from shared core code and is deferred to a later glue task.
  Until confirmed, scope `MaxRequestHeaders` / `MaxRequestHeaderBytes` to the
  CLI server and treat other SAPIs as unconfirmed in the coverage table.

## Environment

Same lab as milestone 0 (`lab/compose.yaml`, images in `lab/images/`), NTS,
Linux x86_64. PHP CLI built-in server (`php -S`): input_filter and the
request-info query string live in SAPI-independent core / request startup, so
this exercises the same paths FPM/Apache use for GET/POST/COOKIE, but the
SAPI-specific `$_SERVER` registration (headers) is CLI-server specific.

## Reproducible commands

```sh
docker compose -f lab/compose.yaml up -d --build php-5.4 php-5.6 php-7.3 php-7.4 php-8.1 php-8.4
# per service S in php-5.4 php-5.6 php-7.3 php-7.4 php-8.1 php-8.4:
docker compose -f lab/compose.yaml exec S sh -c \
  'cp -r /lab/spike /tmp/spike && cd /tmp/spike && phpize && ./configure --enable-input-probe && make'
# -> /tmp/spike/modules/input_probe.so ; response script /tmp/index.php
# (below) echoes input_probe_*() values plus count($_GET/_POST/_COOKIE),
# HTTP_* keys of $_SERVER, getallheaders().
docker compose -f lab/compose.yaml exec S sh -c \
  'php -d extension=/tmp/spike/modules/input_probe.so -S 127.0.0.1:8081 /tmp/index.php &'
U=http://127.0.0.1:8081/
curl -s -X POST -d 'a=1&b=2&c=3&d=4&e=5' $U                          # 1 urlencoded
curl -s -F a=1 -F b=2 -F c=3 -F d=4 -F e=5 $U                         # 2 multipart
curl -s "${U}?x=1&y=2"                                                # 3 GET
curl -s -X POST -d 'p=1&q=2' -H 'Cookie: c1=1; c2=2; c3=3' "${U}?g=1" # 3b all three
curl -s -H 'X-Howdah-One: 1' -H 'X-Howdah-Two: 2' -H 'X-Howdah-Three: 3' $U  # 4 headers
```

The response script is a ~12-line throwaway that json-encodes
`input_probe_count()`, `_by_arg()` ("post,get,cookie"), `_last_arg()`,
`_last_name_len()`, `_rinit_seen()`, `_chain_called()`, `_query_string()`,
`_sapi_name()` and the `$_GET/$_POST/$_COOKIE/$_SERVER` counts.

## Per-version results

`by_arg` = POST,GET,COOKIE calls seen by the chained filter. "Superglobals" =
`count($_GET)/$_POST/$_COOKIE` after the prior filter ran. All six versions
gave identical values below, sapi=`cli-server`, chain intact (`true`) for every
request.

| Request | by_arg (P,G,C) | Superglobals (G/P/C) | `query_string` | rinit_seen |
|---|---|---|---|---|
| 1 urlencoded POST 5 vars | 5,0,0 | 0/5/0 | NULL | 5 |
| 2 multipart POST 5 fields | 5,0,0 | 0/5/0 | NULL | 5 |
| 3 GET `x=1&y=2` | 0,2,0 | 2/0/0 | `x=1&y=2` | 2 |
| 3b POST 2 + GET 1 + cookie 3 | 2,1,3 | 1/2/3 | `g=1` | 6 |
| 4 three custom `X-Howdah-*` headers | 0,0,0 | 0/0/0 | NULL | 0 |

Header request (4), `$_SERVER` `HTTP_X_*` keys: `HTTP_X_HOWDAH_ONE`,
`HTTP_X_HOWDAH_TWO`, `HTTP_X_HOWDAH_THREE` on all six versions.

| PHP | filter chains (urlenc / multipart / GET / cookie) | prior filter kept | query string | SAPI name | headers via `$_SERVER` | `getallheaders()` |
|---|---|---|---|---|---|---|
| 5.4.16 | yes / yes / yes / yes | yes | yes | yes | yes | absent |
| 5.6.40 | yes / yes / yes / yes | yes | yes | yes | yes | yes |
| 7.3.33 | yes / yes / yes / yes | yes | yes | yes | yes | yes |
| 7.4.33 | yes / yes / yes / yes | yes | yes | yes | yes | yes |
| 8.1.34 | yes / yes / yes / yes | yes | yes | yes | yes | yes |
| 8.4.27 | yes / yes / yes / yes | yes | yes | yes | yes | yes |

Total (all-arg) call counts, shown only to prove they are not stable: request
1 = 22 (5.4), 24 (5.6/7.3/7.4/8.1), 12 (8.4). Count only args 0/1/2.

## Not measured (inference only)

5.5, 7.0-7.2, 8.0, 8.2, 8.3, 8.5 are not in compose. The `input_filter`
signature was identical across 5.4 and 5.6 (shared with 5.5, inferred), across
7.3 and 7.4 (shared with 7.0-7.2, inferred), and across 8.1 and 8.4 (shared
with 8.2/8.3/8.5, inferred). 8.0 is the one version where the `const char *`
boundary is not covered by a measurement. These belong to the full-matrix task.

## Go / no-go per protection

| Protection | Hook | Verdict |
|---|---|---|
| Input-shape limits (var count, nesting depth, key length) | chained `sapi_module.input_filter`, args 0/1/2 | **GO** on 5.4, 5.6, 7.3, 7.4, 8.1, 8.4 (urlencoded + multipart + GET + cookie); inferred for others |
| php-cgi arg-injection virtual patch (CVE-2012-1823) | `SG(request_info).query_string` + `sapi_module.name` | **GO** on all six (both readable; the query string is available once the request is parsed; whether it is readable early enough at RINIT on FPM/CGI is not covered by CLI-server evidence) |
| Request-header count/size limits | `input_filter` `PARSE_SERVER` and `$_SERVER` `HTTP_*` | **CONDITIONAL GO**: works on CLI server on all six; production-SAPI (FPM/Apache) confirmation deferred. Scope to confirmed SAPIs in the coverage table until then |

## Committed vs gitignored

Committed: `lab/spike/input_probe.c`, `lab/spike/config.m4` (now builds both
`probe` and `input_probe`), and this doc. Nothing is gitignored for this spike;
the requests are benign and listed above. The throwaway `index.php` response
script lives outside the repo (scratchpad).
