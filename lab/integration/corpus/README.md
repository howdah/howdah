# False-positive corpus

Benign multipart request bodies that MUST NOT be blocked at Howdah's default
limits (Review Focus #1, and the Task-3 ruling that `MalformedMultipart` is a
*Standard* detection — detect/log only — so a strict parser disagreeing with an
unusual-but-legitimate client never blocks by default). `matrix.sh` POSTs each
body in BLOCK mode and asserts HTTP 200 with zero `"action":"block"` log lines.

Every body uses the boundary `CorpusB0`. Regenerate with `sh make-corpus.sh`.

| file | what it is | why it is benign |
|---|---|---|
| `settings_form.bin` | ~500 form fields | large real settings page; under default `max_parts=2000` and stock PHP `max_input_vars=1000` |
| `gallery_upload.bin` | 1 field + 15 file parts | multi-file upload within `max_files=200` and stock `max_file_uploads=20` |
| `nested_array.bin` | 40 deeply-nested array-key fields (`a[b][c][d][e][f N]`) | ordinary PHP nested-array form input |
| `bare_lf_headers.bin` | headers separated by bare `LF` (not `CRLF`) | some clients emit LF; strict-parser case → Standard, not blocked |
| `folded_headers.bin` | an obs-fold continuation header line | legacy header folding; strict-parser case |
| `non_form_data_disposition.bin` | `Content-Disposition: attachment` | non-`form-data` disposition; strict-parser case |
| `data_line_dashdash.bin` | a body line starting with `--` | user text that merely looks boundary-ish; must not be mis-split |

## Input-path corpus (`input/`)

Non-multipart legitimate requests (urlencoded bodies, header lists, query
strings) that MUST NOT block at the shipped input-shape / header / CGI defaults
(`max_input_vars=2000`, `max_input_nesting_depth=64`, `max_request_headers=200`).
These are driven by a separate loop in `matrix_container.sh` /
`matrix_apache_container.sh` (never the `*.bin` multipart loop), which sends each
at the DEFAULT limits and asserts HTTP 200 with zero `"action":"block"` lines.
Shape only — no payloads (design §9). Regenerate with `sh make-corpus.sh`.

| file | what it is | why it is benign |
|---|---|---|
| `input/large_form.urlencoded` | 1500 urlencoded fields | large real form; under `max_input_vars=2000`, above stock PHP 1000 |
| `input/nested_form.urlencoded` | survey/matrix fields, max depth 5 | ordinary nested form; far under `max_input_nesting_depth=64` |
| `input/ordinary_headers.txt` | 50 normal request headers | typical browser/proxy header set; under `max_request_headers=200` |
| `input/safe_queries.txt` | query strings with `-` (`sort=-price`, `q=a-b-c`, …) | each carries a literal `=` and none starts with `-`, so `cgi_arg_injection` never fires |

If any item ever trips a limit, the fix is to lower/adjust the offending default
or rule — never to accept the false positive.
