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

If any item ever trips a limit, the fix is to lower/adjust the offending default
or rule — never to accept the false positive.
