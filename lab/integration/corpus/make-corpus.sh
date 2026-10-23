#!/bin/sh
# Generate the false-positive corpus: BENIGN multipart bodies that MUST NOT be
# blocked at Howdah's default limits (Review Focus #1 + the Task 3 strict-parser
# ruling). Every body uses the boundary "CorpusB0". Run from anywhere; writes
# the .bin files next to this script (or into $1 if given).
#
# The committed .bin files are the output of this script; re-run it to regenerate.
set -eu
OUT="${1:-$(cd "$(dirname "$0")" && pwd)}"
mkdir -p "$OUT"
B=CorpusB0
cr() { printf '%s\r\n' "$1"; }   # one CRLF-terminated line

# 1. A ~500-field settings form (within max_parts=2000; under PHP max_input_vars=1000).
f="$OUT/settings_form.bin"; : > "$f"
i=0; while [ "$i" -lt 500 ]; do
  { cr "--$B"; cr "Content-Disposition: form-data; name=\"setting_$i\""; cr ""; cr "value_$i"; } >> "$f"
  i=$((i+1))
done
cr "--$B--" >> "$f"

# 2. A multi-file gallery upload within limits (15 files << max_files=200,
#    and within the stock PHP max_file_uploads=20), plus a couple of fields.
f="$OUT/gallery_upload.bin"; : > "$f"
{ cr "--$B"; cr 'Content-Disposition: form-data; name="album"'; cr ""; cr "Holidays"; } >> "$f"
i=0; while [ "$i" -lt 15 ]; do
  { cr "--$B"
    cr "Content-Disposition: form-data; name=\"photos[]\"; filename=\"img_$i.jpg\""
    cr "Content-Type: image/jpeg"; cr ""
    printf 'JPEGDATA-%s-binaryish-\xff\xd8\xff\xe0-payload\r\n' "$i"; } >> "$f"
  i=$((i+1))
done
cr "--$B--" >> "$f"

# 3. A deeply-nested-array form (PHP array-key names); 40 parts.
f="$OUT/nested_array.bin"; : > "$f"
i=0; while [ "$i" -lt 40 ]; do
  { cr "--$B"
    cr "Content-Disposition: form-data; name=\"a[b][c][d][e][f$i]\""
    cr ""; cr "deep_$i"; } >> "$f"
  i=$((i+1))
done
cr "--$B--" >> "$f"

# ---- Task 3 strict-parser ruling: MalformedMultipart is Standard (detect->log),
#      so in BLOCK mode these must NOT be blocked (served 200) unless an admin
#      opts in. Each is an unusual-but-legitimate client shape. ----

# 4. Bare-LF header separators (some clients emit LF, not CRLF).
f="$OUT/bare_lf_headers.bin"; : > "$f"
printf -- '--%s\nContent-Disposition: form-data; name="x"\n\nhello\n--%s--\n' "$B" "$B" >> "$f"

# 5. A folded (continuation) header line (obs-fold: leading whitespace).
f="$OUT/folded_headers.bin"; : > "$f"
{ cr "--$B"
  cr 'Content-Disposition: form-data; name="y";'
  cr '	filename="folded.txt"'
  cr 'Content-Type: text/plain'; cr ""; cr "folded body"; cr "--$B--"; } >> "$f"

# 6. A non-form-data disposition (Content-Disposition: attachment).
f="$OUT/non_form_data_disposition.bin"; : > "$f"
{ cr "--$B"
  cr 'Content-Disposition: attachment; name="z"; filename="a.bin"'
  cr 'Content-Type: application/octet-stream'; cr ""; cr "attachment-bytes"; cr "--$B--"; } >> "$f"

# 7. A data line that begins with "--" (must not be mistaken for a boundary).
f="$OUT/data_line_dashdash.bin"; : > "$f"
{ cr "--$B"
  cr 'Content-Disposition: form-data; name="note"'
  cr ""
  cr "--not-a-boundary just user text"
  cr "--$B--"; } >> "$f"

# ===========================================================================
# Input-path false-positive corpus (Task 9): NON-multipart legitimate requests
# that MUST NOT block at the shipped defaults (max_input_vars=2000,
# max_input_nesting_depth=64, max_request_headers=200). These are urlencoded
# bodies / header lists / query strings, NOT multipart, so they live under
# input/ and are driven by a separate loop (never the *.bin multipart loop).
# Shape only -- no payloads (design §9).
IN="$OUT/input"; mkdir -p "$IN"

# A. A large legitimate urlencoded form: 1500 fields, well under max_input_vars
#    (2000) and above stock PHP max_input_vars (1000) so it exercises a raised-
#    cap real form. One line, '&'-joined `field_N=value_N`.
f="$IN/large_form.urlencoded"; : > "$f"
i=0; while [ "$i" -lt 1500 ]; do
  [ "$i" -gt 0 ] && printf '&' >> "$f"
  printf 'field_%s=value_%s' "$i" "$i" >> "$f"
  i=$((i+1))
done

# B. A legitimately nested urlencoded form (survey answers). Depth stays <= 6
#    brackets, far under max_input_nesting_depth (64). ~40 fields.
f="$IN/nested_form.urlencoded"; : > "$f"
first=1
emit() { [ "$first" -eq 1 ] || printf '&' >> "$f"; first=0; printf '%s' "$1" >> "$f"; }
s=0; while [ "$s" -lt 4 ]; do
  q=0; while [ "$q" -lt 5 ]; do
    # answers[section_s][q_q][choice] -> 3 brackets (depth 3)
    emit "answers[section_$s][q_$q][choice]=opt_$q"
    q=$((q+1))
  done
  s=$((s+1))
done
# a few deeper-but-legitimate matrix fields: 5 brackets (depth 5 <= 6)
d=0; while [ "$d" -lt 6 ]; do
  emit "matrix[a][b][c][d][row_$d]=on"
  d=$((d+1))
done

# C. ~50 ordinary request headers, far under max_request_headers (200).
#    One "Name: value" per line, LF-terminated (the harness reads each line and
#    passes it to curl / turns it into an HTTP_* server var; a trailing CR would
#    corrupt the header, so these are plain LF, NOT the CRLF `cr` helper).
lf() { printf '%s\n' "$1"; }
f="$IN/ordinary_headers.txt"; : > "$f"
{ lf 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
  lf 'Accept-Language: en-US,en;q=0.9'
  lf 'Accept-Encoding: gzip, deflate, br'
  lf 'Cache-Control: no-cache'
  lf 'DNT: 1'
  lf 'Upgrade-Insecure-Requests: 1'; } >> "$f"
i=0; while [ "$i" -lt 44 ]; do lf "X-App-Header-$i: value-$i"; i=$((i+1)); done >> "$f"

# D. Query strings that legitimately contain '-' in normal positions. Each must
#    NOT trip the cgi_arg_injection virtual patch (every one carries a literal
#    '=' and none starts with '-'). One query string per line, LF-terminated.
f="$IN/safe_queries.txt"; : > "$f"
{ lf 'sort=-price'
  lf 'q=a-b-c'
  lf 'filter=a-b&order=-date'
  lf 'range=10-20&unit=px-em'
  lf 'slug=my-blog-post&utm-source=news-letter'; } >> "$f"

echo "wrote corpus to $OUT:"
ls -l "$OUT"/*.bin
echo "wrote input corpus to $IN:"
ls -l "$IN"
