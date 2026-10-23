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

echo "wrote corpus to $OUT:"
ls -l "$OUT"/*.bin
