//! Streaming multipart/form-data analyzer.
//!
//! Fed request-body bytes as they arrive. It is a resumable byte state machine
//! that holds only small fixed counters, a bounded partial header line, and a
//! delimiter-match cursor. It never buffers part bodies, so limits on part and
//! header counts can be enforced before the backend allocates per-part memory.
//!
//! Event sequence is independent of how the input is chunked. In particular
//! `PartData` is emitted once per part (total body length) just before
//! `PartEnd`; callers that need running byte totals can count chunk lengths.
//!
//! Strictness (deliberate, for a WAF): bare-LF header lines, obsolete header
//! line folding, non `form-data` dispositions, duplicate/conflicting
//! `Content-Disposition` data, garbage after a delimiter, a repeated boundary
//! after the closing one, and truncated bodies (via `finish`) are all
//! `MalformedBody`.

/// Maximum accepted header line length (bytes, excluding CRLF).
const MAX_LINE: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    PartStart,
    PartHeader { name_len: usize, value_len: usize },
    PartHeadersEnd,
    FileStart { filename_len: usize },
    FieldStart { name_len: usize },
    PartData { len: u64 },
    PartEnd,
    BodyEnd,
}

/// The body violates multipart framing or carries conflicting metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedBody(pub &'static str);

impl std::fmt::Display for MalformedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed multipart body: {}", self.0)
    }
}
impl std::error::Error for MalformedBody {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Scanning for the delimiter; preamble data is not reported.
    Scan { preamble: bool },
    /// Just after a delimiter: expecting `--` or optional padding + CRLF.
    AfterDelim,
    AfterDelimDash,
    Pad,
    PadLf,
    Headers,
    /// After the closing delimiter; only duplicate boundaries are checked.
    Epilogue,
    Failed(&'static str),
}

#[derive(Debug)]
pub struct MultipartState {
    /// `\r\n--` + boundary
    pat: Vec<u8>,
    /// KMP failure table for `pat`.
    fail: Vec<usize>,
    phase: Phase,
    /// Delimiter bytes matched so far.
    m: usize,
    data_len: u64,
    line: Vec<u8>,
    parts: u64,
    files: u64,
    headers: u32,
    saw_disposition: bool,
    closed: bool,
}

impl MultipartState {
    pub fn new(boundary: &[u8]) -> Self {
        let mut pat = b"\r\n--".to_vec();
        pat.extend_from_slice(boundary);
        let mut fail = vec![0usize; pat.len()];
        let mut k = 0;
        for i in 1..pat.len() {
            while k > 0 && pat[i] != pat[k] {
                k = fail[k - 1];
            }
            if pat[i] == pat[k] {
                k += 1;
            }
            fail[i] = k;
        }
        let phase = if boundary.is_empty() {
            Phase::Failed("empty boundary")
        } else {
            Phase::Scan { preamble: true }
        };
        MultipartState {
            pat,
            fail,
            phase,
            // The body begins as if preceded by the CRLF of a delimiter.
            m: 2,
            data_len: 0,
            line: Vec::new(),
            parts: 0,
            files: 0,
            headers: 0,
            saw_disposition: false,
            closed: false,
        }
    }

    pub fn parts(&self) -> u64 {
        self.parts
    }
    pub fn files(&self) -> u64 {
        self.files
    }
    pub fn headers_in_current_part(&self) -> u32 {
        self.headers
    }

    /// Signal end of input. Errors if the closing boundary was never seen.
    pub fn finish(&mut self) -> Result<Vec<Event>, MalformedBody> {
        if let Phase::Failed(m) = self.phase {
            return Err(MalformedBody(m));
        }
        if self.closed {
            Ok(Vec::new())
        } else {
            Err(self.fail_with("truncated body: no closing boundary"))
        }
    }

    fn fail_with(&mut self, msg: &'static str) -> MalformedBody {
        self.phase = Phase::Failed(msg);
        MalformedBody(msg)
    }

    fn step(&self, mut m: usize, c: u8) -> usize {
        loop {
            if self.pat[m] == c {
                return m + 1;
            }
            if m == 0 {
                return 0;
            }
            m = self.fail[m - 1];
        }
    }

    pub fn feed(&mut self, chunk: &[u8]) -> Result<Vec<Event>, MalformedBody> {
        let mut ev = Vec::new();
        let mut i = 0;
        while i < chunk.len() {
            match self.phase {
                Phase::Failed(m) => return Err(MalformedBody(m)),
                Phase::Scan { preamble } => {
                    // Fast skip: with no partial match, jump to the next CR.
                    if self.m == 0 {
                        match chunk[i..].iter().position(|&b| b == b'\r') {
                            None => {
                                if !preamble {
                                    self.data_len += (chunk.len() - i) as u64;
                                }
                                i = chunk.len();
                                continue;
                            }
                            Some(p) => {
                                if !preamble {
                                    self.data_len += p as u64;
                                }
                                i += p;
                            }
                        }
                    }
                    let c = chunk[i];
                    i += 1;
                    let nm = self.step(self.m, c);
                    if !preamble {
                        // Bytes held as a possible delimiter that turned out
                        // to be body data.
                        self.data_len += (self.m + 1 - nm) as u64;
                    }
                    self.m = nm;
                    if self.m == self.pat.len() {
                        if !preamble {
                            ev.push(Event::PartData { len: self.data_len });
                            ev.push(Event::PartEnd);
                        }
                        self.data_len = 0;
                        self.m = 0;
                        self.phase = Phase::AfterDelim;
                    }
                }
                Phase::Epilogue => {
                    let c = chunk[i];
                    i += 1;
                    self.m = self.step(self.m, c);
                    if self.m == self.pat.len() {
                        return Err(self.fail_with("duplicate boundary after closing boundary"));
                    }
                }
                Phase::AfterDelim => {
                    let c = chunk[i];
                    i += 1;
                    match c {
                        b'-' => self.phase = Phase::AfterDelimDash,
                        b' ' | b'\t' => self.phase = Phase::Pad,
                        b'\r' => self.phase = Phase::PadLf,
                        _ => return Err(self.fail_with("bad boundary: garbage after delimiter")),
                    }
                }
                Phase::AfterDelimDash => {
                    let c = chunk[i];
                    i += 1;
                    if c != b'-' {
                        return Err(self.fail_with("bad boundary: garbage after delimiter"));
                    }
                    self.closed = true;
                    self.m = 0;
                    self.phase = Phase::Epilogue;
                    ev.push(Event::BodyEnd);
                }
                Phase::Pad => {
                    let c = chunk[i];
                    i += 1;
                    match c {
                        b' ' | b'\t' => {}
                        b'\r' => self.phase = Phase::PadLf,
                        _ => return Err(self.fail_with("bad boundary: garbage after delimiter")),
                    }
                }
                Phase::PadLf => {
                    let c = chunk[i];
                    i += 1;
                    if c != b'\n' {
                        return Err(self.fail_with("bad boundary: delimiter not followed by CRLF"));
                    }
                    self.parts += 1;
                    self.headers = 0;
                    self.saw_disposition = false;
                    self.line.clear();
                    self.phase = Phase::Headers;
                    ev.push(Event::PartStart);
                }
                Phase::Headers => {
                    let c = chunk[i];
                    i += 1;
                    if c != b'\n' {
                        if self.line.len() >= MAX_LINE {
                            return Err(self.fail_with("header line too long"));
                        }
                        self.line.push(c);
                        continue;
                    }
                    let line = std::mem::take(&mut self.line);
                    let r = self.header_line(&line, &mut ev);
                    self.line = line;
                    self.line.clear();
                    r?;
                }
            }
        }
        Ok(ev)
    }

    fn header_line(&mut self, line: &[u8], ev: &mut Vec<Event>) -> Result<(), MalformedBody> {
        let Some((&b'\r', line)) = line.split_last() else {
            return Err(self.fail_with("header line not terminated by CRLF"));
        };
        if line.is_empty() {
            if !self.saw_disposition {
                return Err(self.fail_with("part without Content-Disposition"));
            }
            ev.push(Event::PartHeadersEnd);
            self.m = 0;
            self.data_len = 0;
            self.phase = Phase::Scan { preamble: false };
            return Ok(());
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(self.fail_with("obsolete header line folding"));
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err(self.fail_with("header without colon"));
        };
        let name = &line[..colon];
        if name.is_empty() || name.iter().any(|&b| b <= b' ' || b == 0x7f) {
            return Err(self.fail_with("invalid header name"));
        }
        let value = trim_ws(&line[colon + 1..]);
        self.headers = self.headers.saturating_add(1);
        ev.push(Event::PartHeader { name_len: name.len(), value_len: value.len() });
        if name.eq_ignore_ascii_case(b"content-disposition") {
            if self.saw_disposition {
                return Err(self.fail_with("conflicting Content-Disposition headers"));
            }
            self.saw_disposition = true;
            match parse_disposition(value) {
                Err(m) => return Err(self.fail_with(m)),
                Ok((_, Some(filename_len))) => {
                    self.files += 1;
                    ev.push(Event::FileStart { filename_len });
                }
                Ok((name_len, None)) => ev.push(Event::FieldStart { name_len }),
            }
        }
        Ok(())
    }
}

fn trim_ws(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

/// Parse `form-data; name="x"; filename="y"` -> (name_len, filename_len).
fn parse_disposition(v: &[u8]) -> Result<(usize, Option<usize>), &'static str> {
    let mut i = 0;
    while i < v.len() && v[i] != b';' {
        i += 1;
    }
    if !trim_ws(&v[..i]).eq_ignore_ascii_case(b"form-data") {
        return Err("Content-Disposition is not form-data");
    }
    let (mut name, mut filename): (Option<usize>, Option<usize>) = (None, None);
    while i < v.len() {
        i += 1; // skip ';'
        while i < v.len() && (v[i] == b' ' || v[i] == b'\t') {
            i += 1;
        }
        let ks = i;
        while i < v.len() && v[i] != b'=' && v[i] != b';' {
            i += 1;
        }
        let key = trim_ws(&v[ks..i]);
        let mut vlen = 0;
        if i < v.len() && v[i] == b'=' {
            i += 1;
            while i < v.len() && (v[i] == b' ' || v[i] == b'\t') {
                i += 1;
            }
            if i < v.len() && v[i] == b'"' {
                i += 1;
                loop {
                    match v.get(i) {
                        None => return Err("unterminated quoted parameter"),
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') if i + 1 < v.len() => {
                            i += 2;
                            vlen += 1;
                        }
                        Some(_) => {
                            i += 1;
                            vlen += 1;
                        }
                    }
                }
                while i < v.len() && v[i] != b';' {
                    i += 1;
                }
            } else {
                let vs = i;
                while i < v.len() && v[i] != b';' {
                    i += 1;
                }
                vlen = trim_ws(&v[vs..i]).len();
            }
        }
        let slot = if key.eq_ignore_ascii_case(b"name") {
            &mut name
        } else if key.eq_ignore_ascii_case(b"filename") {
            &mut filename
        } else {
            continue;
        };
        if slot.is_some() {
            return Err("conflicting Content-Disposition parameters");
        }
        *slot = Some(vlen);
    }
    Ok((name.unwrap_or(0), filename))
}
