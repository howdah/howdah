//! CVE-2026-129289 (FastCGI request smuggling through an unread body):
//! recognise FastCGI record framing carrying a dangerous PARAMS name inside an
//! HTTP request body. A request body has no legitimate reason to contain a
//! FastCGI record stream, so the signature is two co-located facts:
//!
//! 1. a record header: version `0x01`, type in {1 BEGIN_REQUEST, 4 PARAMS,
//!    5 STDIN}, reserved byte (offset 7) `0x00`; and
//! 2. within [`WINDOW`] bytes after it, a length-prefixed name-value NAME from
//!    {`PHP_ADMIN_VALUE`, `PHP_VALUE`, `SCRIPT_FILENAME`, `DOCUMENT_ROOT`}:
//!    `nameLen` byte equal to the name's length, a value-length field
//!    (1 byte `< 0x80`, or 4 bytes with the high bit set), then the name.
//!
//! Streaming and bounded: only a small tail is kept between chunks. Values are
//! never retained beyond that tail and never reported.

/// How far after a record header the NV name may sit.
const WINDOW: usize = 512;
/// Bytes carried between chunks (header + window + the longest name + framing).
const TAIL: usize = WINDOW + 8 + 32;

const NAMES: [&[u8]; 4] = [b"PHP_ADMIN_VALUE", b"PHP_VALUE", b"SCRIPT_FILENAME", b"DOCUMENT_ROOT"];

#[derive(Debug, Default, Clone)]
pub struct FcgiScan {
    buf: Vec<u8>,
    hit: bool,
}

impl FcgiScan {
    pub fn new() -> Self {
        Self::default()
    }

    /// Has the signature been seen? Sticky.
    pub fn hit(&self) -> bool {
        self.hit
    }

    /// Append bytes that are eligible for scanning (caller excludes file-part
    /// data). Call [`FcgiScan::scan`] after a batch of pushes.
    pub fn push(&mut self, data: &[u8]) {
        if self.hit || data.is_empty() {
            return;
        }
        self.buf.extend_from_slice(data);
    }

    /// Search the pending bytes, then keep only the tail for the next chunk.
    pub fn scan(&mut self) {
        if self.hit {
            self.buf = Vec::new();
            return;
        }
        if find(&self.buf) {
            self.hit = true;
            self.buf = Vec::new();
            return;
        }
        if self.buf.len() > TAIL {
            let cut = self.buf.len() - TAIL;
            self.buf.drain(..cut);
        }
    }

    /// Convenience: push + scan one slice.
    pub fn feed(&mut self, data: &[u8]) {
        self.push(data);
        self.scan();
    }
}

fn is_header(b: &[u8], j: usize) -> bool {
    j + 8 <= b.len() && b[j] == 1 && matches!(b[j + 1], 1 | 4 | 5) && b[j + 7] == 0
}

fn find(b: &[u8]) -> bool {
    for (i, &c) in b.iter().enumerate() {
        if !matches!(c, b'P' | b'S' | b'D') {
            continue;
        }
        for name in NAMES {
            let rest = &b[i..];
            if rest.len() < name.len() || &rest[..name.len()] != name {
                continue;
            }
            let l = name.len() as u8;
            // Where the nameLen byte sits: before a 1-byte or a 4-byte valueLen.
            let one = i >= 2 && b[i - 2] == l && b[i - 1] < 0x80;
            let four = i >= 5 && b[i - 5] == l && b[i - 4] & 0x80 != 0;
            if !(one || four) {
                continue;
            }
            // A record header in the WINDOW bytes before the nameLen byte.
            let nl = if one { i - 2 } else { i - 5 };
            let lo = nl.saturating_sub(WINDOW);
            if (lo..nl).any(|j| is_header(b, j)) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PARAMS record carrying one NV pair, framed like a FastCGI client.
    fn params(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut c = vec![name.len() as u8, value.len() as u8];
        c.extend_from_slice(name);
        c.extend_from_slice(value);
        let mut r = vec![1, 4, 0, 1, (c.len() >> 8) as u8, c.len() as u8, 0, 0];
        r.extend_from_slice(&c);
        r
    }

    #[test]
    fn detects_each_name_in_a_params_record() {
        for n in NAMES {
            let mut s = FcgiScan::new();
            s.feed(&params(n, b"auto_prepend_file=php://input"));
            assert!(s.hit(), "{}", String::from_utf8_lossy(n));
        }
    }

    #[test]
    fn detects_after_other_params_and_four_byte_value_len() {
        let mut c = params(b"REQUEST_METHOD", b"POST");
        c.extend_from_slice(&[15, 0x80, 0, 0, 3]);
        c.extend_from_slice(b"PHP_ADMIN_VALUE");
        c.extend_from_slice(b"abc");
        let mut s = FcgiScan::new();
        s.feed(&c);
        assert!(s.hit());
    }

    #[test]
    fn detects_across_arbitrary_chunk_splits() {
        let mut body = b"hello world ".to_vec();
        body.extend(params(b"PHP_VALUE", b"x=1"));
        for step in [1usize, 2, 3, 7, 13] {
            let mut s = FcgiScan::new();
            for ch in body.chunks(step) {
                s.feed(ch);
            }
            assert!(s.hit(), "step {step}");
        }
    }

    #[test]
    fn benign_corpus_is_clean() {
        let mut binary = vec![0u8; 0];
        for i in 0..70000u32 {
            binary.push((i.wrapping_mul(2654435761) >> 13) as u8);
        }
        let corpus: Vec<Vec<u8>> = vec![
            binary,
            vec![1, 4, 0, 0, 0, 0, 0, 0, 1, 4, 5, 1, 1, 1, 4, 4],
            b"a=1&b=PHP_VALUE&c=SCRIPT_FILENAME&d=DOCUMENT_ROOT".to_vec(),
            br#"{"PHP_ADMIN_VALUE":"x","SCRIPT_FILENAME":"/a.php"}"#.to_vec(),
            b"<?xml version=\"1.0\"?><DOCUMENT_ROOT>x</DOCUMENT_ROOT>".to_vec(),
            b"\x01\x04\x00\x01\x00\x08\x00\x00 and plain text only".to_vec(),
            b"export PHP_VALUE=1; SCRIPT_FILENAME is a CGI var".to_vec(),
            // a NV name with a header but wrong length prefix
            {
                let mut v = vec![1, 4, 0, 1, 0, 20, 0, 0, 9, 1];
                v.extend_from_slice(b"PHP_ADMIN_VALUE");
                v
            },
            // name with right framing but NO record header nearby
            {
                let mut v = vec![15, 3];
                v.extend_from_slice(b"PHP_ADMIN_VALUE");
                v
            },
        ];
        for b in corpus {
            let mut s = FcgiScan::new();
            s.feed(&b);
            assert!(!s.hit());
        }
    }
}
