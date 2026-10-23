//! Reconstruct a minimal, well-formed multipart byte stream from PHP's
//! already-parsed `MULTIPART_EVENT_*` callbacks, so the pure-Rust core (which
//! is a streaming *byte* analyzer) can count parts/files/headers and enforce
//! its limits.
//!
//! We do NOT get the raw request bytes in the rfc1867 callback — PHP hands us
//! structured events. So we synthesise the framing the core expects, using a
//! fixed internal boundary (never the request's real one; the core only needs
//! the boundary we pass to `request_begin` to match the frames we feed).
//!
//! This module is pure Rust (no PHP, no `unsafe`) so it can be unit-tested on
//! the host against the real core via its C ABI. The PHP glue in `rfc1867.rs`
//! calls these builders and feeds the results to `howdah_feed`.
//!
//! BEST-EFFORT vs EXACT (important): PHP's rfc1867 callback only hands us the
//! `Content-Disposition` name/filename — not a part's other headers (e.g.
//! `Content-Type`) nor their raw bytes. So we reconstruct a single
//! `Content-Disposition` header per part, which means the glue-level
//! `max_part_headers` / `max_part_header_bytes` checks see FEWER header bytes
//! than PHP actually parsed: they are a best-effort lower bound here. The
//! COUNT-based critical rules — `max_parts` and `max_files` — ARE exact (one
//! reconstructed part per `*_START`/`FORMDATA` event), and together with
//! `max_filename_bytes` / `max_field_name_bytes` (whose lengths we preserve)
//! are the primary, precise PHP2Shell defense.

/// A fixed, long, unlikely-in-user-data internal boundary. The core builds its
/// delimiter from exactly this; a collision would merely split one part in two
/// (never a missed count the wrong way for the DoS defence), and is astronomically
/// unlikely for this 24-byte token.
pub const INTERNAL_BOUNDARY: &[u8] = b"HdHbndYy7Qk3Zx1Lp9Wf2Rs";

/// Builds the synthetic frames, tracking whether a part was already emitted
/// (so the first part omits the leading CRLF the core's state machine assumes).
#[derive(Debug, Default)]
pub struct Feeder {
    started: bool,
}

impl Feeder {
    pub fn new() -> Self {
        Feeder { started: false }
    }

    /// Part separator: the core's delimiter is `\r\n--<boundary>`. For the first
    /// part the leading `\r\n` is implied by the initial state, so emit only
    /// `--<boundary>\r\n`; later parts close the previous part's data with `\r\n`.
    fn sep(&mut self) -> Vec<u8> {
        let mut v = Vec::new();
        if self.started {
            v.extend_from_slice(b"\r\n--");
        } else {
            v.extend_from_slice(b"--");
            self.started = true;
        }
        v.extend_from_slice(INTERNAL_BOUNDARY);
        v.extend_from_slice(b"\r\n");
        v
    }

    /// Frame header for a file part: `name` and `filename` lengths are preserved
    /// so the core's filename/field-name limits see the real sizes.
    pub fn file_part_header(&mut self, name: &[u8], filename: &[u8]) -> Vec<u8> {
        let mut v = self.sep();
        v.extend_from_slice(b"Content-Disposition: form-data; name=\"");
        push_quoted(&mut v, name);
        v.extend_from_slice(b"\"; filename=\"");
        push_quoted(&mut v, filename);
        v.extend_from_slice(b"\"\r\n\r\n");
        v
    }

    /// Frame header for a non-file form field.
    pub fn field_header(&mut self, name: &[u8]) -> Vec<u8> {
        let mut v = self.sep();
        v.extend_from_slice(b"Content-Disposition: form-data; name=\"");
        push_quoted(&mut v, name);
        v.extend_from_slice(b"\"\r\n\r\n");
        v
    }

    /// The closing delimiter, ending the body.
    pub fn closing(&mut self) -> Vec<u8> {
        let mut v = Vec::new();
        if self.started {
            v.extend_from_slice(b"\r\n--");
        } else {
            v.extend_from_slice(b"--");
            self.started = true;
        }
        v.extend_from_slice(INTERNAL_BOUNDARY);
        v.extend_from_slice(b"--\r\n");
        v
    }
}

/// Append `s` into a Content-Disposition quoted-string value, preserving its
/// logical length as the core's parser counts it (`\x` counts as one char).
/// `"` and `\` are backslash-escaped; CR/LF/NUL (which cannot appear in a PHP
/// field name/filename and would break framing) become `_`.
fn push_quoted(out: &mut Vec<u8>, s: &[u8]) {
    for &b in s {
        match b {
            b'"' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            b'\r' | b'\n' | 0 => out.push(b'_'),
            _ => out.push(b),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use howdah_core::ffi::{
        howdah_feed, howdah_free, howdah_init, howdah_request_begin, howdah_request_end,
        howdah_take_log_line, howdah_free_str, HOWDAH_ALLOW, HOWDAH_BLOCK,
    };
    use std::ffi::{c_char, CStr};

    /// Drive the real core through its C ABI exactly as the PHP glue will:
    /// request_begin with the internal boundary, feed synthesised frames, end.
    struct Harness {
        ctx: *mut howdah_core::ffi::howdah_ctx,
        f: Feeder,
    }
    impl Harness {
        fn new(toml: &str) -> Self {
            let ctx = unsafe { howdah_init(toml.as_ptr() as *const c_char, toml.len()) };
            unsafe {
                howdah_request_begin(
                    ctx,
                    INTERNAL_BOUNDARY.as_ptr() as *const c_char,
                    INTERNAL_BOUNDARY.len(),
                    std::ptr::null(),
                )
            };
            Harness { ctx, f: Feeder::new() }
        }
        fn feed(&self, bytes: &[u8]) -> i32 {
            unsafe { howdah_feed(self.ctx, bytes.as_ptr() as *const c_char, bytes.len()) }
        }
        fn file(&mut self, name: &[u8], filename: &[u8]) -> i32 {
            let b = self.f.file_part_header(name, filename);
            self.feed(&b)
        }
        fn field(&mut self, name: &[u8], value: &[u8]) -> i32 {
            let h = self.f.field_header(name);
            self.feed(&h);
            self.feed(value)
        }
        fn end(&mut self) -> i32 {
            let c = self.f.closing();
            self.feed(&c);
            unsafe { howdah_request_end(self.ctx) }
        }
        fn log(&self) -> Option<String> {
            unsafe {
                let p = howdah_take_log_line(self.ctx);
                if p.is_null() {
                    return None;
                }
                let s = CStr::from_ptr(p).to_string_lossy().into_owned();
                howdah_free_str(p);
                Some(s)
            }
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            unsafe { howdah_free(self.ctx) };
        }
    }

    #[test]
    fn clean_small_form_is_allowed() {
        let mut h = Harness::new("");
        assert_eq!(h.field(b"username", b"alice"), HOWDAH_ALLOW);
        assert_eq!(h.file(b"avatar", b"a.png"), HOWDAH_ALLOW);
        assert_eq!(h.end(), HOWDAH_ALLOW);
        assert!(h.log().is_none());
    }

    #[test]
    fn many_file_parts_block_on_max_files() {
        // The PHP2Shell shape: lots of (here empty) file parts.
        let mut h = Harness::new("[limits]\nmax_parts = 100000\nmax_files = 5\n");
        let mut worst = HOWDAH_ALLOW;
        for i in 0..50u32 {
            let fname = format!("f{i}.bin");
            worst = worst.max(h.file(format!("file{i}").as_bytes(), fname.as_bytes()));
        }
        let end = h.end();
        assert_eq!(worst.max(end), HOWDAH_BLOCK, "flood of file parts must block");
        let line = h.log().expect("a block must produce a log line");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["action"], "block");
        assert_eq!(v["rule"], "max_files");
        assert!(v["request_id"].as_str().map(|s| !s.is_empty()).unwrap_or(false));
    }

    #[test]
    fn many_parts_block_on_max_parts() {
        let mut h = Harness::new("[limits]\nmax_parts = 4\n");
        let mut worst = HOWDAH_ALLOW;
        for i in 0..10u32 {
            worst = worst.max(h.field(format!("field{i}").as_bytes(), b"x"));
        }
        assert_eq!(worst.max(h.end()), HOWDAH_BLOCK);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&h.log().unwrap()).unwrap()["rule"],
            "max_parts"
        );
    }

    #[test]
    fn long_filename_blocks_and_preserves_length() {
        // max_filename_bytes default is 512; feed a 600-char filename.
        let mut h = Harness::new("");
        let long = "a".repeat(600);
        h.file(b"f", long.as_bytes());
        assert_eq!(h.end(), HOWDAH_BLOCK);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&h.log().unwrap()).unwrap()["rule"],
            "max_filename_len"
        );
    }

    #[test]
    fn quotes_in_names_do_not_break_framing() {
        // A filename containing a quote must stay one part, still allowed.
        let mut h = Harness::new("");
        assert_eq!(h.file(b"f", br#"ev"il.png"#), HOWDAH_ALLOW);
        assert_eq!(h.field(b"na\"me", b"v"), HOWDAH_ALLOW);
        assert_eq!(h.end(), HOWDAH_ALLOW);
        assert!(h.log().is_none(), "well-formed after escaping: no malformed hit");
    }

    #[test]
    fn empty_body_is_clean() {
        let mut h = Harness::new("");
        assert_eq!(h.end(), HOWDAH_ALLOW);
        assert!(h.log().is_none());
    }
}
