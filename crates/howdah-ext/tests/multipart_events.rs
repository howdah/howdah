//! Drive the core through its C ABI exactly as the PHP glue does for a
//! multipart request: one `howdah_part` per `FORMDATA`/`FILE_START` event, one
//! `howdah_part_data` per `FORMDATA` value / `FILE_DATA` chunk, then
//! `howdah_request_end`. No request bytes are reconstructed or parsed here:
//! part data is attacker-controlled and must never be able to influence how
//! parts are counted.
//!
//! The first test is the regression for the parser-wedge bypass: before the
//! structured API existed the glue synthesised multipart framing with a fixed
//! public boundary and fed part DATA through the same byte parser, so a data
//! chunk containing that boundary wedged the parser into its sticky Failed
//! state and every later part went uncounted (and unsuppressed).
use howdah_core::ffi::{
    howdah_feed, howdah_free, howdah_free_str, howdah_init, howdah_part, howdah_part_data,
    howdah_request_begin, howdah_request_end, howdah_take_log_line, HOWDAH_ALLOW, HOWDAH_BLOCK,
    HOWDAH_LOG, HOWDAH_PART_FIELD, HOWDAH_PART_FILE,
};
use std::ffi::{c_char, CStr};

/// The boundary the old glue used; kept here only as the historical poison.
const OLD_INTERNAL_BOUNDARY: &[u8] = b"HdHbndYy7Qk3Zx1Lp9Wf2Rs";

struct Req {
    ctx: *mut howdah_core::ffi::howdah_ctx,
    worst: i32,
}

impl Req {
    fn new(toml: &str) -> Self {
        let ctx = unsafe { howdah_init(toml.as_ptr() as *const c_char, toml.len()) };
        // No boundary: the glue has no bytes to feed, only events.
        unsafe { howdah_request_begin(ctx, std::ptr::null(), 0, std::ptr::null()) };
        Req { ctx, worst: HOWDAH_ALLOW }
    }
    fn note(&mut self, a: i32) -> i32 {
        self.worst = self.worst.max(a);
        a
    }
    fn file(&mut self, name: &[u8], filename: &[u8]) -> i32 {
        let a = unsafe { howdah_part(self.ctx, HOWDAH_PART_FILE, name.len(), filename.len()) };
        self.note(a)
    }
    fn field(&mut self, name: &[u8], value: &[u8]) -> i32 {
        let a = unsafe { howdah_part(self.ctx, HOWDAH_PART_FIELD, name.len(), 0) };
        self.note(a);
        self.data(value)
    }
    fn data(&mut self, bytes: &[u8]) -> i32 {
        let a = unsafe { howdah_part_data(self.ctx, bytes.len()) };
        self.note(a)
    }
    fn end(&mut self) -> i32 {
        let a = unsafe { howdah_request_end(self.ctx) };
        self.note(a)
    }
    fn log(&self) -> Option<serde_json::Value> {
        unsafe {
            let p = howdah_take_log_line(self.ctx);
            if p.is_null() {
                return None;
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            howdah_free_str(p);
            Some(serde_json::from_str(&s).expect("log line is JSON"))
        }
    }
}

impl Drop for Req {
    fn drop(&mut self) {
        unsafe { howdah_free(self.ctx) };
    }
}

fn poison() -> Vec<u8> {
    let mut p = b"\r\n--".to_vec();
    p.extend_from_slice(OLD_INTERNAL_BOUNDARY);
    p.extend_from_slice(b"zz");
    p
}

#[test]
fn file_flood_is_blocked_even_when_earlier_part_data_carries_the_old_boundary() {
    // Shipped default mode. One ordinary file whose DATA is the poison, then
    // the PHP2Shell shape.
    let mut r = Req::new("mode = \"detect\"");
    assert_eq!(r.file(b"avatar", b"a.png"), HOWDAH_ALLOW);
    r.data(&poison());
    for i in 0..1000 {
        r.file(format!("f{i}").as_bytes(), b"x.bin");
    }
    r.end();
    assert_eq!(r.worst, HOWDAH_BLOCK, "a flood after poisoned data must still block");
    let v = r.log().expect("block log line");
    assert_eq!(v["action"], "block");
    assert_eq!(v["rule"], "max_files");
}

#[test]
fn field_flood_is_blocked_when_a_field_value_carries_the_old_boundary() {
    let mut r = Req::new("mode = \"detect\"");
    assert_eq!(r.field(b"note", &poison()), HOWDAH_ALLOW);
    for i in 0..3000 {
        r.field(format!("p{i}").as_bytes(), b"");
    }
    r.end();
    assert_eq!(r.worst, HOWDAH_BLOCK);
    assert_eq!(r.log().unwrap()["rule"], "max_parts");
}

#[test]
fn part_data_never_produces_a_malformed_multipart_event() {
    // Structured requests have no framing to get wrong: data of any shape is
    // just a byte count, and a request that ends is not "truncated".
    let mut r = Req::new("mode = \"block\"");
    assert_eq!(r.field(b"a", &poison()), HOWDAH_ALLOW);
    assert_eq!(r.data(b"--\r\n\r\n--b--\r\n--b\r\n"), HOWDAH_ALLOW);
    assert_eq!(r.end(), HOWDAH_ALLOW);
    assert!(r.log().is_none(), "no malformed_multipart line for structured input");
}

#[test]
fn clean_small_form_is_allowed() {
    let mut r = Req::new("");
    assert_eq!(r.field(b"username", b"alice"), HOWDAH_ALLOW);
    assert_eq!(r.file(b"avatar", b"a.png"), HOWDAH_ALLOW);
    assert_eq!(r.data(&[0u8; 4096]), HOWDAH_ALLOW);
    assert_eq!(r.end(), HOWDAH_ALLOW);
    assert!(r.log().is_none());
}

#[test]
fn empty_body_is_clean() {
    let mut r = Req::new("");
    assert_eq!(r.end(), HOWDAH_ALLOW);
    assert!(r.log().is_none());
}

#[test]
fn file_flood_blocks_on_max_files_at_the_part_that_crosses_the_limit() {
    let mut r = Req::new("[limits]\nmax_parts = 100000\nmax_files = 5\n");
    for i in 0..5 {
        assert_eq!(r.file(format!("f{i}").as_bytes(), b"f.bin"), HOWDAH_ALLOW, "file {i}");
    }
    // The sixth file is the one PHP must not allocate: Block is returned for it.
    assert_eq!(r.file(b"f5", b"f.bin"), HOWDAH_BLOCK);
    assert_eq!(r.end(), HOWDAH_BLOCK);
    assert_eq!(r.log().unwrap()["rule"], "max_files");
}

#[test]
fn long_filename_and_field_name_block_with_their_real_lengths() {
    let mut r = Req::new("");
    r.file(b"f", "a".repeat(600).as_bytes()); // default max_filename_bytes = 512
    assert_eq!(r.end(), HOWDAH_BLOCK);
    assert_eq!(r.log().unwrap()["rule"], "max_filename_len");

    let mut r = Req::new("");
    r.field("n".repeat(2000).as_bytes(), b"v"); // default max_field_name_bytes = 1024
    assert_eq!(r.end(), HOWDAH_BLOCK);
    assert_eq!(r.log().unwrap()["rule"], "max_field_name_len");
}

#[test]
fn critical_count_rule_downgraded_to_detect_logs_but_does_not_block() {
    let mut r = Req::new("mode = \"block\"\n[limits]\nmax_files = 2\n[rules]\nmax_files = \"detect\"\n");
    for i in 0..10 {
        r.file(format!("f{i}").as_bytes(), b"f.bin");
    }
    assert_eq!(r.end(), HOWDAH_LOG);
    let v = r.log().unwrap();
    assert_eq!(v["action"], "log");
    assert_eq!(v["rule"], "max_files");
}

#[test]
fn parse_memory_budget_counts_part_data_bytes() {
    let mut r = Req::new("[limits]\nmax_parse_memory_bytes = 1000\n");
    r.file(b"f", b"big.bin");
    assert_eq!(r.data(&[0u8; 600]), HOWDAH_ALLOW);
    assert_eq!(r.data(&[0u8; 600]), HOWDAH_BLOCK);
    assert_eq!(r.log().unwrap()["rule"], "parse_memory_budget");
}

#[test]
fn a_wedged_byte_parser_in_the_same_request_cannot_stop_structured_counting() {
    // Defence in depth: even if some caller fed raw bytes that failed to parse,
    // the structured counters must keep working.
    let mut r = Req::new("mode = \"detect\"\n[limits]\nmax_files = 3\n");
    let bad = b"--b\r\ngarbage without colon\r\n\r\n";
    // With no boundary every byte feed is a parse failure (as before).
    assert_eq!(unsafe { howdah_feed(r.ctx, bad.as_ptr() as *const c_char, bad.len()) }, HOWDAH_LOG);
    for i in 0..10 {
        r.file(format!("f{i}").as_bytes(), b"f.bin");
    }
    assert_eq!(r.worst, HOWDAH_BLOCK);
    assert_eq!(r.log().unwrap()["rule"], "max_files");
}

#[test]
fn null_ctx_is_allow() {
    unsafe {
        assert_eq!(howdah_part(std::ptr::null_mut(), HOWDAH_PART_FILE, 3, 3), HOWDAH_ALLOW);
        assert_eq!(howdah_part_data(std::ptr::null_mut(), 99), HOWDAH_ALLOW);
    }
}
