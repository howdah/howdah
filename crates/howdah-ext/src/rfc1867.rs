//! The chained multipart callback — the heart of the extension.
//!
//! For every `MULTIPART_EVENT_*` we (1) reconstruct the equivalent framing and
//! feed it to the core through its C ABI, (2) ALWAYS chain to the prior callback
//! so `session.upload_progress` and any other consumer keep working — even after
//! the allocation cap is hit (carry-forward #1): only the *allocation* of an
//! over-limit part is suppressed, by returning FAILURE for that part's
//! `FILE_START`/`FORMDATA`. (3) On the body's end, if the core decided Block,
//! we refuse the request: emit the 413/403 response and terminate.
//!
//! The milestone-0 spike proved returning FAILURE caps per-part memory but does
//! NOT end the request; the termination here is the piece that actually refuses.

use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::feeder::{self, Feeder};
use crate::module;
use crate::response;

const SUCCESS: c_int = 0;
const FAILURE: c_int = -1;

// Per-request state (NTS: one request at a time per worker).
static mut FEEDER: Option<Feeder> = None;
static mut BLOCKED: bool = false;
static mut SELFTEST_SEEN: bool = false;

/// Installed as `php_rfc1867_callback` by MINIT.
///
/// # Safety
/// Invoked by PHP's multipart parser; `event_data` matches `event`.
pub(crate) unsafe extern "C" fn callback(
    event: c_uint,
    event_data: *mut c_void,
    extra: *mut *mut c_void,
) -> c_int {
    // Our own processing is fully panic-guarded: a glue bug must never unwind
    // into PHP (carry-forward #4). On panic we simply do not suppress.
    let suppress = catch_unwind(AssertUnwindSafe(|| process(event, event_data))).unwrap_or(false);

    // Chain to the prior callback for EVERY event, including past the cap.
    let chained: c_int = match *ptr::addr_of!(module::PRIOR) {
        Some(prior) => prior(event, event_data, extra),
        None => SUCCESS,
    };

    if event == sys::MULTIPART_EVENT_END {
        let decision = catch_unwind(AssertUnwindSafe(|| end_request())).unwrap_or(None);
        if let Some((status, request_id)) = decision {
            emit_and_bail(status, request_id);
        }
    }

    if suppress {
        FAILURE
    } else {
        chained
    }
}

/// Translate one event into core feed calls. Returns whether PHP should cancel
/// (FAILURE) this event's part — true only once the core has decided Block, and
/// only for the part-introducing events, so over-limit parts are not allocated.
unsafe fn process(event: c_uint, event_data: *mut c_void) -> bool {
    match event {
        x if x == sys::MULTIPART_EVENT_START => {
            start();
            false
        }
        x if x == sys::MULTIPART_EVENT_FORMDATA => {
            let ev = &*(event_data as *const sys::multipart_event_formdata);
            let name = cbytes(ev.name);
            note_selftest(&name);
            if let Some(h) = feeder_mut().map(|f| f.field_header(&name)) {
                feed(&h);
            }
            if !ev.value.is_null() {
                let vp = *ev.value;
                if !vp.is_null() && ev.length > 0 {
                    feed(std::slice::from_raw_parts(vp as *const u8, ev.length));
                }
            }
            BLOCKED
        }
        x if x == sys::MULTIPART_EVENT_FILE_START => {
            let ev = &*(event_data as *const sys::multipart_event_file_start);
            let name = cbytes(ev.name);
            note_selftest(&name);
            let filename = if ev.filename.is_null() {
                Vec::new()
            } else {
                cbytes(*ev.filename)
            };
            if let Some(h) = feeder_mut().map(|f| f.file_part_header(&name, &filename)) {
                feed(&h);
            }
            BLOCKED
        }
        x if x == sys::MULTIPART_EVENT_FILE_DATA => {
            let ev = &*(event_data as *const sys::multipart_event_file_data);
            if !ev.data.is_null() && ev.length > 0 {
                feed(std::slice::from_raw_parts(ev.data as *const u8, ev.length));
            }
            false
        }
        _ => false,
    }
}

/// The glue sees real field names (the core only sees lengths), so the
/// self-test marker is matched here and reported through the core. Idempotent
/// per request (the core stashes one Log line; repeated markers add nothing).
unsafe fn note_selftest(name: &[u8]) {
    if !SELFTEST_SEEN && howdah_core::limits::is_selftest_name(name) {
        SELFTEST_SEEN = true;
        core::howdah_selftest(module::CTX);
    }
}

/// On a non-blocked self-test request, expose the request id as a response
/// header so `howdah-check web` can print it. Best-effort; never fatal.
unsafe fn add_selftest_header(request_id: &str) {
    if request_id.is_empty() {
        return;
    }
    let mut line = format!("X-Howdah-Selftest: {request_id}").into_bytes();
    // Zero-init then set fields by name: PHP 8.5 removed `sapi_header_line`'s
    // `response_code` field, so a struct literal naming it fails to compile on
    // 8.5. We only need `line`/`line_len` for a header op; zeroed() fills any
    // remaining field (present or not) with 0, portably across 5/7/8.x.
    let mut hl: sys::sapi_header_line = std::mem::zeroed();
    hl.line = line.as_mut_ptr() as *mut c_char;
    hl.line_len = line.len() as _;
    sys::sapi_header_op(
        sys::sapi_header_op_enum_SAPI_HEADER_REPLACE,
        &mut hl as *mut _ as *mut c_void,
    );
}

/// Begin a request: reset state, build a RequestMeta from the SAPI globals, and
/// open the core request with our fixed internal boundary.
unsafe fn start() {
    BLOCKED = false;
    SELFTEST_SEEN = false;
    ptr::addr_of_mut!(FEEDER).write(Some(Feeder::new()));

    let ri = (*ptr::addr_of!(sys::sapi_globals)).request_info;
    let method = cbytes(ri.request_method);
    let uri_full = cbytes(ri.request_uri);
    let uri = strip_query(&uri_full); // path only: query strings can carry secrets
    let ip = remote_addr();

    let meta = core::RequestMeta {
        client_ip: ip.as_ptr() as *const c_char,
        client_ip_len: ip.len(),
        method: method.as_ptr() as *const c_char,
        method_len: method.len(),
        uri: uri.as_ptr() as *const c_char,
        uri_len: uri.len(),
    };
    core::howdah_request_begin(
        module::CTX,
        feeder::INTERNAL_BOUNDARY.as_ptr() as *const c_char,
        feeder::INTERNAL_BOUNDARY.len(),
        &meta,
    );
    // ip/method/uri outlive this call's request_begin, which copies them.
}

/// End of body: feed the closing delimiter, end the core request, write any log
/// line, and (if blocked) return the (status, request_id) for the response.
unsafe fn end_request() -> Option<(c_int, String)> {
    if let Some(close) = feeder_mut().map(|f| f.closing()) {
        feed(&close);
    }
    let end_action = core::howdah_request_end(module::CTX);
    let line = take_log_line();
    if let Some(l) = line.as_deref() {
        response::write_log_line(l);
    }

    if !BLOCKED && end_action != core::HOWDAH_BLOCK {
        if SELFTEST_SEEN {
            let (rule, id) = line.as_deref().map(parse_line).unwrap_or_default();
            if rule == "self_test" {
                add_selftest_header(&id);
            }
        }
        return None;
    }
    let (rule, request_id) = line.as_deref().map(parse_line).unwrap_or_default();
    let status = if rule.is_empty() {
        403
    } else {
        response::status_for_rule(&rule)
    };
    Some((status, request_id))
}

/// Feed bytes to the core; latch Block.
unsafe fn feed(bytes: &[u8]) {
    let action = core::howdah_feed(module::CTX, bytes.as_ptr() as *const c_char, bytes.len());
    if action == core::HOWDAH_BLOCK {
        BLOCKED = true;
    }
}

unsafe fn feeder_mut() -> Option<&'static mut Feeder> {
    (*ptr::addr_of_mut!(FEEDER)).as_mut()
}

unsafe fn take_log_line() -> Option<String> {
    let p = core::howdah_take_log_line(module::CTX);
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    core::howdah_free_str(p);
    Some(s)
}

fn parse_line(line: &str) -> (String, String) {
    match serde_json::from_str::<serde_json::Value>(line) {
        Ok(v) => (
            v["rule"].as_str().unwrap_or("").to_string(),
            v["request_id"].as_str().unwrap_or("").to_string(),
        ),
        Err(_) => (String::new(), String::new()),
    }
}

/// Bytes of a NUL-terminated C string (empty for NULL).
unsafe fn cbytes(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        Vec::new()
    } else {
        CStr::from_ptr(p).to_bytes().to_vec()
    }
}

/// Everything up to the first `?` (log the path, never the query string).
fn strip_query(uri: &[u8]) -> Vec<u8> {
    match uri.iter().position(|&b| b == b'?') {
        Some(i) => uri[..i].to_vec(),
        None => uri.to_vec(),
    }
}

/// Best-effort client IP from the SAPI environment.
unsafe fn remote_addr() -> Vec<u8> {
    let key = b"REMOTE_ADDR\0";
    let p = sys::sapi_getenv(key.as_ptr() as _, key.len() - 1);
    if p.is_null() {
        Vec::new()
    } else {
        CStr::from_ptr(p).to_bytes().to_vec()
    }
}

/// Terminate the current request (PHP `zend_bailout`, a longjmp). Never returns.
/// Must be called with no live Rust-owned values in scope.
/// Emit the block response, then terminate the request. Takes `request_id` by
/// value and drops it (and every other heap-owned Rust value) BEFORE the
/// `bail()` longjmp, which skips destructors — otherwise each blocked (i.e.
/// attacker-triggerable) request would leak the id string.
unsafe fn emit_and_bail(status: c_int, request_id: String) -> ! {
    // emit_block only borrows request_id; it copies the bytes into the client
    // response and the log sink, leaving nothing of ours alive past its return.
    let _ = catch_unwind(AssertUnwindSafe(|| response::emit_block(status, &request_id)));
    drop(request_id); // explicit: no heap-owned Rust value may be live at bail()
    bail();
}

// `_zend_bailout` is annotated noreturn in some generations' headers (bindgen
// then types it `-> !`) and not in others; the trailing `unreachable_unchecked`
// is needed in the latter case and merely unreachable in the former.
#[allow(unreachable_code)]
unsafe fn bail() -> ! {
    static B: &[u8] = b"howdah\0";
    sys::_zend_bailout(B.as_ptr() as _, 0);
    std::hint::unreachable_unchecked()
}
