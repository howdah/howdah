//! §4.1 glue: feed the raw request body (via the `read_post` wrapper in
//! `read_post_hook.c`) to the byte-stream scanner in howdah-core, so gaps A/B
//! and the §4.5 estimate are checked as PHP reads the body — before it fires any
//! rfc1867 event for the part involved.
//!
//! The scanner is armed lazily on the first body read: only then is the
//! `Content-Type` (for the boundary) and PHP's parsed `memory_limit` /
//! `post_max_size` reliably available, and lazy arming is robust to when the
//! body is actually read (eagerly in `sapi_activate`, or lazily during the
//! script with `auto_globals_jit`). A Block verdict stops the body (return 1)
//! and is recorded in the core ctx's worst action; it is DELIVERED by the
//! existing refusal paths (the rfc1867 END handler during startup, else
//! RSHUTDOWN), so this read-time callback never emits a response or bails — a
//! `zend_bailout` longjmp through this `catch_unwind` would be unsound.

use std::ffi::{c_char, c_int, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::module;

/// Armed-this-request latch (NTS: process-global, reset per request).
static mut ARMED: bool = false;

/// Reset the per-request scanner state. Called from `module::clear_request_state`.
///
/// # Safety
/// Single-threaded (NTS) request teardown.
pub(crate) unsafe fn reset() {
    ARMED = false;
    sys::howdah_read_post_reset();
}

/// `HowdahReadPostDecide`: feed the body bytes just read to the scanner. Returns
/// 1 to stop the body (scanner decided Block), 0 to continue. Fail-open: NULL
/// ctx or any panic returns 0 (Howdah must never wedge a legitimate body read).
///
/// # Safety
/// `buf` is NULL or valid for `len` bytes for the duration of the call.
pub(crate) unsafe extern "C" fn decide(buf: *const c_char, len: usize) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return 0;
        }
        if !ARMED {
            ARMED = true;
            // The body is being read: open the core request (idempotent) and arm
            // the scanner from the Content-Type + PHP's parsed limits.
            module::maybe_begin();
            let ct = sys::howdah_request_content_type();
            let ct_len = if ct.is_null() { 0 } else { CStr::from_ptr(ct).to_bytes().len() };
            core::howdah_scan_post_begin(
                module::CTX,
                ct,
                ct_len,
                sys::howdah_post_max_size(),
                sys::howdah_memory_limit(),
            );
        }
        i32::from(core::howdah_scan_post(module::CTX, buf, len) == core::HOWDAH_BLOCK)
    }))
    .unwrap_or(0)
}
