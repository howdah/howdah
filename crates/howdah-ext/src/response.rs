//! The block response: the milestone-0 findings proved the chained callback
//! returning FAILURE caps per-part allocation but does NOT refuse the request
//! (PHP keeps running the script). This module is the "request is actually
//! refused" half: it picks a status (413 for a size/too-large limit, else 403),
//! emits a short body carrying the request id, and writes the core's JSON log
//! line to the configured destination. The caller terminates the request
//! afterwards (see `rfc1867::bail`).

use std::ffi::{c_char, c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use howdah_sys as sys;

use crate::logsink;
use crate::module;

/// HTTP status for a rule name (as emitted in the core's JSON log line).
/// Size/too-large violations map to 413 Payload Too Large; structural floods
/// (too many parts/files/headers) and everything else to 403 Forbidden.
pub fn status_for_rule(rule: &str) -> c_int {
    match rule {
        "parse_memory_budget"
        | "max_part_header_bytes"
        | "max_field_name_len"
        | "max_filename_len" => 413,
        _ => 403,
    }
}

/// Set the HTTP status and write the block body to the client. Does NOT
/// terminate; the caller must `bail()` right after (with no live Rust owned
/// values, so the longjmp drops nothing).
///
/// # Safety
/// Must run inside an active request, before headers are sent.
pub unsafe fn emit_block(status: c_int, request_id: &str) {
    // Set the response status code (arg is the code cast to a pointer).
    sys::sapi_header_op(
        sys::sapi_header_op_enum_SAPI_HEADER_SET_STATUS,
        status as isize as *mut c_void,
    );
    // Send the status line + headers now. `ub_write` is the raw SAPI writer and
    // does NOT trigger header emission on its own, so without this the client
    // would receive a bare body (an HTTP/0.9 response).
    sys::sapi_send_headers();

    let body = format!(
        "Howdah blocked this request.\nstatus: {status}\nrequest_id: {request_id}\n"
    );
    // Write the body straight to the client. Nothing Rust-owned survives this
    // call, so the subsequent longjmp (bail) drops nothing.
    if let Some(ub_write) = (*ptr::addr_of!(sys::sapi_module)).ub_write {
        ub_write(body.as_ptr() as *const c_char, body.len() as _);
    }
}

/// Write one JSON event line to the configured destination (`[log]
/// destination`: the log file, syslog or stderr) and run the `[log] exec`
/// hook if one is set. Any failure falls back to stderr with a loud note and
/// keeps serving (carry-forward #4); a panic in the writer is caught here.
pub fn write_log_line(line: &str) {
    let written = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: NTS worker: process-global state, never touched concurrently.
        match unsafe { (*ptr::addr_of_mut!(module::LOG)).as_mut() } {
            Some(s) => {
                s.emit(line);
                true
            }
            None => false,
        }
    }));
    if !matches!(written, Ok(true)) {
        // No settings (before MINIT finished) or a caught panic: stderr.
        logsink::stderr_line(line);
    }
}

/// A loud, un-panicking error note to stderr. Never unwinds across the boundary.
pub fn loud_error(msg: &str) {
    logsink::loud_error(msg);
}
