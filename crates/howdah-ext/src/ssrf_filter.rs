//! Layer-3 SSRF glue: the `decide` / `armed` callbacks the C egress
//! trampolines in howdah-sys `ssrf_hook.c` invoke, plus the oversize-host
//! verdict. Mirrors `sink_filter`: the C-passed ctx is ignored (the shim's ctx
//! is never set) and `module::CTX` is used, so there is no per-request ctx to
//! keep in sync. Fail-open everywhere.
use std::ffi::{c_char, c_int, c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;

use crate::{module, response};

/// Take the pending sink-log line (if any), write it, free it.
unsafe fn flush_log_line() {
    let p = core::howdah_take_sink_log_line(module::CTX);
    if !p.is_null() {
        let line = CStr::from_ptr(p).to_string_lossy().into_owned();
        core::howdah_free_str(p);
        response::write_log_line(&line);
    }
}

/// `howdah_ssrf_decide_t`: 0 ALLOW / 1 LOG / 2 BLOCK.
///
/// # Safety
/// Invoked by the C trampolines; pointers valid for their lengths (`ips`: 17 *
/// `ips_count` bytes).
pub(crate) unsafe extern "C" fn decide(
    _ctx: *mut c_void,
    scheme: *const c_char,
    scheme_len: usize,
    host: *const c_char,
    host_len: usize,
    port: u16,
    ips: *const u8,
    ips_count: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action = core::howdah_sink_check_ssrf(
            module::CTX, scheme, scheme_len, host, host_len, port, ips, ips_count,
        );
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

/// `howdah_ssrf_armed_t`: 1 iff the C SSRF path should run DNS/reserved-range
/// work. This is the L3-reserved signal ONLY (`howdah_sink_ssrf_armed`): it is
/// NOT widened for the L4 behavior egress facet. `ssrf_should_block` gates the
/// (no-timeout) `resolve_host` on this signal, so deny_exec_dirs-only mode (SSRF
/// off) never resolves; the C code runs the behavior-egress check under its own
/// separate `howdah_g_behavior_armed(EGRESS)` gate, which needs no resolution
/// (it matches the host string). Fail-open 0.
///
/// # Safety
/// Invoked by the C trampolines.
pub(crate) unsafe extern "C" fn armed(_ctx: *mut c_void) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return 0;
        }
        c_int::from(core::howdah_sink_ssrf_armed(module::CTX) != 0)
    }))
    .unwrap_or(0)
}

/// Oversize-host verdict called directly by `ssrf_hook.c` (it does not go
/// through `decide`): runs the core verdict, then writes the stashed line.
///
/// # Safety
/// Invoked by the C trampolines.
#[no_mangle]
pub unsafe extern "C" fn howdah_ssrf_oversize_glue(_ctx: *mut c_void) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action = core::howdah_sink_ssrf_oversize(module::CTX);
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}
