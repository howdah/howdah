//! Layer-3 SSRF glue: the `decide` / `armed` callbacks the C egress
//! trampolines in howdah-sys `ssrf_hook.c` invoke, plus the oversize-host and
//! scheme-denial verdicts. Mirrors `sink_filter`: the C-passed ctx is ignored
//! (the shim's ctx is never set) and `module::CTX` is used, so there is no
//! per-request ctx to keep in sync. Fail-open everywhere. The executing script
//! is passed to the core for `[[exceptions]]` `script` facets (see `origin`).
use std::ffi::{c_char, c_int, c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;

use crate::{module, origin, response};

/// Take the pending sink-log line (if any), write it, free it.
unsafe fn flush_log_line() {
    let p = core::howdah_take_sink_log_line(module::CTX);
    if !p.is_null() {
        let line = CStr::from_ptr(p).to_string_lossy().into_owned();
        core::howdah_free_str(p);
        response::write_log_line(&line);
    }
}

/// `howdah_ssrf_decide_t`: 0 ALLOW / 1 LOG / 2 BLOCK. `kind` is a
/// `HOWDAH_SSRF_KIND_*` code (range / rebind / redirect), which picks the mode
/// that governs the verdict in the core.
///
/// # Safety
/// Invoked by the C trampolines; pointers valid for their lengths (`ips`: 17 *
/// `ips_count` bytes).
#[allow(clippy::too_many_arguments)]
pub(crate) unsafe extern "C" fn decide(
    _ctx: *mut c_void,
    kind: c_int,
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
        let script = origin::current_script();
        let sha = origin::sha_for(&script);
        let (sp, sl) = origin::sha_args(&sha);
        let action = core::howdah_sink_check_ssrf_kind_at(
            module::CTX,
            kind,
            scheme,
            scheme_len,
            host,
            host_len,
            port,
            ips,
            ips_count,
            script.as_ptr() as *const c_char,
            script.len(),
            sp,
            sl,
        );
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

/// `howdah_ssrf_armed_t`: the `HOWDAH_SSRF_ARM_*` mask of which parts of the C
/// SSRF path must run (0 = none: the zero-overhead chain). Bit 1 is the L3
/// reserved-range signal ONLY (it is NOT widened for the L4 behavior egress
/// facet): `ssrf_should_block` gates the (no-timeout) `resolve_host` on the
/// range / rebind bits, so deny_exec_dirs-only mode (SSRF off) never resolves;
/// the C code runs the behavior-egress check under its own separate
/// `howdah_g_behavior_armed(EGRESS)` gate, which needs no resolution (it matches
/// the host string). Any non-zero value is truthy for the callers that only
/// test "armed". Fail-open 0.
///
/// # Safety
/// Invoked by the C trampolines.
pub(crate) unsafe extern "C" fn armed(_ctx: *mut c_void) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return 0;
        }
        core::howdah_ssrf_armed_mask(module::CTX)
    }))
    .unwrap_or(0)
}

/// Oversize-host verdict called directly by `ssrf_hook.c` (it does not go
/// through `decide`): runs the core verdict for the SSRF event `kind`
/// (`HOWDAH_SSRF_KIND_*`: the range mode, or a redirect hop's own mode), then
/// writes the stashed line.
///
/// # Safety
/// Invoked by the C trampolines.
#[no_mangle]
pub unsafe extern "C" fn howdah_ssrf_oversize_glue(_ctx: *mut c_void, kind: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let script = origin::current_script();
        let sha = origin::sha_for(&script);
        let (sp, sl) = origin::sha_args(&sha);
        let action = core::howdah_sink_ssrf_oversize_kind_at(
            module::CTX,
            kind,
            script.as_ptr() as *const c_char,
            script.len(),
            sp,
            sl,
        );
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

/// Egress-scheme verdict called directly by `ssrf_hook.c`: `via` is
/// `HOWDAH_SSRF_VIA_STREAM` / `HOWDAH_SSRF_VIA_CURL`, `url` the raw argument
/// (read by the core, never logged). Runs the core verdict, then writes the
/// stashed line. Fail-open.
///
/// # Safety
/// Invoked by the C trampolines; `url` valid for `url_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_ssrf_scheme_glue(
    _ctx: *mut c_void,
    via: c_int,
    url: *const c_char,
    url_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let script = origin::current_script();
        let sha = origin::sha_for(&script);
        let (sp, sl) = origin::sha_args(&sha);
        let action = core::howdah_sink_ssrf_scheme_at(
            module::CTX,
            via,
            url,
            url_len,
            script.as_ptr() as *const c_char,
            script.len(),
            sp,
            sl,
        );
        flush_log_line();
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}
