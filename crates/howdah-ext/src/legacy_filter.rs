//! Layer-3 legacy-sink glue: the `mail()` decide callback the C trampoline in
//! howdah-sys `legacy_hook.c` invokes (the other legacy sinks reuse
//! `sink_filter::decide`), plus the first-RINIT install mask and the phpinfo
//! label. Thin bridge; the policy lives in howdah-core. Fail-open.
use std::ffi::{c_char, c_int, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::{module, response};

/// `howdah_mail_decide_t`: 0 ALLOW / 1 LOG / 2 BLOCK; on BLOCK the C refuses
/// the call (returns false, nothing reaches sendmail).
///
/// # Safety
/// Invoked by the C `mail` trampoline mid-call; pointers NULL or valid for
/// their lengths.
pub(crate) unsafe extern "C" fn mail_decide(
    headers: *const c_char,
    headers_len: usize,
    params: *const c_char,
    params_len: usize,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action = core::howdah_sink_check_mail(module::CTX, headers, headers_len, params, params_len);
        let p = core::howdah_take_sink_log_line(module::CTX);
        if !p.is_null() {
            let line = CStr::from_ptr(p).to_string_lossy().into_owned();
            core::howdah_free_str(p);
            response::write_log_line(&line);
        }
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW)
}

/// (sink id, install bit, phpinfo name) for each legacy sink.
const LEGACY: [(i32, c_int, &str); 7] = [
    (core::HOWDAH_SINK_MAIL, sys::HOWDAH_LEGACY_MAIL, "mail"),
    (core::HOWDAH_SINK_PREG_EVAL, sys::HOWDAH_LEGACY_PREG_EVAL, "preg_eval"),
    (core::HOWDAH_SINK_CREATE_FUNCTION, sys::HOWDAH_LEGACY_CREATE_FUNCTION, "create_function"),
    (core::HOWDAH_SINK_ASSERT, sys::HOWDAH_LEGACY_ASSERT, "assert"),
    (core::HOWDAH_SINK_CALLBACK, sys::HOWDAH_LEGACY_CALLBACK, "callback"),
    (core::HOWDAH_SINK_XML, sys::HOWDAH_LEGACY_XML, "xml"),
    (core::HOWDAH_SINK_TLS, sys::HOWDAH_LEGACY_TLS, "tls"),
];

/// The install mask: one bit per legacy sink whose effective mode is not off.
///
/// # Safety
/// `ctx` NULL or live.
pub(crate) unsafe fn armed_mask(ctx: *mut core::howdah_ctx) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    LEGACY
        .iter()
        .filter(|(id, _, _)| core::howdah_sink_armed(ctx, *id) != 0)
        .fold(0, |m, (_, bit, _)| m | bit)
}

/// phpinfo text for an install result: the sinks installed, then the armed
/// ones whose function this PHP does not have, or has removed through
/// `disable_functions` (PHP 8 deletes the function entry, so the two look
/// the same from the function table).
pub(crate) fn describe(armed: c_int, installed: c_int) -> String {
    let names = |mask: c_int| -> Vec<&str> {
        LEGACY.iter().filter(|(_, bit, _)| mask & bit != 0).map(|(_, _, n)| *n).collect()
    };
    let on = names(installed);
    let missing = names(armed & !installed);
    let mut s = if on.is_empty() { "none".to_string() } else { on.join(", ") };
    if !missing.is_empty() {
        s.push_str(" (absent or disabled: ");
        s.push_str(&missing.join(", "));
        s.push(')');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_lists_installed_and_missing() {
        assert_eq!(describe(0, 0), "none");
        assert_eq!(describe(sys::HOWDAH_LEGACY_MAIL, sys::HOWDAH_LEGACY_MAIL), "mail");
        let all = 127;
        assert_eq!(
            describe(all, all & !(sys::HOWDAH_LEGACY_PREG_EVAL | sys::HOWDAH_LEGACY_CREATE_FUNCTION | sys::HOWDAH_LEGACY_ASSERT)),
            "mail, callback, xml, tls (absent or disabled: preg_eval, create_function, assert)"
        );
        assert_eq!(describe(sys::HOWDAH_LEGACY_PREG_EVAL, 0), "none (absent or disabled: preg_eval)");
    }
}
