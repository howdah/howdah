//! The chained `sapi_module.input_filter` — the input-shape half of Layer 1.
//!
//! PHP calls `sapi_module.input_filter` once per request *variable* (GET, POST,
//! COOKIE, and also `$_SERVER`/`PARSE_SERVER`) as it registers the superglobals,
//! BEFORE `RINIT`. We chain it exactly like `rfc1867.rs` chains the multipart
//! callback: at MINIT we save whatever filter is installed and put ours above
//! it; ours counts the variable through the core's input-shape limits, then
//! ALWAYS calls the saved prior filter and returns ITS verdict — so PHP's own
//! filtering and any other extension's filter keep working unchanged.
//!
//! The ONE exception: once the core says Block (too many vars / nesting / key
//! length), we drop that variable (return 0 without chaining) to bound the hash
//! table the parser is building, and latch the block for the request-end
//! response (see `module`'s RSHUTDOWN). We do NOT `zend_bailout` from here: the
//! filter runs mid-parse, before RINIT, where a longjmp is unsafe; the var-drop
//! is the actual DoS mitigation and the response/log is emitted at request end.
//!
//! Panic discipline mirrors `rfc1867::callback`: our processing runs inside
//! `catch_unwind`; on a panic we do NOT drop/suppress — we chain the prior
//! filter and return its verdict (fail-open). A glue bug must never unwind into
//! PHP and must never silently eat a variable.

use std::ffi::{c_char, c_int, c_uint, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::module;

// --- per-generation signature pieces (Task-1 spike) --------------------------
//
// `input_filter` return type is `unsigned int` on every generation. Two params
// shift across generations; both are resolved here so the handler's fn-pointer
// type matches `sys::sapi_module_struct.input_filter` exactly:
//   * `val_len` / `new_val_len`: `unsigned int` before PHP 7.0, `size_t` from
//     7.0 — this tracks the `phpN` feature cleanly (php5 vs php7/php8).
//   * `var`: `char *` before PHP 8.1, `const char *` from 8.1 — this boundary
//     falls inside the `php8` feature, so it is gated on the build-script cfg
//     `howdah_input_filter_const` (set from `php-config --vernum`), not a feature.

#[cfg(feature = "php5")]
type ValLen = c_uint;
#[cfg(not(feature = "php5"))]
type ValLen = usize; // size_t on 7.0+

#[cfg(howdah_input_filter_const)]
type VarPtr = *const c_char; // PHP 8.1+
#[cfg(not(howdah_input_filter_const))]
type VarPtr = *mut c_char; // < 8.1

/// The exact type of `sapi_module.input_filter` for this generation; the glue
/// stores the prior filter as this so the save/install/restore all type-check.
pub(crate) type InputFilter =
    Option<unsafe extern "C" fn(c_int, VarPtr, *mut *mut c_char, ValLen, *mut ValLen) -> c_uint>;

// Per-request latch (NTS: one request at a time per worker). Set when the core
// returns Block for an input variable; read and cleared by RSHUTDOWN.
pub(crate) static mut INPUT_BLOCKED: bool = false;

/// Installed as `sapi_module.input_filter` by MINIT (saving the prior into
/// [`module::PRIOR_INPUT_FILTER`]).
///
/// # Safety
/// Invoked by PHP's variable registration; `val`/`new_val_len` are valid for
/// the call, `var` is a NUL-terminated variable name (or NULL).
pub(crate) unsafe extern "C" fn filter(
    arg: c_int,
    var: VarPtr,
    val: *mut *mut c_char,
    val_len: ValLen,
    new_val_len: *mut ValLen,
) -> c_uint {
    // Our own processing is fully panic-guarded: a glue bug must never unwind
    // into PHP (carry-forward #4). On panic we do NOT drop — we fall through to
    // chaining the prior filter (fail-open), exactly like rfc1867::callback.
    let drop_var = catch_unwind(AssertUnwindSafe(|| process(arg, var))).unwrap_or(false);

    if drop_var {
        // The core decided Block: drop THIS variable (return 0, do not chain) to
        // bound the hash table. The block response + log is emitted at RSHUTDOWN.
        return 0;
    }

    // Always chain the prior filter and return ITS verdict.
    match *ptr::addr_of!(module::PRIOR_INPUT_FILTER) {
        Some(prior) => prior(arg, var, val, val_len, new_val_len),
        None => {
            // No prior filter: accept the value unchanged (the SAPI contract for
            // a NULL filter — keep the length, return "keep this variable").
            if !new_val_len.is_null() {
                *new_val_len = val_len;
            }
            1
        }
    }
}

/// Begin the request (idempotent), then, for GET/POST/COOKIE variables only,
/// feed the variable name's length into the core's input-shape limits. Returns
/// true when the variable must be dropped (the core returned Block).
///
/// `PARSE_SERVER` (`$_SERVER`, incl. `HTTP_*` headers) and any other `arg` are
/// ignored here — request-header handling is a later task.
unsafe fn process(arg: c_int, var: VarPtr) -> bool {
    // Whichever hook fires first in a request begins the core request; the rest
    // skip. The input_filter fires before RINIT, so this may be the first.
    module::maybe_begin();

    // Count GET/POST/COOKIE through the input-shape limits. On a multipart
    // request the POST variables ARE the multipart fields (already counted by
    // the part limits via the rfc1867 path), so skip PARSE_POST there to avoid
    // double-counting and to preserve 0.1's `max_parts` attribution; GET and
    // COOKIE are still counted. PARSE_SERVER (`$_SERVER`, incl. HTTP_* headers)
    // and any other `arg` are ignored here (request headers are a later task).
    let counted = arg == sys::PARSE_GET as c_int
        || arg == sys::PARSE_COOKIE as c_int
        || (arg == sys::PARSE_POST as c_int && !*ptr::addr_of!(module::MULTIPART));
    if !counted {
        return false;
    }

    let (name, name_len) = var_name(var);
    let action = core::howdah_input_var(module::CTX, name, name_len);
    if action == core::HOWDAH_BLOCK {
        INPUT_BLOCKED = true;
        return true;
    }
    false
}

/// The variable name as a `(ptr, len)` pair for the core (the name is inspected
/// by length, never logged). NULL names become the empty name.
unsafe fn var_name(var: VarPtr) -> (*const c_char, usize) {
    if var.is_null() {
        return (ptr::null(), 0);
    }
    let p = var as *const c_char;
    (p, CStr::from_ptr(p).to_bytes().len())
}
