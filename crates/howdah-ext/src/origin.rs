//! The executing script for the `[[exceptions]]` `script` / `script_sha256`
//! facets. The path comes from ONE place: `howdah_sys_current_script()` in
//! `sink_hook.c`, the same `zend_get_executed_filename()` capture the Layer-4
//! trampolines use, so an exception's `script` matches exactly what a Layer-4
//! finding attributes a call to. The hash is computed by `script_hash` only
//! when the core says a hash facet could apply (`howdah_exceptions_want_hash`).

use std::ffi::{c_char, CStr};
use std::path::Path;
use std::ptr;

use howdah_core::ffi as core;
use howdah_sys as sys;

use crate::module;
use crate::script_hash::HashCache;

/// Process-global hash cache (NTS: one request at a time per worker).
static mut CACHE: Option<HashCache> = None;

/// Latched at MINIT: `howdah_exceptions_count(CTX) > 0`. With no
/// `[[exceptions]]` configured nothing below does any work, so a config
/// without exceptions keeps the per-call cost it had before this feature.
pub(crate) static mut ACTIVE: bool = false;

/// The executing script's path as PHP reports it, or empty when no
/// exceptions are configured (no engine call at all) or nothing is executing
/// (PHP yields a bracketed placeholder such as `[no active file]`, which is
/// not a path and is dropped). For code inside `eval()` PHP reports
/// `<file>(<line>) : eval()'d code`, which starts with `/` and is passed on
/// as is: a `**` glob on the file's directory covers it, a literal path or a
/// hash does not (documented).
///
/// # Safety
/// Must be called from a PHP hook with the engine initialised.
pub(crate) unsafe fn current_script() -> Vec<u8> {
    if !*ptr::addr_of!(ACTIVE) {
        return Vec::new();
    }
    let p = sys::howdah_sys_current_script();
    if p.is_null() {
        return Vec::new();
    }
    let b = CStr::from_ptr(p).to_bytes();
    if b.first() != Some(&b'/') {
        return Vec::new();
    }
    b.to_vec()
}

/// SHA-256 of `script`'s bytes when some exception with a `script_sha256`
/// facet could apply to it; `None` otherwise (and for an unreadable file).
///
/// # Safety
/// `module::CTX` live or NULL.
pub(crate) unsafe fn sha_for(script: &[u8]) -> Option<[u8; 32]> {
    if !*ptr::addr_of!(ACTIVE)
        || script.is_empty()
        || module::CTX.is_null()
        || core::howdah_exceptions_want_hash(module::CTX, script.as_ptr() as *const c_char, script.len()) == 0
    {
        return None;
    }
    let path = Path::new(std::str::from_utf8(script).ok()?);
    let cache = (*ptr::addr_of_mut!(CACHE)).get_or_insert_with(|| HashCache::new(256));
    cache.sha256_of(path)
}

/// `(ptr, len)` for an optional digest, as the `_at` entry points take it.
pub(crate) fn sha_args(sha: &Option<[u8; 32]>) -> (*const u8, usize) {
    match sha {
        Some(h) => (h.as_ptr(), 32),
        None => (ptr::null(), 0),
    }
}
