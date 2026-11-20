//! Layer-3 SOAP request-guard glue: the `decide` callback the C trampoline in
//! howdah-sys `soap_hook.c` invokes for each `SoapServer::handle` call
//! (CVE-2026-129506, CVE-2026-15353). Thin bridge — the classifier lives in
//! howdah-core (`sinks::soap`). The request XML is scanned by the core and
//! never logged; only the core's fixed reason string reaches the log line.
//!
//! On BLOCK the refusal is delivered HERE, at the call site: the core already
//! stashed the log line (written below), then a clean 403 goes out through the
//! SAPI and the C trampoline returns without calling ext/soap, so the vulnerable
//! parser is never reached and the worker survives. This is the execution-phase
//! sibling of the RINIT refusal — there is no `zend_bailout` (`SoapServer::
//! handle` is normally the terminal call of a SOAP endpoint). Fail-open: a glue
//! panic never neutralises a legitimate call.
use std::ffi::{c_char, c_int, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};

use howdah_core::ffi as core;

use crate::{module, response, rfc1867};

/// `HowdahSoapDecide`: the raw request XML (`xml`/`xml_len`, scanned never
/// logged) and whether an oversized body was capped (`truncated`). Returns 0
/// ALLOW / 1 LOG / 2 BLOCK. On BLOCK a clean 403 has already been delivered, so
/// the C trampoline must not call the original handler.
///
/// # Safety
/// Invoked by the C SOAP trampoline mid-call; `xml` valid for `xml_len` bytes.
pub(crate) unsafe extern "C" fn decide(xml: *const c_char, xml_len: usize, truncated: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        // No live core context (e.g. a trampoline fires after MSHUTDOWN nulled
        // CTX): chain the call unguarded.
        if module::CTX.is_null() {
            return core::HOWDAH_ALLOW;
        }
        module::maybe_begin();
        let action = core::howdah_soap_check(module::CTX, xml, xml_len, truncated);
        // Take + write the stashed line (the SOAP guard uses the core sink slot).
        let line = {
            let p = core::howdah_take_sink_log_line(module::CTX);
            if p.is_null() {
                None
            } else {
                let s = CStr::from_ptr(p).to_string_lossy().into_owned();
                core::howdah_free_str(p);
                Some(s)
            }
        };
        if let Some(l) = line.as_deref() {
            response::write_log_line(l);
        }
        // On BLOCK deliver the clean 403 now. The request id comes from the log
        // line the core just stamped; emit_block never bails, so the worker
        // survives and the trampoline simply skips ext/soap.
        if action == core::HOWDAH_BLOCK {
            let (_rule, request_id) = line.as_deref().map(rfc1867::parse_line).unwrap_or_default();
            let _ = catch_unwind(AssertUnwindSafe(|| response::emit_block(403, &request_id)));
        }
        action
    }))
    .unwrap_or(core::HOWDAH_ALLOW) // fail-open: never neutralize on a glue bug
}
