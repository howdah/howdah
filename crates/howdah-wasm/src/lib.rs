//! WebAssembly build of the Howdah core for the browser demo.
//!
//! Verdicts come from the REAL core: `howdah_wasm_analyze` drives the same
//! C-ABI entry points the PHP extension uses (init -> request_begin -> feed ->
//! request_end -> take_log_line -> free). Nothing is re-implemented here.
//!
//! # ABI for the JS author (all sizes/pointers are wasm32 u32)
//!
//! * `howdah_wasm_alloc(len) -> ptr`: allocate `len` zeroed bytes in linear
//!   memory. Copy input bytes there (`new Uint8Array(memory.buffer, ptr, len)`;
//!   re-create the view after any call, memory may grow). Free with
//!   `howdah_wasm_free(ptr, len)` using the SAME len.
//! * `howdah_wasm_free(ptr, len)`: free a buffer from `howdah_wasm_alloc` or an
//!   analyze result. Exactly once per buffer.
//! * `howdah_wasm_analyze(cfg_ptr, cfg_len, body_ptr, body_len) -> result_ptr`:
//!   - config: UTF-8 TOML (`cfg_len == 0` => safe defaults: block mode, default
//!     limits; invalid config also falls back to safe defaults, in the core).
//!   - body: raw multipart/form-data body bytes, delimited with the FIXED
//!     boundary [`BOUNDARY`] (`HowdahDemoBoundary`), i.e. delimiter lines are
//!     `--HowdahDemoBoundary`, final `--HowdahDemoBoundary--`. The JS must build
//!     bodies with exactly that boundary.
//!   - Input buffers are only borrowed; the caller still frees them.
//!   - Returns a pointer to a UTF-8 JSON string
//!     `{"action":"allow|log|block","rule":<string|null>,"reason":<string>}`.
//!     Read its length with `howdah_wasm_result_len()` IMMEDIATELY after the
//!     call (before any other analyze), decode it, then
//!     `howdah_wasm_free(result_ptr, result_len)`.
//! * `howdah_wasm_result_len() -> len`: byte length of the most recent result.
//!
//! The module is single-threaded and needs no imports (no WASI, no JS glue).
//! Mode `detect` downgrades standard-severity hits to `"log"`; critical flood
//! rules still block, exactly as in the shipping extension.

use howdah_core::ffi::{
    howdah_feed, howdah_free, howdah_free_str, howdah_init, howdah_request_begin, howdah_request_end,
    howdah_take_log_line,
};
use howdah_core::limits::rule_catalog;
use howdah_core::Config;
use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Fixed multipart boundary the demo body must use.
pub const BOUNDARY: &str = "HowdahDemoBoundary";

static RESULT_LEN: AtomicUsize = AtomicUsize::new(0);

fn into_raw(v: Vec<u8>) -> *mut u8 {
    Box::into_raw(v.into_boxed_slice()) as *mut u8
}

/// Allocate `len` zeroed bytes; release with [`howdah_wasm_free`] (same `len`).
#[no_mangle]
pub extern "C" fn howdah_wasm_alloc(len: usize) -> *mut u8 {
    into_raw(vec![0u8; len])
}

/// Free a buffer from [`howdah_wasm_alloc`] / [`howdah_wasm_analyze`].
///
/// # Safety
/// `ptr`/`len` must be exactly a pair previously handed out, freed at most once.
#[no_mangle]
pub unsafe extern "C" fn howdah_wasm_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// Length in bytes of the last [`howdah_wasm_analyze`] result.
#[no_mangle]
pub extern "C" fn howdah_wasm_result_len() -> usize {
    RESULT_LEN.load(Ordering::Relaxed)
}

/// Run the real core over `body`; see the module docs for the ABI.
///
/// # Safety
/// Each non-null pointer must be valid for reads of its length.
#[no_mangle]
pub unsafe extern "C" fn howdah_wasm_analyze(
    cfg_ptr: *const u8,
    cfg_len: usize,
    body_ptr: *const u8,
    body_len: usize,
) -> *mut u8 {
    let cfg: &[u8] = if cfg_ptr.is_null() || cfg_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(cfg_ptr, cfg_len)
    };
    let body: &[u8] = if body_ptr.is_null() || body_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(body_ptr, body_len)
    };
    let json = analyze(cfg, body);
    RESULT_LEN.store(json.len(), Ordering::Relaxed);
    into_raw(json.into_bytes())
}

/// Drive the core's C ABI end to end and shape the JSON verdict.
fn analyze(cfg: &[u8], body: &[u8]) -> String {
    // SAFETY: all pointers come from live slices valid for the stated lengths;
    // the ctx and the log string are released exactly once below.
    let (code, line) = unsafe {
        let ctx = howdah_init(cfg.as_ptr() as *const c_char, cfg.len());
        howdah_request_begin(ctx, BOUNDARY.as_ptr() as *const c_char, BOUNDARY.len(), std::ptr::null());
        howdah_feed(ctx, body.as_ptr() as *const c_char, body.len());
        let code = howdah_request_end(ctx);
        let p = howdah_take_log_line(ctx);
        let line = if p.is_null() {
            None
        } else {
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            howdah_free_str(p);
            Some(s)
        };
        howdah_free(ctx);
        (code, line)
    };
    let action = match code {
        2 => "block",
        1 => "log",
        _ => "allow",
    };
    let parsed = line.and_then(|l| serde_json::from_str::<serde_json::Value>(&l).ok());
    let field = |k: &str| parsed.as_ref().and_then(|v| v.get(k)).and_then(|v| v.as_str()).map(str::to_owned);
    let rule = field("rule");
    let reason = field("reason").unwrap_or_else(|| {
        if action == "allow" {
            "no limit exceeded".to_string()
        } else {
            String::new()
        }
    });
    serde_json::json!({ "action": action, "rule": rule, "reason": reason }).to_string()
}

// ---- config editor support --------------------------------------------------
//
// The howdah.org config editor validates with THIS code, not a JavaScript copy
// of the parser: `howdah_wasm_validate_config` is `Config::from_toml` behind
// the same alloc/result_len/free protocol as `howdah_wasm_analyze`. The parsed
// config comes back as canonical JSON so the page can fill its form from what
// the core understood, and tests can compare configs by meaning.

/// `Config::from_toml` as JSON: `{"ok":true,"config":{…}}` or
/// `{"ok":false,"error":"…"}` (the core's own error text, verbatim).
fn validate_config(toml: &[u8]) -> String {
    let text = String::from_utf8_lossy(toml);
    match Config::from_toml(&text) {
        Ok(cfg) => serde_json::json!({ "ok": true, "config": cfg }).to_string(),
        Err(e) => serde_json::json!({ "ok": false, "error": e.to_string() }).to_string(),
    }
}

/// Every rule the core accepts under `[rules]`, with its severity:
/// `[{"name":"max_parts","severity":"critical"},…]` in declaration order.
fn rule_catalog_json() -> String {
    let rules: Vec<serde_json::Value> = rule_catalog()
        .iter()
        .map(|r| serde_json::json!({ "name": r, "severity": r.severity() }))
        .collect();
    serde_json::Value::Array(rules).to_string()
}

/// The core version this module was built from (the page shows it).
fn version_str() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn into_result(s: String) -> *mut u8 {
    RESULT_LEN.store(s.len(), Ordering::Relaxed);
    into_raw(s.into_bytes())
}

/// Validate a TOML config with the real core. Result is JSON (see
/// `validate_config`); read `howdah_wasm_result_len()` immediately, then free
/// the result with `howdah_wasm_free`.
///
/// # Safety
/// `toml_ptr` must be NULL or valid for reads of `toml_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_wasm_validate_config(toml_ptr: *const u8, toml_len: usize) -> *mut u8 {
    let toml: &[u8] = if toml_ptr.is_null() || toml_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(toml_ptr, toml_len)
    };
    into_result(validate_config(toml))
}

/// The rule catalog as JSON; same result protocol as the other exports.
#[no_mangle]
pub extern "C" fn howdah_wasm_rule_catalog() -> *mut u8 {
    into_result(rule_catalog_json())
}

/// The core version as a raw UTF-8 string (not JSON); same result protocol.
#[no_mangle]
pub extern "C" fn howdah_wasm_version() -> *mut u8 {
    into_result(version_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The result buffer + RESULT_LEN are process-global (correct for the
    // single-threaded wasm/JS runtime). cargo runs these HOST tests on
    // parallel threads, so two analyze() calls would race on that global and
    // one would read a mismatched ptr/len. Serialize the analyze→read→free
    // sequence across tests; production (single-threaded) never contends.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Full alloc/copy/analyze/read/free dance, as the JS glue does it.
    fn run(cfg: &str, body: &[u8]) -> serde_json::Value {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let c = howdah_wasm_alloc(cfg.len());
            std::slice::from_raw_parts_mut(c, cfg.len()).copy_from_slice(cfg.as_bytes());
            let b = howdah_wasm_alloc(body.len());
            std::slice::from_raw_parts_mut(b, body.len()).copy_from_slice(body);
            let r = howdah_wasm_analyze(c, cfg.len(), b, body.len());
            let n = howdah_wasm_result_len();
            let out = std::str::from_utf8(std::slice::from_raw_parts(r, n)).unwrap().to_owned();
            howdah_wasm_free(r, n);
            howdah_wasm_free(b, body.len());
            howdah_wasm_free(c, cfg.len());
            serde_json::from_str(&out).unwrap()
        }
    }

    // ---- config validator export (config editor) ---------------------------

    #[test]
    fn validate_empty_is_defaults() {
        let v: serde_json::Value = serde_json::from_str(&validate_config(b"")).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["config"]["mode"], "block");
        assert_eq!(v["config"]["limits"]["max_parts"], 2000);
        assert_eq!(v["config"]["sinks"]["unserialize"]["mode"], "off");
        assert!(v["config"]["rules"].is_object());
    }

    #[test]
    fn validate_reports_unknown_key_text() {
        let v: serde_json::Value = serde_json::from_str(&validate_config(b"[limits]\nnope = 1")).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("nope"), "{v}");
    }

    #[test]
    fn validate_reports_zero_limit() {
        let v: serde_json::Value = serde_json::from_str(&validate_config(b"[limits]\nmax_files = 0")).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("max_files"), "{v}");
    }

    #[test]
    fn validate_reports_invalid_toml() {
        let v: serde_json::Value = serde_json::from_str(&validate_config(b"= = =")).unwrap();
        assert_eq!(v["ok"], false);
        assert!(!v["error"].as_str().unwrap().is_empty());
    }

    #[test]
    fn validate_round_trips_detect_mode_and_rule_override() {
        let v: serde_json::Value =
            serde_json::from_str(&validate_config(b"mode = \"detect\"\n[rules]\nsql_injection = \"block\"")).unwrap();
        assert_eq!(v["ok"], true, "{v}");
        assert_eq!(v["config"]["mode"], "detect");
        assert_eq!(v["config"]["rules"]["sql_injection"], "block");
    }

    #[test]
    fn rule_catalog_has_every_rule_with_severity() {
        let v: serde_json::Value = serde_json::from_str(&rule_catalog_json()).unwrap();
        let rules = v.as_array().unwrap();
        let names: Vec<&str> = rules.iter().map(|r| r["name"].as_str().unwrap()).collect();
        assert_eq!(names.len(), 41, "{names:?}");
        assert!(names.contains(&"max_parts") && names.contains(&"unserialize") && names.contains(&"ssrf"));
        // Layer 4 (1.4) rule ids must reach the wasm catalog the config editor reads.
        assert!(names.contains(&"upload_exec") && names.contains(&"php_write"));
        // The out-of-memory backstop's Layer-1 rules, plus the §4.7 recycle rule.
        assert!(names.contains(&"out_of_memory") && names.contains(&"startup_fatal"));
        assert!(names.contains(&"fatal_recycle"));
        // Legacy-era sinks (1.5).
        for n in ["mail_injection", "preg_eval", "create_function", "assert_string", "dangerous_callback", "xxe", "tls_verify"] {
            assert!(names.contains(&n), "{n}");
        }
        assert_eq!(v[0]["name"], "max_parts");
        assert_eq!(v[0]["severity"], "critical");
        let malformed = rules.iter().find(|r| r["name"] == "malformed_multipart").unwrap();
        assert_eq!(malformed["severity"], "standard");
    }

    #[test]
    fn version_is_cargo_version() {
        assert_eq!(version_str(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn validate_export_round_trips_through_the_abi() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let cfg = b"mode = \"detect\"";
        unsafe {
            let c = howdah_wasm_alloc(cfg.len());
            std::slice::from_raw_parts_mut(c, cfg.len()).copy_from_slice(cfg);
            let r = howdah_wasm_validate_config(c, cfg.len());
            let n = howdah_wasm_result_len();
            let out = std::str::from_utf8(std::slice::from_raw_parts(r, n)).unwrap().to_owned();
            howdah_wasm_free(r, n);
            howdah_wasm_free(c, cfg.len());
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["config"]["mode"], "detect");
            let vp = howdah_wasm_version();
            let vn = howdah_wasm_result_len();
            let ver = std::str::from_utf8(std::slice::from_raw_parts(vp, vn)).unwrap().to_owned();
            howdah_wasm_free(vp, vn);
            assert_eq!(ver, env!("CARGO_PKG_VERSION"));
            let cp = howdah_wasm_rule_catalog();
            let cn = howdah_wasm_result_len();
            howdah_wasm_free(cp, cn);
            assert!(cn > 100);
        }
    }

    fn body(parts: usize, file: bool) -> Vec<u8> {
        let mut s = String::new();
        for i in 0..parts {
            let fname = if file { "; filename=\"a.txt\"" } else { "" };
            s += &format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"f{i}\"{fname}\r\n\r\nx\r\n");
        }
        s += &format!("--{BOUNDARY}--\r\n");
        s.into_bytes()
    }

    #[test]
    fn normal_body_allows() {
        let v = run("", &body(3, false));
        assert_eq!(v["action"], "allow");
        assert!(v["rule"].is_null());
    }

    #[test]
    fn part_flood_blocks_max_parts() {
        let v = run("", &body(2500, false));
        assert_eq!(v["action"], "block");
        assert_eq!(v["rule"], "max_parts");
        assert!(!v["reason"].as_str().unwrap().is_empty());
    }

    #[test]
    fn file_flood_blocks_max_files() {
        let v = run("[limits]\nmax_parts = 100000\n", &body(300, true));
        assert_eq!(v["action"], "block");
        assert_eq!(v["rule"], "max_files");
    }

    #[test]
    fn malformed_body_flagged() {
        let b = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx");
        let v = run("", b.as_bytes());
        assert_eq!(v["rule"], "malformed_multipart");
        assert_ne!(v["action"], "allow");
    }

    #[test]
    fn detect_mode_logs_instead_of_blocking() {
        // Critical flood rules still block in detect mode (core semantics);
        // a standard-severity rule (malformed) downgrades to log.
        let b = format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx");
        let v = run("mode = \"detect\"\n", b.as_bytes());
        assert_eq!(v["action"], "log");
        assert_eq!(v["rule"], "malformed_multipart");
    }

    #[test]
    fn empty_inputs_are_safe() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let r = howdah_wasm_analyze(std::ptr::null(), 0, std::ptr::null(), 0);
            let n = howdah_wasm_result_len();
            assert!(n > 0);
            howdah_wasm_free(r, n);
        }
    }
}
