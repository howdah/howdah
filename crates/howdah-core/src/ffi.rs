//! Panic-safe C ABI over the core. The PHP extension calls only this.
//!
//! Safety contract:
//! * Every `extern "C"` entry point runs its body inside `catch_unwind`; a
//!   panic never unwinds into the caller. On a caught panic `feed` and
//!   `request_end` return 0 (Allow, fail-open: Howdah must never take PHP down)
//!   and a "panic caught" log line is stashed for `howdah_take_log_line`.
//! * Ownership: `howdah_init` returns a heap `howdah_ctx*` owned by the caller;
//!   release it exactly once with `howdah_free`. `howdah_take_log_line` returns
//!   a heap C string owned by the caller; release it exactly once with
//!   `howdah_free_str` (never `free()`). All input pointers are borrowed for the
//!   duration of the call only (data is copied). NULL pointers are tolerated
//!   everywhere (NULL ctx = no-op / Allow / NULL; NULL data with len 0 = empty).
//! * BUILD REQUIREMENT: this crate and the consuming cdylib/extension MUST be
//!   built with `panic = "unwind"` (set in the workspace profiles). Under
//!   `panic = "abort"` every `catch_unwind` is a no-op and a panic aborts PHP.
//! * Every non-null pointer + `len` pair must satisfy `len <= isize::MAX` and
//!   be valid for reads of `len` bytes (`slice::from_raw_parts` contract).
//! * A ctx must not be used from two threads at once (PHP workers each own one).
#![allow(non_camel_case_types)]

use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::limits::{LimitHit, RuleId, Severity};
use crate::log::{log_line, new_request_id, EventRecord};
use crate::multipart::{Event, MultipartState};
use crate::rules::{decide, Action};

/// Action codes returned over the ABI. Pinned: Allow=0, Log=1, Block=2.
pub const HOWDAH_ALLOW: i32 = 0;
pub const HOWDAH_LOG: i32 = 1;
pub const HOWDAH_BLOCK: i32 = 2;

fn code(a: Action) -> i32 {
    match a {
        Action::Allow => HOWDAH_ALLOW,
        Action::Log => HOWDAH_LOG,
        Action::Block => HOWDAH_BLOCK,
    }
}

fn rank(a: Action) -> u8 {
    match a {
        Action::Allow => 0,
        Action::Log => 1,
        Action::Block => 2,
    }
}

/// Request metadata for logging. Pointers are borrowed for the call only;
/// any may be NULL (len ignored then).
#[repr(C)]
pub struct RequestMeta {
    pub client_ip: *const c_char,
    pub client_ip_len: usize,
    pub method: *const c_char,
    pub method_len: usize,
    pub uri: *const c_char,
    pub uri_len: usize,
}

#[derive(Default)]
struct Meta {
    client_ip: String,
    method: String,
    uri: String,
}

/// Opaque context: config plus per-request state.
pub struct howdah_ctx {
    config: Config,
    state: Option<MultipartState>,
    request_id: String,
    meta: Meta,
    worst: Action,
    log: Option<String>,
}

fn describe(r: RuleId) -> &'static str {
    match r {
        RuleId::MaxParts => "multipart part count exceeds limit",
        RuleId::MaxFiles => "multipart file count exceeds limit",
        RuleId::MaxPartHeaders => "too many headers in one part",
        RuleId::MaxPartHeaderBytes => "part header too large",
        RuleId::MaxFieldNameLen => "field name too long",
        RuleId::MaxFilenameLen => "filename too long",
        RuleId::ParseMemoryBudget => "body exceeds parse memory budget",
        RuleId::MalformedMultipart => "malformed or truncated multipart body",
        RuleId::UploadProgressAbuse => "upload progress abuse",
        RuleId::SelfTest => "self test",
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Copy `len` bytes at `p` (lossy UTF-8). NULL or zero len gives "".
///
/// # Safety
/// `p` must be NULL or valid for `len` readable bytes.
unsafe fn copy_str(p: *const c_char, len: usize) -> String {
    if p.is_null() || len == 0 {
        return String::new();
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(p as *const u8, len)).into_owned()
}

impl howdah_ctx {
    fn new(config: Config) -> Self {
        howdah_ctx {
            config,
            state: None,
            request_id: new_request_id(),
            meta: Meta::default(),
            worst: Action::Allow,
            log: None,
        }
    }

    fn stash(&mut self, rule: RuleId, action: Action, reason: &str) {
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason: reason.to_string(),
        };
        self.log = Some(log_line(&rec));
    }

    /// Fold a hit into the sticky worst action; log only on escalation.
    fn apply(&mut self, hit: Option<&LimitHit>) {
        let a = decide(hit, self.config.mode, &self.config.rule_modes);
        if rank(a) > rank(self.worst) {
            self.worst = a;
            if let Some(h) = hit {
                self.stash(h.rule, a, describe(h.rule));
            }
        }
    }

    fn malformed(&mut self) {
        let hit = LimitHit {
            rule: RuleId::MalformedMultipart,
            severity: Severity::Standard,
            detail: String::new(),
        };
        self.apply(Some(&hit));
    }

    fn feed(&mut self, chunk: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        if self.worst == Action::Block {
            return self.worst; // already blocked: stop parsing hostile input
        }
        let Some(state) = self.state.as_mut() else {
            return self.worst; // no request in progress: fail-open
        };
        let res = state.feed(chunk);
        let limits = &self.config.limits;
        let mut hits: Vec<Option<LimitHit>> = Vec::new();
        match &res {
            Ok(events) => {
                for ev in events {
                    hits.push(limits.check(state, ev));
                }
                if events.is_empty() {
                    hits.push(limits.check(state, &Event::PartEnd));
                }
            }
            // Events from a failing call are dropped; check counters anyway.
            Err(_) => hits.push(limits.check(state, &Event::PartEnd)),
        }
        hits.push(limits.check_fed_bytes(state.total_fed_bytes()));
        for h in hits {
            self.apply(h.as_ref());
        }
        if res.is_err() {
            self.malformed();
        }
        self.worst
    }

    fn end(&mut self) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let truncated = match self.state.as_mut() {
            Some(state) => state.finish().is_err(),
            None => false,
        };
        if truncated {
            self.malformed();
        }
        self.worst
    }

    fn panic_note(&mut self) {
        // Best effort; must not itself unwind out of the boundary.
        // Do not clobber an already-stashed real Log/Block line.
        if self.log.is_some() {
            return;
        }
        let _ = catch_unwind(AssertUnwindSafe(|| {
            self.stash(RuleId::SelfTest, Action::Log, "internal panic caught at FFI boundary; failed open");
        }));
    }
}

/// Must never unwind: the stderr write ignores errors (`eprintln!` would panic
/// on EIO/EPIPE) and the whole body is itself guarded.
///
/// # Safety
/// `ctx` must be NULL or a live howdah_ctx.
unsafe fn report_panic(ctx: *mut howdah_ctx) {
    use std::io::Write;
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let _ = writeln!(
            std::io::stderr(),
            "howdah: panic caught at FFI boundary; failing open (Allow)"
        );
        if !ctx.is_null() {
            (*ctx).panic_note();
        }
    }));
}

/// Create a context from TOML config. Invalid, non-UTF-8 or NULL config falls
/// back to safe defaults. Never returns NULL (barring allocation failure).
/// Caller owns the result; release with `howdah_free`.
///
/// # Safety
/// `toml` must be NULL or valid for `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_init(toml: *const c_char, len: usize) -> *mut howdah_ctx {
    let cfg = catch_unwind(AssertUnwindSafe(|| {
        if toml.is_null() {
            return Config::safe_defaults();
        }
        let s = copy_str(toml, len);
        Config::from_toml(&s).unwrap_or_else(|_| Config::safe_defaults())
    }))
    .unwrap_or_else(|_| Config::safe_defaults());
    let ctx = catch_unwind(AssertUnwindSafe(|| howdah_ctx::new(cfg)))
        .unwrap_or_else(|_| howdah_ctx::new(Config::safe_defaults()));
    Box::into_raw(Box::new(ctx))
}

/// Begin a new request: resets state, new request id, copies `meta`.
///
/// # Safety
/// `ctx` NULL or live; `boundary` NULL or valid for `len` bytes; `meta` NULL
/// or a valid RequestMeta whose pointers are each NULL or valid for their len.
#[no_mangle]
pub unsafe extern "C" fn howdah_request_begin(
    ctx: *mut howdah_ctx,
    boundary: *const c_char,
    len: usize,
    meta: *const RequestMeta,
) {
    if ctx.is_null() {
        return;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let c = &mut *ctx;
        let b = if boundary.is_null() || len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(boundary as *const u8, len).to_vec()
        };
        c.state = Some(MultipartState::new(&b));
        c.request_id = new_request_id();
        c.worst = Action::Allow;
        c.log = None;
        c.meta = match meta.as_ref() {
            Some(m) => Meta {
                client_ip: copy_str(m.client_ip, m.client_ip_len),
                method: copy_str(m.method, m.method_len),
                uri: copy_str(m.uri, m.uri_len),
            },
            None => Meta::default(),
        };
    }));
    if r.is_err() {
        report_panic(ctx);
    }
}

/// Feed a body chunk; returns the most severe action so far this request
/// (0 Allow, 1 Log, 2 Block). Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live; `chunk` NULL or valid for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_feed(ctx: *mut howdah_ctx, chunk: *const c_char, len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let data: &[u8] = if chunk.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(chunk as *const u8, len)
        };
        code((*ctx).feed(data))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Signal end of body: detects a truncated body (MalformedMultipart) and
/// returns the final action code. Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_request_end(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).end())));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Take the pending JSON log line (single line, no newline), or NULL if none.
/// Caller owns the string; free with `howdah_free_str`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_take_log_line(ctx: *mut howdah_ctx) -> *mut c_char {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    catch_unwind(AssertUnwindSafe(|| match (*ctx).log.take() {
        Some(s) => CString::new(s.replace('\0', ""))
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Free a string from `howdah_take_log_line`. NULL is a no-op.
///
/// # Safety
/// `s` must be NULL or a pointer returned by `howdah_take_log_line`, freed once.
#[no_mangle]
pub unsafe extern "C" fn howdah_free_str(s: *mut c_char) {
    if !s.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(CString::from_raw(s))));
    }
}

/// Free a context. NULL is a no-op.
///
/// # Safety
/// `ctx` must be NULL or from `howdah_init`, freed once.
#[no_mangle]
pub unsafe extern "C" fn howdah_free(ctx: *mut howdah_ctx) {
    if !ctx.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(Box::from_raw(ctx))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::ffi::CStr;

    thread_local! {
        pub(super) static FORCE_PANIC: Cell<bool> = const { Cell::new(false) };
    }

    const BODY: &[u8] = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B--\r\n";

    fn init(toml: &str) -> *mut howdah_ctx {
        unsafe { howdah_init(toml.as_ptr() as *const c_char, toml.len()) }
    }
    fn begin(c: *mut howdah_ctx) {
        let (ip, m, u) = ("1.2.3.4", "POST", "/up");
        let meta = RequestMeta {
            client_ip: ip.as_ptr() as _,
            client_ip_len: ip.len(),
            method: m.as_ptr() as _,
            method_len: m.len(),
            uri: u.as_ptr() as _,
            uri_len: u.len(),
        };
        unsafe { howdah_request_begin(c, b"B".as_ptr() as _, 1, &meta) };
    }
    fn feed(c: *mut howdah_ctx, b: &[u8]) -> i32 {
        unsafe { howdah_feed(c, b.as_ptr() as _, b.len()) }
    }
    fn take(c: *mut howdah_ctx) -> Option<String> {
        unsafe {
            let p = howdah_take_log_line(c);
            if p.is_null() {
                return None;
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            howdah_free_str(p);
            Some(s)
        }
    }

    #[test]
    fn action_codes_pinned() {
        assert_eq!(code(Action::Allow), 0);
        assert_eq!(code(Action::Log), 1);
        assert_eq!(code(Action::Block), 2);
    }

    #[test]
    fn clean_body_allows() {
        let c = init("");
        begin(c);
        assert_eq!(feed(c, BODY), 0);
        assert_eq!(unsafe { howdah_request_end(c) }, 0);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn critical_limit_blocks_and_logs_json() {
        let c = init("[limits]\nmax_parts = 1\n");
        begin(c);
        let body = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\ny\r\n--B--\r\n";
        assert_eq!(feed(c, body), 2);
        let line = take(c).expect("log line");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["action"], "block");
        assert_eq!(v["rule"], "max_parts");
        assert_eq!(v["client_ip"], "1.2.3.4");
        assert_eq!(v["uri"], "/up");
        let rid = unsafe { (*c).request_id.clone() };
        assert_eq!(v["request_id"].as_str().unwrap(), rid);
        assert!(take(c).is_none(), "line is taken once");
        assert_eq!(feed(c, b"more"), 2, "block is sticky");
        begin(c);
        assert_ne!(unsafe { (*c).request_id.clone() }, rid);
        assert_eq!(feed(c, BODY), 0, "new request resets");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn malformed_is_standard_so_blocks_only_in_block_mode() {
        let bad = b"--B\r\nnot a header line\r\n\r\nx";
        let c = init("mode = \"detect\"\n");
        begin(c);
        assert_eq!(feed(c, bad), 1);
        assert!(take(c).unwrap().contains("malformed_multipart"));
        unsafe { howdah_free(c) };
        let c = init("mode = \"block\"\n");
        begin(c);
        assert_eq!(feed(c, bad), 2);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn truncated_body_detected_at_request_end() {
        let c = init("");
        begin(c);
        assert_eq!(feed(c, &BODY[..BODY.len() - 8]), 0);
        assert_eq!(unsafe { howdah_request_end(c) }, 2);
        assert!(take(c).unwrap().contains("malformed_multipart"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn invalid_toml_falls_back_to_safe_defaults() {
        for c in [init("this is = = not toml"), unsafe { howdah_init(std::ptr::null(), 0) }] {
            assert!(!c.is_null());
            unsafe { assert!((*c).config == Config::safe_defaults()) };
            begin(c);
            assert_eq!(feed(c, BODY), 0);
            unsafe { howdah_free(c) };
        }
    }

    #[test]
    fn panic_is_caught_and_fails_open() {
        let c = init("");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(feed(c, BODY), 0);
        assert_eq!(unsafe { howdah_request_end(c) }, 0);
        FORCE_PANIC.with(|f| f.set(false));
        let line = take(c).expect("panic noted in log");
        assert!(line.contains("panic caught"));
        begin(c);
        assert_eq!(feed(c, BODY), 0, "ctx usable after a caught panic");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn null_args_are_safe() {
        unsafe {
            howdah_request_begin(std::ptr::null_mut(), std::ptr::null(), 0, std::ptr::null());
            assert_eq!(howdah_feed(std::ptr::null_mut(), std::ptr::null(), 5), 0);
            assert_eq!(howdah_request_end(std::ptr::null_mut()), 0);
            assert!(howdah_take_log_line(std::ptr::null_mut()).is_null());
            howdah_free_str(std::ptr::null_mut());
            howdah_free(std::ptr::null_mut());
            let c = howdah_init(std::ptr::null(), 0);
            howdah_request_begin(c, std::ptr::null(), 0, std::ptr::null());
            assert_eq!(howdah_feed(c, std::ptr::null(), 0), 0);
            howdah_free(c);
        }
    }
}
