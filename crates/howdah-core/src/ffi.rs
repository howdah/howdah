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

use crate::config::{Config, Mode};
use crate::input::InputState;
use crate::inspect::{class_rule, scan, InspectClass, Source};
use crate::limits::{LimitHit, RuleId, Severity};
use crate::log::{log_line, new_request_id, EventRecord};
use crate::multipart::{Event, MultipartState};
use crate::rules::{decide, Action};
use crate::sinks::{command_allowed, include_allowed, unserialize_classes, SinkId};

/// Action codes returned over the ABI. Pinned: Allow=0, Log=1, Block=2.
pub const HOWDAH_ALLOW: i32 = 0;
pub const HOWDAH_LOG: i32 = 1;
pub const HOWDAH_BLOCK: i32 = 2;

/// Input sources for `howdah_inspect_value`.
pub const HOWDAH_SRC_GET: i32 = 0;
pub const HOWDAH_SRC_POST: i32 = 1;
pub const HOWDAH_SRC_COOKIE: i32 = 2;
pub const HOWDAH_SRC_PATH: i32 = 3;

// Layer-3 sink ids (howdah_sink_check).
pub const HOWDAH_SINK_COMMAND_EXEC: i32 = 0;
pub const HOWDAH_SINK_INCLUDE: i32 = 1;
pub const HOWDAH_SINK_EVAL: i32 = 2;
pub const HOWDAH_SINK_UNSERIALIZE: i32 = 3;

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
    /// True while the only stashed line is the self_test marker (a real hit replaces it).
    selftest_only: bool,
    /// Per-request input-shape counters (vars, headers); reset in `request_begin`.
    input: InputState,
    /// Layer-2 per-request aggregate scan budget; reset in `request_begin`.
    inspect_values: usize,
    inspect_bytes: usize,
    /// Layer-3 per-hit sink line; dedicated slot, never shares `log`/`worst`.
    sink_log: Option<String>,
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
        RuleId::MaxInputVars => "too many input variables",
        RuleId::MaxInputNestingDepth => "input array nesting too deep",
        RuleId::MaxInputKeyBytes => "input variable key too long",
        RuleId::MaxRequestHeaders => "too many request headers",
        RuleId::MaxRequestHeaderBytes => "request header too large",
        RuleId::SqlInjection => "possible SQL injection in request input",
        RuleId::PathTraversal => "possible path traversal in request input",
        RuleId::CommandInjection => "possible command injection in request input",
        RuleId::CommandExec => "command execution sink called with a disallowed command",
        RuleId::Include => "file include sink called with a disallowed path",
        RuleId::Eval => "eval sink invoked",
        RuleId::Unserialize => "unserialize sink invoked on untrusted data",
    }
}

/// Current UTC time as Unix epoch milliseconds, decimal string. The core has no
/// clock of its own; this stamps every stashed log record so emitted JSON lines
/// always carry a real timestamp.
fn now() -> String {
    // wasm32-unknown-unknown has no wall clock (SystemTime::now panics); the
    // browser demo does not need a real timestamp.
    #[cfg(target_arch = "wasm32")]
    {
        return "0".to_string();
    }
    #[allow(unreachable_code)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
        .to_string()
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
            selftest_only: false,
            input: InputState::new(),
            inspect_values: 0,
            inspect_bytes: 0,
            sink_log: None,
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
        self.fold(hit, a, None);
    }

    /// Fold an already-resolved action into the sticky worst action; log only
    /// on escalation. `reason` overrides the rule's generic description.
    fn fold(&mut self, hit: Option<&LimitHit>, a: Action, reason: Option<&str>) {
        // A real hit always replaces a pending self_test-only line.
        if rank(a) > rank(self.worst) || (self.selftest_only && a != Action::Allow && hit.is_some()) {
            self.selftest_only = false;
            self.worst = a;
            if let Some(h) = hit {
                self.stash(h.rule, a, reason.unwrap_or_else(|| describe(h.rule)));
            }
        }
    }

    /// Like `apply`, but resolved against an explicit mode and override map
    /// (Layer 2 uses its own independent mode, not the global one).
    fn apply_with_mode(
        &mut self,
        hit: &LimitHit,
        mode: crate::config::Mode,
        overrides: &std::collections::BTreeMap<RuleId, crate::config::Mode>,
        reason: &str,
    ) -> Action {
        let a = decide(Some(hit), mode, overrides);
        self.fold(Some(hit), a, Some(reason));
        a
    }

    /// Scan one request value (Layer 2). The value is inspected, never logged;
    /// only the (truncated) variable name appears in the reason. Returns the
    /// action for THIS value (the caller decides what to do with it).
    fn inspect_value(&mut self, source: Source, name: &[u8], val: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let ins = &self.config.inspect;
        if !ins.enabled {
            return Action::Allow;
        }
        let limits = ins.limits;
        if self.inspect_values >= limits.max_values || self.inspect_bytes >= limits.max_total_bytes {
            return Action::Allow;
        }
        self.inspect_values += 1;
        self.inspect_bytes = self.inspect_bytes.saturating_add(val.len().min(limits.max_value_bytes));

        let Some(class) = scan(val, source, &limits) else {
            return Action::Allow;
        };
        if !self.config.inspect.class_enabled(class) {
            return Action::Allow;
        }
        let mode = self.config.inspect.effective_mode(self.config.mode);
        // Off is absolute: no rule_modes override may re-arm the layer.
        if mode == crate::config::Mode::Off {
            return Action::Allow;
        }
        let overrides = self.config.inspect.rule_modes.clone();
        let rule = class_rule(class);
        let class_name = match class {
            InspectClass::SqlInjection => "sql_injection",
            InspectClass::PathTraversal => "path_traversal",
            InspectClass::CommandInjection => "command_injection",
        };
        let src_name = match source {
            Source::Get => "get",
            Source::Post => "post",
            Source::Cookie => "cookie",
            Source::Path => "path",
        };
        let n = &name[..name.len().min(64)];
        let reason = format!("{class_name} pattern in {src_name} variable '{}'", String::from_utf8_lossy(n));
        let hit = LimitHit { rule, severity: Severity::Standard, detail: reason.clone() };
        self.apply_with_mode(&hit, mode, &overrides, &reason)
    }

    /// Layer-3 sink check. `arg` is scanned, never logged. Independent of
    /// `worst`/`log`: a hit goes only to `sink_log`. Include/Eval are
    /// detect-only in 1.2 (clamped to Log even in block mode).
    fn sink_check(&mut self, sink: SinkId, name: &[u8], arg: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = self.config.sinks.effective_mode(sink, self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let sinks = &self.config.sinks;
        let n = String::from_utf8_lossy(&name[..name.len().min(64)]).into_owned();
        let (rule, matched): (RuleId, Option<String>) = match sink {
            SinkId::CommandExec => (
                RuleId::CommandExec,
                (!command_allowed(arg, &sinks.command_exec.allow))
                    .then(|| format!("non-allowlisted command via {n}")),
            ),
            SinkId::Include => (
                RuleId::Include,
                (!sinks.include.allow_paths.is_empty() && !include_allowed(arg, &sinks.include.allow_paths))
                    .then(|| format!("include path outside allowlist via {n}")),
            ),
            SinkId::Eval => (RuleId::Eval, Some(format!("dynamic code evaluation via {n}"))),
            SinkId::Unserialize => {
                let scan = unserialize_classes(arg);
                let allow = &sinks.unserialize.allow_classes;
                let bad = scan.classes.iter().find(|c| !allow.contains(c));
                let m = if scan.capped {
                    Some(format!("unserialize via {n}: too many classes to enumerate (fail closed)"))
                } else {
                    bad.map(|c| format!("unserialize via {n}: class '{c}' not allowlisted"))
                };
                (RuleId::Unserialize, m)
            }
        };
        let Some(reason) = matched else {
            return Action::Allow;
        };
        let mut action = match mode {
            Mode::Block => Action::Block,
            _ => Action::Log,
        };
        if matches!(sink, SinkId::Include | SinkId::Eval) && action == Action::Block {
            action = Action::Log;
        }
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason,
        };
        self.sink_log = Some(log_line(&rec));
        action
    }

    /// Record the self-test marker: always a Log event, NEVER a block. A
    /// Standard hit would block in `mode = block`, so clamp Block to Log. Off
    /// (global or per-rule) stays silent. Never masks an already-decided Block.
    fn selftest(&mut self) {
        let hit = crate::limits::selftest_hit();
        let a = decide(Some(&hit), self.config.mode, &self.config.rule_modes);
        // Only when nothing else was flagged: never displace, suppress or
        // downgrade a real detection. A later real hit replaces this line.
        // (Any client can trigger one self_test line per request by sending
        // the marker; low risk, by design.)
        if a == Action::Allow || self.worst != Action::Allow {
            return;
        }
        self.selftest_only = true;
        self.worst = Action::Log;
        self.stash(RuleId::SelfTest, Action::Log, describe(RuleId::SelfTest));
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

    fn input_var(&mut self, name: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        self.input.note_var(name);
        let hit = self.config.limits.check_input(&self.input);
        self.apply(hit.as_ref());
        self.worst
    }

    fn request_header(&mut self, name_len: usize, value_len: usize) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        self.input.note_header(name_len, value_len);
        let hit = self.config.limits.check_input(&self.input);
        self.apply(hit.as_ref());
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
        c.selftest_only = false;
        c.input = InputState::new();
        c.inspect_values = 0;
        c.inspect_bytes = 0;
        c.sink_log = None;
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

/// Record one request variable name (GET/POST/COOKIE key) and run the
/// input-shape checks. The name is inspected, never logged. Returns the most
/// severe action so far this request (0 Allow, 1 Log, 2 Block). Panic or NULL
/// ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live; `name` NULL or valid for `name_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn howdah_input_var(ctx: *mut howdah_ctx, name: *const c_char, name_len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let bytes: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        code((*ctx).input_var(bytes))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Inspect one request value (Layer 2). `source` is a `HOWDAH_SRC_*` code.
/// The value is scanned binary-safe and NEVER logged; the log carries only the
/// class, source and (truncated) variable name. Resolved against the
/// independent `[inspect]` mode, so a global `block` never arms blocking here.
/// Returns the action for this value (0 Allow, 1 Log, 2 Block); it never drops
/// the variable. NULL ctx, unknown source or panic returns 0.
///
/// # Safety
/// `ctx` NULL or live; `name`/`val` NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_inspect_value(
    ctx: *mut howdah_ctx,
    source: i32,
    name: *const c_char,
    name_len: usize,
    val: *const c_char,
    val_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let src = match source {
        HOWDAH_SRC_GET => Source::Get,
        HOWDAH_SRC_POST => Source::Post,
        HOWDAH_SRC_COOKIE => Source::Cookie,
        HOWDAH_SRC_PATH => Source::Path,
        _ => return HOWDAH_ALLOW,
    };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let n: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        let v: &[u8] = if val.is_null() || val_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(val as *const u8, val_len)
        };
        code((*ctx).inspect_value(src, n, v))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Record one request header by LENGTHS ONLY (names and values never cross the
/// ABI) and run the header count/size checks. Returns the most severe action so
/// far this request (0 Allow, 1 Log, 2 Block). Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_request_header(ctx: *mut howdah_ctx, name_len: usize, value_len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).request_header(name_len, value_len))));
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

/// Layer-3 sink check: `sink` is a `HOWDAH_SINK_*` id, `name` the guarded
/// function/construct, `arg` the sink argument (binary-safe; scanned, never
/// logged). Returns 0 Allow / 1 Log / 2 Block. NULL ctx, unknown sink or panic
/// returns 0 (fail-open: a sink-check bug must never neutralize a legitimate
/// call). Include/eval never exceed Log. A hit is retrievable with
/// `howdah_take_sink_log_line`.
///
/// # Safety
/// `ctx` NULL or live; `name`/`arg` NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_check(
    ctx: *mut howdah_ctx,
    sink: i32,
    name: *const c_char,
    name_len: usize,
    arg: *const c_char,
    arg_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let id = match sink {
        HOWDAH_SINK_COMMAND_EXEC => SinkId::CommandExec,
        HOWDAH_SINK_INCLUDE => SinkId::Include,
        HOWDAH_SINK_EVAL => SinkId::Eval,
        HOWDAH_SINK_UNSERIALIZE => SinkId::Unserialize,
        _ => return HOWDAH_ALLOW,
    };
    let r = catch_unwind(AssertUnwindSafe(|| {
        let n: &[u8] = if name.is_null() || name_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(name as *const u8, name_len)
        };
        let a: &[u8] = if arg.is_null() || arg_len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(arg as *const u8, arg_len)
        };
        code((*ctx).sink_check(id, n, a))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Take the pending sink log line, or NULL if none. Same ownership contract as
/// `howdah_take_log_line`; free with `howdah_free_str`.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_take_sink_log_line(ctx: *mut howdah_ctx) -> *mut c_char {
    if ctx.is_null() {
        return std::ptr::null_mut();
    }
    catch_unwind(AssertUnwindSafe(|| match (*ctx).sink_log.take() {
        Some(s) => CString::new(s.replace('\0', ""))
            .map(|c| c.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Report that the request carried the self-test marker (see
/// `limits::SELFTEST_FIELD`): stashes one `self_test` Log line, never a block.
/// Returns the resulting action code (Log=1; 0 if Howdah is off, the ctx is
/// NULL or a panic occurred; 2 if the request was already blocked).
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_selftest(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        (*ctx).selftest();
        code((*ctx).worst)
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        code((*ctx).worst)
    })
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
    fn selftest_logs_in_detect_and_never_blocks_even_in_block_mode() {
        for mode in ["detect", "block"] {
            let c = init(&format!("mode = \"{mode}\""));
            begin(c);
            feed(c, BODY);
            assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_LOG, "{mode}");
            let line = take(c).expect("self_test line");
            assert!(line.contains("\"rule\":\"self_test\""), "{line}");
            assert!(line.contains("\"action\":\"log\""), "{line}");
            assert_eq!(unsafe { howdah_request_end(c) }, HOWDAH_LOG);
            unsafe { howdah_free(c) };
        }
    }

    #[test]
    fn selftest_silent_when_off_and_null_safe() {
        let c = init("mode = \"off\"");
        begin(c);
        assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
        assert_eq!(unsafe { howdah_selftest(std::ptr::null_mut()) }, HOWDAH_ALLOW);
    }

    #[test]
    fn selftest_then_real_standard_hit_logs_the_real_rule() {
        let c = init("mode = \"detect\"");
        begin(c);
        feed(c, BODY);
        assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_LOG);
        // Malformed continuation (garbage after a delimiter) then truncation.
        feed(c, b"--Bzzz");
        unsafe { howdah_request_end(c) };
        let line = take(c).unwrap();
        assert!(line.contains("malformed_multipart"), "{line}");
        assert!(!line.contains("self_test"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn selftest_after_real_log_hit_preserves_it() {
        let c = init("mode = \"detect\"");
        begin(c);
        feed(c, b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx");
        unsafe { howdah_request_end(c) }; // truncated -> malformed Log
        unsafe { howdah_selftest(c) };
        let line = take(c).unwrap();
        assert!(line.contains("malformed_multipart"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn selftest_does_not_mask_a_block() {
        let c = init("mode = \"detect\"\n[limits]\nmax_parts = 1");
        begin(c);
        let two = b"--B\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx\r\n--B\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nx\r\n";
        assert_eq!(feed(c, two), HOWDAH_BLOCK);
        assert_eq!(unsafe { howdah_selftest(c) }, HOWDAH_BLOCK);
        assert!(take(c).unwrap().contains("max_parts"));
        unsafe { howdah_free(c) };
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
    fn input_var_flood_blocks_and_logs_json() {
        let c = init("[limits]\nmax_input_vars = 2\n");
        begin(c);
        for n in ["a", "b", "c"] {
            unsafe { howdah_input_var(c, n.as_ptr() as _, n.len()) };
        }
        let line = take(c).unwrap();
        assert!(line.contains("\"rule\":\"max_input_vars\""), "{line}");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn new_entrypoints_null_and_panic_safe() {
        assert_eq!(unsafe { howdah_input_var(std::ptr::null_mut(), std::ptr::null(), 0) }, 0);
        assert_eq!(unsafe { howdah_request_header(std::ptr::null_mut(), 0, 0) }, 0);
        let c = init("");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(unsafe { howdah_input_var(c, b"a".as_ptr() as _, 1) }, 0);
        assert_eq!(unsafe { howdah_request_header(c, 1, 1) }, 0);
        FORCE_PANIC.with(|f| f.set(false));
        unsafe { howdah_free(c) };
    }

    fn inspect(c: *mut howdah_ctx, src: i32, name: &str, val: &[u8]) -> i32 {
        unsafe { howdah_inspect_value(c, src, name.as_ptr() as _, name.len(), val.as_ptr() as _, val.len()) }
    }

    #[test]
    fn inspect_logs_under_global_block_when_inspect_detect() {
        let c = init("mode = \"block\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_LOG);
        let line = take(c).expect("log line");
        assert!(line.contains("\"rule\":\"sql_injection\""), "{line}");
        assert!(line.contains("\"action\":\"log\""), "{line}");
        assert!(line.contains("sql_injection pattern in get variable 'q'"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_blocks_only_when_inspect_mode_block() {
        let c = init("[inspect]\nmode = \"block\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_BLOCK);
        let line = take(c).expect("log line");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_log_omits_value() {
        let c = init("");
        begin(c);
        inspect(c, HOWDAH_SRC_POST, "q", b"' OR 1=1 --");
        let line = take(c).expect("log line");
        assert!(line.contains('q') && line.contains("sql_injection"), "{line}");
        assert!(!line.contains("OR 1=1") && !line.contains("1=1"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_disabled_is_allow() {
        let c = init("[inspect]\nenabled = false");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn aggregate_budget_caps_total_scan() {
        let c = init("[inspect.limits]\nmax_values = 3");
        begin(c);
        for _ in 0..3 {
            assert_eq!(inspect(c, HOWDAH_SRC_GET, "a", b"hello"), HOWDAH_ALLOW);
        }
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        // a new request resets the budget
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_LOG);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn global_off_silences_inspect() {
        let c = init("mode = \"off\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn global_off_overrides_inspect_rule_modes() {
        let c = init("mode = \"off\"\n[inspect.rule_modes]\nsql_injection = \"block\"");
        begin(c);
        assert_eq!(inspect(c, HOWDAH_SRC_GET, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert!(take(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn inspect_unknown_source_and_null_are_allow() {
        assert_eq!(unsafe { howdah_inspect_value(std::ptr::null_mut(), 0, std::ptr::null(), 0, std::ptr::null(), 0) }, 0);
        let c = init("");
        begin(c);
        assert_eq!(inspect(c, 99, "q", b"' OR 1=1 --"), HOWDAH_ALLOW);
        assert_eq!(unsafe { howdah_inspect_value(c, 0, std::ptr::null(), 0, std::ptr::null(), 0) }, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
    }

    fn sink(c: *mut howdah_ctx, id: i32, name: &str, arg: &[u8]) -> i32 {
        unsafe { howdah_sink_check(c, id, name.as_ptr() as _, name.len(), arg.as_ptr() as _, arg.len()) }
    }
    fn take_sink(c: *mut howdah_ctx) -> Option<String> {
        unsafe {
            let p = howdah_take_sink_log_line(c);
            if p.is_null() {
                return None;
            }
            let s = CStr::from_ptr(p).to_string_lossy().into_owned();
            howdah_free_str(p);
            Some(s)
        }
    }

    #[test]
    fn sink_logs_under_global_block_when_sinks_detect() {
        let c = init("mode = \"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_LOG);
        let line = take_sink(c).expect("sink line");
        assert!(line.contains("\"rule\":\"command_exec\""), "{line}");
        assert!(line.contains("\"action\":\"log\""), "{line}");
        assert!(line.contains("system"), "{line}");
        assert!(take(c).is_none(), "layer-1/2 slot untouched");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_blocks_only_when_sink_mode_block() {
        let c = init("[sinks.command_exec]\nmode=\"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("sink line");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn command_allow_silences() {
        let c = init("[sinks.command_exec]\nmode=\"block\"\nallow=[\"id\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_log_omits_argument() {
        let c = init("");
        begin(c);
        sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"cat /etc/shadow");
        let line = take_sink(c).expect("sink line");
        assert!(line.contains("system") && line.contains("command_exec"), "{line}");
        assert!(!line.contains("shadow") && !line.contains("/etc/"), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn multiple_sink_hits_each_emit() {
        let c = init("[limits]\nmax_input_vars = 2\n");
        begin(c);
        for n in ["a", "b", "c"] {
            unsafe { howdah_input_var(c, n.as_ptr() as _, n.len()) };
        }
        for (i, a) in [&b"id"[..], b"ls", b"whoami"].iter().enumerate() {
            assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", a), HOWDAH_LOG, "{i}");
            assert!(take_sink(c).is_some(), "hit {i} dropped");
            assert!(take_sink(c).is_none());
        }
        let l1 = take(c).expect("layer-1 line survives sink hits");
        assert!(l1.contains("max_input_vars"), "{l1}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_log_reset_on_request_begin() {
        let c = init("");
        begin(c);
        sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id");
        begin(c);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn unserialize_off_by_default_is_allow() {
        let c = init("");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"O:8:\"stdClass\":0:{}"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn unserialize_class_logged_unless_allowed() {
        let c = init("[sinks.unserialize]\nmode=\"block\"\nallow_classes=[\"Good\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"O:4:\"Good\":0:{}"), HOWDAH_ALLOW);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"a:1:{i:0;i:1;}"), HOWDAH_ALLOW);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", b"O:3:\"Bad\":0:{}"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("line");
        assert!(line.contains("Bad") && line.contains("\"rule\":\"unserialize\""), "{line}");
        unsafe { howdah_free(c) };
    }

    #[test]
    fn include_eval_detect_only_even_in_block() {
        let c = init("[sinks.include]\nmode=\"block\"\nallow_paths=[\"/var/www/app\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/etc/passwd"), HOWDAH_LOG);
        let line = take_sink(c).expect("line");
        assert!(line.contains("\"action\":\"log\"") && line.contains("\"rule\":\"include\""), "{line}");
        assert!(!line.contains("passwd"), "{line}");
        unsafe { howdah_free(c) };
        let c = init("[sinks.eval]\nmode=\"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_EVAL, "eval", b"1"), HOWDAH_LOG);
        assert!(take_sink(c).unwrap().contains("\"rule\":\"eval\""));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn include_inert_without_allow_paths() {
        let c = init("");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/etc/passwd"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn unserialize_capped_fails_closed() {
        let c = init("[sinks.unserialize]\nmode=\"block\"\nallow_classes=[\"A\"]");
        begin(c);
        let payload = "O:1:\"A\":0:{}".repeat(70);
        assert_eq!(sink(c, HOWDAH_SINK_UNSERIALIZE, "unserialize", payload.as_bytes()), HOWDAH_BLOCK);
        assert!(take_sink(c).is_some());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn global_off_silences_sinks() {
        let c = init("mode = \"off\"\n[sinks.command_exec]\nmode=\"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_check_panic_fails_open() {
        let c = init("[sinks.command_exec]\nmode=\"block\"");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(sink(c, HOWDAH_SINK_COMMAND_EXEC, "system", b"id"), HOWDAH_ALLOW);
        FORCE_PANIC.with(|f| f.set(false));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_unknown_id_and_null_are_allow() {
        assert_eq!(unsafe { howdah_sink_check(std::ptr::null_mut(), 0, std::ptr::null(), 0, std::ptr::null(), 0) }, 0);
        assert!(unsafe { howdah_take_sink_log_line(std::ptr::null_mut()) }.is_null());
        let c = init("");
        begin(c);
        assert_eq!(sink(c, 99, "x", b"id"), HOWDAH_ALLOW);
        assert_eq!(sink(c, -1, "x", b"id"), HOWDAH_ALLOW);
        assert_eq!(unsafe { howdah_sink_check(c, 0, std::ptr::null(), 0, std::ptr::null(), 0) }, HOWDAH_LOG);
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
