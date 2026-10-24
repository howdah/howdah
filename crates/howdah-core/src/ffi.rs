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
use crate::sinks::ssrf::{classify_ip, decode_literal_ip, host_allowed, parse_host, HostForm, IpRepr};
use crate::sinks::{command_allowed, include_allowed, phar_allowed, unserialize_classes, SinkId};

/// Action codes returned over the ABI. Pinned: Allow=0, Log=1, Block=2.
pub const HOWDAH_ALLOW: i32 = 0;
pub const HOWDAH_LOG: i32 = 1;
pub const HOWDAH_BLOCK: i32 = 2;

/// Part kinds for `howdah_part`: a plain form field, or a file upload.
pub const HOWDAH_PART_FIELD: i32 = 0;
pub const HOWDAH_PART_FILE: i32 = 1;

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
pub const HOWDAH_SINK_PHAR: i32 = 4;
pub const HOWDAH_SINK_SSRF: i32 = 5;

// Layer-4 behavior facets (howdah_behavior_armed).
pub const HOWDAH_BEHAVIOR_EXEC_DIR: i32 = 0;
pub const HOWDAH_BEHAVIOR_BINARY: i32 = 1;
pub const HOWDAH_BEHAVIOR_EGRESS: i32 = 2;
pub const HOWDAH_BEHAVIOR_PHP_WRITE: i32 = 3;

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
        RuleId::Phar => "phar:// stream wrapper access outside the allowlist",
        RuleId::Ssrf => "outbound request to a disallowed destination",
        RuleId::UploadExec => "possible executable or server-side code in an uploaded file",
        RuleId::UnexpectedBinary => "unexpected binary executed following an upload",
        RuleId::UnexpectedEgress => "possible unexpected outbound connection",
        RuleId::PhpWrite => "PHP file written to disk",
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
    /// `worst`/`log`: a hit goes only to `sink_log`. All sinks honor block;
    /// include/eval block is enforced by the C opcode handler (PHP 7.0+); PHP
    /// 5.x has no such handler and uses a compile-time swap instead.
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
            // Never log the path: only the guarded function name.
            SinkId::Phar => (
                RuleId::Phar,
                (!phar_allowed(arg, &sinks.phar.allow_paths))
                    .then(|| format!("phar stream access outside allowlist via {n}")),
            ),
            // SSRF has its own entry point (howdah_sink_check_ssrf).
            SinkId::Ssrf => (RuleId::Ssrf, None),
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
        let action = match mode {
            Mode::Block => Action::Block,
            _ => Action::Log,
        };
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

    /// Layer-4 behavior check. Reuses `sink_log`. `hit` runs the classifier
    /// against the config; the target is never logged (the classifier's
    /// detail is a dir/host/basename only).
    fn behavior_check(
        &mut self,
        hit: impl FnOnce(&crate::config::BehaviorConfig) -> Option<crate::behavior::BehaviorHit>,
    ) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = self.config.behavior.effective_mode(self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let Some(crate::behavior::BehaviorHit { rule, detail }) = hit(&self.config.behavior) else {
            return Action::Allow;
        };
        // Observe is propose-only: never block, and mark the line as a proposal.
        let observe = self.config.behavior.observe;
        let action = match mode {
            Mode::Block if !observe => Action::Block,
            _ => Action::Log,
        };
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason: if observe { format!("proposed: {detail}") } else { detail },
        };
        self.sink_log = Some(log_line(&rec));
        action
    }

    /// SSRF check; `recs` is a multiple of 17 bytes (see `howdah_sink_check_ssrf`).
    fn sink_check_ssrf(&mut self, scheme: &[u8], host: &[u8], port: u16, recs: &[u8]) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        let mode = self.config.sinks.effective_mode(SinkId::Ssrf, self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let literal = decode_literal_ip(host);
        let mut resolved: Vec<IpRepr> = Vec::new();
        #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)] // as_chunks needs Rust 1.88+
        for r in recs.chunks_exact(17) {
            let Ok(r): Result<&[u8; 17], _> = r.try_into() else { continue };
            match r[0] {
                4 => resolved.push(IpRepr::V4([r[1], r[2], r[3], r[4]])),
                6 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&r[1..17]);
                    resolved.push(IpRepr::V6(a));
                }
                _ => {}
            }
        }
        if host_allowed(host, &resolved, literal, &self.config.sinks.ssrf.allow_hosts) {
            return Action::Allow;
        }
        let hit = literal
            .into_iter()
            .chain(resolved.iter().copied())
            .find_map(|ip| classify_ip(ip).map(|c| (ip, c)));
        let Some((ip, class)) = hit else {
            return Action::Allow;
        };
        let ip_s = match ip {
            IpRepr::V4(a) => std::net::Ipv4Addr::from(a).to_string(),
            IpRepr::V6(a) => std::net::Ipv6Addr::from(a).to_string(),
        };
        let clip = |b: &[u8]| -> String {
            String::from_utf8_lossy(&b[..b.len().min(255)])
                .chars()
                .filter(|c| !c.is_control())
                .collect()
        };
        // Defense in depth: log only the bare host. Cut at the first
        // /, ? or #, then drop userinfo.
        let bare_host = {
            let h = clip(host);
            // Cut first (an '@' in path/query is not userinfo), then take the
            // text after the LAST '@' of the authority (userinfo may hold '@').
            let end = h.find(['/', '?', '#']).unwrap_or(h.len());
            let auth = &h[..end];
            auth.rsplit_once('@').map_or(auth, |(_, host)| host).to_string()
        };
        let reason = format!(
            "ssrf via {}: host={} port={} ip={} class={}",
            clip(scheme),
            bare_host,
            port,
            ip_s,
            class.as_str()
        );
        let action = if mode == Mode::Block { Action::Block } else { Action::Log };
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule: RuleId::Ssrf,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason,
        };
        self.sink_log = Some(log_line(&rec));
        action
    }

    /// A host too long to resolve (>256 bytes; DNS max is 253) is never
    /// legitimate and can hide a zero-padded numeric IP, so it is treated as
    /// suspicious per the effective mode. The host bytes are never logged.
    fn sink_ssrf_oversize(&mut self) -> Action {
        let mode = self.config.sinks.effective_mode(SinkId::Ssrf, self.config.mode);
        if mode == Mode::Off {
            return Action::Allow;
        }
        let action = if mode == Mode::Block { Action::Block } else { Action::Log };
        let rec = EventRecord {
            ts: now(),
            request_id: self.request_id.clone(),
            rule: RuleId::Ssrf,
            action,
            client_ip: self.meta.client_ip.clone(),
            method: self.meta.method.clone(),
            uri: self.meta.uri.clone(),
            reason: "ssrf: oversize host (>256 bytes), not resolvable - treated as suspicious".to_string(),
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

    /// One already-parsed multipart part (the PHP glue's `FORMDATA` /
    /// `FILE_START`). Counting happens in `MultipartState::note_part` and does
    /// not depend on any byte parsing, so part data can never suppress it.
    fn part(&mut self, kind: i32, name_len: usize, filename_len: usize) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        if self.worst == Action::Block {
            return self.worst; // already blocked: every further part is refused
        }
        let Some(state) = self.state.as_mut() else {
            return self.worst; // no request in progress: fail-open
        };
        let filename = (kind == HOWDAH_PART_FILE).then_some(filename_len);
        state.note_part(name_len, filename);
        let hit = self.config.limits.check(state, &Event::PartStart);
        self.apply(hit.as_ref());
        self.worst
    }

    /// `len` bytes of part data (a `FORMDATA` value or a `FILE_DATA` chunk).
    fn part_data(&mut self, len: usize) -> Action {
        #[cfg(test)]
        if tests::FORCE_PANIC.with(|f| f.get()) {
            panic!("injected test panic");
        }
        if self.worst == Action::Block {
            return self.worst;
        }
        let Some(state) = self.state.as_mut() else {
            return self.worst;
        };
        state.note_data(len as u64);
        let hit = self.config.limits.check(state, &Event::PartData { len: len as u64 });
        self.apply(hit.as_ref());
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

/// Report one already-parsed multipart part: `kind` is `HOWDAH_PART_FIELD` or
/// `HOWDAH_PART_FILE`; `name_len` is the form field name's byte length and
/// `filename_len` the upload filename's (ignored for a field). This is how the
/// PHP glue reports parts: PHP hands it parsed events, never request bytes, so
/// nothing in the part data can influence the count. Returns the most severe
/// action so far (0 Allow, 1 Log, 2 Block); `Block` for a part means the
/// caller must not let PHP allocate it. Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_part(
    ctx: *mut howdah_ctx,
    kind: i32,
    name_len: usize,
    filename_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).part(kind, name_len, filename_len))));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Report `len` bytes of data for the current part (a field value or one file
/// chunk). Only the length is used, so the bytes are not passed. Returns the
/// most severe action so far. Panic or NULL ctx returns 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_part_data(ctx: *mut howdah_ctx, len: usize) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).part_data(len))));
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
/// call). A hit is retrievable with `howdah_take_sink_log_line`.
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
        HOWDAH_SINK_PHAR => SinkId::Phar,
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

/// 1 iff the given Layer-4 facet (`HOWDAH_BEHAVIOR_*`) is armed; NULL ctx,
/// unknown facet or panic is 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_armed(ctx: *mut howdah_ctx, facet: i32) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        let b = &c.config.behavior;
        if b.effective_mode(c.config.mode) == Mode::Off {
            return 0;
        }
        let scoped = b.observe || !b.deny_exec_dirs.is_empty();
        i32::from(match facet {
            HOWDAH_BEHAVIOR_EXEC_DIR => !b.deny_exec_dirs.is_empty(),
            HOWDAH_BEHAVIOR_BINARY => scoped || !b.allow_exec_binaries.is_empty(),
            HOWDAH_BEHAVIOR_EGRESS => scoped || !b.allow_egress_hosts.is_empty(),
            HOWDAH_BEHAVIOR_PHP_WRITE => b.deny_php_writes,
            _ => false,
        })
    }))
    .unwrap_or(0)
}

/// 1 iff the behavior egress facet is armed (for the widened SSRF hook).
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_egress_active(ctx: *mut howdah_ctx) -> i32 {
    howdah_behavior_armed(ctx, HOWDAH_BEHAVIOR_EGRESS)
}

/// Layer-4: script about to execute at realpath `path`. 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; `path` NULL or valid for `path_len`.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_exec_dir(
    ctx: *mut howdah_ctx,
    path: *const c_char,
    path_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let p = copy_str(path, path_len);
        code((*ctx).behavior_check(|cfg| crate::behavior::exec_dir_hit(&p, cfg)))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Layer-4: caller spawning program `prog`. 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_binary(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    prog: *const c_char,
    prog_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let p = copy_str(prog, prog_len);
        code((*ctx).behavior_check(|cfg| crate::behavior::binary_hit(&c, &p, cfg)))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Layer-4: caller connecting out to `host`. 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_egress(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    host: *const c_char,
    host_len: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let h = copy_str(host, host_len);
        code((*ctx).behavior_check(|cfg| crate::behavior::egress_hit(&c, &h, cfg)))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// Layer-4: caller opening `target`; `is_write_mode` non-zero for write modes.
/// 0/1/2; fail-open.
///
/// # Safety
/// `ctx` NULL or live; pointers NULL or valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn howdah_behavior_check_php_write(
    ctx: *mut howdah_ctx,
    caller: *const c_char,
    caller_len: usize,
    target: *const c_char,
    target_len: usize,
    is_write_mode: i32,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = copy_str(caller, caller_len);
        let t = copy_str(target, target_len);
        code((*ctx).behavior_check(|cfg| crate::behavior::php_write_hit(&c, &t, is_write_mode != 0, cfg)))
    }))
    .unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// 1 iff SSRF guarding is armed (effective mode != off); NULL ctx or panic is
/// 0. Never stashes a log line. Lets the shim skip DNS work when disarmed.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_ssrf_armed(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        i32::from(c.config.sinks.effective_mode(SinkId::Ssrf, c.config.mode) != Mode::Off)
    }))
    .unwrap_or(0)
}

/// 1 iff the given sink (`HOWDAH_SINK_*`) is armed (effective mode != off);
/// NULL ctx, unknown sink or panic is 0. Never stashes a log line. Used by the
/// glue to decide, once per process, whether to install the phar/ssrf hooks.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_armed(ctx: *mut howdah_ctx, sink: i32) -> i32 {
    if ctx.is_null() {
        return 0;
    }
    let id = match sink {
        HOWDAH_SINK_COMMAND_EXEC => SinkId::CommandExec,
        HOWDAH_SINK_INCLUDE => SinkId::Include,
        HOWDAH_SINK_EVAL => SinkId::Eval,
        HOWDAH_SINK_UNSERIALIZE => SinkId::Unserialize,
        HOWDAH_SINK_PHAR => SinkId::Phar,
        HOWDAH_SINK_SSRF => SinkId::Ssrf,
        _ => return 0,
    };
    catch_unwind(AssertUnwindSafe(|| {
        let c = &*ctx;
        i32::from(c.config.sinks.effective_mode(id, c.config.mode) != Mode::Off)
    }))
    .unwrap_or(0)
}

/// SSRF decision for one intercepted outbound call. `ips` points to
/// `ips_count` fixed 17-byte records `[family (4|6)][16 address bytes]` (a v4
/// uses the first 4). Returns 0 Allow / 1 Log / 2 Block; NULL ctx, malformed
/// input or panic is 0 (fail-open). The log line carries scheme/host/port/
/// matched-ip/class only (in `reason`), never userinfo/path/query.
///
/// # Safety
/// `ctx` NULL or live; each pointer NULL or valid for its length (`ips`: 17 *
/// `ips_count` bytes).
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_check_ssrf(
    ctx: *mut howdah_ctx,
    scheme: *const c_char,
    scheme_len: usize,
    host: *const c_char,
    host_len: usize,
    port: u16,
    ips: *const u8,
    ips_count: usize,
) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| {
        let sl = |p: *const c_char, n: usize| -> &[u8] {
            if p.is_null() || n == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(p as *const u8, n)
            }
        };
        let recs: &[u8] = if ips.is_null() || ips_count == 0 {
            &[]
        } else {
            match ips_count.checked_mul(17) {
                Some(total) if total <= (1 << 24) => std::slice::from_raw_parts(ips, total),
                _ => return HOWDAH_ALLOW,
            }
        };
        code((*ctx).sink_check_ssrf(sl(scheme, scheme_len), sl(host, host_len), port, recs))
    }));
    r.unwrap_or_else(|_| {
        report_panic(ctx);
        HOWDAH_ALLOW
    })
}

/// SSRF parse seam: parse the target of an intercepted outbound call so the C
/// shim never parses URLs itself. `scheme_required != 0` selects
/// `HostForm::SchemeRequired` (URL-only sinks), else `BareHostOk` (fsockopen,
/// curl). Returns 2 when the host parsed but is longer than `out_host_cap`
/// (suspicious: nothing is written; call `howdah_sink_ssrf_oversize`). Returns 1 ("act") after writing the clean host (no userinfo/brackets/
/// port, lowercased) to `out_host`, its length to `*out_host_len` and the port
/// (0 if none) to `*out_port`. Returns 0 ("skip") for a non-network target
/// (local path, `unix://`, no scheme when required), any NULL argument, or a
/// panic: fail-open, the call is chained. Return codes: 0 = skip (not a network
/// target), 1 = host written, 2 = oversize (host longer than the buffer; the
/// caller treats it as suspicious via `howdah_sink_ssrf_oversize`).
///
/// # Safety
/// `input` NULL or valid for `input_len` bytes; `out_host` NULL or writable for
/// `out_host_cap` bytes; `out_host_len` / `out_port` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn howdah_ssrf_prepare(
    input: *const u8,
    input_len: usize,
    scheme_required: i32,
    out_host: *mut u8,
    out_host_cap: usize,
    out_host_len: *mut usize,
    out_port: *mut u16,
) -> i32 {
    if input.is_null() || out_host.is_null() || out_host_len.is_null() || out_port.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        let form = if scheme_required != 0 { HostForm::SchemeRequired } else { HostForm::BareHostOk };
        let Some(h) = parse_host(std::slice::from_raw_parts(input, input_len), form) else {
            return 0;
        };
        if h.name.len() > out_host_cap {
            return 2; // oversize: suspicious, see howdah_sink_ssrf_oversize
        }
        std::ptr::copy_nonoverlapping(h.name.as_ptr(), out_host, h.name.len());
        *out_host_len = h.name.len();
        *out_port = h.port.unwrap_or(0);
        1
    }))
    .unwrap_or(0)
}

/// Verdict for an oversize (>cap) SSRF host, called when `howdah_ssrf_prepare`
/// returned 2. 0 Allow (off) / 1 Log / 2 Block per the effective SSRF mode;
/// stashes a log line with no host bytes. NULL ctx or panic is 0.
///
/// # Safety
/// `ctx` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn howdah_sink_ssrf_oversize(ctx: *mut howdah_ctx) -> i32 {
    if ctx.is_null() {
        return HOWDAH_ALLOW;
    }
    let r = catch_unwind(AssertUnwindSafe(|| code((*ctx).sink_ssrf_oversize())));
    r.unwrap_or(HOWDAH_ALLOW)
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

/// The context's parsed `[log]` table (a copy). Rust-only, not part of the C
/// ABI: the glue reads it once at startup to set up the log destination and
/// hook. A NULL ctx or a caught panic gives the defaults, matching the safe
/// defaults an unparseable config falls back to.
///
/// # Safety
/// `ctx` NULL or live.
pub unsafe fn howdah_log_config(ctx: *const howdah_ctx) -> crate::config::LogConfig {
    if ctx.is_null() {
        return crate::config::LogConfig::default();
    }
    catch_unwind(AssertUnwindSafe(|| (*ctx).config.log.clone())).unwrap_or_default()
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

    #[test]
    fn part_entrypoints_null_and_panic_safe() {
        unsafe {
            assert_eq!(howdah_part(std::ptr::null_mut(), HOWDAH_PART_FILE, 1, 1), 0);
            assert_eq!(howdah_part_data(std::ptr::null_mut(), 1), 0);
            // No request begun: fail-open, no state touched.
            let c = init("");
            assert_eq!(howdah_part(c, HOWDAH_PART_FILE, 1, 1), 0);
            assert_eq!(howdah_part_data(c, 1), 0);
            // A panic inside is caught and fails open, and the ctx stays usable.
            howdah_request_begin(c, std::ptr::null(), 0, std::ptr::null());
            FORCE_PANIC.with(|f| f.set(true));
            assert_eq!(howdah_part(c, HOWDAH_PART_FILE, 1, 1), 0);
            assert_eq!(howdah_part_data(c, 1), 0);
            FORCE_PANIC.with(|f| f.set(false));
            assert!(take(c).expect("panic noted").contains("panic caught"));
            for i in 0..300 {
                howdah_part(c, HOWDAH_PART_FILE, 1, 1);
                assert!(i < 200 || howdah_part(c, HOWDAH_PART_FILE, 1, 1) == 2, "part {i}");
            }
            howdah_free(c);
        }
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
    fn include_eval_block_when_armed() {
        // include/eval honor block (enforced by the C opcode handler on PHP 7+);
        // the core returns Block and never logs the path/code (the arg).
        let c = init("[sinks.include]\nmode=\"block\"\nallow_paths=[\"/var/www/app\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/etc/passwd"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("line");
        assert!(line.contains("\"action\":\"block\"") && line.contains("\"rule\":\"include\""), "{line}");
        assert!(!line.contains("passwd"), "{line}");
        unsafe { howdah_free(c) };
        let c = init("[sinks.eval]\nmode=\"block\"");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_EVAL, "eval", b"1"), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("\"action\":\"block\""));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn include_detect_logs_not_block() {
        let c = init("[sinks.include]\nallow_paths=[\"/var/www/app\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_INCLUDE, "include", b"/etc/passwd"), HOWDAH_LOG);
        assert!(take_sink(c).unwrap().contains("\"action\":\"log\""));
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

    fn ssrf_armed(c: *mut howdah_ctx) -> i32 {
        unsafe { howdah_sink_ssrf_armed(c) }
    }
    fn rec4(a: [u8; 4]) -> [u8; 17] {
        let mut r = [0u8; 17];
        r[0] = 4;
        r[1..5].copy_from_slice(&a);
        r
    }
    fn ssrf(c: *mut howdah_ctx, host: &str, ips: &[[u8; 17]]) -> i32 {
        let flat: Vec<u8> = ips.iter().flatten().copied().collect();
        let s = "http";
        unsafe {
            howdah_sink_check_ssrf(c, s.as_ptr() as _, s.len(), host.as_ptr() as _, host.len(), 80, flat.as_ptr(), ips.len())
        }
    }

    #[test]
    fn ssrf_prepare_act_writes_host_and_port() {
        let u = b"http://user:pw@Example.COM:8080/p?q=1";
        let (mut buf, mut n, mut port) = ([0u8; 64], 0usize, 0u16);
        let r = unsafe { howdah_ssrf_prepare(u.as_ptr(), u.len(), 1, buf.as_mut_ptr(), 64, &mut n, &mut port) };
        assert_eq!(r, 1);
        assert_eq!(&buf[..n], b"example.com");
        assert_eq!(port, 8080);
        // bare host ok when scheme not required; no port -> 0
        let b = b"10.0.0.5";
        let r = unsafe { howdah_ssrf_prepare(b.as_ptr(), b.len(), 0, buf.as_mut_ptr(), 64, &mut n, &mut port) };
        assert_eq!((r, &buf[..n], port), (1, &b"10.0.0.5"[..], 0));
    }

    #[test]
    fn ssrf_oversize_follows_mode() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(c) }, HOWDAH_BLOCK);
        let l = unsafe { howdah_take_sink_log_line(c) };
        assert!(!l.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(l) }.to_string_lossy().into_owned();
        assert!(s.contains("oversize host") && s.contains("ssrf"), "{s}");
        unsafe { howdah_free_str(l) };
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        begin(c);
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(c) }, 1);
        unsafe { howdah_free(c) };
        let c = init("");
        begin(c);
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(c) }, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
        assert_eq!(unsafe { howdah_sink_ssrf_oversize(std::ptr::null_mut()) }, 0);
    }

    #[test]
    fn ssrf_prepare_skips() {
        let (mut buf, mut n, mut port) = ([0u8; 8], 0usize, 0u16);
        let mut run = |i: &[u8], f: i32| unsafe {
            howdah_ssrf_prepare(i.as_ptr(), i.len(), f, buf.as_mut_ptr(), 8, &mut n, &mut port)
        };
        assert_eq!(run(b"/etc/passwd", 1), 0); // local path
        assert_eq!(run(b"unix:///var/run/x.sock", 0), 0);
        assert_eq!(run(b"example.com", 1), 0); // no scheme when required
        assert_eq!(run(b"http://averyveryverylonghost.example/", 1), 2); // oversize, not skip
        let r = unsafe {
            howdah_ssrf_prepare(std::ptr::null(), 0, 1, std::ptr::null_mut(), 0, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(r, 0);
    }

    #[test]
    fn phar_arm_block_no_path_in_log() {
        let c = init("[sinks.phar]\nmode=\"block\"\nallow_paths=[\"/srv/app\"]");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_PHAR, "file_get_contents", b"phar:///tmp/secret/evil.phar/x"), HOWDAH_BLOCK);
        let line = take_sink(c).expect("line");
        assert!(line.contains("\"rule\":\"phar\""), "{line}");
        assert!(line.contains("\"action\":\"block\""), "{line}");
        assert!(!line.contains("secret") && !line.contains("evil"), "{line}");
        assert_eq!(sink(c, HOWDAH_SINK_PHAR, "f", b"phar:///srv/app/a.phar"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn phar_default_off_allows() {
        let c = init("");
        begin(c);
        assert_eq!(sink(c, HOWDAH_SINK_PHAR, "f", b"phar:///tmp/x.phar"), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_armed_reflects_mode() {
        let c = init("");
        assert_eq!(ssrf_armed(c), 0);
        unsafe { howdah_free(c) };
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        assert_eq!(ssrf_armed(c), 1);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        let c = init("mode=\"off\"\n[sinks.ssrf]\nmode=\"block\"");
        assert_eq!(ssrf_armed(c), 0);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn behavior_ffi_smoke() {
        let p = "/u/x.php";
        let exec = |c: *mut howdah_ctx| unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) };
        let c = init("[behavior]\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(exec(c), HOWDAH_LOG);
        let line = take_sink(c).unwrap();
        assert!(line.contains("upload_exec") || line.contains("UploadExec"), "{line}");
        assert!(!line.contains("x.php"));
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(exec(c), HOWDAH_BLOCK);
        assert!(take_sink(c).is_some());
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        let o = "/safe/x.php";
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(c, o.as_ptr() as _, o.len()) }, HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(std::ptr::null_mut(), p.as_ptr() as _, p.len()) }, 0);
    }

    #[test]
    fn behavior_observe_never_blocks_and_proposes() {
        let p = "/u/x.php";
        let c = init("[behavior]\nobserve=true\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) }, HOWDAH_LOG);
        let line = take_sink(c).unwrap();
        assert!(line.contains("proposed"), "{line}");
        assert!(!line.contains("x.php"));
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nobserve=true\nallow_exec_binaries=[]");
        let (caller, prog) = ("/var/www/a.php", "/usr/bin/gs");
        let r = unsafe { howdah_behavior_check_binary(c, caller.as_ptr() as _, caller.len(), prog.as_ptr() as _, prog.len()) };
        assert_eq!(r, HOWDAH_LOG);
        assert!(take_sink(c).unwrap().contains("proposed"));
        unsafe { howdah_free(c) };
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        assert_eq!(unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) }, HOWDAH_BLOCK);
        assert!(!take_sink(c).unwrap().contains("proposed"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn behavior_ffi_other_checks_and_armed() {
        let c = init(
            "[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]\nallow_exec_binaries=[\"git\"]\nallow_egress_hosts=[\"ok.example\"]\ndeny_php_writes=true",
        );
        let (caller, prog, host, tgt) = ("/u/a.php", "/bin/nc", "evil.example", "/u/w.php");
        unsafe {
            assert_eq!(howdah_behavior_check_binary(c, caller.as_ptr() as _, caller.len(), prog.as_ptr() as _, prog.len()), HOWDAH_BLOCK);
            assert_eq!(howdah_behavior_check_egress(c, caller.as_ptr() as _, caller.len(), host.as_ptr() as _, host.len()), HOWDAH_BLOCK);
            assert_eq!(howdah_behavior_check_php_write(c, caller.as_ptr() as _, caller.len(), tgt.as_ptr() as _, tgt.len(), 1), HOWDAH_BLOCK);
            assert_eq!(howdah_behavior_check_php_write(c, caller.as_ptr() as _, caller.len(), tgt.as_ptr() as _, tgt.len(), 0), HOWDAH_ALLOW);
            for f in 0..4 {
                assert_eq!(howdah_behavior_armed(c, f), 1);
            }
            assert_eq!(howdah_behavior_egress_active(c), 1);
            assert_eq!(howdah_behavior_armed(c, 99), 0);
            assert_eq!(howdah_behavior_armed(std::ptr::null_mut(), 0), 0);
            howdah_free(c);
        }
        let c = init("");
        unsafe {
            for f in 0..4 {
                assert_eq!(howdah_behavior_armed(c, f), 0);
            }
            assert_eq!(howdah_behavior_egress_active(c), 0);
            howdah_free(c);
        }
        let c = init("mode=\"off\"\n[behavior]\ndeny_exec_dirs=[\"/u\"]");
        unsafe {
            assert_eq!(howdah_behavior_armed(c, HOWDAH_BEHAVIOR_EXEC_DIR), 0);
            howdah_free(c);
        }
    }

    #[test]
    fn behavior_ffi_panic_fails_open() {
        let c = init("[behavior]\nmode=\"block\"\ndeny_exec_dirs=[\"/u\"]");
        FORCE_PANIC.with(|f| f.set(true));
        let p = "/u/x.php";
        let r = unsafe { howdah_behavior_check_exec_dir(c, p.as_ptr() as _, p.len()) };
        FORCE_PANIC.with(|f| f.set(false));
        assert_eq!(r, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn sink_armed_per_sink() {
        let c = init("");
        unsafe {
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_PHAR), 0);
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_SSRF), 0);
            howdah_free(c);
        }
        let c = init("[sinks.phar]\nmode=\"detect\"");
        unsafe {
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_PHAR), 1);
            assert_eq!(howdah_sink_armed(c, HOWDAH_SINK_SSRF), 0);
            assert_eq!(howdah_sink_armed(c, 99), 0);
            howdah_free(c);
            assert_eq!(howdah_sink_armed(std::ptr::null_mut(), HOWDAH_SINK_PHAR), 0);
        }
    }

    #[test]
    fn ssrf_armed_null_ctx_zero() {
        assert_eq!(ssrf_armed(std::ptr::null_mut()), 0);
    }

    #[test]
    fn ssrf_loopback_blocks_when_block() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(ssrf(c, "evil.example", &[rec4([127, 0, 0, 1])]), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("\"action\":\"block\""));
        assert_eq!(ssrf(c, "ok.example", &[rec4([8, 8, 8, 8])]), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        let mut v6 = [0u8; 17];
        v6[0] = 6;
        v6[16] = 1;
        assert_eq!(ssrf(c, "v6.example", &[v6]), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("ip=::1"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_literal_only_no_resolve() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(ssrf(c, "2130706433", &[]), HOWDAH_BLOCK);
        assert!(take_sink(c).unwrap().contains("class=loopback"));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_allow_host_allows() {
        let c = init("[sinks.ssrf]\nmode=\"block\"\nallow_hosts=[\"internal.example\",\"10.0.0.0/8\"]");
        begin(c);
        assert_eq!(ssrf(c, "internal.example", &[rec4([127, 0, 0, 1])]), HOWDAH_ALLOW);
        assert_eq!(ssrf(c, "other.example", &[rec4([10, 1, 2, 3])]), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        assert_eq!(ssrf(c, "other.example", &[rec4([192, 168, 1, 1])]), HOWDAH_BLOCK);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_reason_has_class_not_url() {
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        begin(c);
        assert_eq!(ssrf(c, "user:pw@127.0.0.1/admin?token=secret", &[rec4([127, 0, 0, 1])]), HOWDAH_LOG);
        let line = take_sink(c).unwrap();
        assert!(line.contains("\"rule\":\"ssrf\""), "{line}");
        assert!(line.contains("class=loopback") && line.contains("host=127.0.0.1 port=80 ip=127.0.0.1"), "{line}");
        for bad in ["@", "user", "pw", "/admin", "?", "secret"] {
            assert!(!line.contains(bad), "leaked {bad:?}: {line}");
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_log_host_cut_before_userinfo_strip() {
        let c = init("[sinks.ssrf]\nmode=\"detect\"");
        begin(c);
        let cases = [
            ("evilhost/path?x=a@b.com", "host=evilhost port=80"),
            ("example.com/cb?email=a@b.com", "host=example.com port=80"),
            ("u:p@ss@host", "host=host port=80"),
            ("user:pw@127.0.0.1/admin?token=secret", "host=127.0.0.1 port=80"),
            ("[::1]:80", "host=[::1]:80 port=80"),
        ];
        for (h, want) in cases {
            assert_eq!(ssrf(c, h, &[rec4([127, 0, 0, 1])]), HOWDAH_LOG, "{h}");
            let line = take_sink(c).unwrap();
            assert!(line.contains(want), "{h}: {line}");
            for bad in ["b.com", "@", "ss@", "u:p"] {
                assert!(!line.contains(bad), "{h} leaked {bad:?}: {line}");
            }
        }
        unsafe { howdah_free(c) };
    }

    #[test]
    fn ssrf_resolve_failure_fails_open() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(ssrf(c, "nonexistent.example", &[]), HOWDAH_ALLOW);
        assert!(take_sink(c).is_none());
        unsafe { howdah_free(c) };
    }

    #[test]
    fn panic_in_check_fails_open() {
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        FORCE_PANIC.with(|f| f.set(true));
        assert_eq!(ssrf(c, "2130706433", &[]), HOWDAH_ALLOW);
        FORCE_PANIC.with(|f| f.set(false));
        unsafe { howdah_free(c) };
    }

    #[test]
    fn null_ctx_guarded() {
        let n = std::ptr::null();
        assert_eq!(unsafe { howdah_sink_check_ssrf(std::ptr::null_mut(), n, 0, n, 0, 0, std::ptr::null(), 0) }, HOWDAH_ALLOW);
        let c = init("[sinks.ssrf]\nmode=\"block\"");
        begin(c);
        assert_eq!(unsafe { howdah_sink_check_ssrf(c, n, 0, n, 0, 0, std::ptr::null(), 5) }, HOWDAH_ALLOW);
        unsafe { howdah_free(c) };
    }

    #[test]
    fn log_config_accessor() {
        use crate::config::LogDestination;
        assert_eq!(unsafe { howdah_log_config(std::ptr::null()) }, crate::config::LogConfig::default());
        let c = init("[log]\ndestination = \"syslog\"\nsyslog_ident = \"shop\"\nexec = \"/usr/local/bin/h\"");
        let l = unsafe { howdah_log_config(c) };
        assert_eq!(l.destination(), LogDestination::Syslog);
        assert_eq!(l.ident(), "shop");
        assert_eq!(l.exec.as_deref(), Some("/usr/local/bin/h"));
        unsafe { howdah_free(c) };
        // A config the core rejects falls back to safe defaults, [log] included.
        let c = init("[log]\nexec = \"relative\"");
        assert_eq!(unsafe { howdah_log_config(c) }, crate::config::LogConfig::default());
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
