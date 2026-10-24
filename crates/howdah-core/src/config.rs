//! Configuration loading. Never panics on bad input; `safe_defaults` is always usable.
use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::exceptions::ExceptionEntry;
use crate::inspect::{InspectClass, InspectLimits};
use crate::limits::{Limits, RuleId};
use crate::sinks::SinkId;

/// Global enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Off,
    Detect,
    Block,
}

/// What to enforce when the config file does not parse (`on_invalid_config`).
/// `Block` (the default) is the long-standing fail-toward-protection fallback.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OnInvalidConfig {
    #[default]
    Block,
    Off,
}

/// Logging settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// Log file path; `None` means the host default.
    pub path: Option<String>,
    /// Where event lines go. `None` = `file` (the 1.x behaviour: the
    /// `howdah.log` ini path, else `path`, else stderr).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<LogDestination>,
    /// Syslog facility for `destination = "syslog"`; `None` = `local0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syslog_facility: Option<SyslogFacility>,
    /// Syslog identifier (tag); `None` = `howdah`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syslog_ident: Option<String>,
    /// Absolute path of a program run once per event with the JSON line on
    /// stdin. `None` (the default) = no hook.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec: Option<String>,
    /// Most hook spawns per second per PHP process; `None` = 10.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_rate_limit: Option<u32>,
}

/// `[log] destination`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogDestination {
    /// Append to a file (the `howdah.log` ini path, else `[log] path`); stderr
    /// when neither is set or the file cannot be written.
    File,
    /// Send each line to the local syslog socket (`/dev/log`).
    Syslog,
    /// Write each line to stderr, prefixed `howdah-event `.
    Stderr,
}

/// `[log] syslog_facility`. Only the facilities a userland program may use
/// (no `kern`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFacility {
    User,
    Mail,
    Daemon,
    Auth,
    Syslog,
    Lpr,
    News,
    Uucp,
    Cron,
    Authpriv,
    Ftp,
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl SyslogFacility {
    /// The facility number (RFC 5424 §6.2.1; glibc `LOG_*` >> 3).
    pub fn code(self) -> u8 {
        match self {
            SyslogFacility::User => 1,
            SyslogFacility::Mail => 2,
            SyslogFacility::Daemon => 3,
            SyslogFacility::Auth => 4,
            SyslogFacility::Syslog => 5,
            SyslogFacility::Lpr => 6,
            SyslogFacility::News => 7,
            SyslogFacility::Uucp => 8,
            SyslogFacility::Cron => 9,
            SyslogFacility::Authpriv => 10,
            SyslogFacility::Ftp => 11,
            SyslogFacility::Local0 => 16,
            SyslogFacility::Local1 => 17,
            SyslogFacility::Local2 => 18,
            SyslogFacility::Local3 => 19,
            SyslogFacility::Local4 => 20,
            SyslogFacility::Local5 => 21,
            SyslogFacility::Local6 => 22,
            SyslogFacility::Local7 => 23,
        }
    }

    /// The config spelling (`local0`, `daemon`, ...).
    pub fn name(self) -> &'static str {
        match self {
            SyslogFacility::User => "user",
            SyslogFacility::Mail => "mail",
            SyslogFacility::Daemon => "daemon",
            SyslogFacility::Auth => "auth",
            SyslogFacility::Syslog => "syslog",
            SyslogFacility::Lpr => "lpr",
            SyslogFacility::News => "news",
            SyslogFacility::Uucp => "uucp",
            SyslogFacility::Cron => "cron",
            SyslogFacility::Authpriv => "authpriv",
            SyslogFacility::Ftp => "ftp",
            SyslogFacility::Local0 => "local0",
            SyslogFacility::Local1 => "local1",
            SyslogFacility::Local2 => "local2",
            SyslogFacility::Local3 => "local3",
            SyslogFacility::Local4 => "local4",
            SyslogFacility::Local5 => "local5",
            SyslogFacility::Local6 => "local6",
            SyslogFacility::Local7 => "local7",
        }
    }
}

/// Default `[log] exec_rate_limit` (hook spawns per second per process).
pub const DEFAULT_EXEC_RATE_LIMIT: u32 = 10;
/// Highest accepted `[log] exec_rate_limit`.
pub const MAX_EXEC_RATE_LIMIT: u32 = 100;

impl LogConfig {
    /// Effective destination (`file` when unset).
    pub fn destination(&self) -> LogDestination {
        self.destination.unwrap_or(LogDestination::File)
    }

    /// Effective syslog facility (`local0` when unset).
    pub fn facility(&self) -> SyslogFacility {
        self.syslog_facility.unwrap_or(SyslogFacility::Local0)
    }

    /// Effective syslog identifier (`howdah` when unset).
    pub fn ident(&self) -> &str {
        self.syslog_ident.as_deref().unwrap_or("howdah")
    }

    /// Effective hook rate limit (10 per second when unset).
    pub fn exec_rate_limit(&self) -> u32 {
        self.exec_rate_limit.unwrap_or(DEFAULT_EXEC_RATE_LIMIT)
    }

    /// Reject values the log writer could not use safely. Errors name the key.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(id) = &self.syslog_ident {
            let ok = !id.is_empty()
                && id.len() <= 32
                && id.bytes().all(|b| b.is_ascii_graphic() && !matches!(b, b':' | b'[' | b']'));
            if !ok {
                return Err(format!(
                    "log.syslog_ident {id:?}: must be 1-32 printable ASCII characters with no spaces, ':', '[' or ']'"
                ));
            }
        }
        if let Some(p) = &self.exec {
            if !p.starts_with('/') || p.len() > 4096 || p.chars().any(|c| c.is_control()) {
                return Err(format!(
                    "log.exec {p:?}: must be an absolute path (starting with '/') with no control characters"
                ));
            }
        }
        if let Some(n) = self.exec_rate_limit {
            if n == 0 || n > MAX_EXEC_RATE_LIMIT {
                return Err(format!(
                    "log.exec_rate_limit {n}: must be between 1 and {MAX_EXEC_RATE_LIMIT} (spawns per second per PHP process); remove log.exec to turn the hook off"
                ));
            }
        }
        Ok(())
    }
}

/// Layer-2 input inspection settings. Its `mode` is independent of the global
/// mode: a global `block` never arms content scanning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct InspectConfig {
    pub enabled: bool,
    pub mode: Mode,
    pub sqli: bool,
    pub traversal: bool,
    pub cmdi: bool,
    pub limits: InspectLimits,
    /// Per-class mode overrides.
    pub rule_modes: BTreeMap<RuleId, Mode>,
}

impl Default for InspectConfig {
    fn default() -> Self {
        InspectConfig {
            enabled: true,
            mode: Mode::Detect,
            sqli: true,
            traversal: true,
            cmdi: true,
            limits: InspectLimits::defaults(),
            rule_modes: BTreeMap::new(),
        }
    }
}

impl InspectConfig {
    /// Off if the global mode is off or inspection is disabled; otherwise the
    /// inspect section's own mode (the global `block` is deliberately ignored).
    pub fn effective_mode(&self, global: Mode) -> Mode {
        if global == Mode::Off || !self.enabled {
            Mode::Off
        } else {
            self.mode
        }
    }

    pub fn class_enabled(&self, c: InspectClass) -> bool {
        match c {
            InspectClass::SqlInjection => self.sqli,
            InspectClass::PathTraversal => self.traversal,
            InspectClass::CommandInjection => self.cmdi,
        }
    }
}

/// Layer-3 command-execution sink settings. `mode: None` inherits `SinkConfig.mode`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct CommandExecConfig {
    pub mode: Option<Mode>,
    /// Anchored literal commands; a trailing `*` makes a prefix glob.
    pub allow: Vec<String>,
}

/// Layer-3 include/require sink settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct IncludeConfig {
    pub mode: Option<Mode>,
    pub allow_paths: Vec<String>,
}

/// Layer-3 eval sink settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct EvalConfig {
    pub mode: Option<Mode>,
}

/// Layer-3 unserialize sink settings. Off by default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UnserializeConfig {
    pub mode: Option<Mode>,
    pub allow_classes: Vec<String>,
}

impl Default for UnserializeConfig {
    fn default() -> Self {
        UnserializeConfig { mode: Some(Mode::Off), allow_classes: Vec::new() }
    }
}

/// Layer-3 phar-deserialization sink settings. Off by default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct PharConfig {
    pub mode: Option<Mode>,
    pub allow_paths: Vec<String>,
}

impl Default for PharConfig {
    fn default() -> Self {
        PharConfig { mode: Some(Mode::Off), allow_paths: Vec::new() }
    }
}

/// Layer-3 SSRF sink settings. Off by default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SsrfConfig {
    pub mode: Option<Mode>,
    /// Exact hostnames, literal IPs, or CIDRs.
    pub allow_hosts: Vec<String>,
}

impl Default for SsrfConfig {
    fn default() -> Self {
        SsrfConfig { mode: Some(Mode::Off), allow_hosts: Vec::new() }
    }
}

/// `[sinks] hook`: which mechanism guards `include`/`require`/`eval` on
/// PHP 7.0+. (PHP 5.x always uses the compile pointers; it has no usable
/// opcode-operand access and no JIT.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SinkHook {
    /// The default: `compile` when only `eval` needs the hook (the compile
    /// pointers cover every eval, so the opcode handler would buy nothing and
    /// only cost the JIT), `opcode` when `include` has `allow_paths` or Layer
    /// 4 `deny_exec_dirs` is set (the cases where an include served from a
    /// warm opcache matters).
    Auto,
    /// A `ZEND_INCLUDE_OR_EVAL` user opcode handler: sees every include and
    /// eval, including files served from a warm opcache. PHP's OPcache JIT
    /// refuses to run alongside any user opcode handler, so JIT is off.
    Opcode,
    /// The `zend_compile_file` / `zend_compile_string` pointer swap: invisible
    /// to the JIT check, sees every eval, but an include served from a warm
    /// opcache is not compiled again and so is not re-inspected.
    Compile,
}

/// Why the include/eval hook plan chose its mechanism (phpinfo row).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookReason {
    /// `[sinks] hook` named the mechanism explicitly.
    Configured,
    /// `auto`: only the `eval` sink needs the hook.
    EvalOnly,
    /// `auto`: the `include` sink is on with `allow_paths`.
    IncludeAllowPaths,
    /// `auto`: Layer 4 `deny_exec_dirs` is set.
    DenyExecDirs,
}

impl HookReason {
    /// The phpinfo wording.
    pub fn label(self) -> &'static str {
        match self {
            HookReason::Configured => "configured",
            HookReason::EvalOnly => "auto: eval only",
            HookReason::IncludeAllowPaths => "auto: include allow_paths set",
            HookReason::DenyExecDirs => "auto: deny_exec_dirs set",
        }
    }
}

/// Layer-3 sink hardening settings. Its `mode` is independent of the global
/// mode: a global `block` never arms a sink.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct SinkConfig {
    pub enabled: bool,
    pub mode: Mode,
    pub command_exec: CommandExecConfig,
    pub include: IncludeConfig,
    pub eval: EvalConfig,
    pub unserialize: UnserializeConfig,
    pub phar: PharConfig,
    pub ssrf: SsrfConfig,
    /// Include/eval hook mechanism on PHP 7.0+; `None` = `auto`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<SinkHook>,
}

impl Default for SinkConfig {
    fn default() -> Self {
        SinkConfig {
            enabled: true,
            mode: Mode::Detect,
            command_exec: CommandExecConfig::default(),
            include: IncludeConfig::default(),
            eval: EvalConfig::default(),
            unserialize: UnserializeConfig::default(),
            phar: PharConfig::default(),
            ssrf: SsrfConfig::default(),
            hook: None,
        }
    }
}

impl SinkConfig {
    /// Configured include/eval hook setting (`auto` when unset).
    pub fn hook(&self) -> SinkHook {
        self.hook.unwrap_or(SinkHook::Auto)
    }

    /// True iff the `include` sink needs the hook: on AND with an allowlist
    /// (with an empty `allow_paths` it never produces an event).
    fn include_needs_hook(&self, global: Mode) -> bool {
        self.effective_mode(SinkId::Include, global) != Mode::Off && !self.include.allow_paths.is_empty()
    }

    /// True iff the include/eval hook has to be installed at all for the
    /// Layer-3 sinks: `eval` is on, or `include` needs it. Layer 4's
    /// `deny_exec_dirs` is the other consumer; the FFI combines both.
    pub fn include_eval_hook_needed(&self, global: Mode) -> bool {
        self.effective_mode(SinkId::Eval, global) != Mode::Off || self.include_needs_hook(global)
    }

    /// The startup plan for the include/eval hook: `None` when nothing needs
    /// it (install nothing; JIT stays on), else the mechanism to install
    /// (`Opcode` or `Compile`, never `Auto`) and why. `deny_exec_dirs_armed`
    /// is Layer 4's verdict (its `require`d-file check runs in this hook).
    /// `auto` resolves to `compile` when only `eval` needs the hook and to
    /// `opcode` when `include` has `allow_paths` or `deny_exec_dirs` is set.
    pub fn include_eval_hook_plan(
        &self,
        global: Mode,
        deny_exec_dirs_armed: bool,
    ) -> Option<(SinkHook, HookReason)> {
        let include = self.include_needs_hook(global);
        let eval = self.effective_mode(SinkId::Eval, global) != Mode::Off;
        if !include && !eval && !deny_exec_dirs_armed {
            return None;
        }
        Some(match self.hook() {
            SinkHook::Opcode => (SinkHook::Opcode, HookReason::Configured),
            SinkHook::Compile => (SinkHook::Compile, HookReason::Configured),
            SinkHook::Auto if deny_exec_dirs_armed => (SinkHook::Opcode, HookReason::DenyExecDirs),
            SinkHook::Auto if include => (SinkHook::Opcode, HookReason::IncludeAllowPaths),
            SinkHook::Auto => (SinkHook::Compile, HookReason::EvalOnly),
        })
    }

    /// Off if the global mode is off or sinks are disabled; otherwise the
    /// per-sink mode if set, else the section mode (global `block` is ignored).
    pub fn effective_mode(&self, sink: SinkId, global: Mode) -> Mode {
        if global == Mode::Off || !self.enabled {
            return Mode::Off;
        }
        let sub = match sink {
            SinkId::CommandExec => self.command_exec.mode,
            SinkId::Include => self.include.mode,
            SinkId::Eval => self.eval.mode,
            SinkId::Unserialize => self.unserialize.mode,
            SinkId::Phar => self.phar.mode,
            SinkId::Ssrf => self.ssrf.mode,
        };
        sub.unwrap_or(self.mode)
    }
}

/// Layer-4 post-breach behavior settings. Its `mode` is independent of the
/// global mode: a global `block` never arms behavior enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct BehaviorConfig {
    pub enabled: bool,
    pub mode: Mode,
    pub observe: bool,
    /// Absolute directories in which executing files is denied.
    pub deny_exec_dirs: Vec<String>,
    pub allow_exec_binaries: Vec<String>,
    /// Exact hostnames, literal IPs, or CIDRs.
    pub allow_egress_hosts: Vec<String>,
    pub deny_php_writes: bool,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        BehaviorConfig {
            enabled: true,
            mode: Mode::Detect,
            observe: false,
            deny_exec_dirs: Vec::new(),
            allow_exec_binaries: Vec::new(),
            allow_egress_hosts: Vec::new(),
            deny_php_writes: false,
        }
    }
}

impl BehaviorConfig {
    /// Off if the global mode is off or behavior is disabled; otherwise the
    /// section's own mode (the global `block` is deliberately ignored).
    pub fn effective_mode(&self, global: Mode) -> Mode {
        if global == Mode::Off || !self.enabled {
            Mode::Off
        } else {
            self.mode
        }
    }
}

/// Parsed Howdah configuration.
///
/// Serializes to the same shape as the TOML file (`rule_modes` as `rules`),
/// which is what the wasm validator hands the config editor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Config {
    pub mode: Mode,
    pub limits: Limits,
    pub log: LogConfig,
    /// Per-rule mode overrides.
    #[serde(rename = "rules")]
    pub rule_modes: BTreeMap<RuleId, Mode>,
    pub inspect: InspectConfig,
    pub sinks: SinkConfig,
    pub behavior: BehaviorConfig,
    /// Fallback when this file does not parse; see [`Config::load`].
    pub on_invalid_config: OnInvalidConfig,
    /// Scoped `[[exceptions]]`, validated (see `exceptions::Exceptions`).
    pub exceptions: Vec<ExceptionEntry>,
    /// Log matched exceptions as `action: "excepted"` events.
    pub exceptions_log: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawConfig {
    mode: Mode,
    limits: Limits,
    log: LogConfig,
    rules: BTreeMap<RuleId, Mode>,
    inspect: InspectConfig,
    sinks: SinkConfig,
    behavior: BehaviorConfig,
    on_invalid_config: OnInvalidConfig,
    exceptions: Vec<ExceptionEntry>,
    exceptions_log: bool,
}

impl Default for RawConfig {
    fn default() -> Self {
        let c = Config::safe_defaults();
        RawConfig {
            mode: c.mode,
            limits: c.limits,
            log: c.log,
            rules: c.rule_modes,
            inspect: c.inspect,
            sinks: c.sinks,
            behavior: c.behavior,
            on_invalid_config: c.on_invalid_config,
            exceptions: c.exceptions,
            exceptions_log: c.exceptions_log,
        }
    }
}

/// Error from loading configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid howdah config: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Parse a TOML document. Unknown keys are rejected; absent keys take safe defaults.
    pub fn from_toml(s: &str) -> Result<Config, ConfigError> {
        let raw: RawConfig = toml::from_str(s).map_err(|e| ConfigError(e.to_string()))?;
        raw.limits.validate().map_err(ConfigError)?;
        raw.inspect.limits.validate().map_err(ConfigError)?;
        raw.log.validate().map_err(ConfigError)?;
        for p in &raw.sinks.command_exec.allow {
            if let Some(i) = p.find('*') {
                if i != p.len() - 1 {
                    return Err(ConfigError(format!(
                        "sinks.command_exec.allow pattern {p:?}: '*' is only allowed as the final character"
                    )));
                }
            }
        }
        for h in &raw.sinks.ssrf.allow_hosts {
            if !crate::sinks::ssrf::valid_allow_entry(h) {
                return Err(ConfigError(format!(
                    "sinks.ssrf.allow_hosts entry {h:?}: must be an exact hostname, an IP address, or a CIDR with an in-range prefix length (no wildcards or whitespace)"
                )));
            }
        }
        for d in &raw.behavior.deny_exec_dirs {
            if d.trim().is_empty() || !d.starts_with('/') {
                return Err(ConfigError(format!(
                    "behavior.deny_exec_dirs entry {d:?}: must be a non-blank absolute path"
                )));
            }
        }
        for b in &raw.behavior.allow_exec_binaries {
            if b.trim().is_empty() || b.chars().any(char::is_whitespace) {
                return Err(ConfigError(format!(
                    "behavior.allow_exec_binaries entry {b:?}: must be non-blank with no whitespace"
                )));
            }
        }
        for h in &raw.behavior.allow_egress_hosts {
            if !crate::sinks::ssrf::valid_allow_entry(h) {
                return Err(ConfigError(format!(
                    "behavior.allow_egress_hosts entry {h:?}: must be an exact hostname, an IP address, or a CIDR with an in-range prefix length (no wildcards or whitespace)"
                )));
            }
        }
        crate::exceptions::Exceptions::validate(&raw.exceptions).map_err(ConfigError)?;
        Ok(Config {
            mode: raw.mode,
            limits: raw.limits,
            log: raw.log,
            rule_modes: raw.rules,
            inspect: raw.inspect,
            sinks: raw.sinks,
            behavior: raw.behavior,
            on_invalid_config: raw.on_invalid_config,
            exceptions: raw.exceptions,
            exceptions_log: raw.exceptions_log,
        })
    }

    /// Counts of `[[exceptions]]` entries that compile and that are rejected,
    /// from the raw file text (for `php --ri howdah`). `None` when the text is
    /// not TOML. See `exceptions::report`.
    pub fn exceptions_report(s: &str) -> Option<(usize, usize)> {
        crate::exceptions::report(s)
    }

    /// Read `on_invalid_config` from the raw text of a file that failed to
    /// parse. The parser is all-or-nothing, so this is a tiny line scan: only
    /// top-level lines (before the first `[table]` header) are looked at, the
    /// value must be a quoted `"off"`, and anything else (no such line,
    /// another value, a bare word) yields the default, `Block`.
    pub fn scan_on_invalid_config(s: &str) -> OnInvalidConfig {
        for line in s.lines() {
            let l = line.trim();
            if l.starts_with('[') {
                break;
            }
            let Some(rest) = l.strip_prefix("on_invalid_config") else { continue };
            let Some(v) = rest.trim_start().strip_prefix('=') else { continue };
            let v = v.trim();
            for q in ["\"off\"", "'off'"] {
                if let Some(tail) = v.strip_prefix(q) {
                    let t = tail.trim();
                    if t.is_empty() || t.starts_with('#') {
                        return OnInvalidConfig::Off;
                    }
                }
            }
            return OnInvalidConfig::Block;
        }
        OnInvalidConfig::Block
    }

    /// Load a config file's bytes. On success `error` is `None`. On any parse
    /// or validation failure (including non-UTF-8) `config` is the fallback
    /// (`safe_defaults()` with the mode taken from the pre-parse of
    /// `on_invalid_config`) and `error` carries the message so the caller can
    /// report it loudly.
    pub fn load(bytes: &[u8]) -> LoadOutcome {
        let text = match std::str::from_utf8(bytes) {
            Ok(t) => t,
            Err(e) => {
                return LoadOutcome::fallback(OnInvalidConfig::Block, ConfigError(format!("not valid UTF-8: {e}")))
            }
        };
        match Config::from_toml(text) {
            Ok(config) => LoadOutcome { config, error: None },
            Err(e) => LoadOutcome::fallback(Config::scan_on_invalid_config(text), e),
        }
    }

    /// A usable config: blocking, with critical limits active.
    pub fn safe_defaults() -> Config {
        Config {
            mode: Mode::Block,
            limits: Limits::default(),
            log: LogConfig::default(),
            rule_modes: BTreeMap::new(),
            inspect: InspectConfig::default(),
            sinks: SinkConfig::default(),
            behavior: BehaviorConfig::default(),
            on_invalid_config: OnInvalidConfig::Block,
            exceptions: Vec::new(),
            exceptions_log: false,
        }
    }
}

/// Result of [`Config::load`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOutcome {
    pub config: Config,
    pub error: Option<ConfigError>,
}

impl LoadOutcome {
    fn fallback(on_invalid: OnInvalidConfig, error: ConfigError) -> LoadOutcome {
        let mut config = Config::safe_defaults();
        config.mode = match on_invalid {
            OnInvalidConfig::Block => Mode::Block,
            OnInvalidConfig::Off => Mode::Off,
        };
        config.on_invalid_config = on_invalid;
        LoadOutcome { config, error: Some(error) }
    }
}

impl ConfigError {
    /// The bare parser message, without the "invalid howdah config:" prefix.
    pub fn message(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::RuleId;

    const SAMPLE: &str = r#"
mode = "detect"

[limits]
max_parts = 50
max_part_header_bytes = 1024

[log]
path = "/var/log/howdah.log"

[rules]
self_test = "off"
"#;

    #[test]
    fn behavior_defaults_off_safe() {
        let c = Config::from_toml("mode=\"detect\"").unwrap();
        assert!(c.behavior.enabled);
        assert_eq!(c.behavior.mode, Mode::Detect);
        assert!(!c.behavior.observe);
        assert!(c.behavior.deny_exec_dirs.is_empty());
        assert!(!c.behavior.deny_php_writes);
    }

    #[test]
    fn behavior_effective_mode_independent_of_global_block() {
        let c = Config::from_toml("mode=\"detect\"\n[behavior]\nmode=\"detect\"").unwrap();
        assert_eq!(c.behavior.effective_mode(Mode::Block), Mode::Detect);
        assert_eq!(c.behavior.effective_mode(Mode::Off), Mode::Off);
    }

    #[test]
    fn behavior_disabled_is_off() {
        let c = Config::from_toml("[behavior]\nenabled=false\nmode=\"block\"").unwrap();
        assert_eq!(c.behavior.effective_mode(Mode::Block), Mode::Off);
    }

    #[test]
    fn behavior_rejects_relative_exec_dir() {
        assert!(Config::from_toml("[behavior]\ndeny_exec_dirs=[\"relative/path\"]").is_err());
    }

    #[test]
    fn behavior_rejects_blank_binary() {
        assert!(Config::from_toml("[behavior]\nallow_exec_binaries=[\"  \"]").is_err());
    }

    #[test]
    fn parses_sample() {
        let c = Config::from_toml(SAMPLE).unwrap();
        assert_eq!(c.mode, Mode::Detect);
        assert_eq!(c.limits.max_parts, 50);
        assert_eq!(c.limits.max_part_header_bytes, 1024);
        assert_eq!(c.log.path.as_deref(), Some("/var/log/howdah.log"));
        assert_eq!(c.rule_modes.get(&RuleId::SelfTest), Some(&Mode::Off));
    }

    #[test]
    fn on_invalid_config_parses_and_defaults_to_block() {
        assert_eq!(Config::from_toml("").unwrap().on_invalid_config, OnInvalidConfig::Block);
        let c = Config::from_toml("on_invalid_config = \"off\"\nmode = \"detect\"").unwrap();
        assert_eq!(c.on_invalid_config, OnInvalidConfig::Off);
        assert!(Config::from_toml("on_invalid_config = \"warn\"").is_err());
    }

    #[test]
    fn scan_reads_only_top_level_quoted_value() {
        let scan = Config::scan_on_invalid_config;
        assert_eq!(scan("on_invalid_config = \"off\""), OnInvalidConfig::Off);
        assert_eq!(scan("# c\n  on_invalid_config=\"off\"  # why\nmode = 3"), OnInvalidConfig::Off);
        assert_eq!(scan("on_invalid_config = 'off'"), OnInvalidConfig::Off);
        assert_eq!(scan("on_invalid_config = \"block\""), OnInvalidConfig::Block);
        assert_eq!(scan("on_invalid_config = off"), OnInvalidConfig::Block);
        assert_eq!(scan("on_invalid_config = \"offf\""), OnInvalidConfig::Block);
        assert_eq!(scan("mode = \"detect\""), OnInvalidConfig::Block);
        // Inside a table it is not the top-level key.
        assert_eq!(scan("[log]\non_invalid_config = \"off\""), OnInvalidConfig::Block);
        // A key that merely starts with the name is not it.
        assert_eq!(scan("on_invalid_config_x = \"off\""), OnInvalidConfig::Block);
    }

    #[test]
    fn load_valid_has_no_error() {
        let o = Config::load(b"mode = \"detect\"");
        assert!(o.error.is_none());
        assert_eq!(o.config.mode, Mode::Detect);
    }

    #[test]
    fn load_invalid_falls_back_to_block_with_error() {
        let o = Config::load(b"mode = \"detect\"\n[limits]\nnope = 1");
        assert_eq!(o.config.mode, Mode::Block);
        assert!(o.error.unwrap().message().contains("nope"));
    }

    #[test]
    fn load_invalid_honours_on_invalid_config_off() {
        let o = Config::load(b"on_invalid_config = \"off\"\n[limits]\nnope = 1");
        assert_eq!(o.config.mode, Mode::Off);
        assert_eq!(o.config.on_invalid_config, OnInvalidConfig::Off);
        assert!(o.error.is_some());
    }

    #[test]
    fn load_non_utf8_falls_back_to_block() {
        let o = Config::load(b"\xff\xfe");
        assert_eq!(o.config.mode, Mode::Block);
        assert!(o.error.is_some());
    }

    #[test]
    fn empty_uses_defaults() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c, Config::safe_defaults());
    }

    #[test]
    fn unknown_keys_rejected_with_clear_error() {
        for s in [
            "bogus = 1",
            "[limits]\nnope = 2",
            "[log]\nx = 1",
            "[rules]\nnot_a_rule = \"block\"",
        ] {
            let e = Config::from_toml(s).unwrap_err();
            assert!(!e.to_string().is_empty(), "{s}");
        }
        let e = Config::from_toml("bogus = 1").unwrap_err();
        assert!(e.to_string().contains("bogus"), "{e}");
    }

    #[test]
    fn zero_limit_rejected() {
        let e = Config::from_toml("[limits]\nmax_parts = 0").unwrap_err();
        assert!(e.to_string().contains("max_parts"), "{e}");
    }

    #[test]
    fn zero_inspect_limit_rejected() {
        let e = Config::from_toml("[inspect.limits]\nmax_values = 0").unwrap_err();
        assert!(e.to_string().contains("max_values"), "{e}");
    }

    #[test]
    fn layer1_limits_parse() {
        let c = Config::from_toml(
            "[limits]\nmax_input_vars = 500\nmax_input_nesting_depth = 8\nmax_request_headers = 40",
        )
        .unwrap();
        assert_eq!(c.limits.max_input_vars, 500);
        assert_eq!(c.limits.max_input_nesting_depth, 8);
        assert_eq!(c.limits.max_request_headers, 40);
    }

    #[test]
    fn zero_layer1_limits_rejected() {
        for f in ["max_input_vars", "max_request_header_bytes"] {
            let e = Config::from_toml(&format!("[limits]\n{f} = 0")).unwrap_err();
            assert!(e.to_string().contains(f), "{e}");
        }
    }

    #[test]
    fn unknown_limits_key_rejected() {
        assert!(Config::from_toml("[limits]\nnope = 1").is_err());
    }

    #[test]
    fn invalid_mode_rejected() {
        assert!(Config::from_toml("mode = \"yolo\"").is_err());
    }

    #[test]
    fn invalid_toml_is_error_not_panic() {
        for s in ["= = =", "mode = ", "[[[", "\u{0}", "mode = \"block\"\nmode = \"off\""] {
            assert!(Config::from_toml(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn safe_defaults_block_capable_with_critical_limits() {
        let c = Config::safe_defaults();
        assert_eq!(c.mode, Mode::Block);
        assert!(c.limits.max_parts > 0);
        assert!(c.limits.validate().is_ok());
        assert!(c.rule_modes.is_empty());
    }

    #[test]
    fn inspect_defaults_detect_and_enabled() {
        let c = Config::from_toml("").unwrap();
        assert!(c.inspect.enabled);
        assert_eq!(c.inspect.mode, Mode::Detect);
        for k in [
            crate::inspect::InspectClass::SqlInjection,
            crate::inspect::InspectClass::PathTraversal,
            crate::inspect::InspectClass::CommandInjection,
        ] {
            assert!(c.inspect.class_enabled(k));
        }
    }

    #[test]
    fn inspect_section_parses() {
        let c = Config::from_toml("[inspect]\nmode = \"block\"\ncmdi = false").unwrap();
        assert_eq!(c.inspect.effective_mode(Mode::Block), Mode::Block);
        assert!(!c.inspect.class_enabled(crate::inspect::InspectClass::CommandInjection));
    }

    #[test]
    fn global_block_does_not_arm_inspect() {
        let c = Config::from_toml("mode = \"block\"").unwrap();
        assert_eq!(c.inspect.effective_mode(Mode::Block), Mode::Detect);
    }

    #[test]
    fn global_off_disables_inspect() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.inspect.effective_mode(Mode::Off), Mode::Off);
    }

    #[test]
    fn inspect_unknown_key_rejected() {
        assert!(Config::from_toml("[inspect]\nnope = 1").is_err());
    }

    #[test]
    fn sinks_defaults_detect_enabled_unserialize_off() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("").unwrap();
        assert!(c.sinks.enabled);
        assert_eq!(c.sinks.mode, Mode::Detect);
        for s in [SinkId::CommandExec, SinkId::Include, SinkId::Eval] {
            assert_eq!(c.sinks.effective_mode(s, Mode::Detect), Mode::Detect);
        }
        assert_eq!(c.sinks.effective_mode(SinkId::Unserialize, Mode::Detect), Mode::Off);
    }

    #[test]
    fn global_block_does_not_arm_sinks() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("mode = \"block\"").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::CommandExec, Mode::Block), Mode::Detect);
    }

    #[test]
    fn global_off_disables_sinks() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::CommandExec, Mode::Off), Mode::Off);
    }

    #[test]
    fn per_sink_mode_overrides_section_mode() {
        use crate::sinks::SinkId;
        let c = Config::from_toml(
            "[sinks]\nmode=\"off\"\n[sinks.command_exec]\nmode=\"block\"",
        )
        .unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::CommandExec, Mode::Block), Mode::Block);
        assert_eq!(c.sinks.effective_mode(SinkId::Include, Mode::Block), Mode::Off);
    }

    #[test]
    fn mid_wildcard_command_pattern_rejected() {
        assert!(Config::from_toml("[sinks.command_exec]\nallow=[\"a*b\"]").is_err());
        assert!(Config::from_toml("[sinks.command_exec]\nallow=[\"ok *\"]").is_ok());
        assert!(Config::from_toml("[sinks.command_exec]\nallow=[\"exact\"]").is_ok());
    }

    #[test]
    fn sinks_unknown_key_rejected() {
        assert!(Config::from_toml("[sinks]\nnope = 1").is_err());
    }

    #[test]
    fn phar_defaults_off() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.sinks.phar.mode, Some(Mode::Off));
        assert!(c.sinks.phar.allow_paths.is_empty());
        assert_eq!(c.sinks.effective_mode(SinkId::Phar, Mode::Detect), Mode::Off);
    }

    #[test]
    fn ssrf_defaults_off() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.sinks.ssrf.mode, Some(Mode::Off));
        assert!(c.sinks.ssrf.allow_hosts.is_empty());
        assert_eq!(c.sinks.effective_mode(SinkId::Ssrf, Mode::Detect), Mode::Off);
    }

    #[test]
    fn phar_enable_detect() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("[sinks.phar]\nmode=\"detect\"").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::Phar, Mode::Block), Mode::Detect);
    }

    #[test]
    fn ssrf_enable_block() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("[sinks.ssrf]\nmode=\"block\"").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::Ssrf, Mode::Block), Mode::Block);
    }

    #[test]
    fn explicit_phar_block_arms_phar_only() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("[sinks]\nmode=\"block\"\n[sinks.phar]\nmode=\"block\"").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::Phar, Mode::Detect), Mode::Block);
        assert_eq!(c.sinks.effective_mode(SinkId::Ssrf, Mode::Detect), Mode::Off);
    }

    #[test]
    fn global_block_does_not_arm_phar() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("mode = \"block\"").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::Phar, Mode::Block), Mode::Off);
    }

    #[test]
    fn global_block_does_not_arm_ssrf() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("mode = \"block\"").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::Ssrf, Mode::Block), Mode::Off);
    }

    #[test]
    fn section_block_arms_neither() {
        use crate::sinks::SinkId;
        let c = Config::from_toml("[sinks]\nmode=\"block\"").unwrap();
        assert_eq!(c.sinks.effective_mode(SinkId::Phar, Mode::Block), Mode::Off);
        assert_eq!(c.sinks.effective_mode(SinkId::Ssrf, Mode::Block), Mode::Off);
    }

    #[test]
    fn ssrf_allow_hosts_parse() {
        let c = Config::from_toml(
            "[sinks.ssrf]\nallow_hosts=[\"api.example.com\",\"10.0.0.0/8\",\"2001:db8::/32\",\"1.2.3.4\"]",
        )
        .unwrap();
        assert_eq!(c.sinks.ssrf.allow_hosts.len(), 4);
    }

    #[test]
    fn phar_allow_paths_parse() {
        let c = Config::from_toml("[sinks.phar]\nallow_paths=[\"/var/www/a.phar\"]").unwrap();
        assert_eq!(c.sinks.phar.allow_paths, vec!["/var/www/a.phar".to_string()]);
    }

    #[test]
    fn ssrf_bad_cidr_rejected() {
        for bad in ["10.0.0.0/33", "::1/129", "", " ", "a b", "*.example.com"] {
            let toml = format!("[sinks.ssrf]\nallow_hosts=[{bad:?}]");
            let e = Config::from_toml(&toml).expect_err(bad);
            assert!(e.to_string().contains("sinks.ssrf.allow_hosts"), "{e}");
        }
    }

    #[test]
    fn sinks_phar_ssrf_unknown_key_rejected() {
        assert!(Config::from_toml("[sinks.phar]\nnope = 1").is_err());
        assert!(Config::from_toml("[sinks.ssrf]\nnope = 1").is_err());
    }

    // ---- [sinks] hook (include/eval mechanism, JIT compatibility) --------

    #[test]
    fn sink_hook_defaults_to_auto_and_parses() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.sinks.hook, None);
        assert_eq!(c.sinks.hook(), SinkHook::Auto);
        // Unset keys do not appear when serialized (config editor view).
        let j = serde_json::to_value(&c).unwrap();
        assert!(j["sinks"].get("hook").is_none());
        let c = Config::from_toml("[sinks]\nhook = \"compile\"").unwrap();
        assert_eq!(c.sinks.hook(), SinkHook::Compile);
        assert_eq!(serde_json::to_value(&c).unwrap()["sinks"]["hook"], "compile");
        let c = Config::from_toml("[sinks]\nhook = \"opcode\"").unwrap();
        assert_eq!(c.sinks.hook(), SinkHook::Opcode);
        let c = Config::from_toml("[sinks]\nhook = \"auto\"").unwrap();
        assert_eq!(c.sinks.hook(), SinkHook::Auto);
        assert_eq!(serde_json::to_value(&c).unwrap()["sinks"]["hook"], "auto");
        let e = Config::from_toml("[sinks]\nhook = \"execute\"").unwrap_err();
        assert!(e.to_string().contains("hook"), "{e}");
    }

    #[test]
    fn include_eval_hook_plan_auto_picks_compile_for_eval_only() {
        use HookReason::*;
        use SinkHook::*;
        let plan = |toml: &str, l4: bool| Config::from_toml(toml).unwrap().sinks.include_eval_hook_plan(Mode::Detect, l4);
        // Shipped defaults: eval detect, include inert, no deny_exec_dirs ->
        // compile, so a default install keeps the JIT on.
        assert_eq!(plan("", false), Some((Compile, EvalOnly)));
        // include with allow_paths -> opcode (warm-opcache includes matter).
        assert_eq!(plan("[sinks.include]\nallow_paths=[\"/srv/app\"]", false), Some((Opcode, IncludeAllowPaths)));
        // Layer 4 deny_exec_dirs -> opcode, even with eval off.
        assert_eq!(plan("[sinks.eval]\nmode=\"off\"", true), Some((Opcode, DenyExecDirs)));
        // Nothing needs it -> None.
        assert_eq!(plan("[sinks.eval]\nmode=\"off\"", false), None);
        assert_eq!(plan("[sinks]\nenabled=false", false), None);
        // Explicit settings win over auto, in both directions.
        assert_eq!(plan("[sinks]\nhook=\"opcode\"", false), Some((Opcode, Configured)));
        assert_eq!(plan("[sinks]\nhook=\"compile\"\n[sinks.include]\nallow_paths=[\"/srv\"]", true), Some((Compile, Configured)));
        // Explicit still installs nothing when nothing needs it.
        assert_eq!(plan("[sinks]\nhook=\"opcode\"\n[sinks.eval]\nmode=\"off\"", false), None);
        // Global off beats everything (Layer 4 is off too then; the FFI passes false).
        assert_eq!(Config::from_toml("").unwrap().sinks.include_eval_hook_plan(Mode::Off, false), None);
        assert_eq!(IncludeAllowPaths.label(), "auto: include allow_paths set");
    }

    #[test]
    fn include_eval_hook_needed_follows_eval_and_include_allowlist() {
        // Shipped defaults: eval inherits detect, so the hook is needed.
        let c = Config::from_toml("").unwrap();
        assert!(c.sinks.include_eval_hook_needed(Mode::Detect));
        // Global off / sinks disabled: nothing needs it.
        assert!(!c.sinks.include_eval_hook_needed(Mode::Off));
        let c = Config::from_toml("[sinks]\nenabled = false").unwrap();
        assert!(!c.sinks.include_eval_hook_needed(Mode::Block));
        // eval off, include detect but inert (no allow_paths): not needed.
        let c = Config::from_toml("[sinks.eval]\nmode = \"off\"").unwrap();
        assert!(!c.sinks.include_eval_hook_needed(Mode::Detect));
        // include armed with an allowlist: needed even with eval off.
        let c = Config::from_toml(
            "[sinks.eval]\nmode = \"off\"\n[sinks.include]\nmode = \"detect\"\nallow_paths = [\"/srv/app\"]",
        )
        .unwrap();
        assert!(c.sinks.include_eval_hook_needed(Mode::Detect));
        // Section mode off, eval explicitly block: needed.
        let c = Config::from_toml("[sinks]\nmode = \"off\"\n[sinks.eval]\nmode = \"block\"").unwrap();
        assert!(c.sinks.include_eval_hook_needed(Mode::Detect));
        // Everything off: not needed.
        let c = Config::from_toml("[sinks]\nmode = \"off\"").unwrap();
        assert!(!c.sinks.include_eval_hook_needed(Mode::Block));
    }

    // ---- [log] (schema 2 log contract) ------------------------------------

    #[test]
    fn log_defaults_preserve_file_then_stderr() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.log, LogConfig::default());
        assert_eq!(c.log.destination(), LogDestination::File);
        assert_eq!(c.log.facility(), SyslogFacility::Local0);
        assert_eq!(c.log.ident(), "howdah");
        assert_eq!(c.log.exec, None);
        assert_eq!(c.log.exec_rate_limit(), 10);
        // Unset keys do not appear when the config is serialized (the config
        // editor's view of an empty file is unchanged).
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["log"], serde_json::json!({ "path": null }));
    }

    #[test]
    fn log_table_parses_every_key() {
        let c = Config::from_toml(
            "[log]\npath = \"/var/log/howdah/events.log\"\ndestination = \"syslog\"\n\
             syslog_facility = \"local3\"\nsyslog_ident = \"howdah-shop\"\n\
             exec = \"/usr/local/bin/howdah-hook\"\nexec_rate_limit = 3",
        )
        .unwrap();
        assert_eq!(c.log.path.as_deref(), Some("/var/log/howdah/events.log"));
        assert_eq!(c.log.destination(), LogDestination::Syslog);
        assert_eq!(c.log.facility(), SyslogFacility::Local3);
        assert_eq!(c.log.ident(), "howdah-shop");
        assert_eq!(c.log.exec.as_deref(), Some("/usr/local/bin/howdah-hook"));
        assert_eq!(c.log.exec_rate_limit(), 3);
        for (d, want) in [
            ("file", LogDestination::File),
            ("syslog", LogDestination::Syslog),
            ("stderr", LogDestination::Stderr),
        ] {
            let c = Config::from_toml(&format!("[log]\ndestination = \"{d}\"")).unwrap();
            assert_eq!(c.log.destination(), want);
        }
    }

    #[test]
    fn syslog_facility_codes() {
        for (name, code) in [
            ("user", 1),
            ("daemon", 3),
            ("auth", 4),
            ("authpriv", 10),
            ("local0", 16),
            ("local7", 23),
        ] {
            let c = Config::from_toml(&format!("[log]\nsyslog_facility = \"{name}\"")).unwrap();
            assert_eq!(c.log.facility().code(), code, "{name}");
        }
    }

    #[test]
    fn log_bad_values_rejected_with_the_key_named() {
        for (toml, key) in [
            ("[log]\ndestination = \"udp\"", "destination"),
            ("[log]\nsyslog_facility = \"kern\"", "syslog_facility"),
            ("[log]\nsyslog_facility = \"local8\"", "syslog_facility"),
            ("[log]\nsyslog_ident = \"\"", "syslog_ident"),
            ("[log]\nsyslog_ident = \"has space\"", "syslog_ident"),
            ("[log]\nsyslog_ident = \"a:b\"", "syslog_ident"),
            ("[log]\nsyslog_ident = \"a[1]\"", "syslog_ident"),
            ("[log]\nsyslog_ident = \"0123456789012345678901234567890123\"", "syslog_ident"),
            ("[log]\nexec = \"hook.sh\"", "exec"),
            ("[log]\nexec = \"./hook.sh\"", "exec"),
            ("[log]\nexec = \"\"", "exec"),
            ("[log]\nexec = \"/bin/hook\\nx\"", "exec"),
            ("[log]\nexec_rate_limit = 0", "exec_rate_limit"),
            ("[log]\nexec_rate_limit = 101", "exec_rate_limit"),
            ("[log]\nexec_rate_limit = -1", "exec_rate_limit"),
        ] {
            let e = Config::from_toml(toml).expect_err(toml);
            assert!(e.to_string().contains(key), "{toml}: {e}");
        }
    }

    #[test]
    fn log_unknown_key_still_rejected() {
        assert!(Config::from_toml("[log]\nexec_args = []").is_err());
        assert!(Config::from_toml("[log]\nfacility = \"local0\"").is_err());
    }

    // ---- [[exceptions]] -------------------------------------------------------

    #[test]
    fn exceptions_default_empty_and_log_off() {
        let c = Config::from_toml("").unwrap();
        assert!(c.exceptions.is_empty());
        assert!(!c.exceptions_log);
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(j["exceptions"], serde_json::json!([]));
        assert_eq!(j["exceptions_log"], false);
    }

    #[test]
    fn exceptions_parse_and_serialize_verbatim() {
        let c = Config::from_toml(
            "exceptions_log = true\n\
             [[exceptions]]\nrule = \"sinks.command_exec\"\nscript = \"/var/www/cron.php\"\nreason = \"cron mailer\"\n\
             [[exceptions]]\nrule = \"inspect.sql_injection\"\nparam = \"content\"\nuri_prefix = \"/wp-admin/\"\nclient_cidr = \"10.0.0.0/8\"\nreason = \"editors\"\n",
        )
        .unwrap();
        assert!(c.exceptions_log);
        assert_eq!(c.exceptions.len(), 2);
        assert_eq!(c.exceptions[0].rule.as_deref(), Some("sinks.command_exec"));
        assert_eq!(c.exceptions[1].client_cidr.as_deref(), Some("10.0.0.0/8"));
        // Unset facets are omitted from the canonical JSON the editor reads.
        let j = serde_json::to_value(&c).unwrap();
        assert_eq!(
            j["exceptions"][0],
            serde_json::json!({ "rule": "sinks.command_exec", "script": "/var/www/cron.php", "reason": "cron mailer" })
        );
    }

    #[test]
    fn exceptions_errors_name_index_and_key() {
        let e = Config::from_toml("[[exceptions]]\nrule = \"max_parts\"\nuri_prefix = \"/\"\nreason = \"x\"").unwrap_err();
        assert!(e.to_string().contains("exceptions[0].rule"), "{e}");
        assert!(e.to_string().contains("Critical"), "{e}");
        let e = Config::from_toml(
            "[[exceptions]]\nrule = \"command_exec\"\nscript = \"/a.php\"\nreason = \"ok\"\n[[exceptions]]\nrule = \"eval\"\nscript = \"/b.php\"",
        )
        .unwrap_err();
        assert!(e.to_string().contains("exceptions[1].reason"), "{e}");
        let e = Config::from_toml("[[exceptions]]\nrule = \"sql_injection\"\nscript = \"/a.php\"\nreason = \"x\"").unwrap_err();
        assert!(e.to_string().contains("exceptions[0].script") && e.to_string().contains("uri_prefix"), "{e}");
        assert!(Config::from_toml("[[exceptions]]\nrule = \"eval\"\nscript = \"/a.php\"\nbogus = 1\nreason = \"x\"").is_err());
        assert!(Config::from_toml("exceptions_log = \"yes\"").is_err());
    }

    #[test]
    fn exceptions_report_counts() {
        assert_eq!(Config::exceptions_report("mode = \"detect\""), Some((0, 0)));
        let t = "[[exceptions]]\nrule = \"command_exec\"\nscript = \"/a.php\"\nreason = \"x\"\n[[exceptions]]\nrule = \"max_parts\"\nuri_prefix = \"/\"\nreason = \"x\"\n";
        assert_eq!(Config::exceptions_report(t), Some((1, 1)));
        assert!(Config::from_toml(t).is_err());
    }
}
