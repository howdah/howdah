//! Configuration loading. Never panics on bad input; `safe_defaults` is always usable.
use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

use crate::inspect::{InspectClass, InspectLimits};
use crate::limits::{Limits, RuleId};
use crate::sinks::SinkId;

/// Global enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Off,
    Detect,
    Block,
}

/// Logging settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LogConfig {
    /// Log file path; `None` means the host default.
    pub path: Option<String>,
}

/// Layer-2 input inspection settings. Its `mode` is independent of the global
/// mode: a global `block` never arms content scanning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct CommandExecConfig {
    pub mode: Option<Mode>,
    /// Anchored literal commands; a trailing `*` makes a prefix glob.
    pub allow: Vec<String>,
}

/// Layer-3 include/require sink settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct IncludeConfig {
    pub mode: Option<Mode>,
    pub allow_paths: Vec<String>,
}

/// Layer-3 eval sink settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EvalConfig {
    pub mode: Option<Mode>,
}

/// Layer-3 unserialize sink settings. Off by default.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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

/// Layer-3 sink hardening settings. Its `mode` is independent of the global
/// mode: a global `block` never arms a sink.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
        }
    }
}

impl SinkConfig {
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

/// Parsed Howdah configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    pub limits: Limits,
    pub log: LogConfig,
    /// Per-rule mode overrides.
    pub rule_modes: BTreeMap<RuleId, Mode>,
    pub inspect: InspectConfig,
    pub sinks: SinkConfig,
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
        Ok(Config {
            mode: raw.mode,
            limits: raw.limits,
            log: raw.log,
            rule_modes: raw.rules,
            inspect: raw.inspect,
            sinks: raw.sinks,
        })
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
        }
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
    fn parses_sample() {
        let c = Config::from_toml(SAMPLE).unwrap();
        assert_eq!(c.mode, Mode::Detect);
        assert_eq!(c.limits.max_parts, 50);
        assert_eq!(c.limits.max_part_header_bytes, 1024);
        assert_eq!(c.log.path.as_deref(), Some("/var/log/howdah.log"));
        assert_eq!(c.rule_modes.get(&RuleId::SelfTest), Some(&Mode::Off));
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
    fn sinks_block_arms_phar_but_not_ssrf() {
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
}
