//! Pure translation of the `howdah.mode` / `howdah.log` php.ini knobs into a
//! minimal core-config TOML, used when no `howdah.config` file is present (the
//! shipped path). Pure Rust, host-testable; the PHP glue in `module.rs` calls
//! these and hands the TOML to `howdah_init`.
//!
//! Without this, MINIT passed NULL to the core whenever `howdah.config` was
//! empty, so the core fell back to `Config::safe_defaults()` (Block) and the
//! shipped `howdah.mode = detect` — or an operator's `off` — silently became
//! Block. Here the ini mode becomes real config.
//!
//! THE EMPTY-STRING QUIRK (why `resolve_mode` exists): PHP's ini scanner maps
//! the barewords `off`/`no`/`false`/`none` to the empty string `""` at parse
//! time, so `howdah.mode = off` reaches us as empty — NOT as "off". An *unset*
//! directive, by contrast, returns our registered default `"block"`. So an
//! empty `howdah.mode` means the operator explicitly wrote a falsey word and
//! wants Howdah OFF; only a genuinely unrecognized value falls back to the safe
//! default (Block). (A quoted `howdah.mode = "off"` arrives literally and is
//! handled too.)

/// The mode MINIT will apply when there is no config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeChoice {
    Off,
    Detect,
    Block,
    /// Unrecognized ini value: let the core use its safe default (Block).
    SafeDefault,
}

/// Resolve the `howdah.mode` ini value (as returned by `zend_ini_string`, where
/// an empty value becomes `None`) into the mode to apply. See the module doc
/// for the empty-string quirk: `None` means an explicit falsey word ⇒ `Off`.
pub fn resolve_mode(ini_mode: Option<&str>) -> ModeChoice {
    match ini_mode {
        None => ModeChoice::Off, // off/no/false/none -> "" -> None (explicit disable)
        Some("off") => ModeChoice::Off, // quoted "off"
        Some("detect") => ModeChoice::Detect,
        Some("block") => ModeChoice::Block,
        Some(_) => ModeChoice::SafeDefault,
    }
}

impl ModeChoice {
    /// The `mode = "..."` string to put in the synthesized TOML, or `None` to
    /// emit no `mode` line (so the core applies its safe default, Block).
    pub fn toml_mode(self) -> Option<&'static str> {
        match self {
            ModeChoice::Off => Some("off"),
            ModeChoice::Detect => Some("detect"),
            ModeChoice::Block => Some("block"),
            ModeChoice::SafeDefault => None,
        }
    }

    /// Human label for `phpinfo()` / `php --ri` — matches real behavior.
    pub fn display(self) -> &'static str {
        match self {
            ModeChoice::Off => "off",
            ModeChoice::Detect => "detect",
            ModeChoice::Block => "block",
            ModeChoice::SafeDefault => "block (safe default)",
        }
    }
}

/// Build a minimal core-config TOML from the resolved mode + log destination.
/// `mode` is [`ModeChoice::toml_mode`]; `None` emits no `mode` line. The log
/// destination is carried through as `[log] path` so the core config is
/// self-consistent (the glue resolves the effective destination with
/// `logsink::Settings::resolve`, where the ini path wins anyway).
pub fn synth_config(mode: Option<&str>, log: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(m) = mode {
        s.push_str("mode = \"");
        s.push_str(m);
        s.push_str("\"\n");
    }
    if let Some(l) = log {
        s.push_str("[log]\npath = \"");
        for c in l.chars() {
            match c {
                '"' | '\\' => {
                    s.push('\\');
                    s.push(c);
                }
                '\n' => s.push_str("\\n"),
                '\r' => s.push_str("\\r"),
                _ => s.push(c),
            }
        }
        s.push_str("\"\n");
    }
    s
}

/// What MINIT does with the bytes of the `howdah.config` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePlan {
    /// TOML to hand to `howdah_init`: the file itself when it parses, else a
    /// one-line `mode = ...` fallback.
    pub init_toml: Vec<u8>,
    /// Set when the file did not parse.
    pub invalid: Option<InvalidConfig>,
}

/// A config file that failed to parse, ready to report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidConfig {
    /// One-line parser error (no source excerpt).
    pub error: String,
    /// The mode the process runs in instead: `"block"` or `"off"`.
    pub fallback: &'static str,
}

impl InvalidConfig {
    /// The `phpinfo()` / `php --ri` "Config status" value.
    pub fn status(&self) -> String {
        format!("INVALID (fell back to {}): {}", self.fallback, self.error)
    }

    /// The one-time startup message for the SAPI error log.
    pub fn startup_message(&self, path: &str) -> String {
        format!(
            "Howdah: config file '{path}' is invalid, running in {} mode instead: {}",
            self.fallback, self.error
        )
    }
}

/// Decide what to initialise the core with, from the config file's bytes.
pub fn plan_file_config(bytes: &[u8]) -> FilePlan {
    let out = howdah_core::Config::load(bytes);
    match out.error {
        None => FilePlan { init_toml: bytes.to_vec(), invalid: None },
        Some(e) => {
            let fallback = if out.config.mode == howdah_core::Mode::Off { "off" } else { "block" };
            FilePlan {
                init_toml: synth_config(Some(fallback), None).into_bytes(),
                invalid: Some(InvalidConfig { error: one_line(e.message()), fallback }),
            }
        }
    }
}

/// Collapse a (possibly multi-line, source-excerpting) TOML error to one line:
/// `at line L, column C: <message>`. Single-line errors pass through.
pub fn one_line(msg: &str) -> String {
    let lines: Vec<&str> = msg.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let s = match lines.as_slice() {
        [] => "unknown error".to_string(),
        [only] => (*only).to_string(),
        [first, .., last] => {
            let head = first.strip_prefix("TOML parse error ").unwrap_or(first);
            format!("{head}: {last}")
        }
    };
    // serde appends the full list of valid keys; docs/config.md has it.
    match s.find(", expected ") {
        Some(i) => s[..i].to_string(),
        None => s,
    }
}

#[cfg(test)]
mod tests {
    use super::{one_line, plan_file_config, resolve_mode, synth_config, ModeChoice};
    use howdah_core::{Config, Mode};

    #[test]
    fn valid_file_is_passed_through_untouched() {
        let p = plan_file_config(b"mode = \"detect\"\n");
        assert!(p.invalid.is_none());
        assert_eq!(p.init_toml, b"mode = \"detect\"\n");
    }

    #[test]
    fn invalid_file_falls_back_to_block_and_reports() {
        let p = plan_file_config(b"mode = \"detect\"\n[limits]\nnope = 1\n");
        let inv = p.invalid.expect("must be invalid");
        assert_eq!(inv.fallback, "block");
        assert!(inv.error.contains("nope") && !inv.error.contains('\n'), "{}", inv.error);
        assert!(inv.status().starts_with("INVALID (fell back to block): "));
        assert!(inv.startup_message("/etc/h.toml").contains("/etc/h.toml"));
        assert_eq!(Config::from_toml(std::str::from_utf8(&p.init_toml).unwrap()).unwrap().mode, Mode::Block);
    }

    #[test]
    fn invalid_file_with_on_invalid_config_off_falls_back_to_off() {
        let p = plan_file_config(b"on_invalid_config = \"off\"\n[limits]\nnope = 1\n");
        assert_eq!(p.invalid.as_ref().unwrap().fallback, "off");
        assert_eq!(Config::from_toml(std::str::from_utf8(&p.init_toml).unwrap()).unwrap().mode, Mode::Off);
    }

    #[test]
    fn one_line_collapses_toml_excerpts() {
        let m = "TOML parse error at line 3, column 1\n  |\n3 | nope = 1\n  | ^^^^\nunknown field `nope`\n";
        assert_eq!(one_line(m), "at line 3, column 1: unknown field `nope`");
        assert_eq!(one_line("limits.max_parts must be > 0"), "limits.max_parts must be > 0");
        let long = "TOML parse error at line 3, column 1\n  |\n3 | nope = 1\n  | ^^^^\nunknown field `nope`, expected one of `a`, `b`\n";
        assert_eq!(one_line(long), "at line 3, column 1: unknown field `nope`");
    }

    #[test]
    fn empty_ini_mode_means_explicit_off() {
        // PHP maps bareword off/no/false/none -> "" -> None here.
        assert_eq!(resolve_mode(None), ModeChoice::Off);
    }

    #[test]
    fn recognized_values_map_through() {
        assert_eq!(resolve_mode(Some("off")), ModeChoice::Off);
        assert_eq!(resolve_mode(Some("detect")), ModeChoice::Detect);
        assert_eq!(resolve_mode(Some("block")), ModeChoice::Block);
        assert_eq!(resolve_mode(Some("yolo")), ModeChoice::SafeDefault);
    }

    #[test]
    fn each_choice_round_trips_through_the_core() {
        for (choice, want) in [
            (ModeChoice::Off, Mode::Off),
            (ModeChoice::Detect, Mode::Detect),
            (ModeChoice::Block, Mode::Block),
        ] {
            let toml = synth_config(choice.toml_mode(), Some("/var/log/howdah/events.log"));
            let cfg = Config::from_toml(&toml).expect("synthesized toml must parse");
            assert_eq!(cfg.mode, want, "{choice:?}");
        }
    }

    #[test]
    fn safe_default_emits_no_mode_and_core_blocks() {
        let toml = synth_config(ModeChoice::SafeDefault.toml_mode(), None);
        assert!(!toml.contains("mode ="), "{toml:?}");
        let cfg = Config::from_toml(&toml).unwrap();
        assert_eq!(cfg, Config::safe_defaults());
        assert_eq!(cfg.mode, Mode::Block);
    }

    #[test]
    fn display_matches_behavior() {
        assert_eq!(ModeChoice::Off.display(), "off");
        assert_eq!(ModeChoice::Detect.display(), "detect");
        assert_eq!(ModeChoice::Block.display(), "block");
        assert_eq!(ModeChoice::SafeDefault.display(), "block (safe default)");
    }

    #[test]
    fn log_path_specials_are_escaped_and_parse() {
        let toml = synth_config(Some("block"), Some(r#"a"b\c"#));
        let cfg = Config::from_toml(&toml).expect("escaped log path must parse");
        assert_eq!(cfg.log.path.as_deref(), Some(r#"a"b\c"#));
    }
}
