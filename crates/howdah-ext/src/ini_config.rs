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
/// destination is carried through so the core config is self-consistent (the
/// glue still writes the log via its own `LOG_PATH`, set regardless).
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

#[cfg(test)]
mod tests {
    use super::{resolve_mode, synth_config, ModeChoice};
    use howdah_core::{Config, Mode};

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
