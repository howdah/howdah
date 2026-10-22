//! Rule engine: turns a limit hit plus the current mode into an action.
use std::collections::BTreeMap;

use crate::config::Mode;
use crate::limits::{LimitHit, RuleId, Severity};

/// What the caller should do. Variant order is load-bearing: the FFI layer
/// maps Allow/Log/Block to 0/1/2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Log,
    Block,
}

/// Resolve a hit into an action. A per-rule override wins over the global
/// mode. Critical rules block regardless of the global mode (even `Detect` or
/// `Off`) unless explicitly overridden by name.
pub fn decide(hit: Option<&LimitHit>, mode: Mode, overrides: &BTreeMap<RuleId, Mode>) -> Action {
    let Some(hit) = hit else {
        return Action::Allow;
    };
    let effective = match overrides.get(&hit.rule) {
        Some(m) => *m,
        None if hit.severity == Severity::Critical => Mode::Block,
        None => mode,
    };
    match effective {
        Mode::Off => Action::Allow,
        Mode::Detect => Action::Log,
        Mode::Block => Action::Block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit(rule: RuleId, severity: Severity) -> LimitHit {
        LimitHit { rule, severity, detail: String::new() }
    }
    fn none() -> BTreeMap<RuleId, Mode> {
        BTreeMap::new()
    }

    #[test]
    fn no_hit_allows() {
        assert_eq!(decide(None, Mode::Block, &none()), Action::Allow);
        assert_eq!(decide(None, Mode::Off, &none()), Action::Allow);
    }

    #[test]
    fn critical_blocks_in_detect() {
        let h = hit(RuleId::MaxParts, Severity::Critical);
        assert_eq!(decide(Some(&h), Mode::Detect, &none()), Action::Block);
    }

    #[test]
    fn critical_blocks_in_block_and_off() {
        let h = hit(RuleId::MaxParts, Severity::Critical);
        assert_eq!(decide(Some(&h), Mode::Block, &none()), Action::Block);
        assert_eq!(decide(Some(&h), Mode::Off, &none()), Action::Block);
    }

    #[test]
    fn explicit_override_downgrades_critical() {
        let h = hit(RuleId::MaxParts, Severity::Critical);
        let o = BTreeMap::from([(RuleId::MaxParts, Mode::Detect)]);
        assert_eq!(decide(Some(&h), Mode::Block, &o), Action::Log);
    }

    #[test]
    fn override_for_other_rule_does_not_apply() {
        let h = hit(RuleId::MaxParts, Severity::Critical);
        let o = BTreeMap::from([(RuleId::MaxFiles, Mode::Detect)]);
        assert_eq!(decide(Some(&h), Mode::Detect, &o), Action::Block);
    }

    #[test]
    fn standard_follows_global_mode() {
        let h = hit(RuleId::MalformedMultipart, Severity::Standard);
        assert_eq!(decide(Some(&h), Mode::Detect, &none()), Action::Log);
        assert_eq!(decide(Some(&h), Mode::Block, &none()), Action::Block);
        assert_eq!(decide(Some(&h), Mode::Off, &none()), Action::Allow);
    }

    #[test]
    fn override_beats_global_for_standard() {
        let h = hit(RuleId::MalformedMultipart, Severity::Standard);
        let o = BTreeMap::from([(RuleId::MalformedMultipart, Mode::Block)]);
        assert_eq!(decide(Some(&h), Mode::Detect, &o), Action::Block);
        let o = BTreeMap::from([(RuleId::MalformedMultipart, Mode::Off)]);
        assert_eq!(decide(Some(&h), Mode::Block, &o), Action::Allow);
    }
}
