//! Input-shape accounting: request-variable count, array nesting depth and
//! key length, from PHP bracket syntax (`a[b][c]`). Pure; the glue feeds names.

/// Array nesting depth of a PHP variable name: the number of `[` characters
/// (`a` -> 0, `a[b]` -> 1, `a[b][c]` -> 2, `a[]` -> 1).
pub fn nesting_depth(name: &[u8]) -> usize {
    name.iter().filter(|&&b| b == b'[').count()
}

/// Longest single key in a variable name: the base name or any one bracket
/// segment (`a[bcd][e]` -> 3).
fn longest_key(name: &[u8]) -> usize {
    name.split(|&b| b == b'[' || b == b']').map(<[u8]>::len).max().unwrap_or(0)
}

/// High-water marks over the input variables of one request.
#[derive(Debug, Clone, Default)]
pub struct InputState {
    vars: u64,
    max_depth: usize,
    max_key_bytes: usize,
}

impl InputState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one input variable name.
    pub fn note_var(&mut self, name: &[u8]) {
        self.vars += 1;
        self.max_depth = self.max_depth.max(nesting_depth(name));
        self.max_key_bytes = self.max_key_bytes.max(longest_key(name));
    }

    pub fn vars(&self) -> u64 {
        self.vars
    }

    pub fn max_depth(&self) -> usize {
        self.max_depth
    }

    pub fn max_key_bytes(&self) -> usize {
        self.max_key_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::{Limits, RuleId};

    #[test] fn nesting_depth_matches_php_bracket_counting() {
        assert_eq!(nesting_depth(b"a"), 0);
        assert_eq!(nesting_depth(b"a[b]"), 1);
        assert_eq!(nesting_depth(b"a[b][c]"), 2);
        assert_eq!(nesting_depth(b"a[]"), 1);
        assert_eq!(nesting_depth(b""), 0);
    }
    #[test] fn state_counts_vars_and_tracks_high_water() {
        let mut s = InputState::new();
        for n in [b"a".as_slice(), b"b[c]", b"b[c][d]"] { s.note_var(n); }
        assert_eq!(s.vars(), 3);
        assert_eq!(s.max_depth(), 2);
    }
    #[test] fn check_input_fires_in_field_order() {
        let l = Limits { max_input_vars: 2, ..Limits::defaults() };
        let mut s = InputState::new();
        for n in [b"a".as_slice(), b"b", b"c"] { s.note_var(n); }
        assert_eq!(l.check_input(&s).unwrap().rule, RuleId::MaxInputVars);
        let l = Limits { max_input_nesting_depth: 1, ..Limits::defaults() };
        let mut s = InputState::new(); s.note_var(b"a[b][c]");
        assert_eq!(l.check_input(&s).unwrap().rule, RuleId::MaxInputNestingDepth);
    }
}
