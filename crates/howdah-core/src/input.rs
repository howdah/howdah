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

/// The php-cgi argument-injection shape (CVE-2012-1823): a query string with no
/// literal `=` whose first byte after an optional run of `+`/`%20` is `-`, so
/// php-cgi reads it as an option. A `%3d`-encoded `=` does NOT count: CGI only
/// skips argv parsing for a literal `=`, and the encoded form is the attack.
pub fn cgi_arg_injection(query_string: &[u8]) -> bool {
    if query_string.contains(&b'=') {
        return false;
    }
    let mut rest = query_string;
    loop {
        match rest {
            [b'+', tail @ ..] => rest = tail,
            [b'%', b'2', b'0', tail @ ..] => rest = tail,
            _ => break,
        }
    }
    rest.first() == Some(&b'-')
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
    #[test] fn cgi_arg_injection_fires_only_on_the_cve_shape() {
        assert!(cgi_arg_injection(b"-s"));
        assert!(cgi_arg_injection(b"-dallow_url_include%3d1"));
        assert!(cgi_arg_injection(b"+-d+auto_prepend_file%3dphp://input"));
        assert!(!cgi_arg_injection(b"a=1&b=2"));
        assert!(!cgi_arg_injection(b"sort=-price"));
        assert!(!cgi_arg_injection(b"q=a-b-c"));
        assert!(!cgi_arg_injection(b""));
        assert!(!cgi_arg_injection(b"-d=1")); // contains '=' => treated as a normal query
    }
    #[test] fn check_query_string_respects_is_cgi() {
        let l = Limits::defaults();
        assert_eq!(l.check_query_string(b"-s", true).unwrap().rule, RuleId::CgiArgInjection);
        assert!(l.check_query_string(b"-s", false).is_none());
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
