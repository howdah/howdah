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

/// Per-file weight for the nesting budget (gap C / §4.4): PHP builds several
/// metadata arrays per file (`name`, `type`, `tmp_name`, `error`, `size` under
/// `$_FILES[name]`), so a file name's levels cost more than a field name's.
/// Provisional; calibrated against peak RSS in the lab (plan Task 8).
pub const FILE_NAME_WEIGHT: u64 = 5;

/// High-water marks over the input variables of one request.
#[derive(Debug, Clone, Default)]
pub struct InputState {
    vars: u64,
    max_depth: usize,
    max_key_bytes: usize,
    headers: u64,
    max_header_bytes: usize,
    /// Summed array-nesting levels across ALL variable/field/file names of the
    /// request (gap C / §4.4). Memory grows with the total number of levels, not
    /// with any one depth, so this is a sum, not a high-water mark. File names
    /// are weighted by `FILE_NAME_WEIGHT`.
    total_levels: u64,
}

impl InputState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one input variable name (GET/POST/cookie, the input_filter path).
    pub fn note_var(&mut self, name: &[u8]) {
        self.vars += 1;
        self.max_depth = self.max_depth.max(nesting_depth(name));
        self.max_key_bytes = self.max_key_bytes.max(longest_key(name));
        self.add_levels(name, false);
    }

    /// Record one multipart FORMDATA/FILE_START name for the nesting budget only
    /// (the part count/limits are handled separately by `MultipartState`). The
    /// name is inspected for `[` depth, never logged.
    pub fn note_name(&mut self, name: &[u8], is_file: bool) {
        self.add_levels(name, is_file);
    }

    /// Add one name's weighted array levels to the running total. The `+ 1` base
    /// makes even a flat name (the empty-file-control / trigger-(3) shape, many
    /// flat file names) accumulate.
    fn add_levels(&mut self, name: &[u8], is_file: bool) {
        let base = nesting_depth(name) as u64 + 1;
        let weight = if is_file { FILE_NAME_WEIGHT } else { 1 };
        self.total_levels = self.total_levels.saturating_add(base.saturating_mul(weight));
    }

    /// Summed, file-weighted nesting levels over the whole request (gap C).
    pub fn total_levels(&self) -> u64 {
        self.total_levels
    }

    /// Record one request header (name and value lengths in bytes).
    pub fn note_header(&mut self, name_len: usize, value_len: usize) {
        self.headers += 1;
        self.max_header_bytes = self.max_header_bytes.max(name_len.saturating_add(value_len));
    }

    pub fn headers(&self) -> u64 {
        self.headers
    }

    pub fn max_header_bytes(&self) -> usize {
        self.max_header_bytes
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
    use crate::limits::{Limits, RuleId, Severity};

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
    #[test] fn header_flood_yields_max_request_headers_standard() {
        let l = Limits { max_request_headers: 2, ..Limits::defaults() };
        let mut s = InputState::new();
        for _ in 0..3 { s.note_header(4, 4); }
        assert_eq!(s.headers(), 3);
        let h = l.check_input(&s).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::MaxRequestHeaders, Severity::Standard));
        assert_eq!(RuleId::MaxRequestHeaders.severity(), Severity::Standard);
    }
    #[test] fn oversized_header_yields_max_request_header_bytes_standard() {
        let l = Limits { max_request_header_bytes: 10, ..Limits::defaults() };
        let mut s = InputState::new();
        s.note_header(3, 4);
        assert!(l.check_input(&s).is_none());
        s.note_header(5, 6);
        assert_eq!(s.max_header_bytes(), 11);
        let h = l.check_input(&s).unwrap();
        assert_eq!((h.rule, h.severity), (RuleId::MaxRequestHeaderBytes, Severity::Standard));
        assert_eq!(RuleId::MaxRequestHeaderBytes.severity(), Severity::Standard);
    }
    #[test] fn total_levels_sums_across_vars_file_weighted() {
        let mut s = InputState::new();
        // Two flat field names -> (0+1)*1 each = 2.
        s.note_var(b"a");
        s.note_var(b"b");
        assert_eq!(s.total_levels(), 2);
        // A nested field name a[b][c] -> (2+1)*1 = 3 -> total 5.
        s.note_var(b"a[b][c]");
        assert_eq!(s.total_levels(), 5);
        // A flat FILE name -> (0+1)*FILE_NAME_WEIGHT.
        s.note_name(b"upload", true);
        assert_eq!(s.total_levels(), 5 + FILE_NAME_WEIGHT);
        // A multipart field name feeds it unweighted.
        s.note_name(b"x[y]", false);
        assert_eq!(s.total_levels(), 5 + FILE_NAME_WEIGHT + 2);
    }

    #[test] fn many_shallow_and_few_deep_reach_the_same_total() {
        // The budget is on the SUM of levels, not any one depth.
        let mut shallow = InputState::new();
        for _ in 0..6 { shallow.note_var(b"a[b]"); } // 6 * (1+1) = 12
        let mut deep = InputState::new();
        deep.note_var(b"a[b][c][d][e][f][g][h][i][j][k][l]"); // 11 brackets -> (11+1) = 12
        assert_eq!(shallow.total_levels(), 12);
        assert_eq!(shallow.total_levels(), deep.total_levels());
    }

    #[test] fn variable_checks_precede_header_checks() {
        let l = Limits { max_input_vars: 1, max_request_headers: 1, ..Limits::defaults() };
        let mut s = InputState::new();
        s.note_var(b"a"); s.note_var(b"b"); s.note_header(1, 1); s.note_header(1, 1);
        assert_eq!(l.check_input(&s).unwrap().rule, RuleId::MaxInputVars);
    }
}
