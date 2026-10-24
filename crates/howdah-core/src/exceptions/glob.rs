//! The `script` facet's glob: `*` (any run except `/`), `**` (any run
//! including `/`; `/**/` also matches a single `/`), `?` (one character
//! except `/`); everything else literal. Patterns must be absolute. Matching
//! is byte-wise and case-sensitive on the path PHP reports for the executing
//! file (already realpath-resolved by PHP).

/// Longest path the matcher looks at (PATH_MAX). A longer path never matches:
/// no exception, the rule stays armed.
pub const MAX_PATH: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Lit(u8),
    Star,
    /// `**` not bracketed by slashes: any run of bytes.
    DoubleStar,
    /// `/**/`: a `/`, or `/` + any run ending in `/` (zero or more directories).
    DirStar,
    One,
}

/// A compiled glob. `matches` is a dynamic-programming walk, O(pattern x
/// path): each wildcard row is filled from a suffix-OR of the row below, so
/// no position is rescanned. No regex engine, no backtracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    toks: Vec<Tok>,
    literal: bool,
    source: String,
}

impl Glob {
    /// Parse a pattern. Errors are complete sentences naming the problem.
    pub fn parse(pat: &str) -> Result<Glob, String> {
        if !pat.starts_with('/') {
            return Err(format!("{pat:?} must be an absolute path or glob (start with '/')"));
        }
        if pat.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
            return Err(format!("{pat:?} contains a control character"));
        }
        if pat.len() > MAX_PATH {
            return Err(format!("pattern is longer than {MAX_PATH} bytes"));
        }
        let mut toks: Vec<Tok> = Vec::with_capacity(pat.len());
        let b = pat.as_bytes();
        let mut i = 0;
        let mut literal = true;
        while i < b.len() {
            match b[i] {
                b'*' => {
                    literal = false;
                    if b.get(i + 1) == Some(&b'*') {
                        i += 2;
                        while b.get(i) == Some(&b'*') {
                            i += 1;
                        }
                        // `/**/` : fold the surrounding slashes into one token.
                        if toks.last() == Some(&Tok::Lit(b'/')) && b.get(i) == Some(&b'/') {
                            toks.pop();
                            toks.push(Tok::DirStar);
                            i += 1;
                        } else {
                            toks.push(Tok::DoubleStar);
                        }
                    } else {
                        toks.push(Tok::Star);
                        i += 1;
                    }
                }
                b'?' => {
                    literal = false;
                    toks.push(Tok::One);
                    i += 1;
                }
                c => {
                    toks.push(Tok::Lit(c));
                    i += 1;
                }
            }
        }
        Ok(Glob { toks, literal, source: pat.to_string() })
    }

    /// The pattern as written.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// True iff `path` matches the whole pattern. Paths over [`MAX_PATH`]
    /// bytes never match.
    pub fn matches(&self, path: &str) -> bool {
        if path.len() > MAX_PATH {
            return false;
        }
        if self.literal {
            return path == self.source;
        }
        let s = path.as_bytes();
        let n = self.toks.len();
        let m = s.len();
        // next[j]: can toks[t+1..] match s[j..]; cur[j]: toks[t..] vs s[j..].
        let mut next = vec![false; m + 1];
        next[m] = true;
        let mut cur = vec![false; m + 1];
        // Suffix ORs over `next`, rebuilt per row in O(m):
        //   any[j]   = OR next[k] for k >= j                       (DoubleStar)
        //   seg[j]   = OR next[k] for k in j..=end of segment at j  (Star)
        //   slash[j] = OR next[k] for k >= j with s[k-1] == '/'     (DirStar)
        let mut any = vec![false; m + 2];
        let mut seg = vec![false; m + 2];
        let mut slash = vec![false; m + 2];
        for t in (0..n).rev() {
            let tok = &self.toks[t];
            if matches!(tok, Tok::Star | Tok::DoubleStar | Tok::DirStar) {
                for j in (0..=m).rev() {
                    any[j] = next[j] || any[j + 1];
                    seg[j] = next[j] || (j < m && s[j] != b'/' && seg[j + 1]);
                    slash[j] = (j >= 1 && s[j - 1] == b'/' && next[j]) || slash[j + 1];
                }
            }
            for j in 0..=m {
                cur[j] = match tok {
                    Tok::Lit(c) => j < m && s[j] == *c && next[j + 1],
                    Tok::One => j < m && s[j] != b'/' && next[j + 1],
                    Tok::Star => seg[j],
                    Tok::DoubleStar => any[j],
                    // `/` + zero or more directories: s[j] == '/' and the
                    // consumed run ends in '/' (k is the index after it).
                    Tok::DirStar => j < m && s[j] == b'/' && slash[j + 1],
                };
            }
            std::mem::swap(&mut cur, &mut next);
        }
        next[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, s: &str) -> bool {
        Glob::parse(p).unwrap().matches(s)
    }

    #[test]
    fn literal_is_exact() {
        assert!(m("/var/www/a.php", "/var/www/a.php"));
        assert!(!m("/var/www/a.php", "/var/www/a.php2"));
        assert!(!m("/var/www/a.php", "/var/www/A.php"));
        assert!(!m("/var/www/a.php", "/var/www/./a.php"));
    }

    #[test]
    fn star_does_not_cross_slash() {
        assert!(m("/var/www/wp-admin/*.php", "/var/www/wp-admin/post.php"));
        assert!(!m("/var/www/wp-admin/*.php", "/var/www/wp-admin/includes/x.php"));
        assert!(m("/var/www/*/cron.php", "/var/www/site1/cron.php"));
        assert!(!m("/var/www/*/cron.php", "/var/www/a/b/cron.php"));
        assert!(m("/home/*/public_html/cron.php", "/home/alice/public_html/cron.php"));
        assert!(m("/a/*", "/a/"));
        assert!(!m("/a/*", "/a/b/"));
        assert!(m("/a/*b*", "/a/xbyb"));
        assert!(!m("/a/*b*c", "/a/xbyb"));
    }

    #[test]
    fn double_star_crosses_slash() {
        assert!(m("/var/www/wp-admin/**", "/var/www/wp-admin/includes/x.php"));
        assert!(m("/var/www/wp-admin/**", "/var/www/wp-admin/"));
        assert!(m("/var/www/**/cron.php", "/var/www/a/b/cron.php"));
        assert!(m("/var/www/**/cron.php", "/var/www/cron.php"));
        assert!(!m("/var/www/**/cron.php", "/var/www/xcron.php"));
        assert!(!m("/var/www/**/cron.php", "/srv/cron.php"));
        assert!(m("/**", "/anything/at/all"));
        assert!(m("/**/x.php", "/x.php"));
        assert!(m("/var/**.php", "/var/a/b.php"));
        // eval'd code reports "<file>(<line>) : eval()'d code": `**` covers it.
        assert!(m("/var/www/**", "/var/www/a.php(12) : eval()'d code"));
        assert!(!m("/var/www/a.php", "/var/www/a.php(12) : eval()'d code"));
    }

    #[test]
    fn question_mark_is_one_non_slash_char() {
        assert!(m("/a/?.php", "/a/x.php"));
        assert!(!m("/a/?.php", "/a/xy.php"));
        assert!(!m("/a/?.php", "/a//.php"));
    }

    #[test]
    fn relative_and_control_rejected() {
        assert!(Glob::parse("var/www/a.php").is_err());
        assert!(Glob::parse("*.php").is_err());
        assert!(Glob::parse("").is_err());
        assert!(Glob::parse("/a\n").is_err());
        assert!(Glob::parse(&format!("/{}", "a".repeat(MAX_PATH))).is_err());
    }

    #[test]
    fn linear_time_on_long_paths_and_capped() {
        // 100 wildcard tokens against a 4 KiB path: a linear DP finishes well
        // inside the budget (the earlier O(tokens x path^2) walk took ~200 ms).
        let pat = format!("/{}b", "*a".repeat(50));
        let g = Glob::parse(&pat).unwrap();
        let path = format!("/{}", "a".repeat(MAX_PATH - 1));
        let t = std::time::Instant::now();
        for _ in 0..20 {
            assert!(!g.matches(&path));
        }
        assert!(t.elapsed().as_millis() < 400, "{:?}", t.elapsed());
        // Over the cap: never matches, even a catch-all pattern.
        let long = format!("/var/{}", "x".repeat(MAX_PATH));
        assert!(!Glob::parse("/var/**").unwrap().matches(&long));
        let at_cap = format!("/var/{}", "x".repeat(MAX_PATH - 5));
        assert_eq!(at_cap.len(), MAX_PATH);
        assert!(Glob::parse("/var/**").unwrap().matches(&at_cap));
    }

    #[test]
    fn pathological_pattern_terminates() {
        let p = Glob::parse("/**/**/**/**/**/*a*a*a*a*a*b").unwrap();
        let s = format!("/{}", "a/".repeat(200));
        let t = std::time::Instant::now();
        assert!(!p.matches(&s));
        let long = format!("/{}b", "a".repeat(4000));
        assert!(!Glob::parse("/*a*a*a*a*a*a*a*a*c").unwrap().matches(&long));
        assert!(Glob::parse("/*a*a*a*a*a*a*a*a*b").unwrap().matches(&long));
        assert!(t.elapsed().as_secs() < 5);
    }
}
