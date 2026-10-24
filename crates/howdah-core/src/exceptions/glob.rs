//! The `script` facet's glob: `*` (any run except `/`), `**` (any run
//! including `/`; `/**/` also matches a single `/`), `?` (one character
//! except `/`); everything else literal. Patterns must be absolute. Matching
//! is byte-wise and case-sensitive on the path PHP reports for the executing
//! file (already realpath-resolved by PHP).

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
/// path), with no backtracking blow-up and no regex engine.
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

    /// True iff `path` matches the whole pattern.
    pub fn matches(&self, path: &str) -> bool {
        if self.literal {
            return path == self.source;
        }
        let s = path.as_bytes();
        let n = self.toks.len();
        let m = s.len();
        // dp[j] : can toks[t..] match s[j..]  (computed from the last token back).
        let mut next = vec![false; m + 1];
        next[m] = true;
        let mut cur = vec![false; m + 1];
        for t in (0..n).rev() {
            for j in 0..=m {
                cur[j] = match &self.toks[t] {
                    Tok::Lit(c) => j < m && s[j] == *c && next[j + 1],
                    Tok::One => j < m && s[j] != b'/' && next[j + 1],
                    Tok::Star => {
                        // Consume k >= 0 non-slash bytes.
                        let mut ok = next[j];
                        let mut k = j;
                        while !ok && k < m && s[k] != b'/' {
                            k += 1;
                            ok = next[k];
                        }
                        ok
                    }
                    Tok::DoubleStar => (j..=m).any(|k| next[k]),
                    Tok::DirStar => {
                        // `/` + zero or more directories: s[j] == '/' and the
                        // consumed run ends in '/' (k is the index after it).
                        j < m
                            && s[j] == b'/'
                            && (j + 1..=m).any(|k| s[k - 1] == b'/' && next[k])
                    }
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
    }

    #[test]
    fn pathological_pattern_terminates() {
        let p = Glob::parse("/**/**/**/**/**/*a*a*a*a*a*b").unwrap();
        let s = format!("/{}", "a/".repeat(200));
        let t = std::time::Instant::now();
        assert!(!p.matches(&s));
        let long = format!("/{}b", "a".repeat(4000));
        assert!(!Glob::parse("/*a*a*a*a*a*a*a*a*c").unwrap().matches(&long));
        assert!(t.elapsed().as_secs() < 5);
    }
}
