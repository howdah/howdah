//! Scoped `[[exceptions]]`: downgrade one rule to `off` for one script, request
//! parameter, URI prefix or client network. See
//! `docs/superpowers/specs/2026-10-24-howdah-exceptions-design.md`.
//!
//! Pure and filesystem-free. The matcher is compiled once from the parsed
//! config; every layer hands it the facts it has (`EventFacts`) after a rule
//! has produced a finding and before the mode is applied. Critical rules are
//! never excepted, here and in the validator.

pub mod glob;
pub mod sha256;

use serde::{Deserialize, Serialize};

use crate::limits::{rule_catalog, RuleId, Severity};
use crate::sinks::ssrf::{cidr_contains, decode_literal_ip, parse_cidr, IpRepr};
use glob::Glob;

/// The protection layer a rule belongs to, named after its config section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Limits,
    Inspect,
    Sinks,
    Behavior,
}

impl Layer {
    /// The layer of a rule. Exhaustive: a new `RuleId` does not compile until
    /// it is placed.
    pub fn of(r: RuleId) -> Layer {
        match r {
            RuleId::MaxParts
            | RuleId::MaxFiles
            | RuleId::MaxPartHeaders
            | RuleId::MaxPartHeaderBytes
            | RuleId::MaxFieldNameLen
            | RuleId::MaxFilenameLen
            | RuleId::ParseMemoryBudget
            | RuleId::MalformedMultipart
            | RuleId::UploadProgressAbuse
            | RuleId::SelfTest
            | RuleId::MaxInputVars
            | RuleId::MaxInputNestingDepth
            | RuleId::MaxInputKeyBytes
            | RuleId::MaxRequestHeaders
            | RuleId::MaxRequestHeaderBytes
            | RuleId::OutOfMemory
            | RuleId::StartupFatal
            | RuleId::PostTooLarge
            | RuleId::NestingBudget
            | RuleId::ParseMemoryEstimate => Layer::Limits,
            RuleId::SqlInjection | RuleId::PathTraversal | RuleId::CommandInjection => Layer::Inspect,
            RuleId::CommandExec
            | RuleId::Include
            | RuleId::Eval
            | RuleId::Unserialize
            | RuleId::Phar
            | RuleId::Ssrf
            | RuleId::MailInjection
            | RuleId::PregEval
            | RuleId::CreateFunction
            | RuleId::AssertString
            | RuleId::DangerousCallback
            | RuleId::Xxe
            | RuleId::TlsVerify => Layer::Sinks,
            RuleId::UploadExec
            | RuleId::UnexpectedBinary
            | RuleId::UnexpectedEgress
            | RuleId::PhpWrite => Layer::Behavior,
        }
    }

    /// The config-section spelling (`limits`, `inspect`, `sinks`, `behavior`).
    pub fn name(self) -> &'static str {
        match self {
            Layer::Limits => "limits",
            Layer::Inspect => "inspect",
            Layer::Sinks => "sinks",
            Layer::Behavior => "behavior",
        }
    }

    /// The layer number used in the log (`layer` field): 1..4.
    pub fn number(self) -> u8 {
        match self {
            Layer::Limits => 1,
            Layer::Inspect => 2,
            Layer::Sinks => 3,
            Layer::Behavior => 4,
        }
    }

    fn parse(s: &str) -> Option<Layer> {
        match s {
            "limits" => Some(Layer::Limits),
            "inspect" => Some(Layer::Inspect),
            "sinks" => Some(Layer::Sinks),
            "behavior" => Some(Layer::Behavior),
            _ => None,
        }
    }
}

/// One `[[exceptions]]` table as written. Every key is optional at the
/// serde level so the validator, not serde, reports what is missing, with
/// the entry index and key named.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExceptionEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_cidr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The `rule` key, parsed: a whole layer or one rule of a layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleSelector {
    pub layer: Layer,
    pub rule: Option<RuleId>,
}

/// The rule's log/config spelling (`max_parts`, `sql_injection`, ...).
pub fn rule_name(r: RuleId) -> String {
    match serde_json::to_value(r) {
        Ok(serde_json::Value::String(s)) => s,
        _ => format!("{r:?}"),
    }
}

fn rule_by_name(name: &str) -> Option<RuleId> {
    rule_catalog().iter().copied().find(|r| rule_name(*r) == name)
}

impl RuleSelector {
    /// Parse `sql_injection`, `inspect`, `inspect.*`, `inspect.sql_injection`.
    /// Critical rules are refused: they cannot be excepted.
    pub fn parse(s: &str) -> Result<RuleSelector, String> {
        let unknown = || {
            format!(
                "unknown rule {s:?} (rule ids are the names in the log; layers are limits, inspect, sinks, behavior; or layer.rule such as sinks.command_exec)"
            )
        };
        if s == "*" {
            return Err("\"*\" (every layer) is not accepted; name the layer or rule the exception turns off".to_string());
        }
        let (layer, rule) = match s.split_once('.') {
            Some((l, r)) => {
                let layer = Layer::parse(l).ok_or_else(unknown)?;
                if r == "*" {
                    (layer, None)
                } else {
                    let rule = rule_by_name(r).ok_or_else(unknown)?;
                    if Layer::of(rule) != layer {
                        return Err(format!(
                            "{s:?}: rule {r:?} belongs to layer {}, not {}",
                            Layer::of(rule).name(),
                            layer.name()
                        ));
                    }
                    (layer, Some(rule))
                }
            }
            None => match Layer::parse(s) {
                Some(layer) => (layer, None),
                None => {
                    let rule = rule_by_name(s).ok_or_else(unknown)?;
                    (Layer::of(rule), Some(rule))
                }
            },
        };
        if let Some(r) = rule {
            if r.severity() == Severity::Critical {
                return Err(format!(
                    "{:?} is a Critical rule and cannot be excepted",
                    rule_name(r)
                ));
            }
        }
        Ok(RuleSelector { layer, rule })
    }

    /// True iff this selector covers `r`. Critical rules never match, even
    /// under a whole-layer selector.
    pub fn covers(&self, r: RuleId) -> bool {
        if r.severity() == Severity::Critical {
            return false;
        }
        match self.rule {
            Some(x) => x == r,
            None => Layer::of(r) == self.layer,
        }
    }

    /// Canonical spelling: `layer` or `layer.rule`.
    pub fn display(&self) -> String {
        match self.rule {
            Some(r) => format!("{}.{}", self.layer.name(), rule_name(r)),
            None => self.layer.name().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct Compiled {
    selector: RuleSelector,
    script: Option<Glob>,
    script_sha256: Option<[u8; 32]>,
    param: Option<Vec<u8>>,
    param_prefix: Option<Vec<u8>>,
    uri_prefix: Option<String>,
    client_cidr: Option<(IpRepr, u8)>,
    reason: String,
}

/// The facts a layer has about one event. `None` means "not known here".
#[derive(Debug, Clone, Copy)]
pub struct EventFacts<'a> {
    pub rule: RuleId,
    pub script: Option<&'a str>,
    pub script_sha256: Option<&'a [u8; 32]>,
    pub param: Option<&'a [u8]>,
    pub uri: &'a str,
    pub client_ip: &'a str,
}

/// A matched exception (owned, so the caller can keep mutating the context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// Zero-based index in the `[[exceptions]]` array.
    pub index: usize,
    /// The selector's canonical spelling.
    pub selector: String,
    /// The operator's reason text.
    pub reason: String,
}

impl Match {
    /// The `reason` field of an `excepted` log line: the config text,
    /// truncated so one entry cannot flood the log.
    pub fn log_reason(&self) -> String {
        const MAX: usize = 160;
        let mut r: String = self.reason.chars().filter(|c| !c.is_control()).collect();
        if r.len() > MAX {
            let mut cut = MAX;
            while !r.is_char_boundary(cut) {
                cut -= 1;
            }
            r.truncate(cut);
            r.push_str("...");
        }
        format!("exception #{} ({}): {}", self.index, self.selector, r)
    }
}

/// The compiled matcher.
#[derive(Debug, Clone, Default)]
pub struct Exceptions {
    entries: Vec<Compiled>,
}

fn facet_err(i: usize, key: &str, msg: impl AsRef<str>) -> String {
    format!("exceptions[{i}].{key}: {}", msg.as_ref())
}

/// Which facets a layer accepts, and why not otherwise.
fn facet_allowed(layer: Layer, key: &str) -> Result<(), &'static str> {
    match (layer, key) {
        (_, "uri_prefix") | (_, "client_cidr") => Ok(()),
        (Layer::Limits, _) => Err("Layer 1 rules fire while PHP registers request variables, before any script runs; only uri_prefix and client_cidr apply"),
        (Layer::Inspect, "param") | (Layer::Inspect, "param_prefix") => Ok(()),
        (Layer::Inspect, _) => Err("Layer 2 events are raised while PHP registers request variables, before any script runs; use param, param_prefix, uri_prefix or client_cidr"),
        (Layer::Sinks, "script") | (Layer::Sinks, "script_sha256") => Ok(()),
        (Layer::Behavior, "script") | (Layer::Behavior, "script_sha256") => Ok(()),
        (Layer::Sinks, _) | (Layer::Behavior, _) => Err("a sink or behavior event is not tied to one request variable; use script, script_sha256, uri_prefix or client_cidr"),
    }
}

/// A request path a `uri_prefix` facet may be compared with: absolute, with
/// no `.`/`..` segment, no empty segment (`//`), no backslash and no
/// percent-encoding. Anything else is left to the web server's idea of
/// normalisation, which Howdah cannot see (nginx passes `$request_uri` raw),
/// so it never satisfies the facet: `/wp-admin/../index.php` executes
/// `/index.php` and must not be excepted as `/wp-admin/`.
pub fn uri_is_plain(uri: &str) -> bool {
    if !uri.starts_with('/') || uri.bytes().any(|b| b == b'%' || b == b'\\') {
        return false;
    }
    uri[1..].split('/').all(|seg| !seg.is_empty() && seg != "." && seg != "..")
        || uri == "/"
}

/// Layer 2 scans the request path as these pseudo-parameters; a `param` facet
/// naming (or prefixing) them would silence the path scan, so they are refused.
const PATH_PSEUDO_PARAMS: [&str; 2] = ["REQUEST_URI", "PATH_INFO"];

/// Parse `client_cidr`: a CIDR, or a bare IPv4/IPv6 address (full prefix).
pub fn parse_client_cidr(s: &str) -> Option<(IpRepr, u8)> {
    if s.contains('/') {
        return parse_cidr(s);
    }
    let ip = decode_literal_ip(s.as_bytes())?;
    // A bare address must be spelled plainly (strict dotted quad), like a CIDR.
    if !s.contains(':') && parse_cidr(&format!("{s}/32")).is_none() {
        return None;
    }
    let p = if matches!(ip, IpRepr::V4(_)) { 32 } else { 128 };
    Some((ip, p))
}

fn compile_one(i: usize, e: &ExceptionEntry) -> Result<Compiled, String> {
    let rule = e
        .rule
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| facet_err(i, "rule", "required (a rule id, a layer, or layer.rule)"))?;
    let selector = RuleSelector::parse(rule).map_err(|m| facet_err(i, "rule", m))?;
    let reason = e
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            facet_err(i, "reason", "required (write why this exception exists; it is the audit record)")
        })?
        .to_string();

    let present = [
        ("script", e.script.is_some()),
        ("script_sha256", e.script_sha256.is_some()),
        ("param", e.param.is_some()),
        ("param_prefix", e.param_prefix.is_some()),
        ("uri_prefix", e.uri_prefix.is_some()),
        ("client_cidr", e.client_cidr.is_some()),
    ];
    if !present.iter().any(|(_, p)| *p) {
        return Err(format!(
            "exceptions[{i}]: at least one of script, script_sha256, param, param_prefix, uri_prefix, client_cidr is required"
        ));
    }
    for (key, p) in present {
        if p {
            facet_allowed(selector.layer, key).map_err(|why| {
                facet_err(
                    i,
                    key,
                    format!("not allowed for {} rule {:?} ({why})", selector.layer.name(), rule),
                )
            })?;
        }
    }
    if e.param.is_some() && e.param_prefix.is_some() {
        return Err(facet_err(i, "param_prefix", "set either param or param_prefix, not both"));
    }

    // A facet that matches everything is no facet: it would satisfy the
    // "at least one facet" rail while scoping nothing (the `*` refusal, again).
    let every = |key: &str, what: &str| {
        facet_err(i, key, format!("{what} matches every request; a facet must narrow the scope (name a directory, path, parameter or network)"))
    };
    let script = match &e.script {
        Some(s) => {
            let g = Glob::parse(s).map_err(|m| facet_err(i, "script", m))?;
            if s.bytes().all(|b| matches!(b, b'/' | b'*' | b'?')) {
                return Err(every("script", &format!("{s:?}")));
            }
            Some(g)
        }
        None => None,
    };
    let script_sha256 = match &e.script_sha256 {
        Some(s) => Some(sha256::parse_hex(s.trim()).ok_or_else(|| {
            facet_err(i, "script_sha256", format!("{s:?} is not 64 hex characters (sha256sum of the file)"))
        })?),
        None => None,
    };
    let non_empty = |key: &str, v: &str| -> Result<(), String> {
        if v.is_empty() || v.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
            Err(facet_err(i, key, "must be non-empty with no control characters"))
        } else {
            Ok(())
        }
    };
    let not_pseudo = |key: &str, v: &str| -> Result<(), String> {
        if PATH_PSEUDO_PARAMS.iter().any(|p| p.starts_with(v)) {
            Err(facet_err(
                i,
                key,
                format!("{v:?} names or prefixes the path pseudo-parameters REQUEST_URI / PATH_INFO, which would silence the Layer 2 path scan; use uri_prefix to scope by path"),
            ))
        } else {
            Ok(())
        }
    };
    if let Some(p) = &e.param {
        non_empty("param", p)?;
        not_pseudo("param", p)?;
    }
    if let Some(p) = &e.param_prefix {
        non_empty("param_prefix", p)?;
        not_pseudo("param_prefix", p)?;
    }
    if let Some(u) = &e.uri_prefix {
        non_empty("uri_prefix", u)?;
        if !u.starts_with('/') {
            return Err(facet_err(i, "uri_prefix", format!("{u:?} must start with '/' (a request path prefix)")));
        }
        if u == "/" {
            return Err(every("uri_prefix", "\"/\""));
        }
        let stem = u.trim_end_matches('/');
        if !stem.is_empty() && !uri_is_plain(stem) {
            return Err(facet_err(i, "uri_prefix", format!("{u:?} must be a plain path prefix (no '.'/'..' segments, '//', '\\\\' or '%')")));
        }
    }
    let client_cidr = match &e.client_cidr {
        Some(c) => {
            let (net, prefix) = parse_client_cidr(c.trim()).ok_or_else(|| {
                facet_err(i, "client_cidr", format!("{c:?} is not an IPv4/IPv6 CIDR or address"))
            })?;
            if prefix == 0 {
                return Err(every("client_cidr", &format!("{c:?} (prefix length 0)")));
            }
            Some((net, prefix))
        }
        None => None,
    };
    Ok(Compiled {
        selector,
        script,
        script_sha256,
        param: e.param.as_ref().map(|s| s.as_bytes().to_vec()),
        param_prefix: e.param_prefix.as_ref().map(|s| s.as_bytes().to_vec()),
        uri_prefix: e.uri_prefix.clone(),
        client_cidr,
        reason,
    })
}

impl Exceptions {
    /// Compile every entry. On failure returns every error (one per bad
    /// entry), each naming `exceptions[i].key`.
    pub fn compile(entries: &[ExceptionEntry]) -> Result<Exceptions, Vec<String>> {
        let mut out = Vec::with_capacity(entries.len());
        let mut errs = Vec::new();
        for (i, e) in entries.iter().enumerate() {
            match compile_one(i, e) {
                Ok(c) => out.push(c),
                Err(m) => errs.push(m),
            }
        }
        if errs.is_empty() {
            Ok(Exceptions { entries: out })
        } else {
            Err(errs)
        }
    }

    /// Validate entries for `Config::from_toml`: the errors joined with `; `.
    pub fn validate(entries: &[ExceptionEntry]) -> Result<(), String> {
        Exceptions::compile(entries).map(|_| ()).map_err(|e| e.join("; "))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True iff some entry has a `script_sha256` facet that could apply to
    /// `script` (its `script` glob, if any, matches). The glue hashes the
    /// file only when this is true.
    pub fn want_hash(&self, script: &str) -> bool {
        if self.entries.is_empty() || script.is_empty() {
            return false;
        }
        self.entries.iter().any(|e| {
            e.script_sha256.is_some() && e.script.as_ref().is_none_or(|g| g.matches(script))
        })
    }

    /// The first exception every one of whose facets matches `f`, if any.
    /// Critical rules never match.
    pub fn matches(&self, f: &EventFacts) -> Option<Match> {
        if f.rule.severity() == Severity::Critical {
            return None;
        }
        self.entries.iter().enumerate().find_map(|(index, e)| {
            if !e.selector.covers(f.rule) {
                return None;
            }
            if let Some(g) = &e.script {
                if !f.script.is_some_and(|s| g.matches(s)) {
                    return None;
                }
            }
            if let Some(h) = &e.script_sha256 {
                if f.script_sha256 != Some(h) {
                    return None;
                }
            }
            if let Some(p) = &e.param {
                if f.param != Some(p.as_slice()) {
                    return None;
                }
            }
            if let Some(p) = &e.param_prefix {
                if !f.param.is_some_and(|n| n.starts_with(p)) {
                    return None;
                }
            }
            if let Some(u) = &e.uri_prefix {
                // Fail toward protection: a path Howdah cannot trust to mean
                // what it says (dot segments, `//`, `\`, `%`) never matches.
                if !uri_is_plain(f.uri) || !f.uri.starts_with(u.as_str()) {
                    return None;
                }
            }
            if let Some((net, prefix)) = e.client_cidr {
                let ip = decode_literal_ip(f.client_ip.as_bytes())?;
                if !cidr_contains(net, prefix, ip) {
                    return None;
                }
            }
            Some(Match { index, selector: e.selector.display(), reason: e.reason.clone() })
        })
    }
}

/// Counts for `php --ri howdah`: how many `[[exceptions]]` entries in a
/// config text compile, and how many are rejected. A lenient second pass
/// over the TOML document (the real parser is all-or-nothing), so a file
/// refused for two bad entries still reports `0 configured, 2 rejected`.
/// `None` when the text is not TOML or `exceptions` is not an array.
pub fn report(toml_text: &str) -> Option<(usize, usize)> {
    let doc: toml::Table = toml::from_str(toml_text).ok()?;
    let arr = match doc.get("exceptions") {
        None => return Some((0, 0)),
        Some(toml::Value::Array(a)) => a,
        Some(_) => return None,
    };
    let mut ok = 0;
    let mut bad = 0;
    for (i, v) in arr.iter().enumerate() {
        let parsed: Result<ExceptionEntry, _> = v.clone().try_into();
        match parsed {
            Ok(e) if compile_one(i, &e).is_ok() => ok += 1,
            _ => bad += 1,
        }
    }
    Some((ok, bad))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(toml: &str) -> ExceptionEntry {
        toml::from_str(toml).unwrap()
    }
    fn compile(tomls: &[&str]) -> Result<Exceptions, Vec<String>> {
        let v: Vec<ExceptionEntry> = tomls.iter().map(|t| entry(t)).collect();
        Exceptions::compile(&v)
    }
    fn one(toml: &str) -> Exceptions {
        compile(&[toml]).unwrap()
    }
    fn err(toml: &str) -> String {
        compile(&[toml]).unwrap_err().join("; ")
    }
    fn facts(rule: RuleId) -> EventFacts<'static> {
        EventFacts { rule, script: None, script_sha256: None, param: None, uri: "/up/index.php", client_ip: "" }
    }

    // ---- selector --------------------------------------------------------

    #[test]
    fn selector_forms() {
        let s = RuleSelector::parse("sql_injection").unwrap();
        assert_eq!(s, RuleSelector { layer: Layer::Inspect, rule: Some(RuleId::SqlInjection) });
        assert_eq!(RuleSelector::parse("inspect").unwrap(), RuleSelector { layer: Layer::Inspect, rule: None });
        assert_eq!(RuleSelector::parse("inspect.*").unwrap(), RuleSelector { layer: Layer::Inspect, rule: None });
        assert_eq!(
            RuleSelector::parse("sinks.command_exec").unwrap(),
            RuleSelector { layer: Layer::Sinks, rule: Some(RuleId::CommandExec) }
        );
        assert_eq!(
            RuleSelector::parse("behavior.php_write").unwrap(),
            RuleSelector { layer: Layer::Behavior, rule: Some(RuleId::PhpWrite) }
        );
        assert_eq!(
            RuleSelector::parse("limits.max_request_headers").unwrap(),
            RuleSelector { layer: Layer::Limits, rule: Some(RuleId::MaxRequestHeaders) }
        );
        assert_eq!(RuleSelector::parse("sinks.command_exec").unwrap().display(), "sinks.command_exec");
        assert_eq!(RuleSelector::parse("command_exec").unwrap().display(), "sinks.command_exec");
        assert_eq!(RuleSelector::parse("behavior").unwrap().display(), "behavior");
    }

    #[test]
    fn selector_rejects_critical_unknown_star_and_wrong_layer() {
        assert!(RuleSelector::parse("max_parts").unwrap_err().contains("Critical"));
        assert!(RuleSelector::parse("limits.max_input_vars").unwrap_err().contains("Critical"));
        assert!(RuleSelector::parse("*").is_err());
        assert!(RuleSelector::parse("sqli").unwrap_err().contains("unknown rule"));
        assert!(RuleSelector::parse("inspect.command_exec").unwrap_err().contains("belongs to layer sinks"));
        assert!(RuleSelector::parse("layer2").is_err());
        assert!(RuleSelector::parse("").is_err());
    }

    #[test]
    fn layer_selector_never_covers_critical() {
        let s = RuleSelector::parse("limits").unwrap();
        assert!(s.covers(RuleId::MaxRequestHeaders));
        assert!(s.covers(RuleId::SelfTest));
        assert!(!s.covers(RuleId::MaxParts));
        assert!(!s.covers(RuleId::MaxInputVars));
        assert!(!s.covers(RuleId::SqlInjection));
    }

    #[test]
    fn every_rule_has_a_layer_and_round_trips_by_name() {
        for r in rule_catalog() {
            let name = rule_name(*r);
            assert_eq!(rule_by_name(&name), Some(*r), "{name}");
            let l = Layer::of(*r);
            assert!((1..=4).contains(&l.number()));
            if r.severity() == Severity::Standard {
                let sel = RuleSelector::parse(&name).unwrap();
                assert_eq!(sel.layer, l);
                assert!(sel.covers(*r));
            } else {
                assert!(RuleSelector::parse(&name).is_err(), "{name} must be refused");
            }
        }
    }

    // ---- validation --------------------------------------------------------

    #[test]
    fn requires_rule_reason_and_a_facet() {
        assert!(err("script = \"/a.php\"\nreason = \"x\"").contains("exceptions[0].rule: required"));
        assert!(err("rule = \"command_exec\"\nscript = \"/a.php\"").contains("exceptions[0].reason: required"));
        assert!(err("rule = \"command_exec\"\nscript = \"/a.php\"\nreason = \"  \"").contains("reason"));
        assert!(err("rule = \"command_exec\"\nreason = \"x\"").contains("exceptions[0]: at least one of"));
    }

    #[test]
    fn critical_rule_named_with_index_and_key() {
        let e = err("rule = \"max_parts\"\nuri_prefix = \"/\"\nreason = \"x\"");
        assert!(e.starts_with("exceptions[0].rule:"), "{e}");
        assert!(e.contains("Critical"), "{e}");
    }

    #[test]
    fn facet_applicability_per_layer() {
        // Layer 1 Standard: uri/cidr only.
        assert!(one("rule = \"max_request_headers\"\nclient_cidr = \"10.0.0.0/8\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"limits\"\nuri_prefix = \"/api/\"\nreason = \"x\"").len() == 1);
        assert!(err("rule = \"max_request_headers\"\nscript = \"/a.php\"\nreason = \"x\"").contains("exceptions[0].script: not allowed for limits"));
        assert!(err("rule = \"self_test\"\nparam = \"q\"\nreason = \"x\"").contains("exceptions[0].param"));
        // Layer 2: param/prefix/uri/cidr; no script.
        assert!(one("rule = \"inspect.sql_injection\"\nparam = \"content\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"inspect\"\nparam_prefix = \"jform[\"\nuri_prefix = \"/administrator/\"\nreason = \"x\"").len() == 1);
        let e = err("rule = \"sql_injection\"\nscript = \"/a.php\"\nreason = \"x\"");
        assert!(e.contains("exceptions[0].script: not allowed for inspect") && e.contains("uri_prefix"), "{e}");
        assert!(err("rule = \"sql_injection\"\nscript_sha256 = \"00\"\nreason = \"x\"").contains("script_sha256: not allowed"));
        // Layer 3/4: script/hash/uri/cidr; no param.
        assert!(one("rule = \"sinks.command_exec\"\nscript = \"/a.php\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"behavior.php_write\"\nscript = \"/var/www/**\"\nclient_cidr = \"::1\"\nreason = \"x\"").len() == 1);
        assert!(err("rule = \"command_exec\"\nparam = \"q\"\nreason = \"x\"").contains("exceptions[0].param: not allowed for sinks"));
        assert!(err("rule = \"behavior\"\nparam_prefix = \"q\"\nreason = \"x\"").contains("exceptions[0].param_prefix: not allowed for behavior"));
    }

    #[test]
    fn facet_value_validation() {
        assert!(err("rule = \"command_exec\"\nscript = \"a.php\"\nreason = \"x\"").contains("exceptions[0].script"));
        assert!(err("rule = \"command_exec\"\nscript_sha256 = \"abc\"\nreason = \"x\"").contains("exceptions[0].script_sha256"));
        assert!(err("rule = \"sql_injection\"\nuri_prefix = \"wp-admin\"\nreason = \"x\"").contains("exceptions[0].uri_prefix"));
        assert!(err("rule = \"sql_injection\"\nparam = \"\"\nreason = \"x\"").contains("exceptions[0].param"));
        assert!(err("rule = \"sql_injection\"\nparam = \"a\"\nparam_prefix = \"a\"\nreason = \"x\"").contains("not both"));
        for bad in ["10.0.0.0/33", "::1/129", "10/8", "010.0.0.1", "example.com", "", "10.0.0.0 /8"] {
            let e = err(&format!("rule = \"sql_injection\"\nclient_cidr = {bad:?}\nreason = \"x\""));
            assert!(e.contains("exceptions[0].client_cidr"), "{bad}: {e}");
        }
        for good in ["10.0.0.0/8", "203.0.113.7", "::1", "2001:db8::/32", "::ffff:10.0.0.1"] {
            assert!(one(&format!("rule = \"sql_injection\"\nclient_cidr = {good:?}\nreason = \"x\"")).len() == 1, "{good}");
        }
    }

    #[test]
    fn all_errors_reported_with_indexes() {
        let errs = compile(&[
            "rule = \"command_exec\"\nscript = \"/ok.php\"\nreason = \"fine\"",
            "rule = \"max_parts\"\nuri_prefix = \"/\"\nreason = \"x\"",
            "rule = \"sql_injection\"\nparam = \"q\"",
        ])
        .unwrap_err();
        assert_eq!(errs.len(), 2);
        assert!(errs[0].starts_with("exceptions[1].rule"));
        assert!(errs[1].starts_with("exceptions[2].reason"));
    }

    #[test]
    fn unknown_key_rejected_by_serde() {
        let r: Result<ExceptionEntry, _> = toml::from_str("rule = \"x\"\nparm = \"q\"\nreason = \"r\"");
        assert!(r.is_err());
    }

    // ---- matching ------------------------------------------------------------

    #[test]
    fn script_exact_glob_and_other_script() {
        let x = one("rule = \"sinks.command_exec\"\nscript = \"/var/www/cron.php\"\nreason = \"x\"");
        let mut f = facts(RuleId::CommandExec);
        f.script = Some("/var/www/cron.php");
        let m = x.matches(&f).unwrap();
        assert_eq!((m.index, m.selector.as_str(), m.reason.as_str()), (0, "sinks.command_exec", "x"));
        f.script = Some("/var/www/other.php");
        assert!(x.matches(&f).is_none());
        f.script = None;
        assert!(x.matches(&f).is_none(), "no script known: a script facet cannot match");
        // Different sink in the same layer: not covered.
        f.script = Some("/var/www/cron.php");
        f.rule = RuleId::Eval;
        assert!(x.matches(&f).is_none());
        // Whole layer selector covers eval too.
        let y = one("rule = \"sinks\"\nscript = \"/var/www/**\"\nreason = \"x\"");
        assert!(y.matches(&f).is_some());
        f.rule = RuleId::PhpWrite;
        assert!(y.matches(&f).is_none());
    }

    #[test]
    fn hash_facet_and_want_hash() {
        let d = sha256::digest(b"<?php echo 1;");
        let hex = sha256::hex(&d);
        let x = one(&format!("rule = \"behavior.php_write\"\nscript_sha256 = \"{hex}\"\nreason = \"x\""));
        assert!(x.want_hash("/any/thing.php"));
        let mut f = facts(RuleId::PhpWrite);
        f.script = Some("/a.php");
        assert!(x.matches(&f).is_none(), "hash unknown: no match");
        f.script_sha256 = Some(&d);
        assert!(x.matches(&f).is_some());
        let other = sha256::digest(b"<?php echo 2;");
        f.script_sha256 = Some(&other);
        assert!(x.matches(&f).is_none());
        // Hash plus glob: want_hash only where the glob matches.
        let y = one(&format!("rule = \"behavior.php_write\"\nscript = \"/srv/**\"\nscript_sha256 = \"{hex}\"\nreason = \"x\""));
        assert!(y.want_hash("/srv/x/a.php"));
        assert!(!y.want_hash("/var/a.php"));
        let z = one("rule = \"behavior.php_write\"\nscript = \"/srv/**\"\nreason = \"x\"");
        assert!(!z.want_hash("/srv/a.php"), "no hash facet: never hash");
    }

    #[test]
    fn param_exact_and_prefix() {
        let x = one("rule = \"inspect.sql_injection\"\nparam = \"content\"\nreason = \"x\"");
        let mut f = facts(RuleId::SqlInjection);
        f.param = Some(b"content");
        assert!(x.matches(&f).is_some());
        f.param = Some(b"content2");
        assert!(x.matches(&f).is_none());
        f.param = Some(b"content");
        f.rule = RuleId::PathTraversal;
        assert!(x.matches(&f).is_none(), "one rule only");
        let y = one("rule = \"inspect\"\nparam_prefix = \"jform[\"\nreason = \"x\"");
        f.param = Some(b"jform[articletext]");
        assert!(y.matches(&f).is_some());
        f.param = Some(b"xjform[");
        assert!(y.matches(&f).is_none());
        f.param = None;
        assert!(y.matches(&f).is_none());
    }

    #[test]
    fn uri_prefix_is_raw_bytes() {
        let x = one("rule = \"sql_injection\"\nuri_prefix = \"/wp-admin/\"\nreason = \"x\"");
        let mut f = facts(RuleId::SqlInjection);
        f.uri = "/wp-admin/post.php";
        assert!(x.matches(&f).is_some());
        f.uri = "/WP-ADMIN/post.php";
        assert!(x.matches(&f).is_none());
        f.uri = "/wp-admin";
        assert!(x.matches(&f).is_none());
        f.uri = "";
        assert!(x.matches(&f).is_none());
    }

    #[test]
    fn client_cidr_v4_v6_mapped_and_bare() {
        let x = one("rule = \"max_request_headers\"\nclient_cidr = \"10.0.0.0/8\"\nreason = \"x\"");
        let mut f = facts(RuleId::MaxRequestHeaders);
        for ip in ["10.1.2.3", "10.255.255.255", "::ffff:10.9.9.9"] {
            f.client_ip = ip;
            assert!(x.matches(&f).is_some(), "{ip}");
        }
        for ip in ["11.0.0.1", "", "garbage", "2001:db8::1"] {
            f.client_ip = ip;
            assert!(x.matches(&f).is_none(), "{ip}");
        }
        let v6 = one("rule = \"max_request_headers\"\nclient_cidr = \"2001:db8::/32\"\nreason = \"x\"");
        f.client_ip = "2001:db8:1::5";
        assert!(v6.matches(&f).is_some());
        f.client_ip = "2001:db9::5";
        assert!(v6.matches(&f).is_none());
        let bare = one("rule = \"max_request_headers\"\nclient_cidr = \"203.0.113.7\"\nreason = \"x\"");
        f.client_ip = "203.0.113.7";
        assert!(bare.matches(&f).is_some());
        f.client_ip = "203.0.113.8";
        assert!(bare.matches(&f).is_none());
        let lo6 = one("rule = \"max_request_headers\"\nclient_cidr = \"::1\"\nreason = \"x\"");
        f.client_ip = "::1";
        assert!(lo6.matches(&f).is_some());
        f.client_ip = "127.0.0.1";
        assert!(lo6.matches(&f).is_none());
    }

    #[test]
    fn facets_are_anded_and_first_match_wins() {
        let x = compile(&[
            "rule = \"sinks.command_exec\"\nscript = \"/var/www/cron.php\"\nclient_cidr = \"10.0.0.0/8\"\nreason = \"both\"",
            "rule = \"sinks\"\nuri_prefix = \"/cron\"\nreason = \"uri\"",
        ])
        .unwrap();
        let mut f = facts(RuleId::CommandExec);
        f.script = Some("/var/www/cron.php");
        f.client_ip = "10.0.0.1";
        f.uri = "/cron.php";
        assert_eq!(x.matches(&f).unwrap().index, 0);
        f.client_ip = "11.0.0.1";
        assert_eq!(x.matches(&f).unwrap().index, 1);
        f.uri = "/other";
        assert!(x.matches(&f).is_none());
    }

    #[test]
    fn critical_never_matches_even_hand_built() {
        // A whole-layer selector reaches the matcher; Critical is still refused.
        let x = one("rule = \"limits\"\nuri_prefix = \"/up\"\nreason = \"x\"");
        assert!(x.matches(&facts(RuleId::MaxParts)).is_none());
        assert!(x.matches(&facts(RuleId::MaxInputVars)).is_none());
        assert!(x.matches(&facts(RuleId::MaxRequestHeaders)).is_some());
    }

    #[test]
    fn log_reason_is_bounded_and_single_line() {
        let long = "r\n".repeat(200);
        let x = one(&format!("rule = \"sinks\"\nuri_prefix = \"/up\"\nreason = {long:?}"));
        let m = x.matches(&facts(RuleId::Eval)).unwrap();
        let s = m.log_reason();
        assert!(s.starts_with("exception #0 (sinks): rrr"));
        assert!(!s.contains('\n'));
        assert!(s.len() < 220);
        assert!(s.ends_with("..."));
    }

    #[test]
    fn empty_is_inert() {
        let x = Exceptions::compile(&[]).unwrap();
        assert!(x.is_empty());
        assert!(!x.want_hash("/a.php"));
        for r in rule_catalog() {
            let mut f = facts(*r);
            f.script = Some("/a.php");
            f.param = Some(b"q");
            assert!(x.matches(&f).is_none());
        }
    }

    // ---- review fixes (PR #43) -------------------------------------------------

    #[test]
    fn uri_prefix_never_matches_a_uri_with_dot_segments_or_encoding() {
        let x = one("rule = \"inspect\"\nuri_prefix = \"/wp-admin/\"\nreason = \"x\"");
        let mut f = facts(RuleId::SqlInjection);
        f.uri = "/wp-admin/post.php";
        assert!(x.matches(&f).is_some());
        for bad in [
            "/wp-admin/../index.php",
            "/wp-admin/./post.php",
            "/wp-admin/..",
            "/wp-admin/.",
            "/wp-admin//post.php",
            "/wp-admin/%2e%2e/index.php",
            "/wp-admin/post%2ephp",
            "/wp-admin/..\\index.php",
            "/wp-admin\\post.php",
            "/wp-admin/sub/../../index.php",
            "//wp-admin/post.php",
        ] {
            f.uri = bad;
            assert!(x.matches(&f).is_none(), "{bad} must not satisfy uri_prefix");
        }
        assert!(uri_is_plain("/a/b.c/d.php"));
        assert!(uri_is_plain("/a/.well-known/x"));
        assert!(uri_is_plain("/a/..hidden"));
        assert!(!uri_is_plain(""));
        assert!(!uri_is_plain("wp-admin/x"));
    }

    #[test]
    fn wildcard_facets_do_not_satisfy_the_facet_rail() {
        for (facet, e) in [
            ("script", "rule = \"sinks\"\nscript = \"/**\"\nreason = \"x\""),
            ("script", "rule = \"sinks\"\nscript = \"/*\"\nreason = \"x\""),
            ("script", "rule = \"sinks\"\nscript = \"/**/*\"\nreason = \"x\""),
            ("script", "rule = \"sinks\"\nscript = \"/?\"\nreason = \"x\""),
            ("uri_prefix", "rule = \"inspect\"\nuri_prefix = \"/\"\nreason = \"x\""),
            ("client_cidr", "rule = \"inspect\"\nclient_cidr = \"0.0.0.0/0\"\nreason = \"x\""),
            ("client_cidr", "rule = \"inspect\"\nclient_cidr = \"::/0\"\nreason = \"x\""),
        ] {
            let m = err(e);
            assert!(m.contains(&format!("exceptions[0].{facet}")), "{e}: {m}");
            assert!(m.contains("every"), "{e}: {m}");
        }
        // Combined with a real facet the wildcard is still refused (it adds nothing).
        assert!(err("rule = \"sinks\"\nscript = \"/**\"\nclient_cidr = \"10.0.0.0/8\"\nreason = \"x\"").contains("script"));
        // Narrow spellings stay fine.
        assert!(one("rule = \"sinks\"\nscript = \"/var/**\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"sinks\"\nscript = \"/*/cron.php\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"inspect\"\nuri_prefix = \"/a\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"inspect\"\nclient_cidr = \"0.0.0.0/1\"\nreason = \"x\"").len() == 1);
    }

    #[test]
    fn param_facets_cannot_name_the_path_pseudo_parameters() {
        for bad in [
            "param = \"REQUEST_URI\"",
            "param = \"PATH_INFO\"",
            "param_prefix = \"REQUEST_URI\"",
            "param_prefix = \"R\"",
            "param_prefix = \"REQ\"",
            "param_prefix = \"PATH_\"",
            "param_prefix = \"P\"",
        ] {
            let m = err(&format!("rule = \"inspect\"\n{bad}\nreason = \"x\""));
            assert!(m.contains("exceptions[0].param"), "{bad}: {m}");
            assert!(m.contains("REQUEST_URI"), "{bad}: {m}");
        }
        assert!(one("rule = \"inspect\"\nparam = \"REQUEST_URI2\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"inspect\"\nparam_prefix = \"Rx\"\nreason = \"x\"").len() == 1);
        assert!(one("rule = \"inspect\"\nparam = \"r\"\nreason = \"x\"").len() == 1);
    }

    // ---- report ---------------------------------------------------------------

    #[test]
    fn report_counts_configured_and_rejected() {
        assert_eq!(report(""), Some((0, 0)));
        assert_eq!(report("mode = \"detect\""), Some((0, 0)));
        let t = "[[exceptions]]\nrule = \"command_exec\"\nscript = \"/a.php\"\nreason = \"x\"\n\
                 [[exceptions]]\nrule = \"max_parts\"\nuri_prefix = \"/\"\nreason = \"x\"\n\
                 [[exceptions]]\nrule = \"eval\"\nscript = \"/b.php\"\nbogus = 1\nreason = \"x\"\n";
        assert_eq!(report(t), Some((1, 2)));
        assert_eq!(report("exceptions = 3"), None);
        assert_eq!(report("= = ="), None);
    }
}
