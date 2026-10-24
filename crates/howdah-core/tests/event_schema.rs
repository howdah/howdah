//! The event line contract: `docs/howdah-event.schema.json` must describe
//! what `log_line` actually emits, and every sample line in
//! `docs/log-schema.md` must validate against it.
//!
//! The validator below implements only the keywords the schema uses and
//! FAILS on any other keyword, so the schema cannot quietly rely on a rule
//! this test does not check. `pattern` is limited to the `^[class]+$` form.

use std::collections::HashSet;
use std::path::PathBuf;

use howdah_core::limits::rule_catalog;
use howdah_core::log::{log_line, new_request_id, EventRecord, EVENT_FIELDS, SCHEMA_VERSION};
use howdah_core::rules::Action;
use serde_json::Value;

fn docs(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs").join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

fn schema() -> Value {
    serde_json::from_str(&docs("howdah-event.schema.json")).expect("schema is valid JSON")
}

/// `^[...]+$` only: a character class of literals and `a-z` style ranges.
fn class_match(pattern: &str, s: &str) -> bool {
    let body = pattern
        .strip_prefix("^[")
        .and_then(|p| p.strip_suffix("]+$"))
        .unwrap_or_else(|| panic!("unsupported pattern {pattern:?} (only ^[class]+$)"));
    let cs: Vec<char> = body.chars().collect();
    let mut ranges = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        if i + 2 < cs.len() && cs[i + 1] == '-' {
            ranges.push((cs[i], cs[i + 2]));
            i += 3;
        } else {
            ranges.push((cs[i], cs[i]));
            i += 1;
        }
    }
    !s.is_empty() && s.chars().all(|c| ranges.iter().any(|&(a, b)| a <= c && c <= b))
}

fn validate(schema: &Value, v: &Value, path: &str) -> Result<(), String> {
    let obj = schema.as_object().ok_or(format!("{path}: schema node is not an object"))?;
    for (k, rule) in obj {
        match k.as_str() {
            "$schema" | "$id" | "title" | "description" | "examples" | "$comment" => {}
            "type" => {
                let ok = match rule.as_str().unwrap() {
                    "object" => v.is_object(),
                    "string" => v.is_string(),
                    "integer" => v.is_i64() || v.is_u64(),
                    t => return Err(format!("{path}: unsupported type {t}")),
                };
                if !ok {
                    return Err(format!("{path}: expected {rule}, got {v}"));
                }
            }
            "required" => {
                for r in rule.as_array().unwrap() {
                    let r = r.as_str().unwrap();
                    if v.get(r).is_none() {
                        return Err(format!("{path}: missing required {r}"));
                    }
                }
            }
            "properties" => {
                for (pk, ps) in rule.as_object().unwrap() {
                    if let Some(pv) = v.get(pk) {
                        validate(ps, pv, &format!("{path}.{pk}"))?;
                    }
                }
            }
            "additionalProperties" => {
                if rule == &Value::Bool(false) {
                    let props = obj["properties"].as_object().unwrap();
                    for k in v.as_object().unwrap().keys() {
                        if !props.contains_key(k) {
                            return Err(format!("{path}: unexpected property {k}"));
                        }
                    }
                } else if rule != &Value::Bool(true) {
                    return Err(format!("{path}: unsupported additionalProperties {rule}"));
                }
            }
            "enum" => {
                if !rule.as_array().unwrap().contains(v) {
                    return Err(format!("{path}: {v} not in {rule}"));
                }
            }
            "const" => {
                if rule != v {
                    return Err(format!("{path}: {v} != const {rule}"));
                }
            }
            // As in JSON Schema, numeric and string keywords ignore values of
            // another type (`type` reports those).
            "minimum" => {
                if v.as_i64().is_some_and(|n| n < rule.as_i64().unwrap()) {
                    return Err(format!("{path}: {v} < minimum {rule}"));
                }
            }
            "maximum" => {
                if v.as_i64().is_some_and(|n| n > rule.as_i64().unwrap()) {
                    return Err(format!("{path}: {v} > maximum {rule}"));
                }
            }
            "minLength" => {
                if v.as_str().is_some_and(|s| (s.chars().count() as u64) < rule.as_u64().unwrap()) {
                    return Err(format!("{path}: shorter than {rule}"));
                }
            }
            "maxLength" => {
                if v.as_str().is_some_and(|s| (s.chars().count() as u64) > rule.as_u64().unwrap()) {
                    return Err(format!("{path}: longer than {rule}"));
                }
            }
            "pattern" => {
                if v.as_str().is_some_and(|s| !class_match(rule.as_str().unwrap(), s)) {
                    return Err(format!("{path}: {v} does not match {rule}"));
                }
            }
            other => return Err(format!("{path}: keyword {other} is not implemented by this test")),
        }
    }
    Ok(())
}

fn event(rule: howdah_core::RuleId, action: Action) -> Value {
    let rec = EventRecord {
        ts: "1761318132123".into(),
        request_id: new_request_id(),
        rule,
        action,
        client_ip: "203.0.113.7".into(),
        method: "POST".into(),
        uri: "/upload.php".into(),
        reason: "multipart part count exceeds limit".into(),
    };
    serde_json::from_str(&log_line(&rec)).unwrap()
}

#[test]
fn schema_lists_exactly_the_emitted_fields() {
    let s = schema();
    let want: HashSet<&str> = EVENT_FIELDS.iter().copied().collect();
    let required: HashSet<&str> = s["required"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    let props: HashSet<&str> = s["properties"].as_object().unwrap().keys().map(|k| k.as_str()).collect();
    assert_eq!(required, want);
    assert_eq!(props, want);
    assert_eq!(s["properties"]["schema"]["const"], SCHEMA_VERSION);
}

#[test]
fn every_rule_and_action_validates() {
    let s = schema();
    for r in rule_catalog() {
        for a in [Action::Allow, Action::Log, Action::Block] {
            let v = event(*r, a);
            validate(&s, &v, "$").unwrap_or_else(|e| panic!("{r:?}/{a:?}: {e}\n{v}"));
        }
    }
}

#[test]
fn empty_request_metadata_validates() {
    // CLI requests have no REMOTE_ADDR and may have no method or URI.
    let rec = EventRecord {
        ts: "0".into(),
        request_id: new_request_id(),
        rule: howdah_core::RuleId::Eval,
        action: Action::Log,
        client_ip: String::new(),
        method: String::new(),
        uri: String::new(),
        reason: "dynamic code evaluation via eval".into(),
    };
    let v: Value = serde_json::from_str(&log_line(&rec)).unwrap();
    validate(&schema(), &v, "$").unwrap();
}

#[test]
fn validator_rejects_broken_events() {
    let s = schema();
    let good = event(howdah_core::RuleId::MaxParts, Action::Block);
    validate(&s, &good, "$").unwrap();
    type Mutation = Box<dyn Fn(&mut Value)>;
    let broken: Vec<(&str, Mutation)> = vec![
        ("missing layer", Box::new(|v| drop(v.as_object_mut().unwrap().remove("layer")))),
        ("layer as string", Box::new(|v| v["layer"] = Value::from("1"))),
        ("layer 0", Box::new(|v| v["layer"] = Value::from(0))),
        ("schema 1", Box::new(|v| v["schema"] = Value::from(1))),
        ("ts as number", Box::new(|v| v["ts"] = Value::from(1761318132123u64))),
        ("ts iso", Box::new(|v| v["ts"] = Value::from("2026-10-24T09:41:02Z"))),
        ("bad action", Box::new(|v| v["action"] = Value::from("drop"))),
        ("bad rule", Box::new(|v| v["rule"] = Value::from("Max Parts"))),
        ("upper request id", Box::new(|v| v["request_id"] = Value::from("ABC"))),
    ];
    for (name, f) in broken {
        let mut v = good.clone();
        f(&mut v);
        assert!(validate(&s, &v, "$").is_err(), "{name} was accepted");
    }
}

#[test]
fn docs_sample_lines_validate() {
    let md = docs("log-schema.md");
    let mut n = 0;
    let mut in_json = false;
    for line in md.lines() {
        if line.trim_start().starts_with("```") {
            in_json = line.trim() == "```json";
            continue;
        }
        if in_json && line.trim_start().starts_with('{') {
            let v: Value = serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("sample is not JSON: {e}\n{line}"));
            validate(&schema(), &v, "$").unwrap_or_else(|e| panic!("sample fails the schema: {e}\n{line}"));
            n += 1;
        }
    }
    assert!(n >= 3, "expected at least one sample line per layer in docs/log-schema.md, found {n}");
}
