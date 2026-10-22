use serde::Deserialize;

/// Resource limits applied to multipart bodies.
// placeholder: Task 4 replaces/extends this (full field set, enforcement, tests).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Maximum number of multipart parts accepted.
    pub max_parts: u32,
    /// Maximum size in bytes of a single part.
    pub max_part_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_parts: 1000,
            max_part_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Identifier of a detection rule.
// placeholder: Task 4 replaces/extends this (real rule ids).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleId {
    SelfTest,
}

/// How severe a rule's finding is.
// placeholder: Task 4 replaces/extends this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    Standard,
}
