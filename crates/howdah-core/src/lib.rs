//! Howdah core: pure Rust, no PHP types.
pub mod config;
pub mod limits;

pub use config::{Config, ConfigError, LogConfig, Mode};
pub use limits::{Limits, RuleId, Severity};
