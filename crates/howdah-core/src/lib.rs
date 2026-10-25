//! Howdah core: pure Rust, no PHP types.
pub mod behavior;
pub mod boundary;
pub mod config;
pub mod exceptions;
pub mod ffi;
pub mod input;
pub mod inspect;
pub mod limits;
pub mod log;
pub mod multipart;
pub mod oom;
pub mod rules;
pub mod sinks;

pub use config::{Config, ConfigError, LoadOutcome, LogConfig, LogDestination, Mode, OnInvalidConfig, SyslogFacility};
pub use limits::{Limits, RuleId, Severity};
