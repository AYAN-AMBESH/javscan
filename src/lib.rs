//! javscan — Java static application security testing.
//!
//! Exposed as a library so the rule set can be exercised by the regression
//! corpus in `tests/`. The binary in `main.rs` is a thin CLI over `scanner`.

pub mod baseline;
pub mod config;
pub mod findings;
pub mod parser;
pub mod project;
pub mod report;
pub mod rules;
pub mod scanner;
pub mod suppress;
pub mod taint;
pub mod trust;
pub mod types;
