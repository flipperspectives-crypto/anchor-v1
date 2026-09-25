//! Error type for the offline verifier. Fail-closed: every verification
//! failure surfaces as [`Error`], never as a silent `false` deep inside a
//! chain (the top-level chain API folds those into `false` to match the
//! Python `verify_checkpoint_chain` contract).

use std::fmt;

/// Verification failure. The `reason` is a short machine-stable code plus a
/// human-readable detail; it never includes key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Short stable code, e.g. `"bad-signature"`, `"unknown-kid"`.
    pub reason: &'static str,
    /// Human-readable detail (no secrets).
    pub detail: String,
}

impl Error {
    pub fn new(reason: &'static str, detail: impl Into<String>) -> Self {
        Self { reason, detail: detail.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for Error {}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, Error>;
