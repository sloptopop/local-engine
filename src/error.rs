//! Why `sloptopop local` could not do what it was asked.
//!
//! Standards: SCF TDA-12.1 (Error Handling: one typed error that says
//! why, in words, never a panic).

use std::fmt;

/// Why `sloptopop local` could not do what it was asked: in words (a dirty
/// tree, a moved `HEAD`, no usable secret-scanner report, an existing
/// branch, a response that does not answer the request, a failed git
/// command).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The reason.
    Local(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests;
