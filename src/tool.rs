//! The producing tool named in every document `sloptopop local` writes.
//!
//! Standards: SCF TDA-08 (Technical Documentation Artifacts: the tool
//! identity every document carries).

/// The producing tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tool {
    /// Always `sloptopop-local`.
    pub name: &'static str,
    /// Its version.
    pub version: &'static str,
}

/// The tool entry of every document.
pub const TOOL: Tool = Tool {
    name: "sloptopop-local",
    version: env!("CARGO_PKG_VERSION"),
};
