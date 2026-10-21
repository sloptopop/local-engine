//! `sloptopop local` (decision D-0183): the open-source half of sloptopop
//! on the user's machine, MIT OR Apache-2.0. It does only work that holds
//! no sloptopop logic, and never detects anything itself:
//!
//! 1. builds the snapshot the server analyses ([`run::request`]): the
//!    files of `HEAD` from git's object store, minus what must not leave
//!    the machine, every secret value the secret scanner (`sloptopop
//!    collect`'s gitleaks) reports masked, with the analyzer reports and
//!    the upload manifest; without a usable scanner report nothing is
//!    uploaded;
//! 2. prints the server's Report ([`run::report`]);
//! 3. applies the changes the server verified ([`run::apply`]): byte spans
//!    checked by whole-file digests, the real secret values put back, one
//!    commit per step on a new branch, refusing on a dirty tree, a moved
//!    `HEAD` or any digest mismatch;
//! 4. runs the project's own type check, build and tests on the base and
//!    the branch as evidence for the server's Guider ([`run::evidence`]).
//!
//! The open-source CLI starts the `sloptopop-local` binary ([`cli`]) and
//! makes the one server call between `request` and `report`/`apply`.
//! Everything is deterministic: the same repository gives byte-identical
//! requests, and commits carry the base commit's date.
//!
//! # Module layers
//!
//! Each module imports only from modules in lower layers, never from one
//! in its own layer. Bottom to top:
//!
//! 0. Leaves with no crate imports: `tool`, `error`, `command`, `output`,
//!    `canonical` (deterministic JSON), `digest` (request and file
//!    digests, run ids), `git` (running git), `mask` (secret values masked
//!    and put back), `wire` (what is read of the server's response).
//! 1. `snapshot` (the files of a commit; git), `sarif` (the scanner's
//!    results; mask), `reports` (the analyzer reports to upload;
//!    canonical), `records` (confirmations; canonical, digest, wire),
//!    `evidence` (the project's own checks; canonical, digest, git).
//! 2. `scanner` (what to mask; mask, sarif), `apply` (the deliveries,
//!    committed; digest, git, mask, records, snapshot, wire).
//! 3. `upload` (the request and its manifest; canonical, digest, mask,
//!    reports, sarif, scanner, snapshot), `summary` (`report.json`,
//!    `SUMMARY.md`, `PR.md`; apply, canonical, records, tool, wire).
//! 4. [`run`] (the commands).
//! 5. [`cli`]: the command line.
//!
//! This file declares the modules; `main.rs` is a thin binary over
//! [`cli::run`].
//!
//! Standards: SCF TDA-08 (Technical Documentation Artifacts: the module
//! layers above). Each module states its own controls; every item
//! inherits its module's.

pub mod cli;

mod apply;
mod canonical;
mod command;
mod digest;
mod error;
mod evidence;
mod git;
mod mask;
mod output;
mod records;
mod reports;
pub mod run;
mod sarif;
mod scanner;
mod snapshot;
mod summary;
mod tool;
mod upload;
mod wire;

pub use error::Error;
pub use run::{Options, Outcome};
pub use tool::{TOOL, Tool};

#[cfg(test)]
mod tests;
