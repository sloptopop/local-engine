//! The `sloptopop-local` command line, kept free of process globals so
//! every path can be tested with in-memory streams.
//!
//! ```text
//! sloptopop-local request <root> --mode check|fix|transform   exit 0
//! sloptopop-local report <root> --run <id>                    exit 0 passed, 1 not passed
//! sloptopop-local apply <root> --run <id> [--apply] [--branch <name>]
//!                 [--confirm <id,...> --by <name>]            exit 0 complete, 1 not
//! sloptopop-local evidence <root> --run <id>                  exit 0
//! sloptopop-local version
//! ```
//!
//! `request` prints the run, the request's and the response's paths and
//! the upload manifest; `report` the server's Report; `apply` the run's
//! `report.json`; `evidence` the evidence request's and response's paths.
//! A usage error exits 2; any other failure exits 3 with `error: …` on
//! stderr.
//!
//! Standards: SCF TDA-12 (Input Data Validation), TDA-12.1 (Error
//! Handling: fixed exit codes, `error: …` on stderr, never a panic).

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use crate::command::{Command, USAGE, parse};
use crate::output::{raw, report};
use crate::run::{Options, apply, evidence, report as server_report, request};
use crate::tool::TOOL;

/// Exit code for a usage error.
pub const USAGE_ERROR: u8 = 2;

/// Exit code for any other failure.
pub const INTERNAL_ERROR: u8 = 3;

/// Runs `sloptopop-local` with explicit streams and returns the exit code.
pub fn run(args: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let args: Vec<String> = args
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let command = match parse(&args) {
        Ok(command) => command,
        Err(message) => {
            return report(stderr, &format!("error: {message}\n\n{USAGE}"), USAGE_ERROR);
        }
    };
    let outcome = match command {
        Command::Version => Ok(complete(
            format!("{} {}\n", TOOL.name, TOOL.version).into_bytes(),
        )),
        Command::Request(root, mode) => request(Path::new(root), mode).map(complete),
        Command::Report(root, id) => server_report(Path::new(root), id)
            .map(|outcome| (outcome.document, u8::from(!outcome.complete))),
        Command::Evidence(root, id) => evidence(Path::new(root), id).map(complete),
        Command::Apply(asked) => {
            let options = Options {
                apply: asked.commit,
                branch: asked.branch.map(str::to_owned),
                confirm: asked.confirm.iter().copied().map(str::to_owned).collect(),
                by: asked.by.map(str::to_owned),
            };
            apply(Path::new(asked.root), asked.run, &options)
                .map(|outcome| (outcome.document, u8::from(!outcome.complete)))
        }
    };
    match outcome {
        Ok((bytes, code)) => match raw(stdout, &bytes) {
            Ok(()) => code,
            Err(e) => report(
                stderr,
                &format!("error: cannot write output: {e}\n"),
                INTERNAL_ERROR,
            ),
        },
        Err(e) => report(stderr, &format!("error: {e}\n"), INTERNAL_ERROR),
    }
}

/// A command's output `bytes` with exit code 0.
const fn complete(bytes: Vec<u8>) -> (Vec<u8>, u8) {
    (bytes, 0)
}

#[cfg(test)]
mod tests;
