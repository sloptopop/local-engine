//! Writing documents and messages to the output streams.
//!
//! Standards: SCF TDA-12.1 (Error Handling: documents to stdout, messages
//! to stderr; a failed document write is an error, and the exit code
//! survives a broken stderr).

use std::io::Write;

/// Writes `bytes` (a document that already ends as it should) to stdout.
pub(crate) fn raw(stdout: &mut dyn Write, bytes: &[u8]) -> std::io::Result<()> {
    stdout.write_all(bytes).and_then(|()| stdout.flush())
}

/// Writes `message` to stderr and returns `code`. If stderr itself is
/// broken there is nowhere left to report to; the exit code still says it.
pub(crate) fn report(stderr: &mut dyn Write, message: &str, code: u8) -> u8 {
    let _ignored = stderr.write_all(message.as_bytes());
    code
}
