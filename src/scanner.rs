//! What to mask (D-0174, SPLIT): the secret scanner's report `sloptopop
//! collect` wrote (`.sloptopop/reports/gitleaks.sarif`, from the pinned
//! gitleaks component), if it is usable: the run record says gitleaks ran
//! and exited 0, the report is a gitleaks SARIF log whose every result
//! names a file and a line, and it is not older than `HEAD`'s commit or
//! any file of the snapshot (the tree is clean, so the working tree is
//! `HEAD`). Otherwise nothing is uploaded. Every result in a file of the
//! snapshot is masked on every line it spans, whichever file it is in.
//!
//! Standards: OWASP ASVS 5.0 V13.3.1 (no secret leaves the machine);
//! SCF IAC-14, PRI-05; CWE-200; GDPR Art. 25.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::SystemTime;

use serde_json::Value;

use crate::mask::{Mask, cover, masks};
use crate::sarif::{Found, read};

/// The scanner's report, relative to the root.
pub(crate) const REPORT: &str = ".sloptopop/reports/gitleaks.sarif";

/// `collect`'s run record, relative to the root.
pub(crate) const RECORD: &str = ".sloptopop/reports/.collect.json";

/// What to do instead, in every refusal.
const AGAIN: &str = "run `sloptopop collect` (it runs the pinned gitleaks), then try again";

/// Whether `record` says gitleaks ran and exited 0.
fn ran(record: &Value) -> bool {
    record
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|tool| {
            tool.get("name").and_then(Value::as_str) == Some("gitleaks")
                && tool.get("status").and_then(Value::as_str) == Some("ran")
                && tool.get("exitCode").and_then(Value::as_i64).unwrap_or(0) == 0
        })
}

/// When `path` was last modified, if it can be read.
fn modified(path: &Path) -> Option<SystemTime> {
    fs::symlink_metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

/// The results of the scanner's report under `root` for the files of
/// `snapshot`, by path; the report must be no older than `not_before`
/// (`HEAD`'s commit time) and any file of the snapshot.
///
/// # Errors
///
/// When there is no record of a gitleaks run, the report is missing,
/// unreadable, not a usable gitleaks log, or older than a file.
pub(crate) fn found(
    root: &Path,
    snapshot: &BTreeSet<String>,
    not_before: SystemTime,
) -> Result<BTreeMap<String, Vec<Found>>, String> {
    let record: Value = fs::read(root.join(RECORD))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null);
    if !ran(&record) {
        return Err(format!(
            "{RECORD} records no gitleaks run that ended with exit code 0: {AGAIN}"
        ));
    }
    let report = root.join(REPORT);
    let text = fs::read_to_string(&report)
        .map_err(|error| format!("cannot read {REPORT}: {error}: {AGAIN}"))?;
    let results = read(&text).map_err(|why| format!("{REPORT} is not usable ({why}): {AGAIN}"))?;
    let made = modified(&report).unwrap_or(SystemTime::UNIX_EPOCH);
    let newer = std::iter::once(Some(not_before))
        .chain(snapshot.iter().map(|path| modified(&root.join(path))))
        .flatten()
        .any(|time| time > made);
    if newer {
        return Err(format!(
            "{REPORT} is older than the commit or a file it should cover: {AGAIN}"
        ));
    }
    let mut out: BTreeMap<String, Vec<Found>> = BTreeMap::new();
    for result in results
        .into_iter()
        .filter(|found| snapshot.contains(&found.path))
    {
        out.entry(result.path.clone()).or_default().push(result);
    }
    Ok(out)
}

/// The masks of `text` for the scanner's `results` in it: every line of
/// every result, then every reported span still uncovered.
pub(crate) fn masks_of(text: &str, results: &[Found]) -> Vec<Mask> {
    let lines: BTreeSet<u32> = results
        .iter()
        .flat_map(|found| found.line..=found.end)
        .collect();
    let spans: Vec<_> = results.iter().map(|found| found.span).collect();
    cover(text, &spans, masks(text, &lines))
}

#[cfg(test)]
mod tests;
