//! The secret scanner's report, as masking reads it: a SARIF 2.1.0 log
//! from gitleaks (the D-0184 component `sloptopop collect` runs, with
//! `--redact`), every result's file and lines, and its columns when given.
//! A log that is not gitleaks', or a result without a file and a line, is
//! refused: masking never guesses.
//!
//! Standards: OASIS SARIF 2.1.0 §3.27, §3.30; OWASP ASVS 5.0 V13.3.1;
//! SCF TDA-12 (the report must have this shape, or nothing is uploaded).

use serde_json::Value;

use crate::mask::Span;

/// One result: the file it is about and its span.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Found {
    /// The file, relative to the repository root.
    pub(crate) path: String,
    /// The first line.
    pub(crate) line: u32,
    /// The last line.
    pub(crate) end: u32,
    /// The span on the first line.
    pub(crate) span: Span,
}

/// The path a result's `uri` names, relative to the root: without
/// `file://`, the container's `/src/` mount or a leading `./`.
fn path(uri: &str) -> String {
    let bare = uri.strip_prefix("file://").unwrap_or(uri);
    let bare = bare.strip_prefix("/src/").unwrap_or(bare);
    bare.trim_start_matches("./").to_owned()
}

/// A number member of `value` at `pointer` that fits a line or column.
fn number(value: &Value, pointer: &str) -> Option<u32> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n >= 1)
}

/// The results of the gitleaks SARIF log `text`, sorted.
///
/// # Errors
///
/// When it is not SARIF, a run is not gitleaks', or a result names no
/// file or no line.
pub(crate) fn read(text: &str) -> Result<Vec<Found>, String> {
    let log: Value = serde_json::from_str(text).map_err(|error| format!("not JSON: {error}"))?;
    let runs = log
        .get("runs")
        .and_then(Value::as_array)
        .ok_or("not a SARIF log: no runs")?;
    let mut out = Vec::new();
    for run in runs {
        let name = run
            .pointer("/tool/driver/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !name.eq_ignore_ascii_case("gitleaks") {
            return Err(format!("a run of `{name}`, not of gitleaks"));
        }
        for result in run
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let location = result
                .pointer("/locations/0/physicalLocation")
                .cloned()
                .unwrap_or(Value::Null);
            let uri = location
                .pointer("/artifactLocation/uri")
                .and_then(Value::as_str);
            let line = number(&location, "/region/startLine");
            let (Some(uri), Some(line)) = (uri, line) else {
                return Err("a result names no file or no line".to_owned());
            };
            let end = number(&location, "/region/endLine")
                .unwrap_or(line)
                .max(line);
            out.push(Found {
                path: path(uri),
                line,
                end,
                span: Span {
                    line,
                    start: number(&location, "/region/startColumn").unwrap_or(1),
                    end: number(&location, "/region/endColumn").unwrap_or(u32::MAX),
                },
            });
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests;
