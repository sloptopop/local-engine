//! The analyzer reports uploaded with the snapshot: every regular file in
//! `.sloptopop/reports/` whose name is a report format the server reads
//! (`*.sarif`, `*.sarif.json`, `*.lcov`, `lcov.info`), and `collect`'s run
//! record. SARIF reports go without their code snippets (`snippet`,
//! `contextRegion`) and without the rule catalogue's prose
//! (`shortDescription`, `fullDescription`, `help`): the server reads no
//! snippet and needs no prose (a result carries its own message, §3.27.11),
//! a snippet could quote a secret value, and gitleaks' own catalogue reads
//! as secrets to the server's backstop. A report that is not UTF-8, or a SARIF report that is not
//! JSON, is not uploaded; the manifest says so.
//!
//! Standards: SCF PRI-05 (data minimisation); OWASP ASVS 5.0 V13.3.1;
//! OASIS SARIF 2.1.0 §3.30.13, §3.30.14 (snippets are optional).

use std::fs;
use std::path::Path;

use serde_json::Value;

use crate::canonical::Json;

/// The reports directory, relative to the root.
pub(crate) const DIR: &str = ".sloptopop/reports";

/// The largest report uploaded, in bytes (the server reads nothing larger).
const MAX_BYTES: u64 = 32 * 1024 * 1024;

/// What is uploaded of the reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Reports {
    /// Each uploaded report: its name and text, by name.
    pub(crate) sent: Vec<(String, String)>,
    /// Each report left out, with why.
    pub(crate) left: Vec<(String, &'static str)>,
    /// `collect`'s run record, if there is one.
    pub(crate) record: Option<Value>,
}

/// Whether `name` is a plain report file name the server reads.
pub(crate) fn report_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && !name.starts_with("server.")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && [".sarif", ".sarif.json", ".lcov", "lcov.info"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

/// The members no uploaded SARIF report keeps, at any depth.
const STRIPPED: [&str; 5] = [
    "snippet",
    "contextRegion",
    "shortDescription",
    "fullDescription",
    "help",
];

/// `value` without any of the `STRIPPED` members, at any depth.
fn strip(value: &mut Value) {
    match value {
        Value::Object(members) => {
            for member in STRIPPED {
                members.remove(member);
            }
            members.values_mut().for_each(strip);
        }
        Value::Array(items) => items.iter_mut().for_each(strip),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// The text uploaded for the report `name` holding `text`, or why not.
fn upload(name: &str, text: String) -> Result<String, &'static str> {
    let lcov = Path::new(name)
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("lcov"));
    if lcov || name.ends_with("lcov.info") {
        return Ok(text);
    }
    let mut value: Value =
        serde_json::from_str(&text).map_err(|_| "a SARIF report that is not JSON")?;
    strip(&mut value);
    Ok(String::from_utf8_lossy(&Json::from_value(&value).to_bytes()).into_owned())
}

/// The reports of the repository at `root`, sorted by name.
pub(crate) fn read(root: &Path) -> Reports {
    read_limited(root, MAX_BYTES)
}

/// [`read`], with reports larger than `max` bytes left out.
fn read_limited(root: &Path, max: u64) -> Reports {
    let dir = root.join(DIR);
    let mut out = Reports {
        record: fs::read(dir.join(".collect.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .filter(Value::is_object),
        ..Reports::default()
    };
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            )
        })
        .filter(|(name, _)| report_name(name))
        .collect();
    entries.sort();
    for (name, path) in entries {
        let size = fs::metadata(&path).map_or(u64::MAX, |meta| meta.len());
        let read = if size > max {
            Err("larger than 32 MiB")
        } else {
            fs::read_to_string(&path)
                .map_err(|_| "not UTF-8 text")
                .and_then(|text| upload(&name, text))
        };
        match read {
            Ok(text) => out.sent.push((name, text)),
            Err(why) => out.left.push((name, why)),
        }
    }
    out
}

#[cfg(test)]
mod tests;
