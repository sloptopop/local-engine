//! The upload: the request `sloptopop local` writes for the server
//! (request schema 2: the mode, the base, the masked snapshot, the
//! analyzer reports and `collect`'s record, the Business Context) as
//! canonical JSON, its digest and run id, and the manifest the CLI shows
//! before anything is sent (decision D-0174): how many files and bytes,
//! what is left out and why, how many secret values are masked in which
//! files, and which reports go with it. No finding is ever sent: the
//! server detects.
//!
//! Standards: SCF PRI-05 (data minimisation), PRI-02 (notice: the user
//! sees what is sent first); OWASP ASVS 5.0 V13.3.1; GDPR Art. 25 (data
//! protection by default).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::canonical::Json;
use crate::digest::{REQUEST, digest, run_id};
use crate::mask::apply;
use crate::reports::Reports;
use crate::sarif::Found;
use crate::scanner::masks_of;
use crate::snapshot::Snapshot;

/// The request schema version.
pub(crate) const SCHEMA_VERSION: u32 = 2;

/// How many excluded paths the manifest lists by name.
const LISTED: usize = 100;

/// A prepared upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Upload {
    /// The request's canonical bytes.
    pub(crate) bytes: Vec<u8>,
    /// Its digest.
    pub(crate) digest: String,
    /// The run id.
    pub(crate) run: String,
    /// The manifest.
    pub(crate) manifest: Json,
}

/// What a request is about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct About<'a> {
    /// `check`, `fix` or `transform`.
    pub(crate) mode: &'a str,
    /// The base commit.
    pub(crate) base: &'a str,
    /// The repository's directory name.
    pub(crate) name: &'a str,
    /// The Business Context, if there is one.
    pub(crate) context: Option<&'a Value>,
}

/// A count.
fn count(n: usize) -> Json {
    Json::int(u64::try_from(n).unwrap_or(u64::MAX))
}

/// The upload of `snapshot`, masked where the scanner `found` secrets,
/// with `reports`, for `about`.
pub(crate) fn upload(
    about: About<'_>,
    snapshot: &Snapshot,
    found: &BTreeMap<String, Vec<Found>>,
    reports: &Reports,
) -> Upload {
    let mut masked_values = 0;
    let mut masked_files = Vec::new();
    let files: Vec<Json> = snapshot
        .files
        .iter()
        .map(|(path, text)| {
            let masks = found
                .get(path)
                .map(|results| masks_of(text, results))
                .unwrap_or_default();
            if !masks.is_empty() {
                masked_values += masks.len();
                masked_files.push(Json::text(path));
            }
            Json::object([
                ("path", Json::text(path)),
                ("text", Json::String(apply(text, &masks))),
            ])
        })
        .collect();
    let mut request = BTreeMap::from([
        ("schemaVersion".to_owned(), Json::int(SCHEMA_VERSION)),
        ("mode".to_owned(), Json::text(about.mode)),
        ("base".to_owned(), Json::text(about.base)),
        ("name".to_owned(), Json::text(about.name)),
        ("files".to_owned(), Json::Array(files)),
        (
            "reports".to_owned(),
            Json::Array(
                reports
                    .sent
                    .iter()
                    .map(|(name, text)| {
                        Json::object([("name", Json::text(name)), ("text", Json::text(text))])
                    })
                    .collect(),
            ),
        ),
    ]);
    if let Some(record) = &reports.record {
        request.insert("record".to_owned(), Json::from_value(record));
    }
    if let Some(context) = about.context {
        request.insert("context".to_owned(), Json::from_value(context));
    }
    let bytes = Json::Object(request).to_bytes();
    let digest = digest(REQUEST, &bytes);
    let run = run_id(&digest);
    let manifest = manifest(
        (&run, about),
        snapshot,
        bytes.len(),
        (masked_values, masked_files),
        reports,
    );
    Upload {
        bytes,
        digest,
        run,
        manifest,
    }
}

/// The manifest the CLI shows before the upload.
fn manifest(
    (run, about): (&str, About<'_>),
    snapshot: &Snapshot,
    request_bytes: usize,
    (masked_values, masked_files): (usize, Vec<Json>),
    reports: &Reports,
) -> Json {
    let mut reasons: BTreeMap<&str, u64> = BTreeMap::new();
    for (_, reason) in &snapshot.excluded {
        *reasons.entry(reason).or_default() += 1;
    }
    let listed = snapshot
        .excluded
        .iter()
        .take(LISTED)
        .map(|(path, reason)| {
            Json::object([("path", Json::text(path)), ("reason", Json::text(reason))])
        })
        .collect();
    Json::object([
        ("run", Json::text(run)),
        ("mode", Json::text(about.mode)),
        ("files", count(snapshot.files.len())),
        (
            "bytes",
            count(snapshot.files.values().map(String::len).sum()),
        ),
        ("requestBytes", count(request_bytes)),
        (
            "excluded",
            Json::object([
                ("count", count(snapshot.excluded.len())),
                (
                    "byReason",
                    Json::Object(
                        reasons
                            .into_iter()
                            .map(|(reason, n)| (reason.to_owned(), Json::int(n)))
                            .collect(),
                    ),
                ),
                ("paths", Json::Array(listed)),
            ]),
        ),
        (
            "masked",
            Json::object([
                ("values", count(masked_values)),
                ("files", Json::Array(masked_files)),
                ("scanner", Json::text("gitleaks")),
            ]),
        ),
        (
            "reports",
            Json::object([
                (
                    "sent",
                    Json::Array(
                        reports
                            .sent
                            .iter()
                            .map(|(name, _)| Json::text(name))
                            .collect(),
                    ),
                ),
                (
                    "left",
                    Json::Array(
                        reports
                            .left
                            .iter()
                            .map(|(name, why)| {
                                Json::object([
                                    ("name", Json::text(name)),
                                    ("reason", Json::text(why)),
                                ])
                            })
                            .collect(),
                    ),
                ),
                ("record", Json::Bool(reports.record.is_some())),
            ]),
        ),
        ("context", Json::Bool(about.context.is_some())),
    ])
}

#[cfg(test)]
mod tests;
