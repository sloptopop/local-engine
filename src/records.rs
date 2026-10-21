//! Confirmations of declared behaviour changes: attestation records a
//! person makes with `--confirm <ids> --by <name>`, kept (git-ignored) in
//! `.sloptopop/transform/attestations.json`; they never leave the machine.
//! A record binds the attestation's exact text (its statement digest), the
//! plan, the step and the base commit, so it never carries over to another
//! plan or commit. Who may confirm comes from the Business Context
//! (`.sloptopop/context.json`, `owners`): the attestation's role
//! (`approver`, `operator`, `data_owner`), or an approver for any. A step
//! ships only when every attestation it requires has such a record
//! ([`satisfied`]).
//!
//! Standards: SCF CHG-04 (change approval by an authorised person),
//! IAC-08 (role-based permissions); ISO/IEC 27001:2022 A.8.32 (change
//! management); OWASP ASVS 5.0 V16.3.4 (who approved is recorded).

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::canonical::Json;
use crate::digest::digest;
use crate::wire::{Delivery, Requirement};

/// Where the records are kept, relative to the root.
pub(crate) const FILE: &str = ".sloptopop/transform/attestations.json";

/// The key-derivation context of an attestation's statement digest.
pub(crate) const STATEMENT: &str = "sloptopop attestation statement";

/// Who may confirm what (the Business Context's `owners`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub(crate) struct Owners {
    /// May attest anything.
    pub(crate) approvers: Vec<String>,
    /// Deployment facts.
    pub(crate) operators: Vec<String>,
    /// Consumer facts.
    pub(crate) data: Vec<String>,
}

impl Owners {
    /// The role `by` confirms an attestation of `who` in, if they may.
    fn role<'a>(&self, who: &'a str, by: &str) -> Option<&'a str> {
        let listed = match who {
            "operator" => &self.operators,
            "data_owner" => &self.data,
            _ => &self.approvers,
        };
        if listed.iter().any(|name| name == by) {
            Some(who)
        } else if self.approvers.iter().any(|name| name == by) {
            Some("approver")
        } else {
            None
        }
    }
}

/// A record as kept.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    /// The attestation's id.
    attestation: String,
    /// The plan.
    plan: String,
    /// The digest of the text the person saw.
    statement: String,
    /// The commit attested.
    subject: String,
    /// Who.
    by: String,
}

/// The statement digest of an attestation's text.
pub(crate) fn statement(text: &str) -> String {
    digest(STATEMENT, text.as_bytes())
}

/// The records kept under `root` (none if there is no file yet).
///
/// # Errors
///
/// When the file exists but is not a JSON array.
pub(crate) fn load(root: &Path) -> Result<Vec<Value>, String> {
    let path = root.join(FILE);
    if !path.exists() {
        return Ok(Vec::new());
    }
    fs::read(&path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<Vec<Value>>(&bytes).map_err(|error| error.to_string())
        })
        .map_err(|error| format!("{FILE} is not a list of records: {error}"))
}

/// Keeps `records` under `root`.
///
/// # Errors
///
/// When the file cannot be written.
pub(crate) fn save(root: &Path, records: &[Value]) -> Result<(), String> {
    let path = root.join(FILE);
    let mut bytes = Json::Array(records.iter().map(Json::from_value).collect()).to_bytes();
    bytes.push(b'\n');
    path.parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| fs::write(&path, bytes))
        .map_err(|error| format!("cannot write {FILE}: {error}"))
}

/// The owners the Business Context names (none without one).
pub(crate) fn owners(context: Option<&Value>) -> Owners {
    context
        .and_then(|context| context.get("owners"))
        .and_then(|owners| Owners::deserialize(owners).ok())
        .unwrap_or_default()
}

/// The attestation `id` some delivery requires, with its step.
fn required<'a>(deliveries: &'a [Delivery], id: &str) -> Option<(u32, &'a Requirement)> {
    deliveries.iter().find_map(|delivery| {
        delivery
            .requires
            .iter()
            .find(|requirement| requirement.attestation == id)
            .map(|requirement| (delivery.ordinal, requirement))
    })
}

/// New records: `by` confirms each attestation of `ids` that the
/// deliveries of `plan` require, at `subject`, on `date`.
///
/// # Errors
///
/// When no delivery requires an id, or `by` may not confirm it.
pub(crate) fn confirm(
    deliveries: &[Delivery],
    plan: &str,
    ids: &[String],
    (by, owners): (&str, &Owners),
    subject: &str,
    date: &str,
) -> Result<Vec<Value>, String> {
    ids.iter()
        .map(|id| {
            let (step, requirement) = required(deliveries, id)
                .ok_or_else(|| format!("no step of this run requires the attestation `{id}`"))?;
            let who = requirement.who.as_deref().unwrap_or("approver");
            let role = owners.role(who, by).ok_or_else(|| {
                format!(
                    "`{by}` may not confirm `{id}`: add them to `owners` in .sloptopop/context.json (role {who})"
                )
            })?;
            Ok(json!({
                "attestation": id,
                "plan": plan,
                "step": step,
                "statement": statement(requirement.text.as_deref().unwrap_or_default()),
                "subject": subject,
                "by": by,
                "role": role,
                "evidence": requirement.evidence.as_deref().unwrap_or_default(),
                "evidenceRef": "sloptopop transform --confirm",
                "asOf": date,
            }))
        })
        .collect()
}

/// Whether `records` hold a confirmation of `requirement` for `plan` at
/// `subject` by someone `owners` still lets confirm it.
pub(crate) fn satisfied(
    records: &[Value],
    plan: &str,
    requirement: &Requirement,
    subject: &str,
    owners: &Owners,
) -> bool {
    let text = statement(requirement.text.as_deref().unwrap_or_default());
    let who = requirement.who.as_deref().unwrap_or("approver");
    records
        .iter()
        .filter_map(|record| Record::deserialize(record).ok())
        .any(|record| {
            record.attestation == requirement.attestation
                && record.plan == plan
                && record.statement == text
                && record.subject == subject
                && owners.role(who, &record.by).is_some()
        })
}

/// Who confirmed `id` for `plan`, as recorded.
pub(crate) fn confirmed_by(records: &[Value], plan: &str, id: &str) -> Vec<String> {
    records
        .iter()
        .filter_map(|record| Record::deserialize(record).ok())
        .filter(|record| record.plan == plan && record.attestation == id)
        .map(|record| record.by)
        .collect()
}

/// Today's date (UTC), `YYYY-MM-DD`.
pub(crate) fn today() -> String {
    let days = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() / 86_400);
    date(days)
}

/// The civil date `days` after 1970-01-01 (H. Hinnant's algorithm).
fn date(days: u64) -> String {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests;
