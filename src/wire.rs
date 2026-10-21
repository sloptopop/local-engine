//! What `sloptopop local` reads of the server's response (the server's
//! `docs/api.md`, response schema 2): the request digest it answers, the
//! Report, the deliveries and the evidence verdict. Only the members it
//! uses are read, so new members never break it; it never reads the plan.
//!
//! Standards: SCF TDA-12 (Input Data Validation: the response must have
//! this shape, or nothing is applied).

use serde::Deserialize;
use serde_json::Value;

/// The response schema version this client reads.
pub(crate) const SCHEMA_VERSION: u32 = 2;

/// The server's response.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Response {
    /// Always [`SCHEMA_VERSION`].
    pub(crate) schema_version: u32,
    /// The digests of the request.
    pub(crate) digests: Digests,
    /// The Report v2, except for `evidence`.
    #[serde(default)]
    pub(crate) report: Option<Value>,
    /// What to apply (`fix`, `transform`).
    #[serde(default)]
    pub(crate) deliveries: Vec<Delivery>,
    /// The re-detection (`transform`).
    #[serde(default)]
    pub(crate) redetected: Option<Value>,
    /// The evidence verdict (`evidence`).
    #[serde(default)]
    pub(crate) verdict: Option<Value>,
}

/// The digests of the request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Digests {
    /// Of the request's canonical bytes.
    pub(crate) request: String,
}

/// One step to deliver.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Delivery {
    /// Its ordinal.
    pub(crate) ordinal: u32,
    /// Its kind (`code`, `manual`, `fix`, …).
    pub(crate) kind: String,
    /// `equivalent` or `declared`.
    pub(crate) class: String,
    /// `verified`, `refused`, `manual` or `blocked`.
    pub(crate) status: String,
    /// What it does, in a line.
    pub(crate) title: String,
    /// Its commit message.
    pub(crate) message: String,
    /// The problems it solves.
    #[serde(default)]
    pub(crate) problems: Vec<Problem>,
    /// The attestations a person must record first.
    #[serde(default)]
    pub(crate) requires: Vec<Requirement>,
    /// Its manual tasks.
    #[serde(default)]
    pub(crate) tasks: Vec<Task>,
    /// Its changes (a verified step).
    #[serde(default)]
    pub(crate) changes: Vec<Change>,
    /// Why it was not verified.
    #[serde(default)]
    pub(crate) reason: Option<String>,
    /// The step it stacks on, when blocked.
    #[serde(default)]
    pub(crate) blocked_by: Option<u32>,
}

impl Delivery {
    /// Whether it is work for a person only.
    pub(crate) fn manual(&self) -> bool {
        self.status == "manual"
    }
}

/// A problem a step solves.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Problem {
    /// Its id.
    pub(crate) id: String,
    /// Its goal.
    pub(crate) goal: String,
    /// The control it serves.
    pub(crate) control: String,
}

/// An attestation a step requires.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Requirement {
    /// Its id.
    pub(crate) attestation: String,
    /// What a person attests.
    #[serde(default)]
    pub(crate) text: Option<String>,
    /// Who records it (`approver`, `operator`, `data_owner`).
    #[serde(default)]
    pub(crate) who: Option<String>,
    /// The kind of evidence.
    #[serde(default)]
    pub(crate) evidence: Option<String>,
}

/// A manual task.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Task {
    /// What to do.
    pub(crate) text: String,
    /// Its checklist.
    #[serde(default)]
    pub(crate) checklist: Vec<String>,
}

/// One file a verified step writes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Change {
    /// The file.
    pub(crate) path: String,
    /// `create` or `edit`.
    pub(crate) kind: String,
    /// The digest of the (masked) file before the step; none for a new one.
    #[serde(default)]
    pub(crate) before: Option<String>,
    /// The digest after it.
    pub(crate) after: String,
    /// Its byte spans of the uploaded (masked) base file.
    pub(crate) edits: Vec<Span>,
    /// The mode of a new file (`100755`), if not a plain one.
    #[serde(default)]
    pub(crate) mode: Option<String>,
}

/// One byte span: replace `start..end` of the base file with `text`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
pub(crate) struct Span {
    /// First byte replaced.
    pub(crate) start: usize,
    /// One past the last byte replaced.
    pub(crate) end: usize,
    /// The new text.
    pub(crate) text: String,
}

/// The plan id a delivery's commit message names (`Sloptopop-Plan:`).
pub(crate) fn plan_id(deliveries: &[Delivery]) -> String {
    deliveries
        .iter()
        .flat_map(|delivery| delivery.message.lines())
        .find_map(|line| line.strip_prefix("Sloptopop-Plan: "))
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests;
