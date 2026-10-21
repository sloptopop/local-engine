//! The run's report, in three files: `report.json` (machine readable),
//! `SUMMARY.md` (what changed and why, with the controls each change
//! serves; refusals with their reasons; confirmations still needed; manual
//! tasks as checklists; the server's re-detection) and `PR.md` (a ready
//! pull-request description). Everything here is rendered from the
//! server's deliveries and what happened to them on this machine.
//!
//! Standards: SCF CHG-02 (documented changes), CPL-30 (evidence of the
//! controls each change serves); ISO/IEC 27001:2022 A.8.32; OWASP ASVS
//! 5.0 V16.3.4.

use std::fmt::Write as _;

use serde_json::Value;

use crate::apply::{Delivered, Outcome, Status};
use crate::canonical::Json;
use crate::records::confirmed_by;
use crate::tool::TOOL;
use crate::wire::Delivery;

/// The report's schema version.
pub(crate) const SCHEMA_VERSION: u32 = 2;

/// Appends one formatted line to a `String`.
macro_rules! put {
    ($out:expr) => {
        let _written = writeln!($out);
    };
    ($out:expr, $($arg:tt)*) => {
        let _written = writeln!($out, $($arg)*);
    };
}

/// What the report is about.
#[derive(Debug)]
pub(crate) struct Run<'a> {
    /// The run id.
    pub(crate) id: &'a str,
    /// Whether steps were committed.
    pub(crate) apply: bool,
    /// The base commit.
    pub(crate) base: &'a str,
    /// The branch, if one was made.
    pub(crate) branch: Option<&'a str>,
    /// The plan id.
    pub(crate) plan: &'a str,
    /// The server's deliveries.
    pub(crate) deliveries: &'a [Delivery],
    /// What happened to them.
    pub(crate) outcome: &'a Outcome,
    /// The server's re-detection, if it sent one.
    pub(crate) redetected: Option<&'a Value>,
    /// The confirmations recorded.
    pub(crate) records: &'a [Value],
}

/// The three files and whether every automated step was delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Written {
    /// `report.json`.
    pub(crate) report: Vec<u8>,
    /// `SUMMARY.md`.
    pub(crate) summary: String,
    /// `PR.md`.
    pub(crate) pr: String,
    /// Whether no step is pending, refused or blocked.
    pub(crate) complete: bool,
}

impl Run<'_> {
    /// Each step with its delivery.
    fn steps(&self) -> impl Iterator<Item = (&Delivery, &Delivered)> {
        self.deliveries.iter().zip(&self.outcome.steps)
    }

    /// `report.json`.
    fn json(&self, complete: bool) -> Vec<u8> {
        let steps = self
            .steps()
            .map(|(step, delivered)| {
                Json::object([
                    ("ordinal", Json::int(step.ordinal)),
                    ("kind", Json::text(&step.kind)),
                    ("class", Json::text(&step.class)),
                    ("title", Json::text(&step.title)),
                    ("status", Json::text(delivered.status.as_str())),
                    (
                        "commit",
                        delivered.commit.as_deref().map_or(Json::Null, Json::text),
                    ),
                    (
                        "files",
                        Json::Array(delivered.files.iter().map(|f| Json::text(f)).collect()),
                    ),
                    (
                        "reason",
                        delivered.reason.as_deref().map_or(Json::Null, Json::text),
                    ),
                ])
            })
            .collect();
        Json::object([
            ("schemaVersion", Json::int(SCHEMA_VERSION)),
            (
                "tool",
                Json::object([
                    ("name", Json::text(TOOL.name)),
                    ("version", Json::text(TOOL.version)),
                ]),
            ),
            ("run", Json::text(self.id)),
            ("plan", Json::text(self.plan)),
            ("base", Json::text(self.base)),
            ("applied", Json::Bool(self.apply)),
            ("branch", self.branch.map_or(Json::Null, Json::text)),
            (
                "head",
                self.outcome.head.as_deref().map_or(Json::Null, Json::text),
            ),
            ("complete", Json::Bool(complete)),
            ("steps", Json::Array(steps)),
            (
                "redetected",
                self.redetected.map_or(Json::Null, Json::from_value),
            ),
        ])
        .to_bytes()
    }

    /// `SUMMARY.md`.
    fn summary(&self) -> String {
        let mut out = String::new();
        put!(out, "# sloptopop transform {}", self.id);
        put!(out);
        put!(
            out,
            "Base `{}`{}.",
            self.base,
            self.branch.map_or_else(
                || ", dry run: nothing committed".to_owned(),
                |b| format!(", branch `{b}`")
            )
        );
        put!(out);
        put!(out, "## Steps");
        put!(out);
        for (step, delivered) in self.steps() {
            put!(
                out,
                "- Step {} ({}, {}): {} — **{}**{}",
                step.ordinal,
                step.kind,
                step.class,
                step.title,
                delivered.status.as_str(),
                delivered
                    .commit
                    .as_deref()
                    .map_or(String::new(), |c| format!(" `{c}`"))
            );
            for problem in &step.problems {
                put!(
                    out,
                    "  - {}: {} ({})",
                    problem.id,
                    problem.goal,
                    problem.control
                );
            }
            if let Some(reason) = &delivered.reason {
                put!(out, "  - why: {reason}");
            }
        }
        self.waiting(&mut out);
        self.tasks(&mut out);
        self.redetection(&mut out);
        out
    }

    /// The confirmations still needed.
    fn waiting(&self, out: &mut String) {
        let pending: Vec<(&Delivery, &str, &str)> = self
            .steps()
            .filter(|(_, delivered)| delivered.status == Status::Pending)
            .flat_map(|(step, _)| {
                step.requires
                    .iter()
                    .filter(|needed| {
                        confirmed_by(self.records, self.plan, &needed.attestation).is_empty()
                    })
                    .map(move |needed| {
                        (
                            step,
                            needed.attestation.as_str(),
                            needed.text.as_deref().unwrap_or_default(),
                        )
                    })
            })
            .collect();
        if pending.is_empty() {
            return;
        }
        put!(out);
        put!(out, "## Confirmations needed");
        put!(out);
        for (step, id, text) in pending {
            put!(out, "- `{id}` (step {}): {text}", step.ordinal);
        }
    }

    /// The manual tasks, as checklists.
    fn tasks(&self, out: &mut String) {
        let tasks: Vec<_> = self
            .deliveries
            .iter()
            .flat_map(|step| &step.tasks)
            .collect();
        if tasks.is_empty() {
            return;
        }
        put!(out);
        put!(out, "## Manual tasks");
        put!(out);
        for task in tasks {
            put!(out, "- [ ] {}", task.text);
            for item in &task.checklist {
                put!(out, "  - [ ] {item}");
            }
        }
    }

    /// The server's re-detection.
    fn redetection(&self, out: &mut String) {
        let rules = self
            .redetected
            .and_then(|value| value.get("rules"))
            .and_then(Value::as_array)
            .filter(|rules| !rules.is_empty());
        let Some(rules) = rules else {
            return;
        };
        put!(out);
        put!(
            out,
            "## Re-detection (on the server, with every verified step)"
        );
        put!(out);
        put!(out, "| Rule | Before | After |");
        put!(out, "|---|---:|---:|");
        for rule in rules {
            let get = |key: &str| rule.get(key).map_or_else(String::new, ToString::to_string);
            put!(
                out,
                "| {} | {} | {} |",
                get("rule").trim_matches('"'),
                get("before"),
                get("after")
            );
        }
    }

    /// `PR.md`.
    fn pr(&self) -> String {
        let mut out = String::new();
        put!(out, "sloptopop: verified changes (run {})", self.id);
        put!(out);
        for (step, _) in self.steps().filter(|(_, d)| d.commit.is_some()) {
            put!(out, "- {} ({}, {})", step.title, step.kind, step.class);
            for problem in &step.problems {
                put!(out, "  - {} ({})", problem.goal, problem.control);
            }
        }
        put!(out);
        put!(
            out,
            "Every change was verified by the sloptopop server and applied by `sloptopop local` only where its digests matched. Review before merging; merging is always a person's decision."
        );
        out
    }

    /// The three files.
    pub(crate) fn render(&self) -> Written {
        let complete = !self
            .outcome
            .steps
            .iter()
            .any(|step| step.status.undelivered());
        Written {
            report: self.json(complete),
            summary: self.summary(),
            pr: self.pr(),
            complete,
        }
    }
}

#[cfg(test)]
mod tests;
