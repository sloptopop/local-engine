//! The applier (D-0183 task 3; written fresh for the open-source crate):
//! the server's deliveries in order, each applied only as the server
//! verified it, as one commit on top of the previous one.
//!
//! For each verified step and each file it changes, the file's current
//! bytes (the uploaded, masked base with every earlier step's spans) must
//! have the step's `before` digest (a new file must not exist yet), the
//! step's spans spliced on the base must give its `after` digest, and the
//! real secret values the upload masked are put back (an edit that cuts
//! into a masked value refuses the step). A step that writes a file the
//! server could not have seen (tracked but not uploaded, a link or a
//! submodule, below a file, or where a snapshot never looks) is refused.
//! A step that requires attestations waits (pending) until a person of
//! the right role has recorded them. The first automated step not
//! delivered blocks every automated step above it; manual steps stack on
//! nothing. With `apply`, each delivered step becomes one commit made with
//! git's plumbing in a private index (`read-tree`, `hash-object`,
//! `update-index`, `write-tree`, `commit-tree`), dated as the base commit,
//! by `sloptopop`: the checkout, its index and `HEAD` are never touched.
//!
//! Standards: SCF CHG-03, CHG-04 (approved changes only), CHG-07 (a change
//! kept only once verified); ISO/IEC 27001:2022 A.8.32; OWASP ASVS 5.0
//! V13.3.1 (secret values restored locally, never uploaded); CWE-59 (no
//! write through a link).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;

use crate::digest::{FILE, digest};
use crate::git::Git;
use crate::mask::{Edit, Mask, restore};
use crate::records::{Owners, confirmed_by, satisfied};
use crate::snapshot::left_out;
use crate::wire::{Change, Delivery, Span};

/// The author and committer of delivered commits.
const IDENTITY: (&str, &str) = ("sloptopop", "noreply@sloptopop.dev");

/// What happened to a step here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// Committed.
    Applied,
    /// Would be committed (a dry run).
    Planned,
    /// Work for a person.
    Manual,
    /// Waits for a confirmation.
    Pending,
    /// Not delivered: the server or this client refused it.
    Refused,
    /// Not tried: it stacks on a step that was not delivered.
    Blocked,
}

impl Status {
    /// The status as reported.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Planned => "planned",
            Self::Manual => "manual",
            Self::Pending => "pending",
            Self::Refused => "refused",
            Self::Blocked => "blocked",
        }
    }

    /// Whether the step was not delivered.
    pub(crate) const fn undelivered(self) -> bool {
        matches!(self, Self::Pending | Self::Refused | Self::Blocked)
    }
}

/// One step's delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Delivered {
    /// The step.
    pub(crate) ordinal: u32,
    /// What happened.
    pub(crate) status: Status,
    /// Its commit, if applied.
    pub(crate) commit: Option<String>,
    /// The files it writes.
    pub(crate) files: Vec<String>,
    /// Why it was not delivered.
    pub(crate) reason: Option<String>,
}

impl Delivered {
    /// A step with `status` and nothing else.
    const fn bare(ordinal: u32, status: Status) -> Self {
        Self {
            ordinal,
            status,
            commit: None,
            files: Vec::new(),
            reason: None,
        }
    }
}

/// Every step's delivery and the last commit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// Each step, in order.
    pub(crate) steps: Vec<Delivered>,
    /// The last commit, if any step was applied.
    pub(crate) head: Option<String>,
}

/// The masked files' real bytes and masks, by path.
pub(crate) type Real = BTreeMap<String, (Vec<u8>, Vec<Mask>)>;

/// What a delivery works from.
#[derive(Debug)]
pub(crate) struct Job<'a> {
    /// The repository.
    pub(crate) git: &'a Git,
    /// The base commit.
    pub(crate) base: &'a str,
    /// The run id.
    pub(crate) run: &'a str,
    /// The plan id the deliveries belong to.
    pub(crate) plan: &'a str,
    /// The server's deliveries, in order.
    pub(crate) deliveries: &'a [Delivery],
    /// The uploaded (masked) files.
    pub(crate) uploaded: &'a BTreeMap<String, String>,
    /// The masked files' real bytes and masks.
    pub(crate) real: &'a Real,
    /// The base tree's file modes.
    pub(crate) modes: &'a BTreeMap<String, String>,
    /// The confirmations recorded.
    pub(crate) records: &'a [Value],
    /// Who may confirm.
    pub(crate) owners: &'a Owners,
    /// An empty directory to work in.
    pub(crate) scratch: &'a Path,
    /// Whether to commit.
    pub(crate) apply: bool,
}

/// A file as the delivered steps leave it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Written {
    /// Every delivered step's spans of the base, in order.
    spans: Vec<Span>,
    /// Its real bytes (secret values put back).
    bytes: Vec<u8>,
    /// Its mode.
    mode: String,
}

/// What a delivery carries from step to step.
#[derive(Debug, Default)]
struct State {
    /// Every file the delivered steps changed.
    files: BTreeMap<String, Written>,
    /// The first automated step not delivered.
    stop: Option<u32>,
    /// The last commit.
    head: Option<String>,
}

/// Delivers `job`.
pub(crate) fn deliver(job: &Job<'_>) -> Outcome {
    let mut state = State::default();
    let steps = job
        .deliveries
        .iter()
        .map(|step| next(job, step, &mut state))
        .collect();
    Outcome {
        steps,
        head: state.head,
    }
}

/// Delivers `step`.
fn next(job: &Job<'_>, step: &Delivery, state: &mut State) -> Delivered {
    if step.manual() {
        return Delivered::bare(step.ordinal, Status::Manual);
    }
    if let Some(by) = state.stop {
        return Delivered {
            reason: Some(format!("it stacks on step {by}, which was not delivered")),
            ..Delivered::bare(step.ordinal, Status::Blocked)
        };
    }
    let tried = attempt(job, step, state);
    if tried.status.undelivered() {
        state.stop = Some(step.ordinal);
    }
    tried
}

/// A refusal of `step` for `why`.
fn refused(step: &Delivery, why: String) -> Delivered {
    Delivered {
        reason: Some(why),
        ..Delivered::bare(step.ordinal, Status::Refused)
    }
}

/// Tries `step`: checks it, writes its files and, with `apply`, commits.
fn attempt(job: &Job<'_>, step: &Delivery, state: &mut State) -> Delivered {
    if step.status != "verified" {
        let why = step
            .reason
            .clone()
            .unwrap_or_else(|| match step.blocked_by {
                Some(by) => format!("the server blocked it on step {by}"),
                None => format!("the server did not verify it ({})", step.status),
            });
        return refused(step, why);
    }
    let waiting: Vec<&str> = step
        .requires
        .iter()
        .filter(|needed| !satisfied(job.records, job.plan, needed, job.base, job.owners))
        .map(|needed| needed.attestation.as_str())
        .collect();
    if !waiting.is_empty() {
        return Delivered {
            reason: Some(format!(
                "waits for a confirmation of {} (`sloptopop transform --run {} --confirm {} --by <name>`)",
                waiting.join(", "),
                job.run,
                waiting.join(",")
            )),
            ..Delivered::bare(step.ordinal, Status::Pending)
        };
    }
    let mut written = BTreeMap::new();
    for change in &step.changes {
        match write(job, state, change) {
            Ok(file) => {
                written.insert(change.path.clone(), file);
            }
            Err(why) => return refused(step, why),
        }
    }
    let files: Vec<String> = written.keys().cloned().collect();
    state.files.extend(written);
    if !job.apply {
        return Delivered {
            files,
            ..Delivered::bare(step.ordinal, Status::Planned)
        };
    }
    let parent = state.head.clone().unwrap_or_else(|| job.base.to_owned());
    match commit(job, step, &state.files, &parent) {
        Ok(made) => {
            state.head = Some(made.clone());
            Delivered {
                commit: Some(made),
                files,
                ..Delivered::bare(step.ordinal, Status::Applied)
            }
        }
        Err(why) => refused(step, why),
    }
}

/// Why `path` may not be written, if it may not (the server could not
/// have seen it).
fn unseen(job: &Job<'_>, path: &str) -> Option<String> {
    if let Some(mode) = job.modes.get(path) {
        return if matches!(mode.as_str(), "120000" | "160000") {
            Some(format!("`{path}` is a symbolic link or a submodule"))
        } else if job.uploaded.contains_key(path) {
            None
        } else {
            Some(format!("`{path}` is tracked but was never uploaded"))
        };
    }
    let parent = path
        .char_indices()
        .filter(|(_, c)| *c == '/')
        .map(|(at, _)| path.get(..at).unwrap_or_default())
        .find(|prefix| job.modes.contains_key(*prefix));
    if let Some(prefix) = parent {
        return Some(format!(
            "`{path}` is below `{prefix}`, which is not a directory"
        ));
    }
    left_out(path).map(|why| format!("`{path}` is never uploaded ({why})"))
}

/// `base` with `spans` (base offsets): sorted by start and end, insertions
/// at one offset in their order; `None` when two overlap, one is out of
/// range or off a character boundary.
fn splice(base: &str, spans: &[Span]) -> Option<String> {
    let mut sorted: Vec<&Span> = spans.iter().collect();
    sorted.sort_by_key(|span| (span.start, span.end));
    let mut out = String::with_capacity(base.len());
    let mut at = 0;
    for span in sorted {
        // An overlap (`start < at`) is not a range.
        out.push_str(base.get(at..span.start)?);
        base.get(span.start..span.end)?;
        out.push_str(&span.text);
        at = span.end;
    }
    // Every span's end was checked to lie on a boundary of `base`.
    out.push_str(base.get(at..).unwrap_or_default());
    Some(out)
}

/// The file `change` leaves, checked against its digests, with the real
/// secret values put back.
fn write(job: &Job<'_>, state: &State, change: &Change) -> Result<Written, String> {
    let path = &change.path;
    if let Some(why) = unseen(job, path) {
        return Err(format!(
            "the server could not have seen what it verified: {why}"
        ));
    }
    let earlier = state.files.get(path);
    let exists = job.uploaded.contains_key(path) || earlier.is_some();
    match (change.kind.as_str(), exists, &change.before) {
        ("create", false, None) | ("edit", true, Some(_)) => {}
        _ => {
            return Err(format!(
                "`{path}`: a `{}` of a file that {} exist",
                change.kind,
                if exists { "does" } else { "does not" }
            ));
        }
    }
    let base = job.uploaded.get(path).map_or("", String::as_str);
    let mut spans = earlier.map(|file| file.spans.clone()).unwrap_or_default();
    let now = splice(base, &spans).unwrap_or_default();
    if change
        .before
        .as_ref()
        .is_some_and(|before| *before != digest(FILE, now.as_bytes()))
    {
        return Err(format!("`{path}` is not the file the server verified"));
    }
    spans.extend(change.edits.iter().cloned());
    let after = splice(base, &spans)
        .ok_or_else(|| format!("`{path}`: the spans do not fit the uploaded file"))?;
    if digest(FILE, after.as_bytes()) != change.after {
        return Err(format!(
            "`{path}` would not have the bytes the server verified"
        ));
    }
    let bytes = match job.real.get(path) {
        Some((real, masks)) => {
            let edits: Vec<Edit> = spans
                .iter()
                .map(|span| Edit {
                    start: span.start,
                    end: span.end,
                    len: span.text.len(),
                })
                .collect();
            restore(after.as_bytes(), real, masks, &edits)?
        }
        None => after.into_bytes(),
    };
    let mode = change
        .mode
        .clone()
        .or_else(|| job.modes.get(path).cloned())
        .unwrap_or_else(|| "100644".to_owned());
    Ok(Written { spans, bytes, mode })
}

/// The commit message of `step`: the server's, the confirmations, and
/// this run's trailers.
fn message(job: &Job<'_>, step: &Delivery) -> String {
    let (head, plan) = step
        .message
        .rsplit_once("\nSloptopop-Plan: ")
        .map_or((step.message.trim_end(), None), |(head, plan)| {
            (head, Some(plan.trim_end()))
        });
    let mut text = head.trim_end().to_owned();
    text.push('\n');
    for needed in &step.requires {
        let by = confirmed_by(job.records, job.plan, &needed.attestation);
        let _line = write!(
            text,
            "\nDeclared behaviour change, confirmed by {}: {}\n",
            by.join(", "),
            needed.text.as_deref().unwrap_or_default()
        );
    }
    text.push('\n');
    if let Some(plan) = plan {
        let _line = writeln!(text, "Sloptopop-Plan: {plan}");
    }
    let _trailers = write!(
        text,
        "Sloptopop-Step: {}-{}\nSloptopop-Run: {}\n",
        step.ordinal, step.kind, job.run
    );
    text
}

/// Commits `files` (path → file, over the base) on `parent`; the commit.
///
/// # Errors
///
/// When git fails.
fn commit(
    job: &Job<'_>,
    step: &Delivery,
    files: &BTreeMap<String, Written>,
    parent: &str,
) -> Result<String, String> {
    let index = job.scratch.join("index");
    let date = job
        .git
        .text(&["show", "-s", "--format=%ct +0000", job.base])?;
    let git = job
        .git
        .clone()
        .env("GIT_INDEX_FILE", &index.to_string_lossy())
        .env("GIT_AUTHOR_NAME", IDENTITY.0)
        .env("GIT_AUTHOR_EMAIL", IDENTITY.1)
        .env("GIT_COMMITTER_NAME", IDENTITY.0)
        .env("GIT_COMMITTER_EMAIL", IDENTITY.1)
        .env("GIT_AUTHOR_DATE", &date)
        .env("GIT_COMMITTER_DATE", &date);
    git.run(&["read-tree", job.base])
        .and_then(|_| {
            files.iter().try_for_each(|(path, file)| {
                git.input(
                    &["hash-object", "-w", "--no-filters", "--stdin"],
                    &file.bytes,
                )
                .map(|oid| String::from_utf8_lossy(&oid).trim().to_owned())
                .and_then(|oid| {
                    git.run(&[
                        "update-index",
                        "--add",
                        "--cacheinfo",
                        &format!("{},{oid},{path}", file.mode),
                    ])
                })
                .map(|_| ())
            })
        })
        .and_then(|()| git.text(&["write-tree"]))
        .and_then(|tree| {
            git.input(
                &["commit-tree", &tree, "-p", parent, "-F", "-"],
                message(job, step).as_bytes(),
            )
        })
        .map(|oid| String::from_utf8_lossy(&oid).trim().to_owned())
}

#[cfg(test)]
mod tests;
