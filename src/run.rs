//! The commands of `sloptopop local` around the one server call the CLI
//! makes (decision D-0008 leaves which side makes it to the owner; the
//! request and the response are files in the run directory either way):
//!
//! 1. [`request`]: the repository must be clean at its top level; the
//!    snapshot of `HEAD` is masked from the secret scanner's report
//!    (refused without a usable one), and the request (with the analyzer
//!    reports) and its manifest are written to
//!    `.sloptopop/transform/<run>/request.json`;
//! 2. the CLI shows the manifest, asks, posts the request and writes the
//!    answer to `response.json` next to it;
//! 3. [`report`] prints the server's Report (`check`); [`apply`] checks
//!    that the response answers that request on the same `HEAD`, records
//!    any confirmations, applies the deliveries (a dry run unless asked)
//!    and writes `report.json`, `SUMMARY.md` and `PR.md`; [`evidence`]
//!    runs the project's own checks on the base and the branch and writes
//!    the evidence request for the server's Guider.
//!
//! `.sloptopop/transform/` holds its own `.gitignore` (`*`), so nothing
//! written there is ever committed or makes the tree dirty.
//!
//! Standards: SCF CHG-03 (changes on a new branch, never the checkout),
//! CHG-04, TDA-20.3 (the response is bound to the request); OWASP ASVS 5.0
//! V13.3.1.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use serde_json::Value;

use crate::apply::{Job, Real, deliver};
use crate::canonical::Json;
use crate::digest::{REQUEST, digest};
use crate::error::Error;
use crate::evidence::{About as Evidence, checks, evidence as gather};
use crate::git::Git;
use crate::mask::diff;
use crate::records::{confirm, load, owners, save, today};
use crate::reports;
use crate::scanner::found;
use crate::snapshot::{snapshot, tree};
use crate::summary::Run;
use crate::upload::{About, upload};
use crate::wire::{Response, SCHEMA_VERSION, plan_id};

/// Where runs are kept, relative to the root.
pub const TRANSFORM_DIR: &str = ".sloptopop/transform";

/// The Business Context, relative to the root.
pub const CONTEXT: &str = ".sloptopop/context.json";

/// The time limit of one check run for evidence.
pub const CHECK_LIMIT: Duration = Duration::from_secs(600);

/// What `apply` is asked to do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    /// Commit the delivered steps (otherwise a dry run).
    pub apply: bool,
    /// The branch to make (default `sloptopop/transform-<run>`).
    pub branch: Option<String>,
    /// Attestations to confirm first.
    pub confirm: Vec<String>,
    /// Who confirms them.
    pub by: Option<String>,
}

/// A command's document and whether it is a success (`check`: the Report
/// passed; `apply`: every automated step was delivered).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The document, with a final newline.
    pub document: Vec<u8>,
    /// Whether it is a success.
    pub complete: bool,
}

/// An error in words.
fn failed(why: impl Into<String>) -> Error {
    Error::Local(why.into())
}

/// The base commit of the repository `git` works in, if it is run at the
/// top level and the tree is clean.
fn preflight(git: &Git) -> Result<String, Error> {
    let top = git
        .text(&["rev-parse", "--show-toplevel"])
        .map_err(Error::Local)?;
    if fs::canonicalize(git.root()).ok() != fs::canonicalize(&top).ok() {
        return Err(failed(format!(
            "run it at the top of the repository, `{top}`"
        )));
    }
    let (base, status) = git
        .text(&["rev-parse", "--verify", "HEAD^{commit}"])
        .and_then(|base| {
            git.run(&["status", "--porcelain=v1", "--untracked-files=all"])
                .map(|status| (base, status))
        })
        .map_err(Error::Local)?;
    if status.is_empty() {
        Ok(base)
    } else {
        Err(failed(
            "the working tree has uncommitted or untracked changes: commit or stash them first",
        ))
    }
}

/// The Business Context of `root`, if it has one.
fn context(root: &Path) -> Result<Option<Value>, Error> {
    let path = root.join(CONTEXT);
    if !path.exists() {
        return Ok(None);
    }
    fs::read(&path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
        })
        .and_then(|value| {
            if value.is_object() {
                Ok(Some(value))
            } else {
                Err("not a JSON object".to_owned())
            }
        })
        .map_err(|why| failed(format!("{CONTEXT}: {why}")))
}

/// Writes `bytes` to `path`, creating its directories, and the run
/// directory's `.gitignore`.
fn write(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let ignore = root.join(TRANSFORM_DIR).join(".gitignore");
    path.parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| fs::write(ignore, "*\n"))
        .and_then(|()| fs::write(path, bytes))
        .map_err(|error| failed(format!("cannot write `{}`: {error}", path.display())))
}

/// The document `request` prints: the run, the base, the request's and the
/// response's paths and the manifest, with a final newline.
fn printed(members: [(&str, Json); 6]) -> Vec<u8> {
    let mut document = Json::object(members).to_bytes();
    document.push(b'\n');
    document
}

/// `request`: prepares the request of `mode` (`check`, `fix` or
/// `transform`) for the repository at `root`.
///
/// # Errors
///
/// [`Error::Local`] when `root` is not the top of a git repository with a
/// clean tree, there is no usable secret-scanner report, the Business
/// Context is not a JSON object, or the request cannot be written.
pub fn request(root: &Path, mode: &str) -> Result<Vec<u8>, Error> {
    request_with(&Git::new(root), mode)
}

/// [`request`] with `git`.
fn request_with(git: &Git, mode: &str) -> Result<Vec<u8>, Error> {
    let root = git.root();
    let base = preflight(git)?;
    let snap = tree(git, &base)
        .and_then(|entries| snapshot(git, &entries))
        .map_err(Error::Local)?;
    let committed = git
        .text(&["show", "-s", "--format=%ct", &base])
        .ok()
        .and_then(|seconds| seconds.parse::<u64>().ok())
        .map_or(UNIX_EPOCH, |seconds| {
            UNIX_EPOCH + Duration::from_secs(seconds)
        });
    let paths: BTreeSet<String> = snap.files.keys().cloned().collect();
    let secrets = found(root, &paths, committed).map_err(Error::Local)?;
    let context = context(root)?;
    // The root is a repository's top level, so it has a name; "app" only
    // names the filesystem root.
    let canonical = fs::canonicalize(root).ok();
    let name = canonical
        .as_deref()
        .unwrap_or(root)
        .file_name()
        .unwrap_or(OsStr::new("app"))
        .to_string_lossy()
        .into_owned();
    let about = About {
        mode,
        base: &base,
        name: &name,
        context: context.as_ref(),
    };
    let prepared = upload(about, &snap, &secrets, &reports::read(root));
    let dir = Path::new(TRANSFORM_DIR).join(&prepared.run);
    let file = dir.join("request.json");
    write(root, &root.join(&file), &prepared.bytes)?;
    Ok(printed([
        ("schemaVersion", Json::int(1_u32)),
        ("run", Json::text(&prepared.run)),
        ("base", Json::text(&base)),
        ("request", Json::text(&file.to_string_lossy())),
        (
            "response",
            Json::text(&dir.join("response.json").to_string_lossy()),
        ),
        ("manifest", prepared.manifest),
    ]))
}

/// Reads the JSON file `name` of the run directory `dir`.
fn read<T: serde::de::DeserializeOwned>(dir: &Path, name: &str) -> Result<T, Error> {
    let path = dir.join(name);
    fs::read(&path)
        .map_err(|error| error.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
        .map_err(|why| failed(format!("cannot read `{}`: {why}", path.display())))
}

/// A run's files, checked against each other and `HEAD`.
#[derive(Debug)]
struct Opened {
    /// The base commit (`HEAD`).
    base: String,
    /// The run directory.
    dir: PathBuf,
    /// The request.
    request: Value,
    /// The response.
    response: Response,
}

/// Opens run `run` of the repository `git` works in.
fn open(git: &Git, run: &str) -> Result<Opened, Error> {
    if run.len() != 16 || !run.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(failed(format!("`{run}` is not a run id")));
    }
    let base = preflight(git)?;
    let dir = git.root().join(TRANSFORM_DIR).join(run);
    let request: Value = read(&dir, "request.json")?;
    let response: Response = read(&dir, "response.json")?;
    if request.get("base").and_then(Value::as_str) != Some(base.as_str()) {
        return Err(failed(
            "HEAD moved since the request was made: run `sloptopop transform` again",
        ));
    }
    if response.schema_version != SCHEMA_VERSION
        || response.digests.request != digest(REQUEST, &Json::from_value(&request).to_bytes())
    {
        return Err(failed("the response does not answer this run's request"));
    }
    Ok(Opened {
        base,
        dir,
        request,
        response,
    })
}

/// `report`: the server's Report of run `run`, and whether it passed.
///
/// # Errors
///
/// As opening the run; [`Error::Local`] when the response holds no Report.
pub fn report(root: &Path, run: &str) -> Result<Outcome, Error> {
    let opened = open(&Git::new(root), run)?;
    let report = opened
        .response
        .report
        .ok_or_else(|| failed("the response holds no Report"))?;
    let mut document = Json::from_value(&report).to_bytes();
    document.push(b'\n');
    Ok(Outcome {
        document,
        complete: report.get("passed").and_then(Value::as_bool) == Some(true),
    })
}

/// The uploaded files of a request, by path.
fn uploaded(request: &Value) -> BTreeMap<String, String> {
    request
        .get("files")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|file| {
            let path = file.get("path").and_then(Value::as_str);
            let text = file.get("text").and_then(Value::as_str);
            path.zip(text)
        })
        .map(|(path, text)| (path.to_owned(), text.to_owned()))
        .collect()
}

/// The real bytes and masks of every uploaded file that differs from the
/// base's: each must be the base's file masked.
fn unmasked(git: &Git, base: &str, files: &BTreeMap<String, String>) -> Result<Real, Error> {
    let mut out = BTreeMap::new();
    for (path, text) in files {
        let real = git
            .run(&["cat-file", "blob", &format!("{base}:{path}")])
            .map_err(Error::Local)?;
        if real == text.as_bytes() {
            continue;
        }
        let masks = diff(&real, text.as_bytes()).ok_or_else(|| {
            failed(format!(
                "`{path}` in the request is not the base's file masked"
            ))
        })?;
        out.insert(path.clone(), (real, masks));
    }
    Ok(out)
}

/// Checks that `branch` is a valid name that does not exist yet.
fn claim(git: &Git, branch: &str) -> Result<(), Error> {
    git.run(&["check-ref-format", "--branch", branch])
        .map_err(|_| failed(format!("`{branch}` is not a valid branch name")))?;
    match git.run(&[
        "rev-parse",
        "--verify",
        "--quiet",
        &format!("refs/heads/{branch}"),
    ]) {
        Ok(_) => Err(failed(format!(
            "branch `{branch}` exists: delete it or pass --branch <name>"
        ))),
        Err(_) => Ok(()),
    }
}

/// A private directory for one run, removed when dropped.
#[derive(Debug)]
struct Scratch(PathBuf);

impl Scratch {
    /// A fresh directory at `path` (in the run directory, which git
    /// ignores).
    fn new(path: &Path) -> Result<Self, Error> {
        let _stale = fs::remove_dir_all(path);
        fs::create_dir_all(path)
            .map(|()| Self(path.to_path_buf()))
            .map_err(|error| failed(format!("cannot make a scratch directory: {error}")))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

/// `apply`: delivers run `run` of the repository at `root` as `options`
/// ask; `report.json`, also written with `SUMMARY.md` and `PR.md` to the
/// run directory.
///
/// # Errors
///
/// [`Error::Local`] when the repository is not clean at its top level,
/// `HEAD` moved since the request, the run's files are missing or do not
/// belong together, the branch is invalid or exists, a confirmation is not
/// allowed, or git fails.
pub fn apply(root: &Path, run: &str, options: &Options) -> Result<Outcome, Error> {
    apply_with(&Git::new(root), run, options)
}

/// [`apply`] with `git`.
fn apply_with(git: &Git, run: &str, options: &Options) -> Result<Outcome, Error> {
    let root = git.root();
    let opened = open(git, run)?;
    let deliveries = &opened.response.deliveries;
    let plan = plan_id(deliveries);
    let branch = options
        .branch
        .clone()
        .unwrap_or_else(|| format!("sloptopop/transform-{run}"));
    if options.apply {
        claim(git, &branch)?;
    }
    let people = owners(opened.request.get("context"));
    let mut records = load(root).map_err(Error::Local)?;
    if !options.confirm.is_empty() {
        let by = options.by.as_deref().unwrap_or_default();
        let added = confirm(
            deliveries,
            &plan,
            &options.confirm,
            (by, &people),
            &opened.base,
            &today(),
        )
        .map_err(Error::Local)?;
        records.extend(added);
        save(root, &records).map_err(Error::Local)?;
    }
    let files = uploaded(&opened.request);
    let real = unmasked(git, &opened.base, &files)?;
    let modes: BTreeMap<String, String> = tree(git, &opened.base)
        .map_err(Error::Local)?
        .into_iter()
        .map(|entry| (entry.path, entry.mode))
        .collect();
    let scratch = Scratch::new(&opened.dir.join("work"))?;
    let outcome = deliver(&Job {
        git,
        base: &opened.base,
        run,
        plan: &plan,
        deliveries,
        uploaded: &files,
        real: &real,
        modes: &modes,
        records: &records,
        owners: &people,
        scratch: &scratch.0,
        apply: options.apply,
    });
    if let (Some(head), true) = (&outcome.head, options.apply) {
        git.run(&["update-ref", &format!("refs/heads/{branch}"), head, ""])
            .map_err(Error::Local)?;
    }
    let written = Run {
        id: run,
        apply: options.apply,
        base: &opened.base,
        branch: outcome.head.as_ref().map(|_| branch.as_str()),
        plan: &plan,
        deliveries,
        outcome: &outcome,
        redetected: opened.response.redetected.as_ref(),
        records: &records,
    }
    .render();
    let mut bytes = written.report;
    bytes.push(b'\n');
    write(root, &opened.dir.join("report.json"), &bytes)?;
    write(
        root,
        &opened.dir.join("SUMMARY.md"),
        written.summary.as_bytes(),
    )?;
    write(root, &opened.dir.join("PR.md"), written.pr.as_bytes())?;
    Ok(Outcome {
        document: bytes,
        complete: written.complete,
    })
}

/// `evidence`: runs the project's own checks on the base and on the head of
/// run `run`'s applied branch, and writes the evidence request
/// (`evidence-request.json`) for the server; the document naming it and
/// the response's path.
///
/// # Errors
///
/// As opening the run; [`Error::Local`] when the run was not applied, the
/// checks file is invalid, a worktree cannot be made, or a file cannot be
/// written.
pub fn evidence(root: &Path, run: &str) -> Result<Vec<u8>, Error> {
    evidence_with(&Git::new(root), run)
}

/// [`evidence`] with `git`.
fn evidence_with(git: &Git, run: &str) -> Result<Vec<u8>, Error> {
    let root = git.root();
    let opened = open(git, run)?;
    let applied: Value = read(&opened.dir, "report.json")?;
    let head = applied
        .get("head")
        .and_then(Value::as_str)
        .filter(|_| applied.get("applied").and_then(Value::as_bool) == Some(true))
        .ok_or_else(|| failed("the run was not applied: run `sloptopop transform --apply` first"))?
        .to_owned();
    let list = checks(root).map_err(Error::Local)?;
    let scratch = Scratch::new(&opened.dir.join("checks"))?;
    let about = Evidence {
        run,
        request: &opened.response.digests.request,
        base: &opened.base,
        head: &head,
    };
    let document = gather(git, about, &list, (&scratch.0, CHECK_LIMIT)).map_err(Error::Local)?;
    let name = opened
        .request
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("app");
    let request = Json::object([
        ("schemaVersion", Json::int(2_u32)),
        ("mode", Json::text("evidence")),
        ("base", Json::text(&opened.base)),
        ("name", Json::text(name)),
        ("evidence", document),
    ])
    .to_bytes();
    let rel = Path::new(TRANSFORM_DIR).join(run);
    let path = rel.join("evidence-request.json");
    write(root, &root.join(&path), &request)?;
    Ok(printed([
        ("schemaVersion", Json::int(1_u32)),
        ("run", Json::text(run)),
        ("base", Json::text(&opened.base)),
        ("request", Json::text(&path.to_string_lossy())),
        (
            "response",
            Json::text(&rel.join("evidence-response.json").to_string_lossy()),
        ),
        (
            "checks",
            Json::int(u64::try_from(list.len()).unwrap_or(u64::MAX)),
        ),
    ]))
}

#[cfg(test)]
mod tests;
