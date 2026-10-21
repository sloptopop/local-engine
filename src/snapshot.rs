//! The snapshot a transform uploads: the files of the base commit (from
//! git's object store, so exactly the committed bytes), minus everything
//! that must not or need not leave the machine, each exclusion with its
//! reason for the upload manifest.
//!
//! Standards: SCF PRI-05 (data minimisation: only what the backend
//! needs), AST-04 (the components inventoried from the repository); OWASP
//! ASVS 5.0 V13.3.1 (environment files never leave the machine).

use std::collections::BTreeMap;

use crate::git::Git;

/// Directories never uploaded (business-logic and the backend skip them).
const SKIPPED: [&str; 9] = [
    ".git",
    ".next",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "out",
    "target",
    "vendor",
];

/// The largest file uploaded, in bytes.
const MAX_BYTES: u64 = 1024 * 1024;

/// One entry of the base commit's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Its mode (`100644`, `100755`, `120000`, `160000`).
    pub(crate) mode: String,
    /// `blob` or `commit` (a submodule).
    pub(crate) kind: String,
    /// Its object id.
    pub(crate) oid: String,
    /// Its size in bytes (none for a submodule).
    pub(crate) size: Option<u64>,
    /// Its path.
    pub(crate) path: String,
}

/// What is uploaded and what is not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Snapshot {
    /// The uploaded files' text, by path.
    pub(crate) files: BTreeMap<String, String>,
    /// Every path left out, with why.
    pub(crate) excluded: Vec<(String, &'static str)>,
}

/// The entries of `commit`'s tree.
///
/// # Errors
///
/// When git fails.
pub(crate) fn tree(git: &Git, commit: &str) -> Result<Vec<Entry>, String> {
    git.run(&["ls-tree", "-r", "-z", "-l", "--full-tree", commit])
        .map(|bytes| parse_tree(&bytes))
}

/// `ls-tree -r -z -l` output as entries.
fn parse_tree(bytes: &[u8]) -> Vec<Entry> {
    String::from_utf8_lossy(bytes)
        .split('\0')
        .filter_map(|record| {
            let (meta, path) = record.split_once('\t')?;
            let mut fields = meta.split_whitespace();
            Some(Entry {
                mode: fields.next()?.to_owned(),
                kind: fields.next()?.to_owned(),
                oid: fields.next()?.to_owned(),
                size: fields.next().and_then(|size| size.parse().ok()),
                path: path.to_owned(),
            })
        })
        .collect()
}

/// Why `entry` is not uploaded, if it is not (before reading it).
fn excluded(entry: &Entry) -> Option<&'static str> {
    let name = entry.path.rsplit('/').next().unwrap_or_default();
    if entry.kind != "blob" {
        Some("submodule")
    } else if entry.mode == "120000" {
        Some("symbolic link")
    } else if entry
        .path
        .split('/')
        .any(|segment| SKIPPED.contains(&segment))
    {
        Some("dependency, build or VCS directory")
    } else if entry.path.starts_with(".sloptopop/") {
        Some("sloptopop's own files")
    } else if environment(name) {
        Some("environment file: its values never leave this machine")
    } else if entry.size.unwrap_or(u64::MAX) > MAX_BYTES {
        Some("larger than 1 MiB")
    } else {
        None
    }
}

/// Why a path the base does not hold would be left out of a snapshot,
/// if it would be (L4 root cause 6: delivery never writes where the
/// backend could not see): under a dependency, build or VCS directory or
/// `.sloptopop/`, or a real environment file.
pub(crate) fn left_out(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or_default();
    if path.split('/').any(|segment| SKIPPED.contains(&segment)) {
        Some("dependency, build or VCS directory")
    } else if path.starts_with(".sloptopop/") {
        Some("sloptopop's own files")
    } else if environment(name) {
        Some("environment file: its values never leave this machine")
    } else {
        None
    }
}

/// Whether `name` is a real environment file (`.env`, `.env.local`, …;
/// not `.env.example`, `.env.sample` or `.env.template`).
fn environment(name: &str) -> bool {
    name == ".env"
        || (name.starts_with(".env.")
            && ![".example", ".sample", ".template"]
                .iter()
                .any(|suffix| name.ends_with(suffix)))
}

/// The snapshot of `entries`, read through `git`.
///
/// # Errors
///
/// When git fails.
pub(crate) fn snapshot(git: &Git, entries: &[Entry]) -> Result<Snapshot, String> {
    let mut out = Snapshot::default();
    let mut wanted = Vec::new();
    for entry in entries {
        match excluded(entry) {
            Some(reason) => out.excluded.push((entry.path.clone(), reason)),
            None => wanted.push(entry),
        }
    }
    let ids: String = wanted.iter().fold(String::new(), |mut ids, entry| {
        ids.push_str(&entry.oid);
        ids.push('\n');
        ids
    });
    let objects = git.input(&["cat-file", "--batch"], ids.as_bytes())?;
    let read = parse_batch(&objects);
    for entry in wanted {
        match read.get(&entry.oid).cloned().map(String::from_utf8) {
            Some(Ok(text)) => {
                out.files.insert(entry.path.clone(), text);
            }
            Some(Err(_)) => out.excluded.push((entry.path.clone(), "not UTF-8 text")),
            None => out.excluded.push((entry.path.clone(), "unreadable")),
        }
    }
    out.excluded.sort();
    Ok(out)
}

/// `cat-file --batch` output as object id → bytes; reading stops at
/// anything malformed.
fn parse_batch(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut rest = bytes;
    while let Some((oid, content, after)) = object(rest) {
        out.insert(oid, content);
        rest = after;
    }
    out
}

/// The first object of `bytes` (`<oid> <type> <size>\n<content>\n`) and
/// what follows it.
fn object(bytes: &[u8]) -> Option<(String, Vec<u8>, &[u8])> {
    let end = bytes.iter().position(|byte| *byte == b'\n')?;
    let header = String::from_utf8_lossy(bytes.get(..end).unwrap_or_default()).into_owned();
    let (oid, rest) = header.split_once(' ')?;
    let size: usize = rest.split(' ').nth(1)?.parse().ok()?;
    let content = bytes.get(end + 1..end + 1 + size)?.to_vec();
    let after = bytes.get(end + 2 + size..)?;
    Some((oid.to_owned(), content, after))
}

#[cfg(test)]
mod tests;
