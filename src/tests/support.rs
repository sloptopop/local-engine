//! Helpers shared by the unit tests: temporary directories, repositories,
//! the secret scanner's report and the server's answers.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A directory removed again when dropped.
#[derive(Debug)]
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sloptopop-local-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _stale = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Writes `contents` to `rel`, creating parent directories.
    pub(crate) fn write(&self, rel: &str, contents: impl AsRef<[u8]>) -> &Self {
        let path = self.0.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
        self
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

/// A git repository in a temporary directory, committed once.
#[derive(Debug)]
pub(crate) struct Repo {
    dir: TempDir,
}

impl Repo {
    /// A repository holding `README.md` (`name` as its text).
    pub(crate) fn new(name: &str) -> Self {
        Self::with_files(&[("README.md", name.as_bytes())])
    }

    /// A repository holding `files`, committed on `main`.
    pub(crate) fn with_files(files: &[(&str, &[u8])]) -> Self {
        let dir = TempDir::new();
        for (path, bytes) in files {
            dir.write(path, bytes);
        }
        let repo = Self { dir };
        repo.git(&["init", "-q", "-b", "main"]);
        repo.commit_all("base");
        repo
    }

    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Writes `contents` to `rel` in the checkout.
    pub(crate) fn write(&self, rel: &str, contents: impl AsRef<[u8]>) {
        self.dir.write(rel, contents);
    }

    /// Runs git in the repository; its stdout, trimmed.
    pub(crate) fn git(&self, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(self.path())
            .args(args)
            .env("GIT_AUTHOR_NAME", "test")
            .env("GIT_AUTHOR_EMAIL", "test@localhost")
            .env("GIT_COMMITTER_NAME", "test")
            .env("GIT_COMMITTER_EMAIL", "test@localhost")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// Commits everything; the new commit.
    pub(crate) fn commit_all(&self, message: &str) -> String {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.git(&["rev-parse", "HEAD"])
    }
}

/// The synthetic Next.js App Router project (a typed supabase-js-style
/// client) as files, with `.sloptopop/` ignored.
pub(crate) fn shop_files() -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, Vec<u8>)>) {
        let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &path, out);
            } else {
                out.push((path, fs::read(entry.path()).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/shop-router"),
        "",
        &mut out,
    );
    out
}

/// A token shaped like a GitHub token (made at run time, so no
/// token-shaped literal is ever committed).
pub(crate) fn token() -> String {
    format!("ghp_{}", "a1B2".repeat(9))
}

/// The shop project committed, with the Business Context naming `lead`
/// as an approver, and `edit` applied to its files first.
pub(crate) fn shop(edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>)) -> Repo {
    let mut files = shop_files();
    edit(&mut files);
    let borrowed: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let repo = Repo::with_files(&borrowed);
    repo.write(
        ".sloptopop/context.json",
        r#"{"owners": {"approvers": ["lead"], "operators": ["ops"], "data": ["owner"]}}"#,
    );
    repo
}

/// The shop project whose orders route starts with a comment holding a
/// token (masked before upload, put back after).
pub(crate) fn shop_with_token() -> Repo {
    shop(|files| {
        let orders = files
            .iter_mut()
            .find(|(path, _)| path == "app/orders/[id]/route.ts")
            .unwrap();
        let mut text = format!("// legacy {}\n", token()).into_bytes();
        text.extend_from_slice(&orders.1);
        orders.1 = text;
    })
}

/// The fake git of `tests/fake-git`, failing commands that name `fail`.
pub(crate) fn fake_git(root: &Path, fail: &str) -> crate::git::Git {
    crate::git::Git::with_program(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fake-git"),
        root,
    )
    .env("FAKE_GIT_FAIL", fail)
}

/// Writes the secret scanner's report of `repo` (gitleaks results at
/// (path, line, start column, end column)) and `collect`'s record of a
/// gitleaks run that exited 0.
pub(crate) fn scanned(repo: &Repo, results: &[(&str, u32, u32, u32)]) {
    let results: Vec<serde_json::Value> = results
        .iter()
        .map(|(path, line, start, end)| {
            serde_json::json!({"ruleId": "generic-api-key", "message": {"text": "REDACTED"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": path},
                "region": {"startLine": line, "endLine": line, "startColumn": start, "endColumn": end,
                           "snippet": {"text": "REDACTED"}}}}]})
        })
        .collect();
    let log = serde_json::json!({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks", "version": "8.30.1"}}, "results": results}]});
    repo.write(".sloptopop/reports/gitleaks.sarif", log.to_string());
    repo.write(
        ".sloptopop/reports/.collect.json",
        r#"{"schemaVersion": 2, "mode": "container", "tools": [{"name": "gitleaks", "status": "ran", "exitCode": 0, "output": ".sloptopop/reports/gitleaks.sarif", "image": {"reference": "lib/analyzers/gitleaks@sha256:aa", "version": "8.30.1-1"}}]}"#,
    );
}

/// The whole-file digest of `text`.
pub(crate) fn file_digest(text: &str) -> String {
    crate::digest::digest(crate::digest::FILE, text.as_bytes())
}

/// A verified delivery `ordinal` holding `changes` and requiring
/// `requires` (attestation ids, role approver).
pub(crate) fn delivery(
    ordinal: u32,
    changes: &[serde_json::Value],
    requires: &[&str],
) -> serde_json::Value {
    let requires: Vec<serde_json::Value> = requires
        .iter()
        .map(|id| serde_json::json!({"attestation": id, "text": format!("{id} holds"), "who": "approver", "evidence": "owner_statement"}))
        .collect();
    serde_json::json!({
        "ordinal": ordinal, "kind": "code", "class": "equivalent", "status": "verified",
        "title": format!("Step {ordinal}"),
        "message": format!("sloptopop: step {ordinal} (code, equivalent): Step {ordinal}\n\n- p{ordinal}: Step {ordinal} (C-1)\n\nSloptopop-Plan: blake3:plan\n"),
        "problems": [{"id": format!("p{ordinal}"), "goal": format!("Step {ordinal}"), "control": "C-1", "method": null}],
        "requires": requires, "tasks": [], "changes": changes
    })
}

/// An edit change of `path` from `before` (the masked file before the
/// step) to the file `base` with `spans` (base offsets: every span of the
/// earlier steps and this one) spliced in, carrying this step's `own`
/// spans.
pub(crate) fn edit(
    path: &str,
    before: &str,
    after: &str,
    own: &[(usize, usize, &str)],
) -> serde_json::Value {
    let edits: Vec<serde_json::Value> = own
        .iter()
        .map(|(start, end, text)| serde_json::json!({"start": start, "end": end, "text": text}))
        .collect();
    serde_json::json!({"path": path, "kind": "edit", "before": file_digest(before), "after": file_digest(after), "edits": edits})
}

/// A create change of `path` with `text`.
pub(crate) fn create(path: &str, text: &str, mode: Option<&str>) -> serde_json::Value {
    let mut change = serde_json::json!({"path": path, "kind": "create", "before": null, "after": file_digest(text),
                                        "edits": [{"start": 0, "end": 0, "text": text}]});
    if let Some(mode) = mode {
        change["mode"] = serde_json::json!(mode);
    }
    change
}

/// The server's response to the request in `request` (its bytes) with
/// `deliveries` and a Report that `passed`.
pub(crate) fn response(request: &[u8], deliveries: &[serde_json::Value], passed: bool) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_slice(request).unwrap();
    let digest = crate::digest::digest(
        crate::digest::REQUEST,
        &crate::canonical::Json::from_value(&value).to_bytes(),
    );
    serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2, "mode": "transform", "digests": {"request": digest},
        "report": {"schemaVersion": 2, "passed": passed, "findings": []},
        "redetected": {"rules": [{"rule": "errors.swallowed", "before": 2, "after": 0}]},
        "deliveries": deliveries
    }))
    .unwrap()
}
