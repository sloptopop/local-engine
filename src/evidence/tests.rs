//! Unit tests for [`super`].

use serde_json::json;

use super::*;
use crate::tests::support::{Repo, TempDir};

fn sh(script: &str) -> Check {
    check("test", &["sh", "-c", script], "test")
}

fn value(json: &Json) -> Value {
    serde_json::from_slice(&json.to_bytes()).unwrap()
}

#[test]
fn checks_come_from_the_list_or_the_project() {
    let dir = TempDir::new();
    assert!(checks(dir.path()).unwrap().is_empty(), "nothing declared");
    dir.write(
        "package.json",
        r#"{"scripts": {"build": "tsc", "test": "node --test", "lint": "x"}}"#,
    )
    .write("Cargo.toml", "[package]\n")
    .write("go.mod", "module a\n");
    let found: Vec<(String, Vec<String>, String)> = checks(dir.path())
        .unwrap()
        .into_iter()
        .map(|c| (c.kind, c.command, c.source))
        .collect();
    let words = |list: &[&str]| list.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        found,
        [
            (
                "build".to_owned(),
                words(&["npm", "run", "build"]),
                "package.json scripts.build".to_owned()
            ),
            (
                "test".to_owned(),
                words(&["npm", "test"]),
                "package.json scripts.test".to_owned()
            ),
            (
                "typecheck".to_owned(),
                words(&["cargo", "check", "--locked"]),
                "Cargo.toml".to_owned()
            ),
            (
                "test".to_owned(),
                words(&["cargo", "test", "--locked"]),
                "Cargo.toml".to_owned()
            ),
            (
                "typecheck".to_owned(),
                words(&["go", "vet", "./..."]),
                "go.mod".to_owned()
            ),
            (
                "build".to_owned(),
                words(&["go", "build", "./..."]),
                "go.mod".to_owned()
            ),
            (
                "test".to_owned(),
                words(&["go", "test", "./..."]),
                "go.mod".to_owned()
            ),
        ],
        "declared checks"
    );
    dir.write(
        "package.json",
        r#"{"scripts": {"typecheck": "tsc --noEmit"}}"#,
    );
    assert_eq!(
        checks(dir.path()).unwrap()[0].command,
        words(&["npm", "run", "typecheck"]),
        "typecheck"
    );
    dir.write(CHECKS, r#"{"checks": [{"kind": "test", "command": ["make", "test"]}, {"kind": "x", "command": []}]}"#);
    let listed = checks(dir.path()).unwrap();
    assert_eq!(listed.len(), 1, "empty commands dropped");
    assert_eq!(
        (listed[0].command.clone(), listed[0].source.as_str()),
        (words(&["make", "test"]), CHECKS),
        "listed"
    );
    dir.write(CHECKS, "[]");
    assert!(
        checks(dir.path())
            .unwrap_err()
            .contains("is not a list of checks"),
        "invalid"
    );
}

#[test]
fn a_check_gives_its_exit_code_duration_and_output_digests() {
    let dir = TempDir::new();
    let out = dir.path().join("out");
    let ran = value(&run(
        &sh("echo hello; echo oops >&2; exit 3"),
        dir.path(),
        &out,
        Duration::from_secs(30),
    ));
    assert_eq!(ran["exit"], 3, "exit code");
    assert_eq!(ran["stdout"]["bytes"], 6, "stdout length");
    assert_eq!(
        ran["stdout"]["digest"],
        digest(OUTPUT, b"hello\n"),
        "stdout digest"
    );
    assert_eq!(ran["stderr"]["bytes"], 5, "stderr length");
    assert!(ran["durationMs"].is_u64(), "duration");
    let slow = value(&run(
        &sh("sleep 5"),
        dir.path(),
        &out,
        Duration::from_millis(200),
    ));
    assert_eq!(slow["exit"], Value::Null, "over time: killed");
    let missing = value(&run(
        &check("test", &["no-such-program-x"], "t"),
        dir.path(),
        &out,
        Duration::from_secs(5),
    ));
    assert_eq!(missing["exit"], Value::Null, "cannot start");
    let blocked = dir.path().join("file");
    fs::write(&blocked, "").unwrap();
    let nowhere = value(&run(
        &sh("exit 0"),
        dir.path(),
        &blocked,
        Duration::from_secs(5),
    ));
    assert_eq!(
        (nowhere["exit"].clone(), nowhere["stdout"]["bytes"].clone()),
        (Value::Null, json!(0)),
        "no output directory"
    );
    let killed = value(&run(
        &sh("kill -9 $$"),
        dir.path(),
        &out,
        Duration::from_secs(5),
    ));
    assert_eq!(killed["exit"], Value::Null, "a signal");
}

#[test]
fn versions_are_asked_of_each_program() {
    assert!(version("git").unwrap().starts_with("git version"), "git");
    assert_eq!(version("no-such-program-x"), None, "missing");
    assert_eq!(version("false"), None, "failing");
    let go = version("go");
    assert!(
        go.as_deref()
            .is_none_or(|line| line.starts_with("go version")),
        "go answers `go version`: {go:?}"
    );
}

#[test]
fn evidence_runs_on_the_base_and_the_head() {
    let repo = Repo::with_files(&[("ok.sh", b"exit 0\n"), (".gitignore", b"node_modules/\n")]);
    let base = repo.git(&["rev-parse", "HEAD"]);
    repo.write("ok.sh", "exit 1\n");
    let head = repo.commit_all("break it");
    repo.git(&["checkout", "-q", &base]);
    fs::create_dir_all(repo.path().join("node_modules/x")).unwrap();
    let scratch = TempDir::new();
    let about = About {
        run: "0123456789abcdef",
        request: "blake3:r",
        base: &base,
        head: &head,
    };
    let git = Git::new(repo.path());
    let list = [
        check("test", &["sh", "ok.sh"], "t"),
        check("build", &["sh", "-c", "test -d node_modules/x"], "t"),
        check("lint", &["git", "--version"], "t"),
    ];
    let document = value(
        &evidence(
            &git,
            about,
            &list,
            (scratch.path(), Duration::from_secs(30)),
        )
        .unwrap(),
    );
    assert_eq!(document["schemaVersion"], 1, "schema");
    assert_eq!(
        (document["base"].as_str(), document["head"].as_str()),
        (Some(base.as_str()), Some(head.as_str())),
        "commits"
    );
    assert_eq!(
        (
            document["checks"][0]["base"]["exit"].clone(),
            document["checks"][0]["head"]["exit"].clone()
        ),
        (json!(0), json!(1)),
        "a regression"
    );
    assert_eq!(
        document["checks"][1]["head"]["exit"], 0,
        "dependencies linked"
    );
    let git_version = document["toolchains"][0]["version"].as_str();
    assert!(
        git_version.is_some_and(|line| line.starts_with("git version"))
            && document["toolchains"][1]["name"] == "sh",
        "one per program, sorted, with its version line"
    );
    assert_eq!(
        document["checks"][0]["command"],
        json!(["sh", "ok.sh"]),
        "command"
    );
    assert_eq!(
        repo.git(&["worktree", "list"]).lines().count(),
        1,
        "worktrees removed"
    );
    let bad = About {
        head: "0000000000000000000000000000000000000001",
        ..about
    };
    let failed = evidence(&git, bad, &list, (scratch.path(), Duration::from_secs(30)));
    assert!(failed.unwrap_err().contains("worktree"), "a missing commit");
    assert_eq!(
        repo.git(&["worktree", "list"]).lines().count(),
        1,
        "cleaned up after a failure"
    );
}

#[test]
fn go_is_asked_its_version_its_own_way() {
    assert_eq!(
        (version_flag("go"), version_flag("node")),
        ("version", "--version")
    );
    assert_eq!(MAX_OUTPUT, 16_777_216, "16 MiB of an output is digested");
}

#[test]
fn only_dependency_directories_that_exist_are_linked() {
    let repo = Repo::with_files(&[("a.txt", b"a\n"), (".gitignore", b"node_modules/\n.venv\n")]);
    fs::create_dir_all(repo.path().join("node_modules")).unwrap();
    fs::write(repo.path().join(".venv"), "a file").unwrap();
    let head = repo.git(&["rev-parse", "HEAD"]);
    let scratch = TempDir::new();
    let dir = scratch.path().join("tree");
    worktree(&Git::new(repo.path()), &head, &dir).unwrap();
    let linked = |name: &str| fs::symlink_metadata(dir.join(name)).is_ok();
    assert_eq!(
        (linked("node_modules"), linked(".venv"), linked("venv")),
        (true, false, false),
        "a directory, not a file or nothing"
    );
}
