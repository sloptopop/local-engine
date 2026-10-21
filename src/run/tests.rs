//! Unit tests for [`super`].

use std::fs;

use serde_json::{Value, json};

use super::*;
use crate::tests::support::{
    Repo, delivery, edit, fake_git, response, scanned, shop, shop_with_token, token,
};

/// The request document of `repo` (`mode`).
fn requested(repo: &Repo, mode: &str) -> Value {
    serde_json::from_slice(&request(repo.path(), mode).unwrap()).unwrap()
}

/// Writes the server's answer with `deliveries` for run `run` of `repo`.
fn answer(repo: &Repo, run: &str, deliveries: &[Value], passed: bool) {
    let dir = repo.path().join(TRANSFORM_DIR).join(run);
    let request = fs::read(dir.join("request.json")).unwrap();
    fs::write(
        dir.join("response.json"),
        response(&request, deliveries, passed),
    )
    .unwrap();
}

/// The shop with its orders route reported by the scanner on line 1.
fn scanned_shop() -> Repo {
    let repo = shop_with_token();
    scanned(&repo, &[("app/orders/[id]/route.ts", 1, 11, 50)]);
    repo
}

#[test]
fn a_request_holds_the_masked_snapshot() {
    let repo = scanned_shop();
    let document = requested(&repo, "transform");
    let run = document["run"].as_str().unwrap();
    assert_eq!(
        document["base"],
        repo.git(&["rev-parse", "HEAD"]),
        "the base"
    );
    assert_eq!(document["manifest"]["masked"]["values"], 1, "one value");
    let path = repo.path().join(document["request"].as_str().unwrap());
    let request: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let text = serde_json::to_string(&request).unwrap();
    assert!(!text.contains(&token()), "the token never goes");
    assert_eq!(request["mode"], "transform", "mode");
    assert_eq!(
        request["context"]["owners"]["approvers"],
        json!(["lead"]),
        "context"
    );
    assert_eq!(
        request["reports"][0]["name"], "gitleaks.sarif",
        "the scanner's report goes too"
    );
    assert!(!text.contains("snippet"), "without snippets");
    assert_eq!(
        fs::read_to_string(repo.path().join(TRANSFORM_DIR).join(".gitignore")).unwrap(),
        "*\n",
        "ignored"
    );
    assert!(
        document["response"]
            .as_str()
            .unwrap()
            .ends_with(&format!("{run}/response.json")),
        "the response's path"
    );
    assert_eq!(requested(&repo, "transform")["run"], run, "deterministic");
    assert_ne!(
        requested(&repo, "check")["run"],
        run,
        "the mode is part of the request"
    );
}

#[test]
fn a_request_needs_a_clean_top_level_and_a_scanner_report() {
    let repo = shop(|_| {});
    let refused = |root: &Path| request(root, "check").unwrap_err().to_string();
    assert!(
        refused(repo.path()).contains("records no gitleaks run"),
        "no scanner report"
    );
    scanned(&repo, &[]);
    assert!(
        refused(&repo.path().join("app")).contains("run it at the top"),
        "a subdirectory"
    );
    repo.write("new.ts", "x");
    assert!(
        refused(repo.path()).contains("uncommitted or untracked"),
        "dirty"
    );
    fs::remove_file(repo.path().join("new.ts")).unwrap();
    repo.write(CONTEXT, "[]");
    assert!(
        refused(repo.path()).contains("not a JSON object"),
        "context"
    );
    repo.write(CONTEXT, "{");
    assert!(refused(repo.path()).contains(CONTEXT), "not JSON");
    fs::remove_file(repo.path().join(CONTEXT)).unwrap();
    fs::create_dir_all(repo.path().join(CONTEXT).join("x")).unwrap();
    assert!(refused(repo.path()).contains(CONTEXT), "not a file");
    let bare = Repo::with_files(&[(".gitignore", b".sloptopop/\n"), ("a.ts", b"x\n")]);
    scanned(&bare, &[]);
    assert!(request(bare.path(), "fix").is_ok(), "no context");
    let empty = TempDir::new();
    assert!(refused(empty.path()).contains("git"), "not a repository");
}

use crate::tests::support::TempDir;

#[test]
fn the_report_is_the_servers() {
    let repo = scanned_shop();
    let run = requested(&repo, "check")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    answer(&repo, &run, &[], true);
    let shown = report(repo.path(), &run).unwrap();
    let value: Value = serde_json::from_slice(&shown.document).unwrap();
    assert_eq!(
        (value["schemaVersion"].clone(), shown.complete),
        (json!(2), true),
        "passed"
    );
    assert_eq!(shown.document.last(), Some(&b'\n'), "a newline");
    answer(&repo, &run, &[], false);
    assert!(!report(repo.path(), &run).unwrap().complete, "failed");
    let dir = repo.path().join(TRANSFORM_DIR).join(&run);
    fs::write(
        dir.join("response.json"),
        r#"{"schemaVersion": 2, "digests": {"request": "blake3:other"}}"#,
    )
    .unwrap();
    assert!(
        report(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("does not answer"),
        "another request"
    );
    let request = fs::read(dir.join("request.json")).unwrap();
    let mut no_report: Value = serde_json::from_slice(&response(&request, &[], true)).unwrap();
    no_report.as_object_mut().unwrap().remove("report");
    fs::write(dir.join("response.json"), no_report.to_string()).unwrap();
    assert!(
        report(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("no Report"),
        "none"
    );
    let mut old: Value = serde_json::from_slice(&response(&request, &[], true)).unwrap();
    old["schemaVersion"] = json!(1);
    fs::write(dir.join("response.json"), old.to_string()).unwrap();
    assert!(report(repo.path(), &run).is_err(), "an old response");
    fs::remove_file(dir.join("response.json")).unwrap();
    assert!(
        report(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("cannot read"),
        "missing"
    );
    assert!(
        report(repo.path(), "nope")
            .unwrap_err()
            .to_string()
            .contains("not a run id"),
        "a bad id"
    );
    repo.write("x.ts", "x");
    repo.commit_all("moved");
    answer(&repo, &run, &[], true);
    assert!(
        report(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("HEAD moved"),
        "moved"
    );
}

/// The orders route of the shop with its token masked, and a step that
/// changes its last line.
fn orders_step(repo: &Repo, run: &str, requires: &[&str]) -> Value {
    let dir = repo.path().join(TRANSFORM_DIR).join(run);
    let request: Value =
        serde_json::from_slice(&fs::read(dir.join("request.json")).unwrap()).unwrap();
    let text = request["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "app/orders/[id]/route.ts")
        .unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned();
    let at = text.rfind("404").unwrap();
    let after = format!(
        "{}410{}",
        text.get(..at).unwrap(),
        text.get(at + 3..).unwrap()
    );
    delivery(
        2,
        &[edit(
            "app/orders/[id]/route.ts",
            &text,
            &after,
            &[(at, at + 3, "410")],
        )],
        requires,
    )
}

#[test]
fn applying_commits_on_a_new_branch_and_restores_the_token() {
    let repo = scanned_shop();
    let run = requested(&repo, "transform")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    let step = orders_step(&repo, &run, &[]);
    answer(&repo, &run, &[step], true);
    let dry = apply(repo.path(), &run, &Options::default()).unwrap();
    let report: Value = serde_json::from_slice(&dry.document).unwrap();
    assert_eq!(
        (report["steps"][0]["status"].as_str(), dry.complete),
        (Some("planned"), true),
        "a dry run"
    );
    let options = Options {
        apply: true,
        ..Options::default()
    };
    let done = apply(repo.path(), &run, &options).unwrap();
    let applied: Value = serde_json::from_slice(&done.document).unwrap();
    let branch = format!("sloptopop/transform-{run}");
    assert_eq!(applied["branch"], branch.as_str(), "the branch");
    let shown = repo.git(&["show", &format!("{branch}:app/orders/[id]/route.ts")]);
    assert!(
        shown.contains(&token()) && shown.contains("410"),
        "the real token and the change"
    );
    let dir = repo.path().join(TRANSFORM_DIR).join(&run);
    for file in ["report.json", "SUMMARY.md", "PR.md"] {
        assert!(dir.join(file).is_file(), "{file}");
    }
    assert!(
        apply(repo.path(), &run, &options)
            .unwrap_err()
            .to_string()
            .contains("exists"),
        "the branch exists"
    );
    let bad = Options {
        apply: true,
        branch: Some("bad..name".to_owned()),
        ..Options::default()
    };
    assert!(
        apply(repo.path(), &run, &bad)
            .unwrap_err()
            .to_string()
            .contains("not a valid branch name"),
        "invalid"
    );
}

#[test]
fn confirmations_are_recorded_and_checked() {
    let repo = scanned_shop();
    let run = requested(&repo, "transform")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    answer(&repo, &run, &[orders_step(&repo, &run, &["att-1"])], true);
    let waiting = apply(repo.path(), &run, &Options::default()).unwrap();
    assert!(!waiting.complete, "pending");
    let wrong = Options {
        confirm: vec!["att-1".to_owned()],
        by: Some("stranger".to_owned()),
        ..Options::default()
    };
    assert!(
        apply(repo.path(), &run, &wrong)
            .unwrap_err()
            .to_string()
            .contains("may not confirm"),
        "not an owner"
    );
    let confirmed = Options {
        apply: true,
        confirm: vec!["att-1".to_owned()],
        by: Some("lead".to_owned()),
        ..Options::default()
    };
    let done = apply(repo.path(), &run, &confirmed).unwrap();
    assert!(done.complete, "delivered");
    assert!(repo.path().join(crate::records::FILE).is_file(), "recorded");
    fs::write(repo.path().join(crate::records::FILE), "{").unwrap();
    assert!(
        apply(repo.path(), &run, &Options::default()).is_err(),
        "unreadable records"
    );
}

#[test]
fn an_upload_that_is_not_the_base_masked_is_refused() {
    let repo = scanned_shop();
    let run = requested(&repo, "transform")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    let dir = repo.path().join(TRANSFORM_DIR).join(&run);
    let mut request: Value =
        serde_json::from_slice(&fs::read(dir.join("request.json")).unwrap()).unwrap();
    request["files"][0]["text"] = json!("tampered");
    fs::write(dir.join("request.json"), request.to_string()).unwrap();
    answer(&repo, &run, &[], true);
    assert!(
        apply(repo.path(), &run, &Options::default())
            .unwrap_err()
            .to_string()
            .contains("is not the base's file masked"),
        "tampered"
    );
    request["files"][0]["path"] = json!("no/such/file.ts");
    fs::write(dir.join("request.json"), request.to_string()).unwrap();
    answer(&repo, &run, &[], true);
    assert!(
        apply(repo.path(), &run, &Options::default())
            .unwrap_err()
            .to_string()
            .contains("git cat-file"),
        "not in the base"
    );
}

#[test]
fn evidence_follows_an_applied_run() {
    let repo = scanned_shop();
    let run = requested(&repo, "transform")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    answer(&repo, &run, &[orders_step(&repo, &run, &[])], true);
    assert!(
        evidence(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("cannot read"),
        "no report yet"
    );
    apply(repo.path(), &run, &Options::default()).unwrap();
    assert!(
        evidence(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("was not applied"),
        "a dry run"
    );
    let options = Options {
        apply: true,
        ..Options::default()
    };
    apply(repo.path(), &run, &options).unwrap();
    repo.write(
        crate::evidence::CHECKS,
        r#"{"checks": [{"kind": "test", "command": ["sh", "-c", "exit 0"]}]}"#,
    );
    let document: Value = serde_json::from_slice(&evidence(repo.path(), &run).unwrap()).unwrap();
    assert_eq!(document["checks"], 1, "one check");
    let path = repo.path().join(document["request"].as_str().unwrap());
    let request: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_eq!(
        (request["schemaVersion"].clone(), request["mode"].clone()),
        (json!(2), json!("evidence")),
        "an evidence request"
    );
    assert_eq!(
        request["evidence"]["checks"][0]["head"]["exit"], 0,
        "the result"
    );
    assert!(
        document["response"]
            .as_str()
            .unwrap()
            .ends_with("evidence-response.json"),
        "where the answer goes"
    );
    repo.write(crate::evidence::CHECKS, "[]");
    assert!(
        evidence(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("not a list of checks"),
        "a bad list"
    );
}

#[test]
fn git_failures_stop_every_command() {
    let repo = scanned_shop();
    for fail in ["status", "ls-tree", "cat-file"] {
        let error = request_with(&fake_git(repo.path(), fail), "transform").unwrap_err();
        assert!(error.to_string().contains(fail), "request: {fail}: {error}");
    }
    let run = requested(&repo, "transform")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    answer(&repo, &run, &[orders_step(&repo, &run, &[])], true);
    let options = Options {
        apply: true,
        ..Options::default()
    };
    for fail in ["cat-file", "ls-tree", "update-ref"] {
        let error = apply_with(&fake_git(repo.path(), fail), &run, &options).unwrap_err();
        assert!(error.to_string().contains(fail), "apply: {fail}: {error}");
    }
    apply(repo.path(), &run, &options).unwrap();
    let error = evidence_with(&fake_git(repo.path(), "worktree"), &run).unwrap_err();
    assert!(error.to_string().contains("worktree"), "evidence: {error}");
}

#[test]
fn files_that_cannot_be_written_stop_the_command() {
    let repo = scanned_shop();
    fs::create_dir_all(repo.path().join(".sloptopop")).unwrap();
    fs::write(repo.path().join(TRANSFORM_DIR), "a file").unwrap();
    assert!(
        request(repo.path(), "check")
            .unwrap_err()
            .to_string()
            .contains("cannot write"),
        "request.json"
    );
    fs::remove_file(repo.path().join(TRANSFORM_DIR)).unwrap();
    let run = requested(&repo, "transform")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    answer(&repo, &run, &[orders_step(&repo, &run, &[])], true);
    let dir = repo.path().join(TRANSFORM_DIR).join(&run);
    for name in ["report.json", "SUMMARY.md", "PR.md"] {
        fs::create_dir_all(dir.join(name)).unwrap();
        let error = apply(repo.path(), &run, &Options::default()).unwrap_err();
        assert!(
            error.to_string().contains("cannot write"),
            "{name}: {error}"
        );
        fs::remove_dir_all(dir.join(name)).unwrap();
    }
    fs::write(dir.join("work"), "a file").unwrap();
    assert!(
        apply(repo.path(), &run, &Options::default())
            .unwrap_err()
            .to_string()
            .contains("scratch"),
        "work"
    );
    fs::remove_file(dir.join("work")).unwrap();
    let options = Options {
        apply: true,
        ..Options::default()
    };
    apply(repo.path(), &run, &options).unwrap();
    fs::write(dir.join("checks"), "a file").unwrap();
    assert!(
        evidence(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("scratch"),
        "checks"
    );
    fs::remove_file(dir.join("checks")).unwrap();
    fs::create_dir_all(dir.join("evidence-request.json")).unwrap();
    repo.write(crate::evidence::CHECKS, r#"{"checks": []}"#);
    assert!(
        evidence(repo.path(), &run)
            .unwrap_err()
            .to_string()
            .contains("cannot write"),
        "evidence-request.json"
    );
}

#[test]
fn records_that_cannot_be_saved_stop_a_confirmation() {
    use std::os::unix::fs::PermissionsExt;
    let repo = scanned_shop();
    let run = requested(&repo, "transform")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    answer(&repo, &run, &[orders_step(&repo, &run, &["att-1"])], true);
    let file = repo.path().join(crate::records::FILE);
    fs::write(&file, "[]").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).unwrap();
    let confirming = Options {
        confirm: vec!["att-1".to_owned()],
        by: Some("lead".to_owned()),
        ..Options::default()
    };
    let error = apply(repo.path(), &run, &confirming).unwrap_err();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(error.to_string().contains("cannot write"), "{error}");
}

#[test]
fn a_run_whose_files_are_broken_is_refused() {
    let repo = scanned_shop();
    let run = requested(&repo, "check")["run"]
        .as_str()
        .unwrap()
        .to_owned();
    let dir = repo.path().join(TRANSFORM_DIR).join(&run);
    let refused = || report(repo.path(), &run).unwrap_err().to_string();
    fs::write(dir.join("response.json"), "{").unwrap();
    assert!(
        refused().contains("response.json"),
        "a response that is not JSON"
    );
    fs::remove_file(dir.join("request.json")).unwrap();
    assert!(refused().contains("request.json"), "no request");
    for (name, failed) in [
        (
            "apply",
            apply(repo.path(), "nope", &Options::default()).err(),
        ),
        ("evidence", evidence(repo.path(), "nope").err()),
        ("not hex", report(repo.path(), "zzzzzzzzzzzzzzzz").err()),
        ("short", report(repo.path(), "0123456789abcde").err()),
    ] {
        assert!(
            failed.is_some_and(|error| error.to_string().contains("not a run id")),
            "{name}: a bad id"
        );
    }
}

#[test]
fn a_report_made_before_the_commit_is_refused() {
    let repo = scanned_shop();
    let set = |rel: &str, seconds: u64| {
        fs::File::options()
            .write(true)
            .open(repo.path().join(rel))
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
            .unwrap();
    };
    for file in repo.git(&["ls-files"]).lines() {
        set(file, 500);
    }
    set(".sloptopop/reports/gitleaks.sarif", 1000);
    let refused = request(repo.path(), "check").unwrap_err().to_string();
    assert!(refused.contains("older than the commit"), "{refused}");
}
