//! Unit tests for [`super`].

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::mask::diff;
use crate::records::confirm;
use crate::snapshot::tree;
use crate::tests::support::{Repo, TempDir, create, delivery, edit, fake_git, token};

/// Everything a delivery works from, for a repository.
struct World {
    repo: Repo,
    base: String,
    uploaded: BTreeMap<String, String>,
    real: Real,
    modes: BTreeMap<String, String>,
    scratch: TempDir,
}

/// A repository holding `files`, uploaded with `masked` (path → the
/// masked text) in place of the real text.
fn world(files: &[(&str, &str)], masked: &[(&str, &str)]) -> World {
    let borrowed: Vec<(&str, &[u8])> = files.iter().map(|(p, t)| (*p, t.as_bytes())).collect();
    let repo = Repo::with_files(&borrowed);
    let base = repo.git(&["rev-parse", "HEAD"]);
    let mut uploaded: BTreeMap<String, String> = files
        .iter()
        .map(|(p, t)| ((*p).to_owned(), (*t).to_owned()))
        .collect();
    let mut real = Real::new();
    for (path, text) in masked {
        let original = uploaded[*path].clone();
        let masks = diff(original.as_bytes(), text.as_bytes()).unwrap();
        real.insert((*path).to_owned(), (original.into_bytes(), masks));
        uploaded.insert((*path).to_owned(), (*text).to_owned());
    }
    let modes = tree(&Git::new(repo.path()), &base)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.path, entry.mode))
        .collect();
    World {
        repo,
        base,
        uploaded,
        real,
        modes,
        scratch: TempDir::new(),
    }
}

/// The deliveries of `values`.
fn wire(values: &[Value]) -> Vec<Delivery> {
    serde_json::from_value(Value::Array(values.to_vec())).unwrap()
}

/// Delivers `values` in `world` with `records`, committing if `apply`.
fn run(world: &World, values: &[Value], records: &[Value], apply: bool) -> Outcome {
    run_with(&Git::new(world.repo.path()), world, values, records, apply)
}

fn run_with(git: &Git, world: &World, values: &[Value], records: &[Value], apply: bool) -> Outcome {
    let owners = Owners {
        approvers: vec!["lead".to_owned()],
        ..Owners::default()
    };
    let deliveries = wire(values);
    deliver(&Job {
        git,
        base: &world.base,
        run: "0123456789abcdef",
        plan: "blake3:plan",
        deliveries: &deliveries,
        uploaded: &world.uploaded,
        real: &world.real,
        modes: &world.modes,
        records,
        owners: &owners,
        scratch: world.scratch.path(),
        apply,
    })
}

/// Each step's status and reason.
fn statuses(outcome: &Outcome) -> Vec<(Status, Option<String>)> {
    outcome
        .steps
        .iter()
        .map(|s| (s.status, s.reason.clone()))
        .collect()
}

#[test]
fn verified_steps_become_stacked_commits() {
    let world = world(&[("a.ts", "let a = 1;\n"), ("run.sh", "#!/bin/sh\n")], &[]);
    let one = delivery(
        1,
        &[edit("a.ts", "let a = 1;\n", "let a = 2;\n", &[(8, 9, "2")])],
        &[],
    );
    let two = delivery(
        2,
        &[
            edit("a.ts", "let a = 2;\n", "const a = 2;\n", &[(0, 3, "const")]),
            create(".githooks/pre-push", "#!/bin/sh\nexit 0\n", Some("100755")),
            create("docs/notes.md", "notes\n", None),
        ],
        &[],
    );
    let dry = run(&world, &[one.clone(), two.clone()], &[], false);
    assert_eq!(
        dry.steps
            .iter()
            .map(|s| (s.status, s.files.clone()))
            .collect::<Vec<_>>(),
        [
            (Status::Planned, vec!["a.ts".to_owned()]),
            (
                Status::Planned,
                vec![
                    ".githooks/pre-push".to_owned(),
                    "a.ts".to_owned(),
                    "docs/notes.md".to_owned()
                ]
            )
        ],
        "a dry run"
    );
    assert_eq!(dry.head, None, "nothing committed");
}

#[test]
fn delivered_steps_are_commits_on_the_base() {
    let world = world(&[("a.ts", "let a = 1;\n"), ("run.sh", "#!/bin/sh\n")], &[]);
    let one = delivery(
        1,
        &[edit("a.ts", "let a = 1;\n", "let a = 2;\n", &[(8, 9, "2")])],
        &[],
    );
    let two = delivery(
        2,
        &[
            edit("a.ts", "let a = 2;\n", "const a = 2;\n", &[(0, 3, "const")]),
            create(".githooks/pre-push", "#!/bin/sh\nexit 0\n", Some("100755")),
        ],
        &[],
    );
    let done = run(&world, &[one, two], &[], true);
    let head = done.head.clone().unwrap();
    let first = done.steps[0].commit.clone().unwrap();
    let git = |args: &[&str]| world.repo.git(args);
    assert_eq!(git(&["rev-parse", &format!("{head}^")]), first, "stacked");
    assert_eq!(
        done.steps[0].files,
        ["a.ts"],
        "an applied step names its files"
    );
    assert_eq!(
        git(&["rev-parse", &format!("{first}^")]),
        world.base,
        "on the base"
    );
    assert_eq!(
        git(&["show", &format!("{first}:a.ts")]),
        "let a = 2;",
        "step one"
    );
    assert_eq!(
        git(&["show", &format!("{head}:a.ts")]),
        "const a = 2;",
        "both steps"
    );
    assert!(
        git(&["ls-tree", &head, ".githooks/pre-push"]).starts_with("100755"),
        "executable"
    );
    assert!(
        git(&["ls-tree", &head, "run.sh"]).starts_with("100644"),
        "kept"
    );
    let message = git(&["log", "-1", "--format=%B", &head]);
    assert!(
        message.starts_with("sloptopop: step 2 (code, equivalent): Step 2"),
        "{message}"
    );
    assert!(
        message.ends_with(
            "Sloptopop-Plan: blake3:plan\nSloptopop-Step: 2-code\nSloptopop-Run: 0123456789abcdef"
        ),
        "{message}"
    );
    assert_eq!(
        git(&["log", "-1", "--format=%an <%ae>", &head]),
        "sloptopop <noreply@sloptopop.dev>",
        "author"
    );
    assert_eq!(
        git(&["log", "-1", "--format=%ct", &head]),
        git(&["log", "-1", "--format=%ct", &world.base]),
        "the base's date"
    );
    assert_eq!(git(&["rev-parse", "HEAD"]), world.base, "HEAD never moves");
    assert_eq!(
        git(&["status", "--porcelain"]),
        "",
        "the checkout is untouched"
    );
}

#[test]
fn secret_values_come_back_where_the_spans_leave_them() {
    let secret = format!("const k = '{}';\nlet a = 1;\n", token());
    let hidden = format!("const k = 'ghp_{}';\nlet a = 1;\n", "x".repeat(36));
    let world = world(&[("a.ts", &secret)], &[("a.ts", &hidden)]);
    let at = hidden.find("1;").unwrap();
    let after = hidden.replacen("1;", "2;", 1);
    let step = delivery(
        1,
        &[edit("a.ts", &hidden, &after, &[(at, at + 1, "2")])],
        &[],
    );
    let done = run(&world, &[step], &[], true);
    let head = done.head.unwrap();
    assert_eq!(
        world.repo.git(&["show", &format!("{head}:a.ts")]),
        secret.replacen("1;", "2;", 1).trim_end(),
        "the real token, the edit applied"
    );
    // An edit replacing the whole masked value removes it.
    let start = hidden.find("'ghp").unwrap();
    let end = start + 42;
    let gone = format!(
        "{}process.env.K{}",
        hidden.get(..start).unwrap(),
        hidden.get(end..).unwrap()
    );
    let replace = delivery(
        1,
        &[edit(
            "a.ts",
            &hidden,
            &gone,
            &[(start, end, "process.env.K")],
        )],
        &[],
    );
    let replaced = run(&world, &[replace], &[], true);
    assert_eq!(
        replaced.steps[0].status,
        Status::Applied,
        "{:?}",
        replaced.steps[0].reason
    );
    // An edit cutting into it is refused.
    let cut = format!(
        "{}{}",
        hidden.get(..start + 8).unwrap(),
        hidden.get(start + 9..).unwrap()
    );
    let cutting = delivery(
        1,
        &[edit("a.ts", &hidden, &cut, &[(start + 8, start + 9, "")])],
        &[],
    );
    let refused = run(&world, &[cutting], &[], false);
    assert!(
        refused.steps[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("cuts into the masked value"),
        "{:?}",
        refused.steps[0].reason
    );
}

#[test]
fn changes_that_are_not_what_the_server_verified_are_refused() {
    let world = world(&[("a.ts", "abc\n")], &[]);
    let wrong_before = json!({"path": "a.ts", "kind": "edit", "before": crate::tests::support::file_digest("zzz"),
                              "after": crate::tests::support::file_digest("xbc\n"), "edits": [{"start": 0, "end": 1, "text": "x"}]});
    let wrong_after = edit("a.ts", "abc\n", "nope", &[(0, 1, "x")]);
    let out_of_range = edit("a.ts", "abc\n", "x", &[(0, 99, "x")]);
    let created_twice = create("a.ts", "abc\n", None);
    let missing = edit("b.ts", "", "x", &[(0, 0, "x")]);
    let odd = json!({"path": "a.ts", "kind": "rename", "before": null, "after": "x", "edits": []});
    let expected = [
        (wrong_before, "`a.ts` is not the file the server verified"),
        (
            wrong_after,
            "`a.ts` would not have the bytes the server verified",
        ),
        (
            out_of_range,
            "`a.ts`: the spans do not fit the uploaded file",
        ),
        (
            created_twice,
            "`a.ts`: a `create` of a file that does exist",
        ),
        (missing, "`b.ts`: a `edit` of a file that does not exist"),
        (odd, "`a.ts`: a `rename` of a file that does exist"),
    ];
    for (change, why) in expected {
        let outcome = run(&world, &[delivery(1, &[change], &[])], &[], false);
        assert_eq!(
            statuses(&outcome),
            [(Status::Refused, Some(why.to_owned()))],
            "{why}"
        );
    }
    let overlapping = edit("a.ts", "abc\n", "x", &[(0, 2, "x"), (1, 3, "y")]);
    let outcome = run(&world, &[delivery(1, &[overlapping], &[])], &[], false);
    assert_eq!(
        outcome.steps[0].status,
        Status::Refused,
        "overlapping spans"
    );
    let boundary = world_with_unicode();
    let off = edit("u.ts", "é\n", "x", &[(1, 2, "x")]);
    let unicode = run(&boundary, &[delivery(1, &[off], &[])], &[], false);
    assert_eq!(
        unicode.steps[0].status,
        Status::Refused,
        "off a character boundary"
    );
}

fn world_with_unicode() -> World {
    world(&[("u.ts", "é\n")], &[])
}

#[test]
fn files_the_server_could_not_have_seen_are_never_written() {
    let mut world = world(&[("a.ts", "a\n"), ("vendor.txt", "v\n")], &[]);
    world.uploaded.remove("vendor.txt");
    world.modes.insert("link".to_owned(), "120000".to_owned());
    let cases = [
        (
            edit("vendor.txt", "v\n", "w\n", &[(0, 1, "w")]),
            "`vendor.txt` is tracked but was never uploaded",
        ),
        (
            edit("link", "", "x", &[(0, 0, "x")]),
            "`link` is a symbolic link or a submodule",
        ),
        (
            create("a.ts/b", "x", None),
            "`a.ts/b` is below `a.ts`, which is not a directory",
        ),
        (
            create("node_modules/x.js", "x", None),
            "`node_modules/x.js` is never uploaded (dependency, build or VCS directory)",
        ),
    ];
    for (change, why) in cases {
        let outcome = run(&world, &[delivery(1, &[change], &[])], &[], false);
        assert_eq!(
            outcome.steps[0].reason.as_deref(),
            Some(format!("the server could not have seen what it verified: {why}").as_str()),
            "{why}"
        );
    }
}

#[test]
fn confirmations_gate_declared_steps_and_stops_block_the_rest() {
    let world = world(&[("a.ts", "a\nz\n")], &[]);
    let gated = delivery(
        2,
        &[edit("a.ts", "a\nz\n", "b\nz\n", &[(0, 1, "b")])],
        &["att-1"],
    );
    let later = delivery(3, &[edit("a.ts", "b\nz\n", "b\nc\n", &[(2, 3, "c")])], &[]);
    let manual = json!({"ordinal": 1, "kind": "manual", "class": "declared", "status": "manual", "title": "Rotate",
                        "message": "m", "tasks": [{"text": "Rotate it"}]});
    let waiting = run(
        &world,
        &[manual.clone(), gated.clone(), later.clone()],
        &[],
        true,
    );
    assert_eq!(
        waiting.steps.iter().map(|s| s.status).collect::<Vec<_>>(),
        [Status::Manual, Status::Pending, Status::Blocked],
        "pending, then blocked"
    );
    assert!(
        waiting.steps[1]
            .reason
            .as_deref()
            .unwrap()
            .contains("--confirm att-1 --by"),
        "how to confirm"
    );
    assert_eq!(
        waiting.steps[2].reason.as_deref(),
        Some("it stacks on step 2, which was not delivered"),
        "why blocked"
    );
    let owners = Owners {
        approvers: vec!["lead".to_owned()],
        ..Owners::default()
    };
    let records = confirm(
        &wire(std::slice::from_ref(&gated)),
        "blake3:plan",
        &["att-1".to_owned()],
        ("lead", &owners),
        &world.base,
        "2026-10-21",
    )
    .unwrap();
    let shipped = run(&world, &[manual, gated, later], &records, true);
    assert_eq!(
        shipped.steps.iter().map(|s| s.status).collect::<Vec<_>>(),
        [Status::Manual, Status::Applied, Status::Applied],
        "confirmed"
    );
    let message = world.repo.git(&[
        "log",
        "-1",
        "--format=%B",
        shipped.steps[1].commit.as_deref().unwrap(),
    ]);
    assert!(message.contains("\n\nDeclared behaviour change, confirmed by lead: att-1 holds\n\nSloptopop-Plan: blake3:plan\n"), "{message}");
}

#[test]
fn the_servers_refusals_are_kept() {
    let world = world(&[("a.ts", "a\n")], &[]);
    let refused = json!({"ordinal": 1, "kind": "code", "class": "equivalent", "status": "refused", "title": "t",
                         "message": "m", "reason": "unit p1.a.1 was refused"});
    let blocked = json!({"ordinal": 2, "kind": "code", "class": "equivalent", "status": "blocked", "title": "t",
                         "message": "m", "blockedBy": 7});
    let odd = json!({"ordinal": 3, "kind": "code", "class": "equivalent", "status": "pondering", "title": "t", "message": "m"});
    for (value, why) in [
        (refused, "unit p1.a.1 was refused"),
        (blocked, "the server blocked it on step 7"),
        (odd, "the server did not verify it (pondering)"),
    ] {
        let outcome = run(&world, &[value], &[], false);
        assert_eq!(
            statuses(&outcome),
            [(Status::Refused, Some(why.to_owned()))],
            "{why}"
        );
    }
}

#[test]
fn a_failed_commit_refuses_the_step() {
    let world = world(&[("a.ts", "a\n")], &[]);
    let step = delivery(1, &[edit("a.ts", "a\n", "b\n", &[(0, 1, "b")])], &[]);
    for fail in [
        "commit-tree",
        "write-tree",
        "hash-object",
        "update-index",
        "read-tree",
        "show",
    ] {
        let git = fake_git(world.repo.path(), fail);
        let outcome = run_with(&git, &world, std::slice::from_ref(&step), &[], true);
        assert_eq!(outcome.steps[0].status, Status::Refused, "{fail}");
        assert!(
            outcome.steps[0].reason.as_deref().unwrap().contains(fail),
            "{fail}"
        );
        assert_eq!(outcome.head, None, "{fail}");
    }
    let plain = message_of(
        &world,
        json!({"ordinal": 4, "kind": "fix", "class": "equivalent", "status": "verified",
                                           "title": "t", "message": "sloptopop: create x\n\nfrom a template\n"}),
    );
    assert_eq!(
        plain,
        "sloptopop: create x\n\nfrom a template\n\nSloptopop-Step: 4-fix\nSloptopop-Run: 0123456789abcdef\n",
        "no plan trailer"
    );
}

/// The commit message of `value` in `world`.
fn message_of(world: &World, value: Value) -> String {
    let deliveries = wire(&[value]);
    let owners = Owners::default();
    let git = Git::new(world.repo.path());
    let job = Job {
        git: &git,
        base: &world.base,
        run: "0123456789abcdef",
        plan: "blake3:plan",
        deliveries: &deliveries,
        uploaded: &world.uploaded,
        real: &world.real,
        modes: &world.modes,
        records: &[],
        owners: &owners,
        scratch: world.scratch.path(),
        apply: false,
    };
    message(&job, &deliveries[0])
}

#[test]
fn statuses_have_names() {
    let names: Vec<&str> = [
        Status::Applied,
        Status::Planned,
        Status::Manual,
        Status::Pending,
        Status::Refused,
        Status::Blocked,
    ]
    .iter()
    .map(|s| s.as_str())
    .collect();
    assert_eq!(
        names,
        [
            "applied", "planned", "manual", "pending", "refused", "blocked"
        ],
        "names"
    );
    assert!(
        Status::Pending.undelivered()
            && Status::Refused.undelivered()
            && Status::Blocked.undelivered(),
        "undelivered"
    );
    assert!(
        !Status::Applied.undelivered()
            && !Status::Planned.undelivered()
            && !Status::Manual.undelivered(),
        "delivered"
    );
}
