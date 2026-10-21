//! Unit tests for [`super`].

use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;
use crate::tests::support::{Repo, scanned};

/// Sets the modification time of `path` to `time`.
fn touch(path: &Path, time: SystemTime) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

fn paths(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|p| (*p).to_owned()).collect()
}

#[test]
fn a_usable_report_gives_its_results_by_file() {
    let repo = Repo::with_files(&[
        (".gitignore", b".sloptopop/\n"),
        ("a.ts", b"k = 'x'\n"),
        ("b.ts", b"\n"),
    ]);
    scanned(
        &repo,
        &[("a.ts", 1, 5, 7), ("b.ts", 1, 1, 1), ("gone.ts", 3, 1, 2)],
    );
    let found = found(repo.path(), &paths(&["a.ts", "b.ts"]), UNIX_EPOCH).unwrap();
    assert_eq!(
        found.keys().collect::<Vec<_>>(),
        ["a.ts", "b.ts"],
        "files of the snapshot only"
    );
    assert_eq!(found["a.ts"][0].span.start, 5, "columns");
}

#[test]
fn without_a_usable_report_nothing_is_uploaded() {
    let repo = Repo::with_files(&[(".gitignore", b".sloptopop/\n"), ("a.ts", b"x\n")]);
    let all = paths(&["a.ts"]);
    let error = found(repo.path(), &all, UNIX_EPOCH).unwrap_err();
    assert!(
        error.contains("records no gitleaks run") && error.contains("sloptopop collect"),
        "{error}"
    );
    repo.write(
        RECORD,
        r#"{"tools": [{"name": "gitleaks", "status": "ran", "exitCode": 1}]}"#,
    );
    assert!(
        found(repo.path(), &all, UNIX_EPOCH)
            .unwrap_err()
            .contains("records no gitleaks run"),
        "exit 1"
    );
    repo.write(RECORD, r#"{"tools": [{"name": "gitleaks", "status": "failed"}, {"name": "ruff", "status": "ran"}]}"#);
    assert!(found(repo.path(), &all, UNIX_EPOCH).is_err(), "failed");
    repo.write(
        RECORD,
        r#"{"tools": [{"name": "gitleaks", "status": "ran"}]}"#,
    );
    assert!(
        found(repo.path(), &all, UNIX_EPOCH)
            .unwrap_err()
            .starts_with("cannot read"),
        "no report"
    );
    repo.write(
        REPORT,
        r#"{"runs": [{"tool": {"driver": {"name": "semgrep"}}}]}"#,
    );
    let other = found(repo.path(), &all, UNIX_EPOCH).unwrap_err();
    assert!(
        other.contains("is not usable (a run of `semgrep`"),
        "{other}"
    );
    scanned(&repo, &[]);
    assert!(
        found(repo.path(), &all, UNIX_EPOCH).unwrap().is_empty(),
        "a clean report"
    );
    let later = SystemTime::now() + Duration::from_secs(3600);
    assert!(
        found(repo.path(), &all, later)
            .unwrap_err()
            .contains("is older than"),
        "older than the commit"
    );
    let made = fs::metadata(repo.path().join(REPORT))
        .unwrap()
        .modified()
        .unwrap();
    touch(&repo.path().join("a.ts"), made);
    assert!(
        found(repo.path(), &all, made).is_ok(),
        "a file and a commit as old as the report"
    );
    repo.write("a.ts", "y\n");
    // Changed after the scan: an mtime tick can hold both writes.
    touch(&repo.path().join("a.ts"), later);
    assert!(
        found(repo.path(), &all, UNIX_EPOCH)
            .unwrap_err()
            .contains("is older than"),
        "older than a file"
    );
    assert!(
        found(repo.path(), &paths(&["missing.ts"]), UNIX_EPOCH).is_ok(),
        "a file that is not there"
    );
}

#[test]
fn masks_cover_every_line_and_span_of_a_result() {
    let text = "a = 1\nkey = \"s3cr3tvalue\"\nshort: ab1\n";
    let results = [
        Found {
            path: "a".to_owned(),
            line: 2,
            end: 2,
            span: crate::mask::Span {
                line: 2,
                start: 7,
                end: 19,
            },
        },
        Found {
            path: "a".to_owned(),
            line: 3,
            end: 3,
            span: crate::mask::Span {
                line: 3,
                start: 8,
                end: 10,
            },
        },
    ];
    assert_eq!(
        crate::mask::apply(text, &masks_of(text, &results)),
        "a = 1\nkey = \"xxxxxxxxxxx\"\nshort: xxx\n",
        "every reported value"
    );
}
