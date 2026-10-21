//! Unit tests for [`super`].

use std::os::unix::fs::PermissionsExt;

use serde_json::json;

use super::*;
use crate::tests::support::TempDir;

#[test]
fn reports_are_read_without_snippets() {
    let dir = TempDir::new();
    let sarif = json!({"runs": [{"results": [{"locations": [{"physicalLocation": {"region":
        {"startLine": 1, "snippet": {"text": "const k = 'value'"}, "contextRegion": {"startLine": 1}}}}]}]}]});
    dir.write(".sloptopop/reports/semgrep.sarif", sarif.to_string())
        .write(".sloptopop/reports/unit.lcov", "SF:a\nend_of_record\n")
        .write(".sloptopop/reports/py.lcov.info", "TN:\n")
        .write(".sloptopop/reports/bad.sarif", "not json")
        .write(".sloptopop/reports/bin.sarif", [0xff_u8])
        .write(".sloptopop/reports/notes.md", "#")
        .write(".sloptopop/reports/server.ruff.sarif", "{}")
        .write(
            ".sloptopop/reports/.collect.json",
            r#"{"schemaVersion": 2}"#,
        )
        .write(".sloptopop/reports/sub/x.sarif", "{}");
    let read = read(dir.path());
    assert_eq!(
        read.sent
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        ["py.lcov.info", "semgrep.sarif", "unit.lcov"],
        "report formats, sorted"
    );
    assert!(
        !read.sent[1].1.contains("snippet") && !read.sent[1].1.contains("contextRegion"),
        "{}",
        read.sent[1].1
    );
    assert!(read.sent[1].1.contains("startLine"), "the rest stays");
    assert_eq!(read.sent[2].1, "SF:a\nend_of_record\n", "LCOV as is");
    assert_eq!(
        read.left,
        [
            ("bad.sarif".to_owned(), "a SARIF report that is not JSON"),
            ("bin.sarif".to_owned(), "not UTF-8 text")
        ],
        "left out, with why"
    );
    assert_eq!(read.record, Some(json!({"schemaVersion": 2})), "the record");
    assert_eq!(
        super::read(TempDir::new().path()),
        Reports::default(),
        "nothing"
    );
}

#[test]
fn large_or_odd_reports_are_left_out() {
    let dir = TempDir::new();
    dir.write(".sloptopop/reports/.collect.json", "[]");
    let big = dir.path().join(".sloptopop/reports/big.sarif");
    let file = fs::File::create(&big).unwrap();
    file.set_len(MAX_BYTES + 1).unwrap();
    let read = read(dir.path());
    assert_eq!(
        read.left,
        [("big.sarif".to_owned(), "larger than 32 MiB")],
        "too large"
    );
    assert_eq!(read.record, None, "a record that is not an object");
    fs::set_permissions(&big, fs::Permissions::from_mode(0o644)).unwrap();
}

#[test]
fn names_are_plain_report_formats() {
    for name in [
        "a.sarif",
        "a.sarif.json",
        "u.lcov",
        "lcov.info",
        "x-y_z.lcov.info",
    ] {
        assert!(report_name(name), "{name}");
    }
    let long = format!("{}.sarif", "a".repeat(250));
    for name in [
        "",
        ".a.sarif",
        "server.a.sarif",
        "a b.sarif",
        "a.md",
        long.as_str(),
        "a/b.sarif",
    ] {
        assert!(!report_name(name), "{name}");
    }
}

#[test]
fn snippets_go_at_any_depth() {
    let mut value = json!([{"snippet": 1, "a": [{"contextRegion": 2, "b": true, "c": null, "d": 1.5}]},
        {"id": "rule-a", "shortDescription": {"text": "s"}, "fullDescription": {"text": "f"}, "help": {"text": "h"}}]);
    strip(&mut value);
    assert_eq!(
        value,
        json!([{"a": [{"b": true, "c": null, "d": 1.5}]}, {"id": "rule-a"}]),
        "stripped"
    );
}

#[test]
fn reports_up_to_the_limit_are_read() {
    assert_eq!(MAX_BYTES, 33_554_432, "32 MiB");
    let dir = TempDir::new();
    fs::create_dir_all(dir.path().join(DIR)).unwrap();
    fs::write(dir.path().join(DIR).join("a.lcov"), "12345").unwrap();
    fs::write(dir.path().join(DIR).join("b.lcov"), "123456").unwrap();
    let read = read_limited(dir.path(), 5);
    assert_eq!(
        read.sent,
        [("a.lcov".to_owned(), "12345".to_owned())],
        "at the limit"
    );
    assert_eq!(
        read.left,
        [("b.lcov".to_owned(), "larger than 32 MiB")],
        "past it"
    );
}
