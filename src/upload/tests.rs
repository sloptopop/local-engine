//! Unit tests for [`super`].

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;
use crate::mask::Span;
use crate::tests::support::token;

fn snapshot() -> Snapshot {
    Snapshot {
        files: BTreeMap::from([
            ("a.ts".to_owned(), format!("const k = '{}';\n", token())),
            ("b.ts".to_owned(), "export {};\n".to_owned()),
        ]),
        excluded: vec![
            (
                ".env".to_owned(),
                "environment file: its values never leave this machine",
            ),
            ("logo.png".to_owned(), "not UTF-8 text"),
            ("logo2.png".to_owned(), "not UTF-8 text"),
        ],
    }
}

fn found() -> BTreeMap<String, Vec<Found>> {
    BTreeMap::from([(
        "a.ts".to_owned(),
        vec![Found {
            path: "a.ts".to_owned(),
            line: 1,
            end: 1,
            span: Span {
                line: 1,
                start: 12,
                end: 51,
            },
        }],
    )])
}

fn reports() -> Reports {
    Reports {
        sent: vec![("gitleaks.sarif".to_owned(), "{}".to_owned())],
        left: vec![("bad.sarif".to_owned(), "a SARIF report that is not JSON")],
        record: Some(json!({"schemaVersion": 2})),
    }
}

fn about(context: Option<&Value>) -> About<'_> {
    About {
        mode: "transform",
        base: "abc",
        name: "shop",
        context,
    }
}

#[test]
fn the_request_holds_the_masked_snapshot_and_the_reports() {
    let context = json!({"owners": {"approvers": ["lead"]}});
    let made = upload(about(Some(&context)), &snapshot(), &found(), &reports());
    let request: Value = serde_json::from_slice(&made.bytes).unwrap();
    assert_eq!(request["schemaVersion"], 2, "schema 2");
    assert_eq!(request["mode"], "transform", "mode");
    assert_eq!(
        request["files"][0]["text"],
        format!("const k = 'ghp_{}';\n", "x".repeat(36)),
        "masked"
    );
    assert_eq!(request["files"][1]["text"], "export {};\n", "untouched");
    assert_eq!(
        request["reports"],
        json!([{"name": "gitleaks.sarif", "text": "{}"}]),
        "reports"
    );
    assert_eq!(request["record"], json!({"schemaVersion": 2}), "record");
    assert_eq!(request["context"], context, "context");
    assert!(request.get("report").is_none(), "no findings ever");
    assert_eq!(made.digest, digest(REQUEST, &made.bytes), "digest");
    assert_eq!(made.run, run_id(&made.digest), "run");
    let manifest: Value = serde_json::from_slice(&made.manifest.to_bytes()).unwrap();
    assert_eq!(
        manifest["masked"],
        json!({"values": 1, "files": ["a.ts"], "scanner": "gitleaks"}),
        "masked"
    );
    assert_eq!(manifest["files"], 2, "files");
    assert_eq!(manifest["excluded"]["count"], 3, "excluded");
    assert_eq!(
        manifest["excluded"]["byReason"]["not UTF-8 text"], 2,
        "by reason"
    );
    assert_eq!(
        manifest["reports"],
        json!({"sent": ["gitleaks.sarif"], "left": [{"name": "bad.sarif", "reason": "a SARIF report that is not JSON"}], "record": true}),
        "reports"
    );
    assert_eq!(manifest["context"], true, "context");
    assert_eq!(manifest["requestBytes"], made.bytes.len(), "size");
    assert_eq!(manifest["mode"], "transform", "mode");
}

#[test]
fn without_context_record_or_secrets() {
    let bare = Reports::default();
    let made = upload(about(None), &snapshot(), &BTreeMap::new(), &bare);
    let request: Value = serde_json::from_slice(&made.bytes).unwrap();
    assert!(
        request.get("context").is_none() && request.get("record").is_none(),
        "absent"
    );
    assert!(
        request["files"][0]["text"]
            .as_str()
            .unwrap()
            .contains(&token()),
        "nothing reported, nothing masked"
    );
    let manifest: Value = serde_json::from_slice(&made.manifest.to_bytes()).unwrap();
    assert_eq!(manifest["masked"]["values"], 0, "none");
    assert_eq!(manifest["context"], false, "no context");
    let many = Snapshot {
        excluded: (0..150)
            .map(|n| (format!("f{n:03}"), "larger than 1 MiB"))
            .collect(),
        ..Snapshot::default()
    };
    let listed = upload(about(None), &many, &BTreeMap::new(), &bare);
    let long: Value = serde_json::from_slice(&listed.manifest.to_bytes()).unwrap();
    assert_eq!(
        long["excluded"]["paths"].as_array().unwrap().len(),
        LISTED,
        "listed up to 100"
    );
    assert_eq!(long["excluded"]["count"], 150, "counted");
    assert_eq!(
        upload(about(None), &snapshot(), &found(), &reports()).bytes,
        upload(about(None), &snapshot(), &found(), &reports()).bytes,
        "deterministic"
    );
}
