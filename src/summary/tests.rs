//! Unit tests for [`super`].

use serde_json::{Value, json};

use super::*;
use crate::apply::Delivered;

fn deliveries() -> Vec<Delivery> {
    serde_json::from_value(json!([
        {"ordinal": 1, "kind": "manual", "class": "declared", "status": "manual", "title": "Rotate the key",
         "message": "m", "tasks": [{"text": "Rotate it", "checklist": ["revoke", "issue"]}, {"text": "Tell ops"}]},
        {"ordinal": 2, "kind": "code", "class": "equivalent", "status": "verified", "title": "Check results",
         "message": "m", "problems": [{"id": "p2", "goal": "Check results", "control": "ASVS V16"}]},
        {"ordinal": 3, "kind": "code", "class": "declared", "status": "verified", "title": "Fail loudly",
         "message": "m", "requires": [{"attestation": "att-1", "text": "it now fails"}, {"attestation": "att-2"}]}
    ]))
    .unwrap()
}

fn outcome() -> Outcome {
    let step = |ordinal, status, commit: Option<&str>, reason: Option<&str>| Delivered {
        ordinal,
        status,
        commit: commit.map(str::to_owned),
        files: vec!["a.ts".to_owned()],
        reason: reason.map(str::to_owned),
    };
    Outcome {
        steps: vec![
            step(1, Status::Manual, None, None),
            step(2, Status::Applied, Some("c0ffee"), None),
            step(3, Status::Pending, None, Some("waits for att-1")),
        ],
        head: Some("c0ffee".to_owned()),
    }
}

fn render(redetected: Option<&Value>, records: &[Value]) -> Written {
    let list = deliveries();
    let done = outcome();
    Run {
        id: "0123456789abcdef",
        apply: true,
        base: "abc",
        branch: Some("sloptopop/transform-0123456789abcdef"),
        plan: "blake3:p",
        deliveries: &list,
        outcome: &done,
        redetected,
        records,
    }
    .render()
}

#[test]
fn the_report_names_every_step() {
    let redetected = json!({"rules": [{"rule": "db.result-unchecked", "before": 3, "after": 1}]});
    let written = render(Some(&redetected), &[]);
    assert!(!written.complete, "a step is pending");
    let report: Value = serde_json::from_slice(&written.report).unwrap();
    assert_eq!(report["schemaVersion"], 2, "schema");
    assert_eq!(report["tool"]["name"], "sloptopop-local", "tool");
    assert_eq!(
        (report["head"].as_str(), report["applied"].as_bool()),
        (Some("c0ffee"), Some(true)),
        "head"
    );
    assert_eq!(
        report["steps"][1],
        json!({"ordinal": 2, "kind": "code", "class": "equivalent", "title": "Check results",
        "status": "applied", "commit": "c0ffee", "files": ["a.ts"], "reason": null}),
        "a step"
    );
    assert_eq!(report["steps"][2]["reason"], "waits for att-1", "why");
    assert_eq!(
        report["redetected"], redetected,
        "the server's re-detection"
    );
    let summary = &written.summary;
    for part in [
        "# sloptopop transform 0123456789abcdef",
        "Base `abc`, branch `sloptopop/transform-0123456789abcdef`.",
        "- Step 2 (code, equivalent): Check results — **applied** `c0ffee`",
        "  - p2: Check results (ASVS V16)",
        "  - why: waits for att-1",
        "## Confirmations needed",
        "- `att-1` (step 3): it now fails",
        "- `att-2` (step 3): \n",
        "## Manual tasks",
        "- [ ] Rotate it",
        "  - [ ] revoke",
        "- [ ] Tell ops",
        "| db.result-unchecked | 3 | 1 |",
    ] {
        assert!(summary.contains(part), "{part:?} in {summary}");
    }
    assert!(
        written
            .pr
            .contains("- Check results (code, equivalent)\n  - Check results (ASVS V16)"),
        "{}",
        written.pr
    );
    assert!(!written.pr.contains("Fail loudly"), "only committed steps");
}

#[test]
fn quiet_runs_leave_their_sections_out() {
    let records = [
        json!({"attestation": "att-1", "plan": "blake3:p", "statement": "s", "subject": "abc", "by": "lead"}),
        json!({"attestation": "att-2", "plan": "blake3:p", "statement": "s", "subject": "abc", "by": "ops"}),
    ];
    let written = render(Some(&json!({"rules": []})), &records);
    assert!(
        !written.summary.contains("## Confirmations needed"),
        "confirmed already"
    );
    assert!(
        !written.summary.contains("## Re-detection"),
        "no rule changed"
    );
    let none = render(None, &records);
    assert!(!none.summary.contains("## Re-detection"), "no re-detection");
    let report: Value = serde_json::from_slice(&none.report).unwrap();
    assert_eq!(report["redetected"], Value::Null, "null");
    let list: Vec<Delivery> = deliveries().into_iter().skip(1).take(1).collect();
    let done = Outcome {
        steps: vec![Delivered {
            ordinal: 2,
            status: Status::Planned,
            commit: None,
            files: Vec::new(),
            reason: None,
        }],
        head: None,
    };
    let dry = Run {
        id: "r",
        apply: false,
        base: "abc",
        branch: None,
        plan: "p",
        deliveries: &list,
        outcome: &done,
        redetected: None,
        records: &[],
    }
    .render();
    assert!(dry.complete, "nothing left");
    assert!(
        dry.summary
            .contains("Base `abc`, dry run: nothing committed."),
        "{}",
        dry.summary
    );
    assert!(!dry.summary.contains("## Manual tasks"), "no tasks");
    let plain: Value = serde_json::from_slice(&dry.report).unwrap();
    assert_eq!(
        (plain["branch"].clone(), plain["head"].clone()),
        (Value::Null, Value::Null),
        "no branch"
    );
}
