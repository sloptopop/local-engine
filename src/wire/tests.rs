//! Unit tests for [`super`].

use serde_json::json;

use super::*;

#[test]
fn a_response_reads_with_defaults() {
    let response: Response = serde_json::from_value(json!({
        "schemaVersion": 2, "mode": "transform", "digests": {"request": "blake3:r", "snapshot": "x"},
        "report": {"schemaVersion": 2}, "plan": {"ignored": true},
        "deliveries": [
            {"ordinal": 1, "kind": "manual", "class": "declared", "status": "manual", "title": "t",
             "message": "m\n\nSloptopop-Plan: blake3:p\n", "tasks": [{"text": "do"}]},
            {"ordinal": 2, "kind": "code", "class": "equivalent", "status": "verified", "title": "t",
             "message": "m", "requires": [{"attestation": "att-1"}],
             "changes": [{"path": "a", "kind": "edit", "before": "blake3:b", "after": "blake3:a",
                          "edits": [{"start": 0, "end": 1, "text": "y"}]}]},
            {"ordinal": 3, "kind": "code", "class": "equivalent", "status": "blocked", "title": "t",
             "message": "m", "blockedBy": 2, "reason": "r"}
        ]
    }))
    .unwrap();
    assert_eq!(response.schema_version, SCHEMA_VERSION, "version");
    assert_eq!(response.digests.request, "blake3:r", "digest");
    assert!(response.deliveries[0].manual(), "manual");
    assert!(!response.deliveries[1].manual(), "not manual");
    assert_eq!(
        response.deliveries[0].tasks[0].checklist,
        Vec::<String>::new(),
        "no checklist"
    );
    assert_eq!(response.deliveries[1].requires[0].text, None, "no text");
    assert_eq!(response.deliveries[1].changes[0].mode, None, "no mode");
    assert_eq!(response.deliveries[2].blocked_by, Some(2), "blocked");
    assert_eq!(plan_id(&response.deliveries), "blake3:p", "the plan id");
    assert_eq!(plan_id(&[]), "", "none");
    assert!(
        response.verdict.is_none() && response.redetected.is_none(),
        "absent"
    );
    let bare: Response =
        serde_json::from_value(json!({"schemaVersion": 2, "digests": {"request": "r"}})).unwrap();
    assert!(
        bare.deliveries.is_empty() && bare.report.is_none(),
        "check-less defaults"
    );
}
