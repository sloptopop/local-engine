//! Unit tests for [`super`].

use std::fs;

use serde_json::json;

use super::*;
use crate::tests::support::TempDir;
use crate::wire::Delivery;

fn deliveries() -> Vec<Delivery> {
    serde_json::from_value(json!([
        {"ordinal": 2, "kind": "A", "class": "declared", "status": "verified", "title": "t", "message": "m",
         "requires": [{"attestation": "att-1", "text": "a", "who": "approver", "evidence": "owner_statement"},
                      {"attestation": "att-2", "text": "b", "who": "operator", "evidence": "deploy_record"}]},
        {"ordinal": 3, "kind": "A", "class": "declared", "status": "verified", "title": "t", "message": "m",
         "requires": [{"attestation": "att-3", "text": "c", "who": "data_owner"}, {"attestation": "att-4"}]}
    ]))
    .unwrap()
}

fn people() -> Owners {
    Owners {
        approvers: vec!["lead".to_owned()],
        operators: vec!["ops".to_owned()],
        data: vec!["owner".to_owned()],
    }
}

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|id| (*id).to_owned()).collect()
}

#[test]
fn records_load_save_and_bind_to_their_plan() {
    let dir = TempDir::new();
    assert!(load(dir.path()).unwrap().is_empty(), "none yet");
    let made = confirm(
        &deliveries(),
        "blake3:p",
        &ids(&["att-1"]),
        ("lead", &people()),
        "abc",
        "2026-10-16",
    )
    .unwrap();
    assert_eq!(
        made[0],
        json!({"attestation": "att-1", "plan": "blake3:p", "step": 2,
               "statement": statement("a"), "subject": "abc", "by": "lead",
               "role": "approver", "evidence": "owner_statement",
               "evidenceRef": "sloptopop transform --confirm", "asOf": "2026-10-16"}),
        "a record"
    );
    assert_eq!(
        statement("a"),
        format!(
            "blake3:{}",
            blake3::Hash::from(blake3::derive_key("sloptopop attestation statement", b"a"))
                .to_hex()
        ),
        "the statement digest"
    );
    save(dir.path(), &made).unwrap();
    assert_eq!(load(dir.path()).unwrap(), made, "round trip");
    fs::write(dir.path().join(FILE), "{}").unwrap();
    assert!(
        load(dir.path()).unwrap_err().contains("not a list"),
        "not a list"
    );
    fs::remove_file(dir.path().join(FILE)).unwrap();
    fs::create_dir_all(dir.path().join(FILE)).unwrap();
    assert!(load(dir.path()).is_err(), "unreadable");
    assert!(
        save(dir.path(), &made)
            .unwrap_err()
            .contains("cannot write"),
        "unwritable"
    );
}

#[test]
fn roles_come_from_the_business_context() {
    let made = confirm(
        &deliveries(),
        "p",
        &ids(&["att-2", "att-3"]),
        ("ops", &people()),
        "s",
        "d",
    );
    assert!(
        made.unwrap_err().contains("`ops` may not confirm `att-3`"),
        "ops is no data owner"
    );
    let roles: Vec<String> = [
        ("att-2", "ops"),
        ("att-3", "owner"),
        ("att-2", "lead"),
        ("att-4", "lead"),
    ]
    .iter()
    .map(|(id, by)| {
        let record = confirm(&deliveries(), "p", &ids(&[id]), (by, &people()), "s", "d").unwrap();
        record[0]["role"].as_str().unwrap().to_owned()
    })
    .collect();
    assert_eq!(
        roles,
        ["operator", "data_owner", "approver", "approver"],
        "listed role, else approver"
    );
    let unknown = confirm(
        &deliveries(),
        "p",
        &ids(&["att-9"]),
        ("lead", &people()),
        "s",
        "d",
    );
    assert!(
        unknown
            .unwrap_err()
            .contains("requires the attestation `att-9`"),
        "unknown"
    );
    let bare = confirm(
        &deliveries(),
        "p",
        &ids(&["att-4"]),
        ("lead", &people()),
        "s",
        "d",
    )
    .unwrap();
    assert_eq!(
        (bare[0]["step"].as_u64(), bare[0]["evidence"].as_str()),
        (Some(3), Some("")),
        "defaults"
    );
    assert_eq!(owners(None), Owners::default(), "no context");
    assert_eq!(
        owners(Some(&json!({"owners": {"approvers": 1}}))),
        Owners::default(),
        "invalid"
    );
    let context =
        json!({"owners": {"approvers": ["lead"], "operators": ["ops"], "data": ["owner"]}});
    assert_eq!(owners(Some(&context)), people(), "listed");
    assert_eq!(
        owners(Some(&json!({"owners": {"operators": ["ops"]}}))).approvers,
        Vec::<String>::new(),
        "missing lists are empty"
    );
}

#[test]
fn a_requirement_is_satisfied_only_by_a_matching_record() {
    let list = deliveries();
    let needed = &list[0].requires[0];
    let records = confirm(
        &list,
        "blake3:p",
        &ids(&["att-1"]),
        ("lead", &people()),
        "base",
        "d",
    )
    .unwrap();
    assert!(
        satisfied(&records, "blake3:p", needed, "base", &people()),
        "recorded"
    );
    assert!(
        !satisfied(&records, "blake3:other", needed, "base", &people()),
        "another plan"
    );
    assert!(
        !satisfied(&records, "blake3:p", needed, "moved", &people()),
        "another commit"
    );
    assert!(
        !satisfied(
            &records,
            "blake3:p",
            &list[0].requires[1],
            "base",
            &people()
        ),
        "another attestation"
    );
    let mut changed = needed.clone();
    changed.text = Some("other words".to_owned());
    assert!(
        !satisfied(&records, "blake3:p", &changed, "base", &people()),
        "another text"
    );
    assert!(
        !satisfied(&records, "blake3:p", needed, "base", &Owners::default()),
        "no longer an owner"
    );
    let mut junk = records.clone();
    junk.insert(0, json!({"attestation": 1}));
    assert!(
        satisfied(&junk, "blake3:p", needed, "base", &people()),
        "malformed records are skipped"
    );
    let untexted = &list[1].requires[1];
    let none = confirm(
        &list,
        "p",
        &ids(&["att-4"]),
        ("lead", &people()),
        "base",
        "d",
    )
    .unwrap();
    assert!(
        satisfied(&none, "p", untexted, "base", &people()),
        "no text, no role: an approver's"
    );
    assert_eq!(confirmed_by(&junk, "blake3:p", "att-1"), ["lead"], "who");
    assert!(
        confirmed_by(&junk, "blake3:other", "att-1").is_empty(),
        "another plan"
    );
    assert!(
        confirmed_by(&junk, "blake3:p", "att-2").is_empty(),
        "another attestation"
    );
}

#[test]
fn dates_are_civil_utc() {
    assert_eq!(date(0), "1970-01-01", "epoch");
    assert_eq!(date(20_742), "2026-10-16", "a day in 2026");
    assert_eq!(date(11_016), "2000-02-29", "a leap day");
    assert_eq!(date(10_957), "2000-01-01", "january");
    for (days, text) in [
        (11_017, "2000-03-01"),
        (47_540, "2100-02-28"),
        (47_541, "2100-03-01"),
        (157_113, "2400-02-29"),
        (20_088, "2024-12-31"),
        (10_956, "1999-12-31"),
    ] {
        assert_eq!(date(days), text, "{days}");
    }
    let system = std::process::Command::new("date")
        .args(["-u", "+%F"])
        .output()
        .unwrap();
    let expected = String::from_utf8(system.stdout).unwrap();
    assert_eq!(today(), expected.trim(), "the system's UTC date");
}
