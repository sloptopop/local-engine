//! Unit tests for [`super`].

use serde_json::json;

use super::Json;

#[test]
fn members_are_sorted_and_strings_escaped() {
    let value = json!({"b": [1, true, null, false], "a": "q\"\\\n\r\t\u{1}\u{1f} é", "c": {"z": 2.5, "y": -3}});
    let bytes = Json::from_value(&value).to_bytes();
    assert_eq!(
        String::from_utf8(bytes).unwrap(),
        r#"{"a":"q\"\\\n\r\t\u0001\u001f é","b":[1,true,null,false],"c":{"y":-3,"z":2.5}}"#,
        "canonical"
    );
}

#[test]
fn helpers_build_values() {
    let value = Json::object([
        ("n", Json::int(7_u32)),
        ("s", Json::text("t")),
        ("e", Json::Array(Vec::new())),
        ("o", Json::Object(std::collections::BTreeMap::new())),
    ]);
    assert_eq!(
        String::from_utf8(value.to_bytes()).unwrap(),
        r#"{"e":[],"n":7,"o":{},"s":"t"}"#,
        "helpers"
    );
}
