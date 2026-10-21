//! Unit tests for [`super`].

use super::*;

/// A gitleaks log holding `results` (JSON members).
fn log(results: &str) -> String {
    format!(
        r#"{{"version":"2.1.0","runs":[{{"tool":{{"driver":{{"name":"gitleaks"}}}},"results":[{results}]}}]}}"#
    )
}

/// A result in `uri` at `region` (JSON members).
fn result(uri: &str, region: &str) -> String {
    format!(
        r#"{{"ruleId":"generic-api-key","locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"{uri}"}},"region":{{{region}}}}}}}]}}"#
    )
}

#[test]
fn results_give_their_file_lines_and_columns() {
    let text = log(&[
        result(
            "file:///src/app/config.ts",
            r#""startLine":4,"endLine":4,"startColumn":11,"endColumn":30"#,
        ),
        result("./.env.example", r#""startLine":2"#),
        result("keys/id_rsa", r#""startLine":1,"endLine":27"#),
        result("keys/id_rsa", r#""startLine":1,"endLine":27"#),
        result("a.ts", r#""startLine":5,"endLine":3"#),
    ]
    .join(","));
    let found = read(&text).unwrap();
    assert_eq!(
        found,
        [
            Found {
                path: ".env.example".to_owned(),
                line: 2,
                end: 2,
                span: Span {
                    line: 2,
                    start: 1,
                    end: u32::MAX
                },
            },
            Found {
                path: "a.ts".to_owned(),
                line: 5,
                end: 5,
                span: Span {
                    line: 5,
                    start: 1,
                    end: u32::MAX
                },
            },
            Found {
                path: "app/config.ts".to_owned(),
                line: 4,
                end: 4,
                span: Span {
                    line: 4,
                    start: 11,
                    end: 30
                },
            },
            Found {
                path: "keys/id_rsa".to_owned(),
                line: 1,
                end: 27,
                span: Span {
                    line: 1,
                    start: 1,
                    end: u32::MAX
                },
            },
        ],
        "sorted, once, paths relative"
    );
    assert!(read(&log("")).unwrap().is_empty(), "no results");
    let none = r#"{"runs":[{"tool":{"driver":{"name":"Gitleaks"}}}]}"#;
    assert!(
        read(none).unwrap().is_empty(),
        "no results member, any case"
    );
}

#[test]
fn other_logs_and_results_without_a_place_are_refused() {
    assert!(
        read("nope").unwrap_err().starts_with("not JSON"),
        "not JSON"
    );
    assert_eq!(
        read("{}").unwrap_err(),
        "not a SARIF log: no runs",
        "no runs"
    );
    assert_eq!(
        read(r#"{"runs":[{"tool":{"driver":{"name":"semgrep"}}}]}"#).unwrap_err(),
        "a run of `semgrep`, not of gitleaks",
        "another tool"
    );
    assert_eq!(
        read(r#"{"runs":[{}]}"#).unwrap_err(),
        "a run of ``, not of gitleaks",
        "no tool"
    );
    for bad in [
        r#"{"ruleId":"x"}"#.to_owned(),
        result("a.ts", r#""startColumn":3"#),
        result("a.ts", r#""startLine":0"#),
        result("a.ts", r#""startLine":99999999999"#),
    ] {
        assert_eq!(
            read(&log(&bad)).unwrap_err(),
            "a result names no file or no line",
            "{bad}"
        );
    }
}
