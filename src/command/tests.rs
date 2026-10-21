//! Unit tests for [`super`].

use super::*;

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|a| (*a).to_owned()).collect()
}

#[test]
fn commands_parse() {
    let cases = [
        (vec!["version"], Command::Version),
        (vec!["-V"], Command::Version),
        (vec!["--version"], Command::Version),
        (
            vec!["request", ".", "--mode", "check"],
            Command::Request(".", "check"),
        ),
        (
            vec!["request", "r", "--mode", "fix"],
            Command::Request("r", "fix"),
        ),
        (
            vec!["request", "r", "--mode", "transform"],
            Command::Request("r", "transform"),
        ),
        (
            vec!["report", "r", "--run", "0123"],
            Command::Report("r", "0123"),
        ),
        (
            vec!["evidence", "r", "--run", "0123"],
            Command::Evidence("r", "0123"),
        ),
        (
            vec![
                "apply",
                "r",
                "--run",
                "id",
                "--apply",
                "--branch",
                "b",
                "--confirm",
                "a,,b",
                "--by",
                "lead",
            ],
            Command::Apply(Apply {
                root: "r",
                run: "id",
                commit: true,
                branch: Some("b"),
                confirm: vec!["a", "b"],
                by: Some("lead"),
            }),
        ),
    ];
    for (list, expected) in cases {
        let owned = args(&list);
        assert_eq!(parse(&owned).unwrap(), expected, "{list:?}");
    }
}

#[test]
fn anything_else_is_a_usage_error() {
    for (list, why) in [
        (vec![], "unrecognised arguments"),
        (vec!["check", "."], "unrecognised arguments"),
        (
            vec!["request", "--mode", "check"],
            "expected a repository root",
        ),
        (vec!["report", "-r"], "expected a repository root"),
        (vec!["apply", "--run", "x"], "expected a repository root"),
        (vec!["evidence", "--run", "x"], "expected a repository root"),
        (
            vec!["request", ".", "--mode", "evidence"],
            "unrecognised arguments",
        ),
        (vec!["report", "."], "unrecognised arguments"),
        (vec!["apply", "."], "apply needs --run"),
        (vec!["apply", ".", "--run"], "--run needs a value"),
        (
            vec!["apply", ".", "--run", "--apply"],
            "--run needs a value",
        ),
        (
            vec!["apply", ".", "--run", "x", "--other", "y"],
            "unknown option: --other",
        ),
        (
            vec!["apply", ".", "--run", "x", "--confirm", "a"],
            "go together",
        ),
        (vec!["apply", ".", "--run", "x", "--by", "a"], "go together"),
    ] {
        let owned = args(&list);
        let error = parse(&owned).unwrap_err();
        assert!(error.contains(why), "{list:?}: {error}");
    }
    assert!(USAGE.starts_with("Usage: sloptopop-local request"), "usage");
}
