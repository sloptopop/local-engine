//! Unit tests for [`super`].

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};

use serde_json::Value;

use super::*;
use crate::run::TRANSFORM_DIR;
use crate::tests::support::{response, scanned, shop_with_token};

/// A writer that always fails.
struct Broken;

impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("broken"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("broken"))
    }
}

/// Runs the command line; the exit code, stdout and stderr.
fn cli(list: &[&str]) -> (u8, String, String) {
    let args: Vec<OsString> = list.iter().map(OsString::from).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&args, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn the_commands_run_end_to_end() {
    let repo = shop_with_token();
    scanned(&repo, &[("app/orders/[id]/route.ts", 1, 11, 50)]);
    let root = repo.path().to_str().unwrap();
    let (code, out, _) = cli(&["request", root, "--mode", "check"]);
    assert_eq!(code, 0, "request");
    let document: Value = serde_json::from_str(&out).unwrap();
    let run_id = document["run"].as_str().unwrap().to_owned();
    let dir = repo.path().join(TRANSFORM_DIR).join(&run_id);
    let request = fs::read(dir.join("request.json")).unwrap();
    fs::write(dir.join("response.json"), response(&request, &[], false)).unwrap();
    let (failed, report, _) = cli(&["report", root, "--run", &run_id]);
    assert_eq!(failed, 1, "the Report did not pass");
    assert!(report.contains("\"schemaVersion\":2"), "{report}");
    fs::write(dir.join("response.json"), response(&request, &[], true)).unwrap();
    assert_eq!(cli(&["report", root, "--run", &run_id]).0, 0, "passed");
    let (applied, json, _) = cli(&["apply", root, "--run", &run_id]);
    assert_eq!(applied, 0, "nothing to deliver is complete");
    assert!(json.contains("\"applied\":false"), "{json}");
    let (refused, _, error) = cli(&["evidence", root, "--run", &run_id]);
    assert_eq!(
        (refused, error.contains("was not applied")),
        (INTERNAL_ERROR, true),
        "{error}"
    );
    let (version, text, _) = cli(&["version"]);
    assert_eq!(
        (version, text),
        (
            0,
            format!("sloptopop-local {}\n", env!("CARGO_PKG_VERSION"))
        ),
        "version"
    );
    let (pending, _, _) = {
        let step = crate::tests::support::delivery(2, &[], &["att-1"]);
        fs::write(dir.join("response.json"), response(&request, &[step], true)).unwrap();
        cli(&["apply", root, "--run", &run_id, "--branch", "x"])
    };
    assert_eq!(pending, 1, "a pending step");
}

#[test]
fn errors_have_exit_codes() {
    let (usage, _, message) = cli(&["nope"]);
    assert_eq!(usage, USAGE_ERROR, "usage");
    assert!(
        message.starts_with("error: unrecognised arguments: nope\n\nUsage:"),
        "{message}"
    );
    let (failed, _, why) = cli(&[
        "report",
        "/nonexistent/sloptopop",
        "--run",
        "0123456789abcdef",
    ]);
    assert_eq!(failed, INTERNAL_ERROR, "a failure");
    assert!(why.starts_with("error: "), "{why}");
    let args = [OsString::from("version")];
    let mut err = Vec::new();
    assert_eq!(
        run(&args, &mut Broken, &mut err),
        INTERNAL_ERROR,
        "a broken stdout"
    );
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("cannot write output"),
        "said so"
    );
}
