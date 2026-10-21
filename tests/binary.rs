//! The `sloptopop-local` binary end to end: its version, a usage error,
//! and a refusal to upload without a usable secret-scanner report.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_sloptopop-local");

#[test]
fn version_usage_and_a_refusal() {
    let version = Command::new(BIN).arg("version").output().unwrap();
    assert!(version.status.success(), "version exits 0");
    assert_eq!(
        String::from_utf8(version.stdout).unwrap(),
        format!("sloptopop-local {}\n", env!("CARGO_PKG_VERSION")),
        "version"
    );
    let usage = Command::new(BIN).arg("check").output().unwrap();
    assert_eq!(usage.status.code(), Some(2), "usage error");
    assert!(
        String::from_utf8(usage.stderr)
            .unwrap()
            .contains("Usage: sloptopop-local"),
        "usage text"
    );
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("binary-repo");
    let _stale = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@localhost")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@localhost")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    std::fs::write(dir.join("a.ts"), "export {};\n").unwrap();
    git(&["init", "-q", "-b", "main"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "base"]);
    let refused = Command::new(BIN)
        .args(["request", dir.to_str().unwrap(), "--mode", "check"])
        .output()
        .unwrap();
    assert_eq!(refused.status.code(), Some(3), "refused");
    let message = String::from_utf8(refused.stderr).unwrap();
    assert!(message.contains("sloptopop collect"), "{message}");
}
