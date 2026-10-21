//! Unit tests for [`super`].

use super::Git;
use crate::tests::support::Repo;

#[test]
fn git_runs_in_the_root_with_input_and_environment() {
    let repo = Repo::new("git-runs");
    let git = Git::new(repo.path());
    assert_eq!(git.root(), repo.path(), "root");
    let head = git.text(&["rev-parse", "HEAD"]).unwrap();
    assert_eq!(head.len(), 40, "{head}");
    let blob = git.input(&["hash-object", "--stdin"], b"x\n").unwrap();
    assert_eq!(
        String::from_utf8(blob).unwrap().trim(),
        "587be6b4c3f93f93c489c0111bba5596147a26cb",
        "stdin"
    );
    let named = git
        .clone()
        .env("GIT_AUTHOR_NAME", "someone")
        .env("GIT_AUTHOR_EMAIL", "someone@localhost")
        .text(&["var", "GIT_AUTHOR_IDENT"])
        .unwrap();
    assert!(named.starts_with("someone <"), "{named}");
}

#[test]
fn failures_carry_stderr() {
    let repo = Repo::new("git-fails");
    let error = Git::new(repo.path())
        .run(&["rev-parse", "nope"])
        .unwrap_err();
    assert!(error.starts_with("git rev-parse nope failed: "), "{error}");
    let missing = Git::with_program("/nonexistent/git", repo.path())
        .run(&["status"])
        .unwrap_err();
    assert!(missing.starts_with("cannot run git: "), "{missing}");
}
