//! Unit tests for [`super`].

use super::{Entry, environment, excluded, left_out, parse_batch, parse_tree, snapshot, tree};
use crate::git::Git;
use crate::tests::support::Repo;

fn entry(mode: &str, kind: &str, size: Option<u64>, path: &str) -> Entry {
    Entry {
        mode: mode.to_owned(),
        kind: kind.to_owned(),
        oid: "0".repeat(40),
        size,
        path: path.to_owned(),
    }
}

#[test]
fn exclusions_have_reasons() {
    let cases = [
        (entry("160000", "commit", None, "lib"), Some("submodule")),
        (
            entry("120000", "blob", Some(3), "link"),
            Some("symbolic link"),
        ),
        (
            entry("100644", "blob", Some(3), "a/node_modules/x.js"),
            Some("dependency, build or VCS directory"),
        ),
        (
            entry("100644", "blob", Some(3), ".sloptopop/context.json"),
            Some("sloptopop's own files"),
        ),
        (
            entry("100644", "blob", Some(3), "app/.env.local"),
            Some("environment file: its values never leave this machine"),
        ),
        (
            entry("100644", "blob", Some(1_048_577), "big.json"),
            Some("larger than 1 MiB"),
        ),
        (
            entry("100644", "blob", None, "unsized"),
            Some("larger than 1 MiB"),
        ),
        (entry("100644", "blob", Some(1_048_576), "max.json"), None),
        (entry("100755", "blob", Some(3), "run.sh"), None),
    ];
    for (entry, reason) in cases {
        assert_eq!(excluded(&entry), reason, "{}", entry.path);
    }
    for name in [".env", ".env.production"] {
        assert!(environment(name), "{name}");
    }
    for name in [
        ".env.example",
        ".env.sample",
        ".env.template",
        ".envrc",
        "x.env",
        "env",
    ] {
        assert!(!environment(name), "{name}");
    }
}

#[test]
fn a_commits_files_are_read_from_git() {
    let repo = Repo::with_files(&[
        ("src/a.ts", b"export const a = 1;\n"),
        ("bin.dat", b"\xff\xfe"),
        (".env", b"KEY=value\n"),
        ("dist/x.js", b"x"),
        ("src/same.ts", b"export const a = 1;\n"),
    ]);
    let git = Git::new(repo.path());
    let entries = tree(&git, "HEAD").unwrap();
    assert_eq!(entries.len(), 5, "{entries:?}");
    assert_eq!(entries[0].size, Some(10), "sizes");
    let snap = snapshot(&git, &entries).unwrap();
    assert_eq!(
        snap.files.keys().collect::<Vec<_>>(),
        ["src/a.ts", "src/same.ts"],
        "text only; two files with one object are both read"
    );
    assert_eq!(snap.files["src/a.ts"], "export const a = 1;\n", "bytes");
    let reasons: Vec<(&str, &str)> = snap
        .excluded
        .iter()
        .map(|(p, r)| (p.as_str(), *r))
        .collect();
    assert_eq!(
        reasons,
        [
            (
                ".env",
                "environment file: its values never leave this machine"
            ),
            ("bin.dat", "not UTF-8 text"),
            ("dist/x.js", "dependency, build or VCS directory"),
        ],
        "sorted reasons"
    );
    assert!(tree(&git, "nope").is_err(), "an unknown commit");
    let broken = Git::with_program("/nonexistent/git", repo.path());
    assert!(snapshot(&broken, &entries).is_err(), "git missing");
}

#[test]
fn malformed_git_output_is_read_up_to_the_fault() {
    assert_eq!(parse_tree(b"no tab\0"), [], "no tab");
    assert_eq!(parse_tree(b"100644 blob\tp\0"), [], "no object id");
    assert_eq!(parse_tree(b"100644\tp\0"), [], "no kind");
    assert_eq!(parse_tree(b"\tp\0"), [], "no mode");
    assert_eq!(parse_tree(b""), [], "empty");
    let read = parse_batch(b"aa blob 2\nhi\nbb blob 9\nshort\n");
    assert_eq!(read.len(), 1, "stops at a short object");
    assert_eq!(read["aa"], b"hi", "the first");
    assert!(parse_batch(b"no newline").is_empty(), "no header end");
    assert!(parse_batch(b"nospace\n").is_empty(), "no fields");
    assert!(parse_batch(b"cc missing\n").is_empty(), "a missing object");
    assert!(parse_batch(b"dd blob x\n").is_empty(), "no size");
    assert!(
        parse_batch(b"ee blob 1\nz").is_empty(),
        "no trailing newline"
    );
    let missing = snapshot_with_missing();
    assert_eq!(
        missing,
        [("gone.ts".to_owned(), "unreadable")],
        "an object git does not have"
    );
}

/// A snapshot of an entry whose object does not exist.
fn snapshot_with_missing() -> Vec<(String, &'static str)> {
    let repo = Repo::new("missing");
    let mut gone = entry("100644", "blob", Some(1), "gone.ts");
    gone.oid = "1".repeat(40);
    snapshot(&Git::new(repo.path()), &[gone]).unwrap().excluded
}

#[test]
fn a_new_path_where_nothing_is_uploaded_is_left_out() {
    assert_eq!(
        left_out("node_modules/x/.env.example"),
        Some("dependency, build or VCS directory")
    );
    assert_eq!(
        left_out(".sloptopop/run/x.json"),
        Some("sloptopop's own files")
    );
    assert_eq!(
        left_out("apps/web/.env"),
        Some("environment file: its values never leave this machine")
    );
    for path in ["src/new.ts", ".env.example", "apps/.sloptopop/x"] {
        assert_eq!(left_out(path), None, "{path}");
    }
}
