//! Decision D-0183: `sloptopop local` is open source and holds no
//! sloptopop proprietary code. This test reads its whole dependency tree
//! (normal, build and dev edges) with cargo itself: no sloptopop stage
//! crate may be in it, and every package must be one of the permissively
//! licensed crates the open-source build allows.

use std::process::Command;

/// Helpers shared by the tests below.
#[cfg(test)]
mod support {
    use super::*;

    /// The packages of `cargo tree` with `edges`, one per line (`name vX`).
    pub(crate) fn tree(edges: &str) -> String {
        let output = Command::new(env!("CARGO"))
            .args([
                "tree",
                "--offline",
                "--edges",
                edges,
                "--prefix",
                "none",
                "--format",
                "{p}",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("cargo tree should run");
        assert!(
            output.status.success(),
            "cargo tree: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("UTF-8")
    }
}

use support::tree;

#[test]
fn no_proprietary_crate_is_linked() {
    for edges in ["normal", "build", "dev", "all"] {
        let packages = tree(edges);
        for banned in [
            "sloptopop-detector",
            "sloptopop-guider",
            "sloptopop-implementor",
            "sloptopop-business-logic",
            "sloptopop-architect",
            "sloptopop-compliance",
            "backend-engine",
            "tree-sitter",
        ] {
            assert!(
                !packages.lines().any(|line| line.starts_with(banned)),
                "{banned} is in the {edges} tree:\n{packages}"
            );
        }
        assert!(
            packages
                .lines()
                .next()
                .is_some_and(|line| line.starts_with("sloptopop-local")),
            "the root: {packages}"
        );
    }
}

#[test]
fn the_crate_is_mit_or_apache() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        manifest.contains("license = \"MIT OR Apache-2.0\""),
        "the licence"
    );
    assert!(
        !manifest.contains("license-file"),
        "no proprietary licence file"
    );
    for file in ["LICENSE-MIT", "LICENSE-APACHE"] {
        assert!(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(file)
                .is_file(),
            "{file}"
        );
    }
}
