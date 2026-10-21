//! Coverage gate shared by every sloptopop Rust repo; keep identical.
//!
//! This crate does not compile unless all of its tests pass with 100% line,
//! region and function coverage: `cargo build`, `check`, `test` and `doc`
//! all run this script, which runs the test suite under cargo-llvm-cov in a
//! separate target directory and fails the build if anything is missing.

use std::env;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, ExitCode};

/// Inputs whose change must re-run the gate.
const WATCHED: [&str; 6] = [
    "src",
    "tests",
    "examples",
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
];

/// Environment variables Cargo sets for build scripts that must not leak
/// into the nested Cargo run (they would retarget or reconfigure it).
fn leaks_into_nested_cargo(name: &str) -> bool {
    (name.starts_with("CARGO_") && name != "CARGO_HOME")
        || matches!(
            name,
            "OUT_DIR"
                | "TARGET"
                | "HOST"
                | "PROFILE"
                | "OPT_LEVEL"
                | "DEBUG"
                | "NUM_JOBS"
                | "RUSTC"
                | "RUSTDOC"
                | "RUSTC_LINKER"
                | "RUSTC_WRAPPER"
                | "RUSTC_WORKSPACE_WRAPPER"
        )
}

fn main() -> ExitCode {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default();
    let mut stdout = io::stdout().lock();
    // A missing path would make Cargo re-run this script on every build.
    for path in WATCHED
        .iter()
        .filter(|p| Path::new(&manifest_dir).join(p).exists())
    {
        if writeln!(stdout, "cargo::rerun-if-changed={path}").is_err() {
            return ExitCode::FAILURE;
        }
    }
    // cargo-llvm-cov builds this crate again for the coverage run; the gate
    // is that run, so it must not start another one.
    if env::var_os("CARGO_LLVM_COV").is_some() {
        return ExitCode::SUCCESS;
    }
    // cargo-mutants builds deliberately broken copies of the crate in a
    // `cargo-mutants-*` scratch directory; whether their tests fail is what
    // mutation testing measures, so they must still compile.
    let is_mutant_copy = Path::new(&manifest_dir).ancestors().any(|dir| {
        dir.extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"))
            && dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("cargo-mutants-"))
    });
    if is_mutant_copy {
        return ExitCode::SUCCESS;
    }
    let target_dir = Path::new(&env::var_os("OUT_DIR").unwrap_or_default()).join("coverage-gate");
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command.current_dir(&manifest_dir).args([
        "llvm-cov",
        "--all-features",
        "--locked",
        "--fail-under-lines",
        "100",
        "--fail-under-regions",
        "100",
        "--fail-under-functions",
        "100",
        "--fail-uncovered-lines",
        "0",
        "--fail-uncovered-regions",
        "0",
        "--fail-uncovered-functions",
        "0",
        "--show-missing-lines",
    ]);
    for (name, _) in env::vars_os() {
        if name.to_str().is_some_and(leaks_into_nested_cargo) {
            command.env_remove(&name);
        }
    }
    command.env("CARGO_TARGET_DIR", &target_dir);
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(_) => {
            let _reported = writeln!(
                io::stderr(),
                "coverage gate: tests failed or coverage is below 100%; see the report above"
            );
            ExitCode::FAILURE
        }
        Err(e) => {
            let _reported = writeln!(
                io::stderr(),
                "coverage gate: could not run cargo llvm-cov ({e}); install it with `brew install cargo-llvm-cov`"
            );
            ExitCode::FAILURE
        }
    }
}
