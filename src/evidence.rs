//! Evidence (D-0183 task 4): the project's own type check, build and tests,
//! run on the base commit and on the head of the delivered branch, each in
//! a temporary detached worktree (the dependency directories at the root,
//! such as `node_modules` and `.venv`, are linked in, so nothing is
//! installed; the checkout, its index and `HEAD` are never touched). Only
//! exit codes, durations and the length and digest of each output leave
//! the machine: the output itself stays here. The server's Guider judges
//! the result.
//!
//! The commands come from `.sloptopop/checks.json` when there is one
//! (`{"checks": [{"kind": "test", "command": ["npm", "test"]}]}`), else
//! from what the project declares: `package.json` scripts `typecheck`,
//! `build` and `test`; `cargo check` and `cargo test` (`--locked`); `go
//! vet`, `go build` and `go test` over `./...`.
//!
//! Standards: SCF CHG-07 (a change kept only once verified), TDA-09
//! (testing); NIST SSDF PW.8.2; OWASP ASVS 5.0 V13.3.1 (outputs, which can
//! hold secrets, never leave the machine).

use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::Value;

use crate::canonical::Json;
use crate::digest::digest;
use crate::git::Git;

/// The user's own list of checks, relative to the root.
pub(crate) const CHECKS: &str = ".sloptopop/checks.json";

/// The dependency directories linked into each worktree.
const LINKED: [&str; 3] = ["node_modules", ".venv", "venv"];

/// The key-derivation context of an output's digest.
const OUTPUT: &str = "sloptopop check output v1";

/// The most of an output that is digested, in bytes.
const MAX_OUTPUT: u64 = 16 * 1024 * 1024;

/// How often a running check is polled.
const POLL: Duration = Duration::from_millis(50);

/// One check.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) struct Check {
    /// `typecheck`, `build` or `test`.
    pub(crate) kind: String,
    /// The command line.
    pub(crate) command: Vec<String>,
    /// Where it came from.
    #[serde(default)]
    pub(crate) source: String,
}

/// The user's list.
#[derive(Debug, Deserialize)]
struct Listed {
    /// The checks.
    checks: Vec<Check>,
}

/// A check of `kind`, `command`, from `source`.
fn check(kind: &str, command: &[&str], source: &str) -> Check {
    Check {
        kind: kind.to_owned(),
        command: command.iter().map(|arg| (*arg).to_owned()).collect(),
        source: source.to_owned(),
    }
}

/// The checks of the repository at `root`.
///
/// # Errors
///
/// When `.sloptopop/checks.json` exists and is not a list of checks.
pub(crate) fn checks(root: &Path) -> Result<Vec<Check>, String> {
    if let Ok(bytes) = fs::read(root.join(CHECKS)) {
        return serde_json::from_slice::<Listed>(&bytes)
            .map(|listed| {
                listed
                    .checks
                    .into_iter()
                    .filter(|one| !one.command.is_empty())
                    .map(|one| Check {
                        source: CHECKS.to_owned(),
                        ..one
                    })
                    .collect()
            })
            .map_err(|error| format!("{CHECKS} is not a list of checks: {error}"));
    }
    let mut out = Vec::new();
    let scripts: Value = fs::read(root.join("package.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|package| package.get("scripts").cloned())
        .unwrap_or(Value::Null);
    for (kind, script, command) in [
        (
            "typecheck",
            "typecheck",
            ["npm", "run", "typecheck"].as_slice(),
        ),
        ("build", "build", &["npm", "run", "build"]),
        ("test", "test", &["npm", "test"]),
    ] {
        if scripts.get(script).is_some() {
            out.push(check(
                kind,
                command,
                &format!("package.json scripts.{script}"),
            ));
        }
    }
    if root.join("Cargo.toml").is_file() {
        out.push(check(
            "typecheck",
            &["cargo", "check", "--locked"],
            "Cargo.toml",
        ));
        out.push(check("test", &["cargo", "test", "--locked"], "Cargo.toml"));
    }
    if root.join("go.mod").is_file() {
        out.push(check("typecheck", &["go", "vet", "./..."], "go.mod"));
        out.push(check("build", &["go", "build", "./..."], "go.mod"));
        out.push(check("test", &["go", "test", "./..."], "go.mod"));
    }
    Ok(out)
}

/// The length and digest of the output in `file`.
fn output(file: &Path) -> Json {
    let bytes = fs::read(file).unwrap_or_default();
    let cut = usize::try_from(MAX_OUTPUT)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    Json::object([
        (
            "bytes",
            Json::int(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
        ),
        (
            "digest",
            Json::text(&digest(OUTPUT, bytes.get(..cut).unwrap_or_default())),
        ),
    ])
}

/// Runs `check` in `dir` within `limit`, its output in `out`: its exit
/// code (none when it could not start, was killed or ran over), duration
/// and outputs.
pub(crate) fn run(check: &Check, dir: &Path, out: &Path, limit: Duration) -> Json {
    let (stdout, stderr) = (out.join("stdout"), out.join("stderr"));
    let started = Instant::now();
    let child = fs::create_dir_all(out)
        .and_then(|()| File::create(&stdout))
        .and_then(|so| File::create(&stderr).map(|se| (so, se)))
        .and_then(|(so, se)| {
            let program = check.command.first().map_or("", String::as_str);
            Command::new(program)
                .args(check.command.iter().skip(1))
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(so)
                .stderr(se)
                .spawn()
        });
    let exit = child.ok().and_then(|mut child| {
        let (_keep, pause) = mpsc::channel::<()>();
        loop {
            if let Some(status) = child.try_wait().ok().flatten() {
                return status.code();
            }
            if started.elapsed() >= limit {
                let _killed = child.kill();
                let _reaped = child.wait();
                return None;
            }
            let _tick = pause.recv_timeout(POLL);
        }
    });
    Json::object([
        (
            "exit",
            exit.map_or(Json::Null, |code| Json::Number(code.to_string())),
        ),
        (
            "durationMs",
            Json::int(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
        ),
        ("stdout", output(&stdout)),
        ("stderr", output(&stderr)),
    ])
}

/// The version line of the program `program` (`go version`, else
/// `<program> --version`), if it answers.
fn version(program: &str) -> Option<String> {
    Command::new(program)
        .arg(version_flag(program))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .map(|line| line.trim().to_owned())
        })
}

/// How `program` is asked its version.
fn version_flag(program: &str) -> &'static str {
    if program == "go" {
        "version"
    } else {
        "--version"
    }
}

/// A detached worktree of `commit` at `dir` with the root's dependency
/// directories linked in.
///
/// # Errors
///
/// When git cannot add it.
pub(crate) fn worktree(git: &Git, commit: &str, dir: &Path) -> Result<(), String> {
    git.run(&[
        "worktree",
        "add",
        "--detach",
        "--force",
        &dir.to_string_lossy(),
        commit,
    ])?;
    for name in LINKED {
        let source = git.root().join(name);
        if source.is_dir() && !dir.join(name).exists() {
            let _linked = std::os::unix::fs::symlink(&source, dir.join(name));
        }
    }
    Ok(())
}

/// What evidence is about.
#[derive(Debug, Clone, Copy)]
pub(crate) struct About<'a> {
    /// The run id.
    pub(crate) run: &'a str,
    /// The request digest of the run.
    pub(crate) request: &'a str,
    /// The base commit.
    pub(crate) base: &'a str,
    /// The head of the delivered branch.
    pub(crate) head: &'a str,
}

/// The evidence document: `checks` run on the base and the head (in
/// worktrees under `scratch`, each within `limit`), with the toolchains'
/// versions.
///
/// # Errors
///
/// When a worktree cannot be made.
pub(crate) fn evidence(
    git: &Git,
    about: About<'_>,
    checks: &[Check],
    (scratch, limit): (&Path, Duration),
) -> Result<Json, String> {
    let (base_dir, head_dir) = (scratch.join("base"), scratch.join("head"));
    let made =
        worktree(git, about.base, &base_dir).and_then(|()| worktree(git, about.head, &head_dir));
    let results: Vec<Json> = if made.is_ok() {
        checks
            .iter()
            .enumerate()
            .map(|(n, one)| {
                let base = run(
                    one,
                    &base_dir,
                    &scratch.join(format!("out/{n}/base")),
                    limit,
                );
                let head = run(
                    one,
                    &head_dir,
                    &scratch.join(format!("out/{n}/head")),
                    limit,
                );
                Json::object([
                    ("kind", Json::text(&one.kind)),
                    (
                        "command",
                        Json::Array(one.command.iter().map(|arg| Json::text(arg)).collect()),
                    ),
                    ("source", Json::text(&one.source)),
                    ("base", base),
                    ("head", head),
                ])
            })
            .collect()
    } else {
        Vec::new()
    };
    for dir in [&base_dir, &head_dir] {
        let _removed = git.run(&["worktree", "remove", "--force", &dir.to_string_lossy()]);
    }
    made?;
    let mut programs: Vec<&str> = checks
        .iter()
        .filter_map(|one| one.command.first().map(String::as_str))
        .collect();
    programs.sort_unstable();
    programs.dedup();
    let toolchains = programs
        .into_iter()
        .map(|program| {
            Json::object([
                ("name", Json::text(program)),
                (
                    "version",
                    version(program).map_or(Json::Null, |v| Json::text(&v)),
                ),
            ])
        })
        .collect();
    Ok(Json::object([
        ("schemaVersion", Json::int(1_u32)),
        ("run", Json::text(about.run)),
        ("request", Json::text(about.request)),
        ("base", Json::text(about.base)),
        ("head", Json::text(about.head)),
        ("toolchains", Json::Array(toolchains)),
        ("checks", Json::Array(results)),
    ]))
}

#[cfg(test)]
mod tests;
