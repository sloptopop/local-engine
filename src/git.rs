//! Running `git` for the transform, the way delivery needs it: argument
//! vectors only (never a shell), `LC_ALL=C`, no prompts, no hooks, no
//! signing, no pager or colours, and none of the caller's `GIT_DIR`,
//! `GIT_WORK_TREE` or `GIT_INDEX_FILE` unless the engine sets them itself.
//! The engine never runs a command that changes the checkout, its index
//! or `HEAD`.
//!
//! Standards: SCF CHG-03 (Configuration Change Control: changes only on a
//! new branch), TDA-12.1; OWASP ASVS 5.0 V1.2.5 (no OS command injection:
//! argument vectors, never a shell); CWE-78.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

/// A `git` to run in one repository.
#[derive(Debug, Clone)]
pub(crate) struct Git {
    /// The program (`git`, found on `PATH`).
    program: OsString,
    /// The repository root.
    root: PathBuf,
    /// Extra environment variables.
    env: Vec<(String, String)>,
}

impl Git {
    /// `git` in `root`.
    pub(crate) fn new(root: &Path) -> Self {
        Self::with_program("git", root)
    }

    /// `program` as git in `root`.
    pub(crate) fn with_program(program: impl Into<OsString>, root: &Path) -> Self {
        Self {
            program: program.into(),
            root: root.to_path_buf(),
            env: Vec::new(),
        }
    }

    /// This git with `key=value` in its environment.
    pub(crate) fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.to_owned(), value.to_owned()));
        self
    }

    /// The repository root.
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Runs `git <args>`; its stdout.
    ///
    /// # Errors
    ///
    /// Why git could not run or failed, with its stderr.
    pub(crate) fn run(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        self.exec(args, None)
    }

    /// Runs `git <args>` with `stdin`; its stdout.
    ///
    /// # Errors
    ///
    /// As [`Git::run`].
    pub(crate) fn input(&self, args: &[&str], stdin: &[u8]) -> Result<Vec<u8>, String> {
        self.exec(args, Some(stdin))
    }

    /// Runs `git <args>`; its stdout as text, without the final newline.
    ///
    /// # Errors
    ///
    /// As [`Git::run`].
    pub(crate) fn text(&self, args: &[&str]) -> Result<String, String> {
        self.run(args)
            .map(|out| String::from_utf8_lossy(&out).trim_end().to_owned())
    }

    /// Runs the command.
    fn exec(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let mut command = Command::new(&self.program);
        command
            .arg("-C")
            .arg(&self.root)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.quotepath=off",
                "-c",
                "color.ui=never",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.pager=cat",
            ])
            .args(args)
            .env("LC_ALL", "C")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = command
            .spawn()
            .and_then(|mut child| {
                let pipe = child.stdin.take();
                thread::scope(|scope| {
                    if let (Some(mut pipe), Some(bytes)) = (pipe, stdin) {
                        scope.spawn(move || {
                            let _fed = pipe.write_all(bytes);
                        });
                    }
                    child.wait_with_output()
                })
            })
            .map_err(|error| format!("cannot run git: {error}"))?;
        if output.status.success() {
            Ok(output.stdout)
        } else {
            Err(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }
}

#[cfg(test)]
mod tests;
