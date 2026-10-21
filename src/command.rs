//! Parsing the `sloptopop-local` command line.
//!
//! Standards: SCF TDA-12 (Input Data Validation: only the documented
//! commands and options are accepted; anything else is a usage error).

/// The usage text printed after a usage error.
pub(crate) const USAGE: &str = "\
Usage: sloptopop-local request <root> --mode check|fix|transform
       sloptopop-local report <root> --run <id>
       sloptopop-local apply <root> --run <id> [--apply] [--branch <name>]
                       [--confirm <id,...> --by <name>]
       sloptopop-local evidence <root> --run <id>
       sloptopop-local version
";

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command<'a> {
    /// `request <root> --mode <mode>`.
    Request(&'a str, &'a str),
    /// `report <root> --run <id>`.
    Report(&'a str, &'a str),
    /// `apply <root> --run <id> …`.
    Apply(Apply<'a>),
    /// `evidence <root> --run <id>`.
    Evidence(&'a str, &'a str),
    /// `version`.
    Version,
}

/// The arguments of `apply`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Apply<'a> {
    /// The repository root.
    pub(crate) root: &'a str,
    /// The run id.
    pub(crate) run: &'a str,
    /// `--apply`: commit the delivered steps.
    pub(crate) commit: bool,
    /// `--branch <name>`.
    pub(crate) branch: Option<&'a str>,
    /// `--confirm <id,...>`.
    pub(crate) confirm: Vec<&'a str>,
    /// `--by <name>`.
    pub(crate) by: Option<&'a str>,
}

/// Parses the arguments after the program name.
pub(crate) fn parse(args: &[String]) -> Result<Command<'_>, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["version" | "--version" | "-V"] => Ok(Command::Version),
        ["request" | "report" | "apply" | "evidence", root, ..] if root.starts_with('-') => {
            Err(format!("expected a repository root, got {root}"))
        }
        [
            "request",
            root,
            "--mode",
            mode @ ("check" | "fix" | "transform"),
        ] => Ok(Command::Request(root, mode)),
        ["report", root, "--run", run] => Ok(Command::Report(root, run)),
        ["evidence", root, "--run", run] => Ok(Command::Evidence(root, run)),
        ["apply", root, rest @ ..] => apply(root, rest).map(Command::Apply),
        _ => Err(format!("unrecognised arguments: {}", args.join(" "))),
    }
}

/// The options of `apply <root>`.
fn apply<'a>(root: &'a str, rest: &[&'a str]) -> Result<Apply<'a>, String> {
    let mut out = Apply {
        root,
        ..Apply::default()
    };
    let mut rest = rest.iter();
    while let Some(&flag) = rest.next() {
        if flag == "--apply" {
            out.commit = true;
            continue;
        }
        let value = rest
            .next()
            .copied()
            .filter(|value| !value.starts_with('-'))
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag {
            "--run" => out.run = value,
            "--branch" => out.branch = Some(value),
            "--confirm" => out
                .confirm
                .extend(value.split(',').filter(|id| !id.is_empty())),
            "--by" => out.by = Some(value),
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if out.run.is_empty() {
        return Err("apply needs --run <id>".to_owned());
    }
    if out.confirm.is_empty() != out.by.is_none() {
        return Err("--confirm and --by go together".to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
