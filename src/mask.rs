//! Masking secret values before upload (decision D-0174, SPLIT): on every
//! line the secret scanner reports a result on, in any file, each
//! value-like token is replaced by `x`s of the same length (a documented
//! public prefix such as `sk_live_` or `ghp_` is kept, so the provider
//! stays known); when a result's reported columns are still not covered,
//! the longest token in them is masked too ([`cover`]), so every reported
//! span ends up masked. After a step the real bytes are put back at the
//! same tokens, moved by the step's edits. When a run is applied, the masks
//! are found again by comparing the real file with the uploaded one
//! ([`diff`]): no copy of a secret, and no list of where secrets are, is
//! ever written.
//!
//! A token is a run of ASCII letters, digits and `_ - + / =`: inside a
//! quoted string (`'`, `"` or `` ` ``) any run of at least 8; outside one,
//! a run of at least 16 holding a letter and a digit; and every run on the
//! lines of a PEM private-key block. PEM armour (any run holding `-----`)
//! is never masked.
//!
//! Standards: OWASP ASVS 5.0 V13.3.1 (secrets never leave the machine),
//! V14.2.4; SCF IAC-14 (credential protection), PRI-05 (data minimisation);
//! CWE-200.

use std::collections::BTreeSet;

/// Documented public prefixes of credential formats (Stripe, GitHub,
/// GitLab, Slack, AWS, Google, npm), kept in the clear.
const PREFIXES: [&str; 20] = [
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "pk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "AKIA",
    "ASIA",
    "AIza",
    "npm_",
];

/// The shortest token masked inside quotes.
const QUOTED: usize = 8;

/// The shortest token masked outside quotes.
const BARE: usize = 16;

/// A masked byte range of a file (after any kept prefix), never empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Mask {
    /// First byte.
    pub(crate) start: usize,
    /// One past the last byte.
    pub(crate) end: usize,
}

/// An edit of the base, as the Implementor reports it: the replaced range
/// and the length of the text that replaces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Edit {
    /// First byte replaced.
    pub(crate) start: usize,
    /// One past the last byte replaced.
    pub(crate) end: usize,
    /// The length of the new text.
    pub(crate) len: usize,
}

/// Whether `byte` may be part of a token.
const fn token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=')
}

/// The masks of `text` on the 1-based `lines`.
pub(crate) fn masks(text: &str, lines: &BTreeSet<u32>) -> Vec<Mask> {
    let mut out = Vec::new();
    let mut offset = 0;
    let mut in_key = false;
    for (number, line) in (1..).zip(text.split_inclusive('\n')) {
        let bytes = line.as_bytes();
        if in_key {
            if line.contains("-----END") {
                in_key = false;
            } else {
                runs(bytes, offset, 1, false, &mut out);
            }
        } else if lines.contains(&number) {
            line_masks(bytes, offset, &mut out);
            in_key = line.contains("-----BEGIN")
                && line.contains("PRIVATE KEY-----")
                && !line.contains("-----END");
        }
        offset += line.len();
    }
    out
}

/// The masks of one named line starting at `offset`.
fn line_masks(bytes: &[u8], offset: usize, out: &mut Vec<Mask>) {
    let mut at = 0;
    let mut bare = 0;
    while let Some(&byte) = bytes.get(at) {
        if matches!(byte, b'\'' | b'"' | b'`') {
            segment(bytes, bare, at, offset, BARE, true, out);
            let close = closing(bytes, at + 1, byte);
            segment(bytes, at, close, offset, QUOTED, false, out);
            at = close + 1;
            bare = at;
        } else {
            at += 1;
        }
    }
    segment(bytes, bare, bytes.len(), offset, BARE, true, out);
}

/// The index of the quote that closes one opened before `from` (or the
/// end of the line).
fn closing(bytes: &[u8], from: usize, quote: u8) -> usize {
    let mut at = from;
    while let Some(&byte) = bytes.get(at) {
        if byte == quote {
            return at;
        }
        at += if byte == b'\\' { 2 } else { 1 };
    }
    bytes.len()
}

/// The token runs of `bytes[from..to]` of at least `min` bytes, as masks
/// shifted by `offset` (see [`runs`]).
fn segment(
    bytes: &[u8],
    from: usize,
    to: usize,
    offset: usize,
    min: usize,
    mixed: bool,
    out: &mut Vec<Mask>,
) {
    runs(
        bytes.get(from..to).unwrap_or_default(),
        offset + from,
        min,
        mixed,
        out,
    );
}

/// The token runs of `bytes` of at least `min` bytes (with `mixed`, only
/// those holding a letter and a digit; never PEM armour), as masks shifted
/// by `offset`, a documented prefix kept.
fn runs(bytes: &[u8], offset: usize, min: usize, mixed: bool, out: &mut Vec<Mask>) {
    let mut start = offset;
    for run in bytes.split(|byte| !token(*byte)) {
        let letter = run.iter().any(u8::is_ascii_alphabetic);
        let digit = run.iter().any(u8::is_ascii_digit);
        let armour = run.windows(5).any(|window| window == b"-----");
        let kept = PREFIXES
            .iter()
            .filter(|prefix| run.starts_with(prefix.as_bytes()))
            .map(|prefix| prefix.len())
            .max()
            .unwrap_or(0);
        if run.len() >= min && kept < run.len() && !armour && (!mixed || (letter && digit)) {
            out.push(Mask {
                start: start + kept,
                end: start + run.len(),
            });
        }
        start += run.len() + 1;
    }
}

/// A span a scanner reported: a 1-based line and 1-based byte columns on
/// it (the end column included), as SARIF regions give them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Span {
    /// The line.
    pub(crate) line: u32,
    /// The first column.
    pub(crate) start: u32,
    /// The last column.
    pub(crate) end: u32,
}

/// `masks` (of `text`) with, for every span of `spans` that no mask
/// overlaps, the longest token run within it, from one column before to one
/// after (scanners differ by one), masked too (a documented prefix kept),
/// sorted.
pub(crate) fn cover(text: &str, spans: &[Span], mut masks: Vec<Mask>) -> Vec<Mask> {
    let starts: Vec<usize> = std::iter::once(0)
        .chain(text.match_indices('\n').map(|(at, _)| at + 1))
        .collect();
    for span in spans {
        let Some(&line_start) = usize::try_from(span.line)
            .ok()
            .and_then(|line| starts.get(line.saturating_sub(1)))
        else {
            continue;
        };
        let line_end = text
            .get(line_start..)
            .and_then(|rest| rest.find('\n'))
            .map_or(text.len(), |at| line_start + at);
        let column = |c: u32| usize::try_from(c).unwrap_or(usize::MAX);
        let from = (line_start + column(span.start).saturating_sub(2)).min(line_end);
        let to = line_start
            .saturating_add(column(span.end).saturating_add(1))
            .min(line_end);
        if masks.iter().any(|mask| mask.start < to && mask.end > from) {
            continue;
        }
        let bytes = text
            .as_bytes()
            .get(line_start..line_end)
            .unwrap_or_default();
        let mut found = Vec::new();
        runs(bytes, line_start, 1, false, &mut found);
        if let Some(longest) = found
            .into_iter()
            .filter(|mask| mask.start < to && mask.end > from)
            .max_by_key(|mask| (mask.end - mask.start, mask.start))
        {
            masks.push(longest);
        }
    }
    masks.sort_by_key(|mask| (mask.start, mask.end));
    masks
}

/// The masks that turn `real` into `uploaded`: every maximal run of `x`s
/// in `uploaded` in which `real` differs; `None` when the two differ in
/// length or anywhere else (the upload is not this file masked).
pub(crate) fn diff(real: &[u8], uploaded: &[u8]) -> Option<Vec<Mask>> {
    if real.len() != uploaded.len() {
        return None;
    }
    let differs = |start: usize, end: usize| real.get(start..end) != uploaded.get(start..end);
    let mut out = Vec::new();
    let mut run = None;
    for (at, (real_byte, uploaded_byte)) in real.iter().zip(uploaded).enumerate() {
        if *uploaded_byte == b'x' {
            run.get_or_insert(at);
            continue;
        }
        if let Some(start) = run.take()
            && differs(start, at)
        {
            out.push(Mask { start, end: at });
        }
        if real_byte != uploaded_byte {
            return None;
        }
    }
    if let Some(start) = run
        && differs(start, uploaded.len())
    {
        out.push(Mask {
            start,
            end: uploaded.len(),
        });
    }
    Some(out)
}

/// `text` with every mask's bytes replaced by `x`.
pub(crate) fn apply(text: &str, masks: &[Mask]) -> String {
    let mut bytes = text.as_bytes().to_vec();
    for mask in masks {
        for byte in bytes.get_mut(mask.start..mask.end).unwrap_or_default() {
            *byte = b'x';
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `after` (the base with `edits`, which are in base offsets) with the real
/// bytes of `base` put back at every mask an edit did not replace.
///
/// # Errors
///
/// When an edit cuts into a mask, or the masked bytes are not where the
/// edits say (the file is not the masked base with these edits).
pub(crate) fn restore(
    after: &[u8],
    base: &[u8],
    masks: &[Mask],
    edits: &[Edit],
) -> Result<Vec<u8>, String> {
    let mut out = after.to_vec();
    for mask in masks {
        let covered = edits
            .iter()
            .any(|edit| edit.start <= mask.start && edit.end >= mask.end);
        let cut = edits
            .iter()
            .any(|edit| edit.start < mask.end && edit.end > mask.start);
        if covered {
            continue;
        }
        if cut {
            return Err(format!(
                "an edit cuts into the masked value at byte {}",
                mask.start
            ));
        }
        let before: usize = edits
            .iter()
            .filter(|edit| edit.end <= mask.start)
            .map(|edit| edit.len)
            .sum();
        let removed: usize = edits
            .iter()
            .filter(|edit| edit.end <= mask.start)
            .map(|edit| edit.end - edit.start)
            .sum();
        let at = (mask.start + before)
            .checked_sub(removed)
            .unwrap_or(usize::MAX);
        let len = mask.end - mask.start;
        let placed = out
            .get_mut(at..at.saturating_add(len))
            .filter(|bytes| bytes.iter().all(|byte| *byte == b'x'));
        let real = base.get(mask.start..mask.end);
        match (placed, real) {
            (Some(placed), Some(real)) => placed.copy_from_slice(real),
            _ => {
                return Err(format!(
                    "the masked value at byte {} is not where it should be",
                    mask.start
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
