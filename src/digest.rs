//! The digests `sloptopop local` exchanges with the server: the request
//! digest (`blake3:` and 64 hex digits of `derive_key("sloptopop
//! transform request v1", canonical bytes)`, as the server computes it),
//! the run id taken from it, and the whole-file digests of the changes it
//! applies (`derive_key("sloptopop bir v2 span", bytes)`).
//!
//! Standards: SCF TDA-20.3 (integrity: the response is bound to the
//! request it answers); NIST SSDF PS.2.1.

/// The key-derivation context of a request digest.
pub(crate) const REQUEST: &str = "sloptopop transform request v1";

/// The key-derivation context of a whole-file digest (the server's
/// `before` and `after`: the Implementor's span digest of the whole file).
pub(crate) const FILE: &str = "sloptopop bir v2 span";

/// The digest of `bytes` under `context`.
pub(crate) fn digest(context: &str, bytes: &[u8]) -> String {
    format!(
        "blake3:{}",
        blake3::Hash::from(blake3::derive_key(context, bytes)).to_hex()
    )
}

/// The run id of a request digest: its first 16 hex digits.
pub(crate) fn run_id(digest: &str) -> String {
    digest.chars().skip("blake3:".len()).take(16).collect()
}

#[cfg(test)]
mod tests;
