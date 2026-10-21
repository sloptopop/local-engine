//! Unit tests for [`super`].

use super::{FILE, REQUEST, digest, run_id};

#[test]
fn request_digests_and_run_ids() {
    let text = digest(REQUEST, b"{}");
    assert_eq!(
        text,
        format!(
            "blake3:{}",
            blake3::Hash::from(blake3::derive_key("sloptopop transform request v1", b"{}"))
                .to_hex()
        ),
        "derive_key"
    );
    let id = run_id(&text);
    assert_eq!(id.len(), 16, "{id}");
    assert!(text.starts_with(&format!("blake3:{id}")), "a prefix");
}

#[test]
fn file_digests_are_the_servers_span_digest() {
    assert_eq!(
        digest(FILE, b"abc"),
        format!(
            "blake3:{}",
            blake3::Hash::from(blake3::derive_key("sloptopop bir v2 span", b"abc")).to_hex()
        ),
        "the whole-file digest"
    );
}
