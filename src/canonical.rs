//! Deterministic JSON output: object members sorted by key (byte order),
//! no insignificant whitespace.
//! Writing never fails, so the same value always gives the same bytes.
//! The backend writes requests the same way, so the request digest the
//! engine computes is the one the backend reports (`docs/api.md`).
//!
//! Standards: SCF TDA-06.5 (reproducible outputs); OWASP ASVS 5.0 V1.2
//! (output encoding: every string is escaped).

use std::collections::BTreeMap;

use serde_json::Value;

/// A JSON value to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, already in its JSON form (an integer, or as `serde_json`
    /// printed it).
    Number(String),
    /// A string.
    String(String),
    /// An array, in order.
    Array(Vec<Self>),
    /// An object; its members are written sorted by key.
    Object(BTreeMap<String, Self>),
}

impl Json {
    /// A string value.
    pub(crate) fn text(text: &str) -> Self {
        Self::String(text.to_owned())
    }

    /// An integer value.
    pub(crate) fn int(value: impl Into<u64>) -> Self {
        Self::Number(value.into().to_string())
    }

    /// An object from `members`.
    pub(crate) fn object<const N: usize>(members: [(&str, Self); N]) -> Self {
        Self::Object(
            members
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }

    /// `value` with every object's members sorted.
    pub(crate) fn from_value(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(flag) => Self::Bool(*flag),
            Value::Number(number) => Self::Number(number.to_string()),
            Value::String(text) => Self::text(text),
            Value::Array(items) => Self::Array(items.iter().map(Self::from_value).collect()),
            Value::Object(members) => Self::Object(
                members
                    .iter()
                    .map(|(key, member)| (key.clone(), Self::from_value(member)))
                    .collect(),
            ),
        }
    }

    /// The value's bytes.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    /// Appends the value's bytes to `out`.
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.extend_from_slice(b"null"),
            Self::Bool(true) => out.extend_from_slice(b"true"),
            Self::Bool(false) => out.extend_from_slice(b"false"),
            Self::Number(number) => out.extend_from_slice(number.as_bytes()),
            Self::String(text) => string(text, out),
            Self::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    item.write(out);
                }
                out.push(b']');
            }
            Self::Object(members) => {
                out.push(b'{');
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    string(key, out);
                    out.push(b':');
                    value.write(out);
                }
                out.push(b'}');
            }
        }
    }
}

/// Appends `text` as a JSON string: `"` and `\` escaped, control
/// characters as `\n`, `\r`, `\t` or `\u00XX`, everything else as UTF-8.
fn string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in text.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if u32::from(c) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", u32::from(c)).as_bytes());
            }
            c => {
                let mut buffer = [0; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests;
