//! Crate-wide unit tests, and the helpers every module's tests share.
//! Kept under `tests` so coverage measures product code only.

pub(crate) mod support;

#[test]
fn the_tool_is_sloptopop_local() {
    assert_eq!(super::TOOL.name, "sloptopop-local", "name");
    assert_eq!(super::TOOL.version, env!("CARGO_PKG_VERSION"), "version");
}
