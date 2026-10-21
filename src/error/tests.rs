//! Unit tests for [`super`].

use super::Error;

#[test]
fn errors_say_why() {
    let error = Error::Local("the tree is dirty".to_owned());
    assert_eq!(error.to_string(), "the tree is dirty", "display");
    let dynamic: &dyn std::error::Error = &error;
    assert!(dynamic.source().is_none(), "no source");
}
