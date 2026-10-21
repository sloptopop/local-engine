//! Unit tests for [`super`].

use std::collections::BTreeSet;

use super::{Edit, Mask, Span, apply, cover, diff, masks, restore};

fn lines(list: &[u32]) -> BTreeSet<u32> {
    list.iter().copied().collect()
}

/// The masked text of `text` on `list`.
fn masked(text: &str, list: &[u32]) -> String {
    apply(text, &masks(text, &lines(list)))
}

#[test]
fn quoted_tokens_on_named_lines_are_masked_keeping_documented_prefixes() {
    let text = concat!(
        "const a = 'sk_",
        "live_4eC39HqLyjWDarjtT1zdp7dc';\nconst b = 'sk_",
        "live_4eC39HqLyjWDarjtT1zdp7dc';\n"
    );
    assert_eq!(
        masked(text, &[1]),
        concat!(
            "const a = 'sk_",
            "live_xxxxxxxxxxxxxxxxxxxxxxxx';\nconst b = 'sk_",
            "live_4eC39HqLyjWDarjtT1zdp7dc';\n"
        ),
        "only the named line, the prefix kept, the same length"
    );
    assert_eq!(
        masked(
            "x = \"Bearer abcdefgh1\" + `short` + 'it\\'s abcdefghij'\n",
            &[1]
        ),
        "x = \"Bearer xxxxxxxxx\" + `short` + 'it\\'s xxxxxxxxxx'\n",
        "runs of 8 or more inside quotes, escapes skipped"
    );
    assert_eq!(
        masked("key = 'unterminated abcdefghijk\n", &[1]),
        "key = 'xxxxxxxxxxxx xxxxxxxxxxx\n",
        "an open quote runs to the end of the line"
    );
    assert_eq!(
        masked("const github = 'github_pat_11ABCDEFG0123456789';\n", &[1]),
        "const github = 'github_pat_xxxxxxxxxxxxxxxxxxx';\n",
        "the longest prefix"
    );
    assert!(
        masks("x = 'github_pat_'\n", &lines(&[1])).is_empty(),
        "a bare prefix holds nothing to mask"
    );
}

#[test]
fn bare_tokens_need_sixteen_bytes_a_letter_and_a_digit() {
    assert_eq!(
        masked(
            "token: AKIAIOSFODNN7EXAMPLE1 SUPABASE_SERVICE_ROLE_KEY 123456789012345678\n",
            &[1]
        ),
        "token: AKIAxxxxxxxxxxxxxxxxx SUPABASE_SERVICE_ROLE_KEY 123456789012345678\n",
        "letters and digits mixed, 16 or more"
    );
    assert_eq!(
        masked("short a1b2c3d4e5f6g7\n", &[1]),
        "short a1b2c3d4e5f6g7\n",
        "15 bytes"
    );
    assert_eq!(
        masked("k = 'x' abcdefgh12 'y'\n", &[1]),
        "k = 'x' abcdefgh12 'y'\n",
        "text between two strings is bare"
    );
    assert_eq!(
        masked("a = 'x' b0123456789abcdefg\n", &[1]),
        "a = 'x' xxxxxxxxxxxxxxxxxx\n",
        "after a quote"
    );
}

#[test]
fn private_key_blocks_are_masked_to_their_end() {
    let text = concat!(
        "key = '''\n-----BEGIN RSA PRIVATE ",
        "KEY-----\nMIIEowIBAAKCAQEA0123456789\nabc\n-----END RSA PRIVATE ",
        "KEY-----\nafter_0123456789abcdef\n"
    );
    assert_eq!(
        masked(text, &[2]),
        concat!(
            "key = '''\n-----BEGIN RSA PRIVATE ",
            "KEY-----\nxxxxxxxxxxxxxxxxxxxxxxxxxx\nxxx\n-----END RSA PRIVATE ",
            "KEY-----\nafter_0123456789abcdef\n"
        ),
        "every token of the block's lines, however short, not after it"
    );
    let one_line = concat!(
        "\"key\": \"-----BEGIN PRIVATE ",
        "KEY-----\\nMIIEvgIBADANBgkq\\n-----END PRIVATE ",
        "KEY-----\\n\",\nnext 'abcdefghij'\n"
    );
    assert_eq!(
        masked(one_line, &[1]),
        concat!(
            "\"key\": \"-----BEGIN PRIVATE ",
            "KEY-----\\xxxxxxxxxxxxxxxxx\\n-----END PRIVATE ",
            "KEY-----\\n\",\nnext 'abcdefghij'\n"
        ),
        "a key on one line is masked as quoted text and opens no block"
    );
    assert_eq!(
        masked(
            concat!("-----BEGIN PRIVATE ", "KEY-----\nMIIEvgIBADANBgkq\n"),
            &[]
        ),
        concat!("-----BEGIN PRIVATE ", "KEY-----\nMIIEvgIBADANBgkq\n"),
        "an unnamed line opens no block"
    );
}

#[test]
fn real_bytes_come_back_where_the_edits_moved_them() {
    let base = b"a = 'secret12345';\nb = 'other123456';\n";
    let text = std::str::from_utf8(base).unwrap();
    let found = masks(text, &lines(&[1, 2]));
    assert_eq!(
        found,
        [Mask { start: 5, end: 16 }, Mask { start: 24, end: 35 }],
        "masks"
    );
    let masked_base = apply(text, &found);
    let mut after = masked_base.as_bytes().to_vec();
    after.splice(0..0, b"// x\n".iter().copied());
    let insert = Edit {
        start: 0,
        end: 0,
        len: 5,
    };
    let restored = restore(&after, base, &found, &[insert]).unwrap();
    assert_eq!(
        restored,
        [b"// x\n".as_slice(), base].concat(),
        "moved by an insertion"
    );

    let replace = Edit {
        start: 4,
        end: 17,
        len: 3,
    };
    let mut replaced = masked_base.as_bytes().to_vec();
    replaced.splice(4..17, b"env".iter().copied());
    let expected = b"a = env;\nb = 'other123456';\n";
    assert_eq!(
        restore(&replaced, base, &found, &[replace]).unwrap(),
        expected,
        "a replaced value stays replaced, the next one moves back"
    );
    let shrink = Edit {
        start: 0,
        end: 4,
        len: 0,
    };
    let mut fewer = masked_base.as_bytes().to_vec();
    fewer.drain(0..4);
    assert_eq!(
        restore(&fewer, base, &found, &[shrink]).unwrap(),
        &base[4..],
        "moved back by a deletion"
    );
}

#[test]
fn edits_that_cut_into_masks_or_misplaced_bytes_are_refused() {
    let base = b"a = 'secret12345';\n";
    let found = [Mask { start: 5, end: 16 }];
    let masked_base = apply(std::str::from_utf8(base).unwrap(), &found);
    let cut = restore(
        masked_base.as_bytes(),
        base,
        &found,
        &[Edit {
            start: 10,
            end: 20,
            len: 1,
        }],
    );
    assert!(cut.unwrap_err().contains("cuts into"), "a partial overlap");
    let inside = restore(
        masked_base.as_bytes(),
        base,
        &found,
        &[Edit {
            start: 8,
            end: 8,
            len: 1,
        }],
    );
    assert!(
        inside.unwrap_err().contains("cuts into"),
        "an insertion inside"
    );
    let at_end = restore(
        masked_base.as_bytes(),
        base,
        &found,
        &[Edit {
            start: 16,
            end: 16,
            len: 0,
        }],
    );
    assert_eq!(at_end.unwrap(), base, "an insertion right after is fine");
    let moved = restore(base, base, &found, &[]);
    assert!(
        moved.unwrap_err().contains("not where"),
        "no placeholder there"
    );
    let short = restore(masked_base.as_bytes(), b"a", &found, &[]);
    assert!(
        short.unwrap_err().contains("not where"),
        "a base without those bytes"
    );
    let mut shifted = masked_base.as_bytes().to_vec();
    shifted.splice(5..5, b"zz".iter().copied());
    let before = restore(
        &shifted,
        base,
        &found,
        &[Edit {
            start: 5,
            end: 5,
            len: 2,
        }],
    );
    assert_eq!(
        before.unwrap(),
        b"a = 'zzsecret12345';\n",
        "an insertion right before moves it"
    );
}

/// The masked text of `text` with the line masks of `lines` and the
/// spans `spans` covered.
fn covered(text: &str, list: &[u32], spans: &[Span]) -> String {
    apply(text, &cover(text, spans, masks(text, &lines(list))))
}

/// A span on `line` from column `start` to `end`.
const fn span(line: u32, start: u32, end: u32) -> Span {
    Span { line, start, end }
}

#[test]
fn reported_spans_no_line_mask_covers_get_their_longest_token() {
    assert_eq!(
        covered("pw = abc1\n", &[1], &[span(1, 6, 9)]),
        "pw = xxxx\n",
        "a short bare value the line rules leave"
    );
    assert_eq!(
        covered("a\nkey: s3cr3t # note\n", &[], &[span(2, 6, 11)]),
        "a\nkey: xxxxxx # note\n",
        "the longest token in the span, one column either side"
    );
    assert_eq!(
        covered("x = 'ghp_aaaaaaaaaaaaaaaa'\n", &[1], &[span(1, 6, 25)]),
        "x = 'ghp_xxxxxxxxxxxxxxxx'\n",
        "already covered: nothing more"
    );
    assert_eq!(
        covered("k = ab cd\n", &[], &[span(1, 5, 9)]),
        "k = ab xx\n",
        "equal lengths: the later token"
    );
    assert_eq!(
        covered(
            "k = !!\nz",
            &[],
            &[span(1, 5, 6), span(9, 1, 1), span(2, 1, u32::MAX)]
        ),
        "k = !!\nx",
        "no token, a line past the end, a span to the end of the last line"
    );
    assert_eq!(
        covered("k = abcd e\n", &[], &[span(1, 5, 10)]),
        "k = xxxx e\n",
        "the longest token, not the last"
    );
    for (beside, why) in [
        (
            Mask { start: 7, end: 9 },
            "a mask starting where the span ends",
        ),
        (
            Mask { start: 0, end: 3 },
            "a mask ending where the span starts",
        ),
    ] {
        let mut expected = vec![beside, Mask { start: 4, end: 6 }];
        expected.sort_by_key(|mask| mask.start);
        assert_eq!(
            cover("k = ab cd\n", &[span(1, 5, 6)], vec![beside]),
            expected,
            "{why} does not cover it"
        );
    }
    let twice = cover("aa bb\n", &[span(1, 1, 2), span(1, 1, 2)], Vec::new());
    assert_eq!(twice, [Mask { start: 0, end: 2 }], "each mask once");
}

#[test]
fn masks_are_found_again_from_the_real_and_the_uploaded_file() {
    let real = b"k = 'ghp_s3cretx1'\n";
    let uploaded = b"k = 'ghp_xxxxxxxx'\n";
    assert_eq!(
        diff(real, uploaded),
        Some(vec![Mask { start: 9, end: 17 }]),
        "the masked run, its real x included"
    );
    assert_eq!(diff(b"xox", b"xox"), Some(Vec::new()), "x that are real");
    assert_eq!(
        diff(b"ab=cd", b"xx=xx"),
        Some(vec![Mask { start: 0, end: 2 }, Mask { start: 3, end: 5 }]),
        "two runs"
    );
    assert_eq!(diff(b"abc", b"abcd"), None, "another length");
    assert_eq!(diff(b"abc", b"abd"), None, "another byte outside a mask");
    assert_eq!(
        diff(b"ab", b"xx"),
        Some(vec![Mask { start: 0, end: 2 }]),
        "at the start and end"
    );
}
