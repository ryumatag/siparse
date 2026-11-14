/*!
Lexical scans over text already checked by the public input boundary.

Keep raw slices private so production parsers can compose scans without
revalidating each intermediate token.
*/

use crate::{iter::Bytes, simd};

#[inline]
pub(crate) fn sws(src: &str) -> &str {
    // Whitespace is ASCII, so the split is on a character boundary.
    &src[whitespace_len(src.as_bytes())..]
}

#[inline]
pub(crate) fn lws(src: &str) -> Option<&str> {
    let n = whitespace_len(src.as_bytes());
    if n == 0 {
        return None;
    }
    Some(&src[n..])
}

#[inline]
pub(crate) fn separator(src: &str, sep: char) -> Option<&str> {
    Some(sws(sws(src).strip_prefix(sep)?))
}

#[inline]
pub(crate) fn token(src: &str) -> Option<(&str, &str)> {
    split_run(src, simd::match_token_vectored)
}

#[inline]
pub(crate) fn digits(src: &str) -> Option<(&str, &str)> {
    split_run(src, simd::match_digits_vectored)
}

#[inline]
pub(crate) fn host(src: &str) -> Option<(&str, &str)> {
    // Only find the character-class extent. The public host scan and value
    // productions validate structure, while checked iteration need not.
    if let Some(rest) = src.strip_prefix('[') {
        let (address, rest) = split_run(rest, simd::match_ipv6_vectored)?;
        if !rest.starts_with(']') {
            return None;
        }
        // The brackets and the address are ASCII.
        return Some(src.split_at(address.len() + 2));
    }
    split_run(src, simd::match_hostname_vectored)
}

#[inline]
pub(crate) fn quoted_string(src: &str) -> Option<(&str, &str)> {
    if !src.starts_with('"') {
        return None;
    }
    let mut bytes = Bytes::new(src.as_bytes());
    // SAFETY: `starts_with` saw the opening quote.
    unsafe { bytes.advance(1) };

    loop {
        simd::match_qdtext_vectored(&mut bytes);
        match bytes.next()? {
            // The closing quote is ASCII, so the split is on a character
            // boundary.
            b'"' => return Some(src.split_at(bytes.pos())),
            _ => match bytes.next()? {
                b'\r' | b'\n' | 0x80.. => return None,
                _ => {}
            },
        }
    }
}

#[inline]
pub(crate) fn comment(src: &str) -> Option<(&str, &str)> {
    let bytes = src.as_bytes();
    if bytes.first() != Some(&b'(') {
        return None;
    }

    // Comments are rare and short, so a byte loop serves them. A counter in
    // place of recursion keeps deep nesting from growing the stack.
    let mut depth = 0usize;
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    // The parenthesis is ASCII, so the split is on a
                    // character boundary.
                    return Some(src.split_at(i + 1));
                }
            }
            b'\\' => match bytes.get(i + 1)? {
                b'\r' | b'\n' | 0x80.. => return None,
                _ => i += 1,
            },
            _ => {}
        }
        i += 1;
    }
    None
}

#[inline(always)]
pub(crate) fn split_run(
    src: &str,
    scan: fn(&mut Bytes<'_>),
) -> Option<(&str, &str)> {
    // Each supplied scanner consumes only ASCII, so its stopping position
    // is a character boundary in the original string.
    let mut bytes = Bytes::new(src.as_bytes());
    scan(&mut bytes);
    let n = bytes.pos();
    if n == 0 {
        return None;
    }
    Some(src.split_at(n))
}

#[inline]
fn whitespace_len(src: &[u8]) -> usize {
    // Whitespace runs are short, usually zero or one byte, so a block scan
    // would mostly miss.
    src.iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(src.len())
}

#[cfg(test)]
mod tests {
    use std::{
        format,
        string::{String, ToString},
        vec::Vec,
    };

    use super::*;

    #[test]
    fn whitespace() {
        assert_eq!(sws(""), "");
        assert_eq!(sws("a"), "a");
        assert_eq!(sws(" \t\r\n \t a b"), "a b");
        assert_eq!(sws("  "), "");
        assert_eq!(lws(""), None);
        assert_eq!(lws("a"), None);
        assert_eq!(lws("\r\n a"), Some("a"));
        assert_eq!(lws(" "), Some(""));
    }

    #[test]
    fn separators() {
        assert_eq!(separator("/UDP", '/'), Some("UDP"));
        assert_eq!(separator(" \r\n / \r\n UDP", '/'), Some("UDP"));
        assert_eq!(separator("/", '/'), Some(""));
        assert_eq!(separator("", '/'), None);
        assert_eq!(separator(" ", '/'), None);
        assert_eq!(separator("UDP", '/'), None);
        assert_eq!(separator("//", '/'), Some("/"));
    }

    #[test]
    fn tokens() {
        assert_eq!(token("INVITE"), Some(("INVITE", "")));
        assert_eq!(token("INVITE sip:"), Some(("INVITE", " sip:")));
        assert_eq!(
            token("-.!%*_+`'~09azAZ;"),
            Some(("-.!%*_+`'~09azAZ", ";"))
        );
        assert_eq!(token(""), None);
        assert_eq!(token(" INVITE"), None);
        assert_eq!(token(";"), None);
        assert_eq!(token("\u{e9}"), None);
        assert_eq!(token("a\u{e9}"), Some(("a", "\u{e9}")));
        // Longer than one SWAR block.
        let long = "z9hG4bK776asdhds-z9hG4bK776asdhds";
        assert_eq!(token(long), Some((long, "")));
        assert_eq!(
            token("z9hG4bK776asdhds,next"),
            Some(("z9hG4bK776asdhds", ",next"))
        );
    }

    #[test]
    fn digit_runs() {
        assert_eq!(digits("0"), Some(("0", "")));
        assert_eq!(digits("007 ACK"), Some(("007", " ACK")));
        assert_eq!(
            digits("12345678901234567890x"),
            Some(("12345678901234567890", "x"))
        );
        assert_eq!(digits(""), None);
        assert_eq!(digits("-1"), None);
        assert_eq!(digits("+1"), None);
        assert_eq!(digits(" 1"), None);
    }

    #[test]
    fn hosts() {
        assert_eq!(host("a"), Some(("a", "")));
        assert_eq!(
            host("pc33.atlanta.example.com;branch=1"),
            Some(("pc33.atlanta.example.com", ";branch=1"))
        );
        assert_eq!(host("192.0.2.4:5060"), Some(("192.0.2.4", ":5060")));
        assert_eq!(host("a-b.c_d"), Some(("a-b.c", "_d")));
        assert_eq!(host("[::1]"), Some(("[::1]", "")));
        assert_eq!(
            host("[2001:db8::192.0.2.4]:5060"),
            Some(("[2001:db8::192.0.2.4]", ":5060"))
        );
        assert_eq!(host("[fe80::1%25eth0]"), None);
        assert_eq!(host(""), None);
        assert_eq!(host(":5060"), None);
        assert_eq!(host("["), None);
        assert_eq!(host("[]"), None);
        assert_eq!(host("[::1"), None);
        assert_eq!(host("[::1 ]"), None);
        assert_eq!(host("[g::1]"), None);
        assert_eq!(host("\u{e9}.example"), None);
    }

    #[test]
    fn quoted_strings() {
        assert_eq!(quoted_string("\"\""), Some(("\"\"", "")));
        assert_eq!(quoted_string("\"a\" b"), Some(("\"a\"", " b")));
        assert_eq!(quoted_string("\"a;b,c\";x"), Some(("\"a;b,c\"", ";x")));
        assert_eq!(quoted_string("\"a\\\"b\""), Some(("\"a\\\"b\"", "")));
        assert_eq!(quoted_string("\"a\\\\\"b"), Some(("\"a\\\\\"", "b")));
        assert_eq!(quoted_string("\"\\\x01\""), Some(("\"\\\x01\"", "")));
        assert_eq!(
            quoted_string("\"\u{7530}\u{4e2d}\" <sip:t@example.com>"),
            Some(("\"\u{7530}\u{4e2d}\"", " <sip:t@example.com>"))
        );
        assert_eq!(quoted_string("\"a \r\n b\""), Some(("\"a \r\n b\"", "")));
        // Longer than one SWAR block before the escape and the end.
        let long = "\"0123456789abcdef\\\"0123456789abcdef\" rest";
        assert_eq!(
            quoted_string(long),
            Some((&long[..long.len() - 5], " rest"))
        );
        assert_eq!(quoted_string(""), None);
        assert_eq!(quoted_string("a\"b\""), None);
        assert_eq!(quoted_string("\""), None);
        assert_eq!(quoted_string("\"abc"), None);
        assert_eq!(quoted_string("\"abc\\"), None);
        assert_eq!(quoted_string("\"abc\\\""), None);
        assert_eq!(quoted_string("\"\\\r\n \""), None);
        assert_eq!(quoted_string("\"\\\u{e9}\""), None);
    }

    #[test]
    fn comments() {
        assert_eq!(comment("()"), Some(("()", "")));
        assert_eq!(comment("(a) b"), Some(("(a)", " b")));
        assert_eq!(comment("(a (b) c);x"), Some(("(a (b) c)", ";x")));
        assert_eq!(comment("((()))()"), Some(("((()))", "()")));
        assert_eq!(comment("(a \\) b) c"), Some(("(a \\) b)", " c")));
        assert_eq!(comment("(a \\( b)"), Some(("(a \\( b)", "")));
        assert_eq!(comment("(\\\\)x"), Some(("(\\\\)", "x")));
        assert_eq!(comment("(\\\x01)"), Some(("(\\\x01)", "")));
        // A quote is plain `ctext` in a comment, so it does not protect the
        // parenthesis after it.
        assert_eq!(comment("(\"(\")"), None);
        assert_eq!(comment("(\"(\"))"), Some(("(\"(\"))", "")));
        assert_eq!(comment("(a \r\n b)"), Some(("(a \r\n b)", "")));
        assert_eq!(
            comment("(\u{7530}\u{4e2d}) rest"),
            Some(("(\u{7530}\u{4e2d})", " rest"))
        );

        assert_eq!(comment(""), None);
        assert_eq!(comment("a(b)"), None);
        assert_eq!(comment(" (a)"), None);
        assert_eq!(comment("("), None);
        assert_eq!(comment("(a (b)"), None);
        assert_eq!(comment("(a\\"), None);
        assert_eq!(comment("(a\\)"), None);
        assert_eq!(comment("(\\\r\n b)"), None);
        assert_eq!(comment("(\\\u{e9})"), None);

        // Nesting deeper than any recursion could go is still read.
        let deep = format!("{}{}", "(".repeat(10_000), ")".repeat(10_000));
        assert_eq!(comment(&deep), Some((deep.as_str(), "")));
    }

    #[test]
    #[cfg_attr(miri, ignore = "exhaustive input is too slow under Miri")]
    fn comments_match_the_scalar_reference() {
        // Every string of up to four bytes from the bytes a comment turns on,
        // at every character boundary.
        const ALPHABET: &[char] = &['(', ')', '\\', 'a', '\r', '\u{e9}'];
        let mut inputs = Vec::from([String::new()]);
        for _ in 0..4 {
            let longer: Vec<_> = inputs
                .iter()
                .flat_map(|s| ALPHABET.iter().map(move |c| format!("{s}{c}")))
                .collect();
            inputs.extend(longer);
        }
        inputs.sort();
        inputs.dedup();

        for input in &inputs {
            let starts = input.char_indices().map(|(i, _)| i);
            for start in starts.chain([input.len()]) {
                let src = &input[start..];
                assert_eq!(comment(src), reference::comment(src), "{src:?}");
            }
        }
    }

    mod reference {
        pub(super) fn run(
            src: &str,
            accept: impl Fn(u8) -> bool,
        ) -> Option<(&str, &str)> {
            let n = src.bytes().take_while(|&b| accept(b)).count();
            if n == 0 {
                return None;
            }
            Some(src.split_at(n))
        }

        pub(super) fn is_token(b: u8) -> bool {
            b.is_ascii_alphanumeric() || b"-.!%*_+`'~".contains(&b)
        }

        pub(super) fn comment(src: &str) -> Option<(&str, &str)> {
            let bytes = src.as_bytes();
            if bytes.first() != Some(&b'(') {
                return None;
            }
            let mut open = 0;
            let mut i = 0;
            loop {
                match *bytes.get(i)? {
                    b'(' => open += 1,
                    b')' if open == 1 => return Some(src.split_at(i + 1)),
                    b')' => open -= 1,
                    b'\\' => match *bytes.get(i + 1)? {
                        b'\r' | b'\n' | 0x80.. => return None,
                        _ => i += 1,
                    },
                    _ => {}
                }
                i += 1;
            }
        }

        pub(super) fn quoted_string(src: &str) -> Option<(&str, &str)> {
            let bytes = src.as_bytes();
            if bytes.first() != Some(&b'"') {
                return None;
            }
            let mut i = 1;
            loop {
                match *bytes.get(i)? {
                    b'"' => return Some(src.split_at(i + 1)),
                    b'\\' => match *bytes.get(i + 1)? {
                        b'\r' | b'\n' | 0x80.. => return None,
                        _ => i += 2,
                    },
                    _ => i += 1,
                }
            }
        }
    }

    #[test]
    fn scans_match_the_scalar_references() {
        // Every string of up to three bytes from an alphabet that covers each
        // class, plus a few longer ones, at every character boundary.
        const ALPHABET: &[char] =
            &['a', '0', '-', '[', ']', ':', '"', '\\', ' ', '\r', '\u{e9}'];
        let mut inputs = Vec::new();
        for a in ALPHABET {
            inputs.push(a.to_string());
            for b in ALPHABET {
                inputs.push(format!("{a}{b}"));
                for c in ALPHABET {
                    inputs.push(format!("{a}{b}{c}"));
                }
            }
        }
        inputs.push("\"0123456789abcdef\\\"0123456789abcdef\" rest".into());
        inputs.push("pc33.atlanta.example.com:5060;branch=z9hG4bK".into());
        inputs.push("[2001:db8::192.0.2.4]:5060".into());

        for input in &inputs {
            let starts = input.char_indices().map(|(i, _)| i);
            for start in starts.chain([input.len()]) {
                let src = &input[start..];
                assert_eq!(
                    token(src),
                    reference::run(src, reference::is_token),
                    "token {src:?}"
                );
                assert_eq!(
                    digits(src),
                    reference::run(src, |b| b.is_ascii_digit()),
                    "digits {src:?}"
                );
                assert_eq!(
                    quoted_string(src),
                    reference::quoted_string(src),
                    "quoted_string {src:?}"
                );
            }
        }
    }
}
