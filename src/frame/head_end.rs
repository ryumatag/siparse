use crate::{iter::Bytes, simd};

/// The empty line that ends a head.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// Finds the end of the first head in `buf`.
///
/// Returns the offset just past the first `\r\n\r\n` in `buf`, the same
/// offset that a head parser returns in [`Status::Complete`], or `None` if
/// there is none yet. A framer on a stream transport calls this after each
/// read and parses only once the end has arrived, instead of parsing the
/// whole buffer again after every [`Status::Partial`].
///
/// `scanned` is how many leading bytes of `buf` an earlier call already
/// covered without finding the end, usually the length `buf` had before the
/// last read. The scan starts three bytes before it, in case the empty line
/// straddles the old and new bytes. Pass `0` for a new head.
///
/// This is a byte search, not a grammar check. The head may still fail to
/// parse. `CRLF`s before the start-line, which [RFC 3261 section 7.5]
/// requires the parser to skip, match as well, so a buffer that holds only
/// an [RFC 5626] ping or other empty lines finds an end that the parser then
/// reports as `Partial`. The parser that follows a match handles both cases,
/// and a false match only costs one extra parse.
///
/// [RFC 3261 section 7.5]: https://www.rfc-editor.org/rfc/rfc3261#section-7.5
/// [RFC 5626]: https://www.rfc-editor.org/rfc/rfc5626
/// [`Status::Complete`]: crate::Status::Complete
/// [`Status::Partial`]: crate::Status::Partial
///
/// A `scanned` greater than `buf.len()` is a caller bug, such as a count
/// kept across a buffer that was drained or replaced. It panics in debug
/// builds. In release builds the search starts over from the beginning of
/// `buf`, since the count says nothing about the bytes `buf` now holds.
///
/// # Panics
///
/// Panics in debug builds if `scanned` is greater than `buf.len()`.
///
/// # Example
///
/// A head arrives in small reads. The parser runs once, for the read that
/// brings the end.
///
/// ```
/// use siparse::{frame::find_head_end, HeaderBuf, RequestHead, Status};
///
/// let message = b"OPTIONS sip:carol@example.com SIP/2.0\r\n\
///                 Call-ID: a84b4c76e66710@pc33.example.com\r\n\
///                 Content-Length: 0\r\n\
///                 \r\n";
///
/// let mut buf = Vec::new();
/// let mut parses = 0;
/// for read in message.chunks(10) {
///     let scanned = buf.len();
///     buf.extend_from_slice(read);
///
///     let Some(head_end) = find_head_end(&buf, scanned) else {
///         continue;
///     };
///
///     let mut headers = HeaderBuf::<16>::new();
///     let mut head = RequestHead::new(&mut headers);
///     assert_eq!(head.parse(&buf)?, Status::Complete(head_end));
///     parses += 1;
/// }
///
/// assert_eq!(parses, 1);
/// # Ok::<(), siparse::Error>(())
/// ```
#[inline]
pub fn find_head_end(buf: &[u8], scanned: usize) -> Option<usize> {
    find_head_end_with(buf, scanned, simd::find_head_end_vectored)
}

/// [`find_head_end`] with the scan given, so the benchmarks can measure the
/// SWAR scan alone.
#[inline(always)]
pub(crate) fn find_head_end_with(
    buf: &[u8],
    scanned: usize,
    scan: fn(&mut Bytes<'_>) -> bool,
) -> Option<usize> {
    debug_assert!(
        scanned <= buf.len(),
        "scanned is past the end of the buffer"
    );
    // A count past the end cannot describe this buffer. Searching all of it
    // still finds the end, where clamping to the length could skip it and
    // leave the caller waiting for a read that already happened.
    let scanned = if scanned > buf.len() { 0 } else { scanned };

    // The empty line can start no earlier than three bytes before the
    // scanned part ends, or it would have ended inside it.
    let start = scanned.saturating_sub(HEAD_END.len() - 1);
    let mut bytes = Bytes::new(&buf[start..]);

    scan(&mut bytes).then(|| start + bytes.pos() + HEAD_END.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderBuf, RequestHead};

    const REQUEST: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
        From: <sip:alice@example.com>;tag=1928301774\r\n\
        To: <sip:bob@example.com>\r\n\
        Call-ID: a84b4c76e66710\r\n\
        CSeq: 314159 INVITE\r\n\
        Content-Length: 0\r\n\
        \r\n";

    /// The reference search, one window at a time.
    fn scalar(buf: &[u8], scanned: usize) -> Option<usize> {
        let start = scanned.saturating_sub(HEAD_END.len() - 1);
        buf[start..]
            .windows(HEAD_END.len())
            .position(|window| window == HEAD_END)
            .map(|i| start + i + HEAD_END.len())
    }

    #[test]
    fn finds_the_end_that_the_parser_returns() {
        let mut headers = HeaderBuf::<16>::new();
        let mut head = RequestHead::new(&mut headers);
        let head_end = head.parse(REQUEST).unwrap().unwrap();

        assert_eq!(find_head_end(REQUEST, 0), Some(head_end));
    }

    #[test]
    fn finds_the_first_end_when_a_body_follows() {
        let mut buf = REQUEST.to_vec();
        buf.extend_from_slice(b"v=0\r\n\r\nmore");

        assert_eq!(find_head_end(&buf, 0), Some(REQUEST.len()));
    }

    #[test]
    fn returns_none_before_the_end_arrives() {
        for cut in 0..REQUEST.len() {
            assert_eq!(find_head_end(&REQUEST[..cut], 0), None, "cut={cut}");
        }
    }

    #[test]
    fn returns_none_for_near_misses() {
        for buf in [
            b"".as_slice(),
            b"\r",
            b"\r\n",
            b"\r\n\r",
            b"\n\r\n\r",
            b"\r\n\n\r\n",
            b"\r\n\r\r\n",
            b"\n\n\n\n",
            b"\r\r\r\r",
        ] {
            assert_eq!(find_head_end(buf, 0), None, "{buf:?}");
        }
    }

    #[test]
    fn matches_leading_empty_lines() {
        // A ping, or `CRLF`s before the start-line, end a "head" that the
        // parser then skips. The docs say so.
        assert_eq!(find_head_end(b"\r\n\r\n", 0), Some(4));
        assert_eq!(find_head_end(b"\r\n\r\n\r\nINVITE", 0), Some(4));
    }

    /// Scanning a buffer as it grows must find what a scan of the whole
    /// buffer finds. Every prefix that holds no end is a valid `scanned`.
    #[test]
    fn incremental_scans_agree_with_a_whole_scan() {
        let mut with_ping = b"\r\n\r\n".to_vec();
        with_ping.extend_from_slice(REQUEST);
        let mut with_body = REQUEST.to_vec();
        with_body.extend_from_slice(b"v=0\r\n\r\n");

        for buf in [REQUEST, &with_ping, &with_body, b"\r\n\r\n", b"x\r\n\r\n"]
        {
            let whole = find_head_end(buf, 0);
            for scanned in 0..=buf.len() {
                if find_head_end(&buf[..scanned], 0).is_none() {
                    assert_eq!(
                        find_head_end(buf, scanned),
                        whole,
                        "scanned={scanned}"
                    );
                }
            }
        }
    }

    #[test]
    fn scanned_may_equal_the_length() {
        assert_eq!(find_head_end(REQUEST, REQUEST.len()), None);
        assert_eq!(find_head_end(b"", 0), None);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "scanned is past the end of the buffer")]
    fn panics_in_debug_when_scanned_exceeds_the_length() {
        let _ = find_head_end(b"\r\n", 3);
    }

    /// A stale count from a longer buffer would skip the end if it were
    /// clamped to the length.
    #[test]
    #[cfg(not(debug_assertions))]
    fn searches_again_when_scanned_exceeds_the_length() {
        assert_eq!(
            find_head_end(REQUEST, REQUEST.len() + 1),
            find_head_end(REQUEST, 0),
        );
        assert!(find_head_end(REQUEST, 0).is_some());
    }

    /// Every string over `CR`, `LF`, and one other byte, up to `MAX_LEN`
    /// bytes, at every offset within a block, compared against the scalar
    /// search at every `scanned`. This covers every way a match or a near
    /// miss can fall across a block boundary or the end of the buffer.
    #[test]
    fn matches_scalar_exhaustively() {
        const ALPHABET: [u8; 3] = *b"\r\na";
        const MAX_LEN: usize = 8;
        const BLOCK_SIZE: usize = core::mem::size_of::<usize>();

        let mut buf = [b'a'; BLOCK_SIZE + MAX_LEN];
        for len in 0..=MAX_LEN {
            for pad in 0..BLOCK_SIZE {
                for mut index in 0..ALPHABET.len().pow(len as u32) {
                    for i in 0..len {
                        buf[pad + i] = ALPHABET[index % ALPHABET.len()];
                        index /= ALPHABET.len();
                    }
                    let buf = &buf[..pad + len];

                    for scanned in 0..=buf.len() {
                        assert_eq!(
                            find_head_end(buf, scanned),
                            scalar(buf, scanned),
                            "buf={buf:?} scanned={scanned}"
                        );
                    }
                }
                buf[pad..pad + len].fill(b'a');
            }
        }
    }

    #[test]
    fn matches_scalar_on_a_head() {
        for scanned in 0..=REQUEST.len() {
            assert_eq!(
                find_head_end(REQUEST, scanned),
                scalar(REQUEST, scanned),
                "scanned={scanned}"
            );
        }
    }
}
