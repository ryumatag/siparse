/*!
RFC 5626 CRLF keepalives travel between SIP messages on connection-oriented
transports. They are not part of a message head, so they get their own
entry points instead of a variant in the head parsers' results. The head
parsers keep skipping leading `CRLF`s as RFC 3261 section 7.5 requires.

The ping and pong checks are separate because the receiver's role decides
how a buffer that ends in `CRLF` reads. A server may have received half of
a split ping, so it has to wait. A client is waiting for a pong, so it must
not wait for bytes that may never come.
*/

use crate::parse::Status;

/// The RFC 5626 keepalive ping that a client sends.
const PING: &[u8] = b"\r\n\r\n";

/// The RFC 5626 keepalive pong that a server answers a ping with.
const PONG: &[u8] = b"\r\n";

/// Checks whether `buf` starts with an [RFC 5626] keepalive ping.
///
/// A ping is a double `CRLF` that a client sends between SIP messages on a
/// connection-oriented transport such as TCP or TLS. [RFC 5626 section 5.4]
/// requires an edge proxy to answer each ping with a single `CRLF` pong. Call
/// this at a message boundary on the server side, before parsing a head. The
/// head parsers skip leading `CRLF`s, so they never report a ping.
///
/// Returns one of the following:
///
/// * `Complete(Some(4))` if `buf` starts with a ping. Consume those 4 bytes,
///   send the pong, and check again, because more pings or a message may
///   follow.
/// * `Partial` if `buf` is a proper prefix of a ping, including an empty
///   buffer. Read more input and check again.
/// * `Complete(None)` if `buf` does not start with a ping. Parse a head from
///   the same position. A lone leading `CRLF` lands here and is skipped by the
///   head parser.
///
/// RFC 5626 forbids `CRLF` keepalives on UDP, so this is not meant for
/// datagrams.
///
/// [RFC 5626]: https://www.rfc-editor.org/rfc/rfc5626
/// [RFC 5626 section 5.4]: https://www.rfc-editor.org/rfc/rfc5626#section-5.4
///
/// # Example
///
/// ```
/// use siparse::{parse_ping, Status};
///
/// let buf = b"\r\n\r\nOPTIONS sip:carol@example.com SIP/2.0\r\n";
///
/// assert_eq!(parse_ping(buf), Status::Complete(Some(4)));
/// assert_eq!(parse_ping(&buf[4..]), Status::Complete(None));
/// assert_eq!(parse_ping(b"\r\n"), Status::Partial);
/// ```
#[inline]
pub fn parse_ping(buf: &[u8]) -> Status<Option<usize>> {
    parse_crlf_keepalive(buf, PING)
}

/// Checks whether `buf` starts with an [RFC 5626] keepalive pong.
///
/// A pong is a single `CRLF` that a server sends in reply to a ping. Call this
/// at a message boundary on the client side, before parsing a head. Unlike
/// [`parse_ping`], a buffer that holds exactly `CRLF` is a complete pong,
/// because a client that sent a ping should not wait for more bytes to confirm
/// the reply. [RFC 5626 section 4.4.1] gives the client only 10 seconds to
/// receive it.
///
/// Returns one of the following:
///
/// * `Complete(Some(2))` if `buf` starts with a pong. Consume those 2 bytes
///   and check again.
/// * `Partial` if `buf` is empty or holds only `CR`.
/// * `Complete(None)` if `buf` does not start with a pong. Parse a head from
///   the same position.
///
/// [RFC 5626]: https://www.rfc-editor.org/rfc/rfc5626
/// [RFC 5626 section 4.4.1]: https://www.rfc-editor.org/rfc/rfc5626#section-4.4.1
///
/// # Example
///
/// ```
/// use siparse::{parse_pong, Status};
///
/// assert_eq!(parse_pong(b"\r\n"), Status::Complete(Some(2)));
/// assert_eq!(parse_pong(b"SIP/2.0 200 OK\r\n"), Status::Complete(None));
/// assert_eq!(parse_pong(b"\r"), Status::Partial);
/// ```
#[inline]
pub fn parse_pong(buf: &[u8]) -> Status<Option<usize>> {
    parse_crlf_keepalive(buf, PONG)
}

#[inline]
fn parse_crlf_keepalive(
    buf: &[u8],
    keepalive: &[u8],
) -> Status<Option<usize>> {
    if buf.starts_with(keepalive) {
        Status::Complete(Some(keepalive.len()))
    } else if keepalive.starts_with(buf) {
        Status::Partial
    } else {
        Status::Complete(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_waits_for_every_proper_prefix() {
        for len in 0..PING.len() {
            assert_eq!(parse_ping(&PING[..len]), Status::Partial, "len={len}");
        }
    }

    #[test]
    fn ping_consumes_only_the_first_double_crlf() {
        assert_eq!(parse_ping(b"\r\n\r\n"), Status::Complete(Some(4)));
        assert_eq!(parse_ping(b"\r\n\r\n\r\n"), Status::Complete(Some(4)));
        assert_eq!(
            parse_ping(b"\r\n\r\nINVITE sip:bob@example.com SIP/2.0\r\n"),
            Status::Complete(Some(4))
        );
    }

    #[test]
    fn ping_rejects_inputs_that_diverge_from_double_crlf() {
        for buf in [
            b"INVITE".as_slice(),
            b"\n",
            b"\rX",
            b"\r\nINVITE",
            b"\r\n\n",
            b"\r\n\rX",
        ] {
            assert_eq!(parse_ping(buf), Status::Complete(None), "{buf:?}");
        }
    }

    #[test]
    fn pong_completes_on_a_single_crlf() {
        assert_eq!(parse_pong(b"\r\n"), Status::Complete(Some(2)));
        assert_eq!(parse_pong(b"\r\n\r\n"), Status::Complete(Some(2)));
        assert_eq!(
            parse_pong(b"\r\nSIP/2.0 200 OK\r\n"),
            Status::Complete(Some(2))
        );
    }

    #[test]
    fn pong_waits_for_every_proper_prefix() {
        for len in 0..PONG.len() {
            assert_eq!(parse_pong(&PONG[..len]), Status::Partial, "len={len}");
        }
    }

    #[test]
    fn pong_rejects_inputs_that_diverge_from_crlf() {
        for buf in [b"SIP/2.0".as_slice(), b"\n", b"\rX", b"\r\r"] {
            assert_eq!(parse_pong(buf), Status::Complete(None), "{buf:?}");
        }
    }
}
