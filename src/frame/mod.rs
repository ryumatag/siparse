/*!
Finds where messages and keepalives begin and end on a stream transport.

On UDP each datagram holds one message. On TCP and other streams, messages
arrive back to back, split across reads, with RFC 5626 keepalives between
them. A framer uses these functions to find the boundaries, and parses a head
with [`RequestHead`](crate::RequestHead) and the other head types once one has
arrived:

* [`find_head_end`] finds the empty line that ends a head, scanning only the
  bytes it has not seen, so a framer avoids parsing a head again after every
  read.
* [`parse_ping`] and [`parse_pong`] recognize the `CRLF` keepalives a server
  and a client exchange between messages.

The body that follows a head is framed by its `Content-Length`, which is left
to the caller.
*/

mod head_end;
mod keepalive;

pub use self::{
    head_end::find_head_end,
    keepalive::{parse_ping, parse_pong},
};
// The SWAR scan alone, for `crate::bench`.
#[cfg(feature = "__bench")]
pub(crate) use self::head_end::find_head_end_with;

#[cfg(test)]
mod tests {
    #[test]
    #[allow(deprecated)]
    fn the_old_root_paths_still_work() {
        let buf = b"\r\n\r\nOPTIONS sip:carol@example.com SIP/2.0\r\n\r\n";
        for at in 0..buf.len() {
            let buf = &buf[at..];
            assert_eq!(
                crate::find_head_end(buf, 0),
                super::find_head_end(buf, 0)
            );
            assert_eq!(crate::parse_ping(buf), super::parse_ping(buf));
            assert_eq!(crate::parse_pong(buf), super::parse_pong(buf));
        }
    }
}
