macro_rules! complete {
    ($e:expr) => {
        match $e? {
            Status::Complete(v) => v,
            Status::Partial => return Ok(Status::Partial),
        }
    };
}

macro_rules! next {
    ($bytes:ident) => {{
        match $bytes.next() {
            Some(b) => b,
            _ => return Ok(Status::Partial),
        }
    }};
}

macro_rules! peek {
    ($bytes:ident) => {{
        match $bytes.peek() {
            Some(b) => b,
            _ => return Ok(Status::Partial),
        }
    }};
}

// Peeks at the next byte of a token parsed under the boundary `$B`. Inside a
// head, running out of input means more may arrive, so this returns
// `Partial`. For a `Whole` token, it is the end of the token and yields
// `None`.
macro_rules! peek_or_end {
    ($bytes:ident, $B:ident) => {
        match $bytes.peek() {
            Some(b) => Some(b),
            None if $B::WHOLE => None,
            None => return Ok(Status::Partial),
        }
    };
}

macro_rules! ensure {
    ($bytes:ident.next() == $($p:pat_param)|+ => $err:expr) => {
        ensure!(next!($bytes), $($p)|+, $err)
    };
    ($bytes:ident.peek() == $($p:pat_param)|+ => $err:expr) => {
        ensure!(peek!($bytes), $($p)|+, $err)
    };
    ($bytes:expr, $($p:pat_param)|+, $err:expr) => {
        match $bytes {
            $(
                b @ $p => b,
            )+
            _ => return Err($err),
        }
    };
}
