use siparse::{HeaderBuf, RequestHead, Status};

fn main() {
    let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let mut headers = HeaderBuf::<4>::new();
    let mut head = RequestHead::new(&mut headers);

    match head.parse(buf) {
        Ok(Status::Complete(head_end)) => {
            println!("input:");
            println!(
                "{:?}",
                core::str::from_utf8(buf)
                    .expect("example input is valid UTF-8")
            );
            println!();
            println!("head_end: {head_end}");

            // Every start-line field is `Some` once the head is complete.
            let line = head.start_line;
            println!("method:   {}", line.method.unwrap_or_default());
            println!("uri:      {}", line.uri.unwrap_or_default());
            println!("version:  {}", line.version.unwrap_or_default());

            for header in head.headers.iter() {
                println!("header:   {} = {}", header.name, header.value);
            }
        }
        Ok(Status::Partial) => {
            eprintln!("partial input");
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("parse error: {err}");
            std::process::exit(1);
        }
    }
}
