use siparse::{Header, RequestHead, Status};

fn main() {
    let buf = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK\r\n\
                Content-Length: 0\r\n\
                \r\n";

    let mut headers = [Header::EMPTY; 4];

    match RequestHead::parse(buf, &mut headers) {
        Ok(Status::Complete((head, head_end))) => {
            println!("input:");
            println!(
                "{:?}",
                core::str::from_utf8(buf)
                    .expect("example input is valid UTF-8")
            );
            println!();
            println!("head_end: {head_end}");

            let line = head.start_line;
            println!("method:   {}", line.method);
            println!("uri:      {}", line.uri);
            println!("version:  {}", line.version);

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
