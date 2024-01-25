use std::{io, net};

use polling::Event;
use socket2::Type;

fn main() -> io::Result<()> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, Type::STREAM, None)?;
    let poller = polling::Poller::new()?;
    unsafe {
        poller.add(&socket, Event::new(0, true, true))?;
    }
    let addr = net::SocketAddr::new(net::Ipv4Addr::LOCALHOST.into(), 8080);
    socket.set_nonblocking(true)?;
    let res = socket.connect(&addr.into());

    let mut events = polling::Events::new();
    // while let Err(ref e) = res {
        // if e.kind() != io::ErrorKind::WouldBlock {
        //     return Err(io::Error::new(e.kind(), e.to_string()));
        // }

        events.clear();
        poller.wait(&mut events, None)?;

        let event = events.iter().next();
        if event.is_none() {
            println!("no event");
            // break;
        }

        let event = event.unwrap();
        println!("event: {:?}", event);
        if event.is_connect_failed() {
            println!("connect failed");
            // break;
        }
    // }

    Ok(())
}
