use std::io;
use std::net::TcpListener;

use polling::{Event, Poller};

fn main() -> io::Result<()> {
    let l1 = TcpListener::bind("127.0.0.1:8001")?;
    let l2 = TcpListener::bind("127.0.0.1:8002")?;

    l1.set_nonblocking(true)?;
    l2.set_nonblocking(true)?;

    let poller = Poller::new()?;
    poller.insert(&l1)?;
    poller.insert(&l2)?;

    poller.interest(&l1, Event::readable(1))?;
    poller.interest(&l2, Event::readable(2))?;

    let mut events = Vec::new();
    loop {
        events.clear();
        poller.wait(&mut events, None)?;

        for ev in &events {
            match ev.key {
                1 => {
                    println!("Accept on l1");
                    l1.accept()?;
                    poller.interest(&l1, Event::readable(1))?;
                }
                2 => {
                    println!("Accept on l2");
                    l2.accept()?;
                    poller.interest(&l2, Event::readable(2))?;
                }
                _ => unreachable!(),
            }
        }
    }
}
