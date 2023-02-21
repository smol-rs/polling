use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use easy_parallel::Parallel;
use polling::{Event, Poller};

#[test]
fn concurrent_add() -> io::Result<()> {
    let (reader, mut writer) = tcp_pair()?;
    let poller = Poller::new()?;

    let mut events = Vec::new();

    Parallel::new()
        .add(|| {
            poller.wait(&mut events, None)?;
            Ok(())
        })
        .add(|| {
            thread::sleep(Duration::from_millis(100));
            poller.add(&reader, Event::readable(0))?;
            writer.write_all(&[1])?;
            Ok(())
        })
        .run()
        .into_iter()
        .collect::<io::Result<()>>()?;

    assert_eq!(events, [Event::readable(0)]);

    Ok(())
}

#[test]
fn concurrent_modify() -> io::Result<()> {
    let (reader, mut writer) = tcp_pair()?;
    let poller = Poller::new()?;
    poller.add(&reader, Event::none(0))?;

    let mut events = Vec::new();

    Parallel::new()
        .add(|| {
            poller.wait(&mut events, Some(Duration::from_secs(10)))?;
            Ok(())
        })
        .add(|| {
            thread::sleep(Duration::from_millis(100));
            poller.modify(&reader, Event::readable(0))?;
            writer.write_all(&[1])?;
            Ok(())
        })
        .run()
        .into_iter()
        .collect::<io::Result<()>>()?;

    assert_eq!(events, [Event::readable(0)]);

    Ok(())
}

fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let a = TcpStream::connect(listener.local_addr()?)?;
    let (b, _) = listener.accept()?;
    Ok((a, b))
}
