//! Tests for level triggered and edge triggered mode.

#![allow(clippy::unused_io_amount)]

use std::io::{self, prelude::*};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use polling::{Event, PollMode, Poller};

#[test]
fn level_triggered() {
    // Create our streams.
    let (mut reader, mut writer) = tcp_pair().unwrap();
    let reader_token = 1;

    // Create our poller and register our streams.
    let poller = Poller::new().unwrap();
    if poller
        .add_with_mode(&reader, Event::readable(reader_token), PollMode::Level)
        .is_err()
    {
        // Only panic if we're on a platform that should support level mode.
        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "solaris", target_os = "illumos"))] {
                return;
            } else {
                panic!("Level mode should be supported on this platform");
            }
        }
    }

    // Write some data to the writer.
    let data = [1, 2, 3, 4, 5];
    writer.write_all(&data).unwrap();

    // A "readable" notification should be delivered.
    let mut events = Vec::new();
    poller
        .wait(&mut events, Some(Duration::from_secs(10)))
        .unwrap();

    assert_eq!(events, [Event::readable(reader_token)]);

    // If we read some of the data, the notification should still be available.
    reader.read_exact(&mut [0; 3]).unwrap();
    events.clear();
    poller
        .wait(&mut events, Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(events, [Event::readable(reader_token)]);

    // If we read the rest of the data, the notification should be gone.
    reader.read_exact(&mut [0; 2]).unwrap();
    events.clear();
    poller
        .wait(&mut events, Some(Duration::from_secs(0)))
        .unwrap();

    assert_eq!(events, []);

    // After modifying the stream and sending more data, it should be oneshot.
    poller
        .modify_with_mode(&reader, Event::readable(reader_token), PollMode::Oneshot)
        .unwrap();

    writer.write(&data).unwrap();
    events.clear();

    // BUG: Somehow, the notification here is delayed?
    poller
        .wait(&mut events, Some(Duration::from_secs(10)))
        .unwrap();

    assert_eq!(events, [Event::readable(reader_token)]);

    // After reading, the notification should vanish.
    reader.read(&mut [0; 5]).unwrap();
    events.clear();
    poller
        .wait(&mut events, Some(Duration::from_secs(0)))
        .unwrap();

    assert_eq!(events, []);
}

#[test]
fn edge_triggered() {
    // Create our streams.
    let (mut reader, mut writer) = tcp_pair().unwrap();
    let reader_token = 1;

    // Create our poller and register our streams.
    let poller = Poller::new().unwrap();
    if poller
        .add_with_mode(&reader, Event::readable(reader_token), PollMode::Edge)
        .is_err()
    {
        // Only panic if we're on a platform that should support level mode.
        cfg_if::cfg_if! {
            if #[cfg(all(
                any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "tvos",
                    target_os = "watchos",
                    target_os = "freebsd",
                    target_os = "netbsd",
                    target_os = "openbsd",
                    target_os = "dragonfly"
                ),
                not(polling_test_poll_backend)
            ))] {
                panic!("Edge mode should be supported on this platform");
            } else {
                return;
            }
        }
    }

    // Write some data to the writer.
    let data = [1, 2, 3, 4, 5];
    writer.write_all(&data).unwrap();

    // A "readable" notification should be delivered.
    let mut events = Vec::new();
    poller
        .wait(&mut events, Some(Duration::from_secs(10)))
        .unwrap();

    assert_eq!(events, [Event::readable(reader_token)]);

    // If we read some of the data, the notification should not still be available.
    reader.read_exact(&mut [0; 3]).unwrap();
    events.clear();
    poller
        .wait(&mut events, Some(Duration::from_secs(0)))
        .unwrap();
    assert_eq!(events, []);

    // If we write more data, a notification should be delivered.
    writer.write_all(&data).unwrap();
    events.clear();
    poller
        .wait(&mut events, Some(Duration::from_secs(10)))
        .unwrap();
    assert_eq!(events, [Event::readable(reader_token)]);

    // After modifying the stream and sending more data, it should be oneshot.
    poller
        .modify_with_mode(&reader, Event::readable(reader_token), PollMode::Oneshot)
        .unwrap();

    writer.write_all(&data).unwrap();
    events.clear();
    poller
        .wait(&mut events, Some(Duration::from_secs(10)))
        .unwrap();

    assert_eq!(events, [Event::readable(reader_token)]);
}

#[cfg_attr(
    any(target_os = "solaris", target_os = "illumos"),
    ignore = "Solaris doesn't support level triggered mode"
)]
#[test]
fn ping_source_edge_check() {
    // Create two ping sources.
    let (mut reader1, mut writer1) = tcp_pair().unwrap();
    let (mut reader2, mut writer2) = tcp_pair().unwrap();

    reader1.set_nonblocking(true).unwrap();
    reader2.set_nonblocking(true).unwrap();

    // Create our poller and register our streams.
    let poller = Poller::new().unwrap();
    poller
        .add_with_mode(&reader1, Event::readable(1), PollMode::Level)
        .unwrap();
    poller
        .add_with_mode(&reader2, Event::readable(2), PollMode::Level)
        .unwrap();

    let mut events = vec![];

    // Write to the first writer.
    writer1.write_all(&[1]).unwrap();
    poller.wait(&mut events, Some(Duration::from_secs(10))).unwrap();
    assert_eq!(events, [Event::readable(1)]);
    reader1.read_exact(&mut [0; 1]).unwrap();

    // Write to the second writer.
    writer2.write_all(&[1]).unwrap();
    events.clear();
    poller.wait(&mut events, Some(Duration::from_secs(10))).unwrap();
    assert_eq!(events, [Event::readable(2)]);
    reader2.read_exact(&mut [0; 1]).unwrap();

    // Write to both at once.
    writer1.write_all(&[1]).unwrap();
    writer2.write_all(&[1]).unwrap();
    events.clear();
    poller.wait(&mut events, Some(Duration::from_secs(10))).unwrap();

    // Order is not guaranteed.
    assert_eq!(events.len(), 2);
    assert!(events.contains(&Event::readable(1)));
    assert!(events.contains(&Event::readable(2)));

    reader1.read_exact(&mut [0; 1]).unwrap();
    reader2.read_exact(&mut [0; 1]).unwrap();
}

fn tcp_pair() -> io::Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let a = TcpStream::connect(listener.local_addr()?)?;
    let (b, _) = listener.accept()?;
    Ok((a, b))
}
