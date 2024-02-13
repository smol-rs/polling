#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::net;
    use std::{io::Write, time::Duration};

    use polling::Event;
    use socket2::Type;

    std::thread::spawn(|| {
        let listener = net::TcpListener::bind("0.0.0.0:8080").unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            stream.write_all(b"Hello, world!\n").unwrap();
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let socket = socket2::Socket::new(socket2::Domain::IPV4, Type::STREAM, None)?;
    let poller = polling::Poller::new()?;
    unsafe {
        poller.add(&socket, Event::new(0, true, true))?;
    }

    socket.set_nonblocking(true)?;

    let mut events = polling::Events::new();
    poller.wait(&mut events, Some(Duration::from_secs(3)))?;

    let event = events.iter().next().expect("no event");

    assert!(event.is_interrupt());

    let addr = net::SocketAddr::new("127.0.0.1".parse().unwrap(), 8080);
    let err = socket.connect(&addr.into()).unwrap_err();

    // EINPROGRESS
    assert_eq!(115, err.raw_os_error().expect("No OS error"));

    poller
        .modify(&socket, Event::writable(0))
        .expect("modify failed");
    events.clear();
    poller.wait(&mut events, Some(Duration::from_secs(3)))?;

    let event = events.iter().next().expect("no event");

    assert!(event.writable);
    assert!(!event.is_interrupt());
    assert!(!event.is_err().unwrap());

    println!("event: {:?}", event);
    println!("socket is now writable");
    // ========================================================================
    // the below is example of a bad socket
    println!("testing bad socket");
    let bad_socket = socket2::Socket::new(socket2::Domain::IPV4, Type::STREAM, None)?;
    let addr = net::SocketAddr::new("127.0.0.1".parse().unwrap(), 12345);
    bad_socket.set_nonblocking(true)?;

    unsafe {
        poller.add(&bad_socket, Event::writable(0))?;
    }

    events.clear();
    poller.wait(&mut events, Some(Duration::from_secs(3)))?;

    let err = bad_socket.connect(&addr.into()).unwrap_err();
    assert_eq!(115, err.raw_os_error().expect("No OS error"));

    poller
        .modify(&bad_socket, Event::writable(0))
        .expect("modify failed");

    events.clear();
    poller.wait(&mut events, Some(Duration::from_secs(3)))?;

    let event = events.iter().next().expect("no event");

    assert!(event.is_err().unwrap());
    println!("bad socket is now in error state");

    Ok(())
}

#[cfg(target_os = "windows")]
fn main() -> std::io::Result<()> {
    use polling::Event;
    use std::io;
    use std::{io::Write, time::Duration};

    std::thread::spawn(|| {
        let listener = std::net::TcpListener::bind("0.0.0.0:8080").unwrap();
        println!("Listening on {}", listener.local_addr().unwrap());
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(_) => {
                    continue;
                }
            };
            stream.write_all(b"Hello, world!\n").unwrap();
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let poller = polling::Poller::new()?;
    unsafe {
        poller.add(&socket, Event::new(0, true, true))?;
    }

    socket.set_nonblocking(true)?;

    let addr = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), 8080);
    let err = socket.connect(&addr.into()).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

    let mut events = polling::Events::new();
    poller.wait(&mut events, Some(Duration::from_secs(3)))?;

    let event = events.iter().next().expect("no event");

    assert!(event.writable);
    assert!(!event.is_interrupt());
    assert!(!event.is_err().unwrap());

    println!("event: {:?}", event);
    println!("socket is now writable");
    // // ========================================================================
    // // the below is example of a bad socket
    println!("testing bad socket");
    let bad_socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    let addr = std::net::SocketAddr::new("127.0.0.1".parse().unwrap(), 12345);
    bad_socket.set_nonblocking(true)?;
    bad_socket.connect(&addr.into()).unwrap_err();

    unsafe {
        poller.add(&bad_socket, Event::writable(0))?;
    }

    events.clear();
    poller.wait(&mut events, Some(Duration::from_secs(3)))?;

    let event = events.iter().next().expect("no event");

    assert!(event.is_err().unwrap());
    println!("bad socket is now in error state");

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn main() {
    println!("This example is not yet supported on this platform.");
}
