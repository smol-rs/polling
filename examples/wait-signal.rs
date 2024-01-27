#[cfg(all(
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ),
    not(polling_test_poll_backend),
))]
mod example {
    use polling::os::kqueue::{PollerKqueueExt, Signal};
    use polling::{Events, PollMode, Poller};

    pub(super) fn main2() {
        // Create a poller.
        let poller = Poller::new().unwrap();

        // Register SIGINT in the poller.
        let sigint = Signal(rustix::process::Signal::Int as _);
        poller.add_filter(sigint, 1, PollMode::Oneshot).unwrap();

        let mut events = Events::new();

        println!("Press Ctrl+C to exit...");

        // Wait for events.
        poller.wait(&mut events, None).unwrap();

        // Process events.
        let ev = events.iter().next().unwrap();
        match ev.key {
            1 => {
                println!("SIGINT received");
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(all(
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ),
    not(polling_test_poll_backend),
))]
fn main() {
    example::main2();
}

#[cfg(not(all(
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ),
    not(polling_test_poll_backend),
)))]
fn main() {
    eprintln!("This example is only supported on kqueue-based platforms.");
}
