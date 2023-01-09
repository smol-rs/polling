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
    use polling::os::kqueue::PollerExt;
    use polling::{PollMode, Poller};
    use std::process::Command;

    // Create a new poller.
    let poller = Poller::new().unwrap();

    // Add a signal handler for SIGCHLD.
    poller
        .add_signal(libc::SIGCHLD, 1, PollMode::Oneshot)
        .unwrap();

    // Spawn a new child process.
    let mut child = Command::new("sleep").arg("3").spawn().unwrap();

    // Wait for the SIGCHLD signal.
    let mut events = Vec::new();
    loop {
        poller.wait(&mut events, None).unwrap();

        for ev in events.drain(..) {
            // See if we got the SIGCHLD signal.
            if ev.readable && ev.key == 1 {
                println!("Got SIGCHLD signal!");

                // Check if the child process has exited.
                if let Ok(Some(status)) = child.try_wait() {
                    println!("Child exited with status: {}", status);
                    return;
                }
            }
        }
    }
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
    eprintln!("This example is only supported on kqueue-compatible OS.")
}
