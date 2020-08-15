use std::io;
use std::time::{Duration, Instant};

use polling::Poller;

#[test]
fn timeout() -> io::Result<()> {
    let poller = Poller::new()?;
    let mut events = Vec::new();

    for _ in 0..5 {
        let start = Instant::now();
        poller.wait(&mut events, Some(Duration::from_secs(1)))?;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_secs(1));
    }

    Ok(())
}
