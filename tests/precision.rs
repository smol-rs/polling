//! Makes sure that timeouts have precision lower than 1ns on non-Windows systems.

#![cfg(not(windows))]

use std::io;
use std::time::{Instant, Duration};

use polling::Poller;

#[test]
fn below_ms() -> io::Result<()> {
    let poller = Poller::new()?;
    let mut events = Vec::new();
    let margin = Duration::from_micros(500);

    for _ in 0..1_000 {
        let now = Instant::now();
        let dur = Duration::from_micros(100);

        let n = poller.wait(&mut events, Some(dur))?;
        let elapsed = now.elapsed();
        assert_eq!(n, 0);
        assert!(elapsed >= dur);

        if elapsed < dur + margin {
            return Ok(());
        }
    }

    panic!("timeouts are not precise enough");
}

#[test]
fn above_ms() -> io::Result<()> {
    let poller = Poller::new()?;
    let mut events = Vec::new();
    let margin = Duration::from_micros(500);

    for _ in 0..1_000 {
        let now = Instant::now();
        let dur = Duration::from_micros(10_100);

        let n = poller.wait(&mut events, Some(dur))?;
        let elapsed = now.elapsed();
        assert_eq!(n, 0);
        assert!(elapsed >= dur);

        if elapsed < dur + margin {
            return Ok(());
        }
    }

    panic!("timeouts are not precise enough");
}
