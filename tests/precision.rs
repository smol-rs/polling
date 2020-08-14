use std::io;
use std::time::{Duration, Instant};

use polling::Poller;

#[test]
fn below_ms() -> io::Result<()> {
    let poller = Poller::new()?;
    let mut events = Vec::new();

    let margin = Duration::from_micros(500);
    let mut lowest = Duration::from_secs(1000);

    for _ in 0..1_000 {
        let now = Instant::now();
        let dur = Duration::from_micros(100);

        let n = poller.wait(&mut events, Some(dur))?;
        let elapsed = now.elapsed();
        assert_eq!(n, 0);
        assert!(elapsed >= dur);
        lowest = lowest.min(elapsed);
    }

    if cfg!(not(windows)) && lowest > dur + margin {
        panic!("timeouts are not precise enough");
    }
    Ok(())
}

#[test]
fn above_ms() -> io::Result<()> {
    let poller = Poller::new()?;
    let mut events = Vec::new();

    let margin = Duration::from_micros(500);
    let mut lowest = Duration::from_secs(1000);

    for _ in 0..1_000 {
        let now = Instant::now();
        let dur = Duration::from_micros(10_100);

        let n = poller.wait(&mut events, Some(dur))?;
        let elapsed = now.elapsed();
        assert_eq!(n, 0);
        assert!(elapsed >= dur);
        lowest = lowest.min(elapsed);
    }

    if cfg!(not(windows)) && lowest > dur + margin {
        panic!("timeouts are not precise enough");
    }
    Ok(())
}
