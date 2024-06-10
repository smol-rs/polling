cfg_if::cfg_if! {
    if #[cfg(feature = "iocp-psn")] {
        mod psn;
        pub use psn::*;
    } else {
        mod wepoll;
        pub use wepoll::*;
    }
}

use std::time::Duration;

use windows_sys::Win32::System::Threading::INFINITE;

// Implementation taken from https://github.com/rust-lang/rust/blob/db5476571d9b27c862b95c1e64764b0ac8980e23/src/libstd/sys/windows/mod.rs
fn dur2timeout(dur: Duration) -> u32 {
    // Note that a duration is a (u64, u32) (seconds, nanoseconds) pair, and the
    // timeouts in windows APIs are typically u32 milliseconds. To translate, we
    // have two pieces to take care of:
    //
    // * Nanosecond precision is rounded up
    // * Greater than u32::MAX milliseconds (50 days) is rounded up to INFINITE
    //   (never time out).
    dur.as_secs()
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add((dur.subsec_nanos() as u64) / 1_000_000))
        .and_then(|ms| {
            if dur.subsec_nanos() % 1_000_000 > 0 {
                ms.checked_add(1)
            } else {
                Some(ms)
            }
        })
        .and_then(|x| u32::try_from(x).ok())
        .unwrap_or(INFINITE)
}
