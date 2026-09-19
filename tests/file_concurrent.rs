//! Concurrency tests for the v2 IOCP file-handle submission API.
//!
//! Spec: `docs/named-pipe.implement.checklist.md` Step 3.2 / 3.4 / 7.
//!
//! Step 7 reworked the API: `OpHandle` owns the completion lifecycle
//! directly. There is no `FileCompletion` token and no
//! `Events::*_file_completions` channel any more — the dispatcher
//! parks the result on the originating `OpHandle` and emits a normal
//! `Event { key, readable, writable }` (Step 7b). The user discovers
//! completion via `is_complete` / `try_take` / `take` and routes the
//! wake through the reactor that owns the key.

#![cfg(windows)]

mod common;

use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use polling::os::iocp::{OpHandle, PollerIocpFileExt, Submission};
use polling::{Events, Poller};

use windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Drive `poller.wait` until every handle in `ops` (slot is `Some`)
/// has its completion published, draining each `Some` slot via `take`
/// and pushing `(n, B)` into `out` (or `Err` for cancelled ops).
fn drain_handles<B>(
    poller: &Poller,
    events: &mut Events,
    ops: &mut [Option<OpHandle<B>>],
    out: &mut Vec<std::io::Result<(usize, B)>>,
) {
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let mut all_taken = true;
        for slot in ops.iter_mut() {
            if let Some(op) = slot {
                if op.is_complete() {
                    let op = slot.take().unwrap();
                    let (res, buf) = op.take();
                    out.push(res.map(|n| (n, buf)));
                } else {
                    all_taken = false;
                }
            }
        }
        if all_taken {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "timeout waiting for {} pending op(s)",
                ops.iter().filter(|s| s.is_some()).count()
            );
        }
        poller.wait(events, Some(remaining)).unwrap();
    }
}

#[test]
fn async_path_still_returns_pending() {
    skip_on_wine!();
    let (server, _client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    let buf = Vec::<u8>::with_capacity(64);
    let op = match server_reg.submit_read(buf) {
        Submission::Pending(op) => op,
        Submission::Complete { .. } => panic!("expected Pending on empty pipe"),
        Submission::Failed { error, .. } => panic!("read failed: {error}"),
    };

    op.cancel().unwrap();
    let mut events = Events::new();
    common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
    let _ = op.take();
}

#[test]
fn sync_success_returns_complete_variant() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    match client_reg.submit_write(b"hello".to_vec()) {
        Submission::Complete { bytes, .. } => assert_eq!(bytes, 5),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let (res, _) = op.take();
            let n = res.unwrap();
            assert_eq!(n, 5);
        }
        Submission::Failed { error, .. } => panic!("write failed: {error}"),
    }

    let buf = Vec::<u8>::with_capacity(16);
    match server_reg.submit_read(buf) {
        Submission::Complete { bytes, buf } => {
            assert_eq!(bytes, 5);
            let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), bytes) };
            assert_eq!(slice, b"hello");
        }
        Submission::Pending(_) => panic!("expected sync Complete when data was buffered"),
        Submission::Failed { error, .. } => panic!("read failed: {error}"),
    }
}

#[test]
fn two_concurrent_writes_distinguish_completions() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let payload_a = vec![b'A'; 5000];
    let payload_b = vec![b'B'; 6000];

    let op_a = match client_reg.submit_write(payload_a) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending for write A, got {other:?}"),
    };
    let op_b = match client_reg.submit_write(payload_b) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending for write B, got {other:?}"),
    };

    // Drain on the server end so the kernel can complete the writes.
    let mut events = Events::new();
    let mut completions = 0usize;
    let deadline = Instant::now() + TEST_TIMEOUT;
    while completions < 11_000 {
        let buf = Vec::<u8>::with_capacity(16 * 1024);
        match server_reg.submit_read(buf) {
            Submission::Complete { bytes, .. } => completions += bytes,
            Submission::Pending(op) => {
                common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
                let (res, _) = op.take();
                let n = res.unwrap();
                completions += n;
            }
            Submission::Failed { error, .. } => panic!("server read failed: {error}"),
        }
    }

    // Both writes should have completion entries posted; drain them.
    while !(op_a.is_complete() && op_b.is_complete()) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!("write completions did not arrive in time");
        }
        poller.wait(&mut events, Some(remaining)).unwrap();
    }

    let (res, ba) = op_a.take();
    let na = res.unwrap();
    let (res, bb) = op_b.take();
    let nb = res.unwrap();
    assert_eq!(na, 5000);
    assert_eq!(nb, 6000);
    assert!(ba.iter().all(|&b| b == b'A'));
    assert!(bb.iter().all(|&b| b == b'B'));
}

#[test]
fn two_concurrent_reads_dispatch_correctly() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let op1 = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };
    let op2 = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    for payload in [b"AAAA".to_vec(), b"BBBB".to_vec()] {
        match client_reg.submit_write(payload) {
            Submission::Complete { bytes, .. } => assert_eq!(bytes, 4),
            Submission::Pending(op) => {
                let mut events = Events::new();
                common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
                let _ = op.take().0.unwrap();
            }
            Submission::Failed { error, .. } => panic!("write failed: {error}"),
        }
    }

    let mut ops = [Some(op1), Some(op2)];
    let mut got = Vec::new();
    let mut events = Events::new();
    drain_handles(&poller, &mut events, &mut ops, &mut got);

    assert_eq!(got.len(), 2);
    for r in &got {
        let (n, buf) = r.as_ref().unwrap();
        assert_eq!(*n, 4);
        let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), *n) };
        assert!(slice == b"AAAA" || slice == b"BBBB", "got {slice:?}");
    }
}

#[test]
fn mixed_read_write_concurrent() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let read_op = match server_reg.submit_read(Vec::<u8>::with_capacity(8)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending read, got {other:?}"),
    };

    let write_outcome = server_reg.submit_write(b"SVR->CLI".to_vec());

    match client_reg.submit_write(b"CLI->SVR".to_vec()) {
        Submission::Complete { bytes, .. } => assert_eq!(bytes, 8),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let _ = op.take().0.unwrap();
        }
        Submission::Failed { error, .. } => panic!("client write failed: {error}"),
    }

    let mut events = Events::new();
    common::wait_for_handle(&read_op, &poller, &mut events, TEST_TIMEOUT);
    let (res, buf) = read_op.take();
    let n = res.unwrap();
    assert_eq!(n, 8);
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    assert_eq!(slice, b"CLI->SVR");

    if let Submission::Pending(op) = write_outcome {
        let _ = op.cancel();
        common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
        let _ = op.take();
    }
}

#[test]
fn cancel_pending_read_returns_aborted() {
    skip_on_wine!();
    let (server, _client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    let op = match server_reg.submit_read(Vec::<u8>::with_capacity(8)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };
    op.cancel().unwrap();

    let mut events = Events::new();
    common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
    let err = op
        .take()
        .0
        .expect_err("cancelled op should report an error");
    assert_eq!(
        err.raw_os_error(),
        Some(ERROR_OPERATION_ABORTED as i32),
        "expected ERROR_OPERATION_ABORTED, got {err:?}"
    );
}

#[test]
fn cancel_after_completion_is_noop() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let op = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    let _ = client_reg.submit_write(b"DATA".to_vec());

    let mut events = Events::new();
    common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);

    // Cancel after completion — must not panic / UAF, must return Ok.
    op.cancel().unwrap();

    let (res, _) = op.take();
    let n = res.unwrap();
    assert_eq!(n, 4);
}

#[test]
fn cancel_one_of_many_does_not_affect_siblings() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let mut ops: Vec<Option<OpHandle<Vec<u8>>>> = (0..3)
        .map(
            |_| match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
                Submission::Pending(op) => Some(op),
                other => panic!("expected Pending, got {other:?}"),
            },
        )
        .collect();

    ops[1].as_ref().unwrap().cancel().unwrap();

    let _ = client_reg.submit_write(b"AAAA".to_vec());
    let _ = client_reg.submit_write(b"CCCC".to_vec());

    let mut events = Events::new();
    let mut results = Vec::new();
    drain_handles(&poller, &mut events, &mut ops, &mut results);

    assert_eq!(results.len(), 3);
    let mut sibling_ok = 0;
    let mut middle_aborted = false;
    for (i, r) in results.into_iter().enumerate() {
        match r {
            Ok((n, _)) => {
                assert_ne!(i, 1, "cancelled middle op should not have completed Ok");
                assert_eq!(n, 4);
                sibling_ok += 1;
            }
            Err(e) => {
                assert_eq!(i, 1, "non-cancelled op errored: {e}");
                assert_eq!(e.raw_os_error(), Some(ERROR_OPERATION_ABORTED as i32));
                middle_aborted = true;
            }
        }
    }
    assert!(middle_aborted);
    assert_eq!(sibling_ok, 2);
}

// --- Step 3.4: stress test ---------------------------------------------

#[test]
#[ignore]
fn many_ops_stress() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    const ROUNDS: usize = 5_000;

    let mut events = Events::new();
    let mut payload = [0u8; 4];

    for i in 0..ROUNDS {
        payload.copy_from_slice(&(i as u32).to_le_bytes());

        let read_op = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
            Submission::Pending(op) => Some(op),
            Submission::Complete { .. } => None,
            Submission::Failed { error, .. } => panic!("read failed at i={i}: {error}"),
        };
        let write_op = match client_reg.submit_write(payload.to_vec()) {
            Submission::Pending(op) => Some(op),
            Submission::Complete { .. } => None,
            Submission::Failed { error, .. } => panic!("write failed at i={i}: {error}"),
        };

        if let Some(op) = read_op {
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let _ = op.take().0.unwrap();
        }
        if let Some(op) = write_op {
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let _ = op.take().0.unwrap();
        }
    }
}

/// Step 7c: `RegisteredFile::set_user_key` rebinds the key the
/// dispatcher emits in subsequent `Event`s. Register with a sentinel,
/// rebind before the peer writes, then assert the completion event
/// carries the new key (and `readable: true`).
#[test]
fn set_user_key_takes_effect() {
    skip_on_wine!();
    const SENTINEL: usize = 0;
    const KEY: usize = 4242;

    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe {
        poller
            .register_file(server.as_raw_handle(), SENTINEL)
            .unwrap()
    };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 1).unwrap() };

    let read_op = match server_reg.submit_read(Vec::<u8>::with_capacity(8)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending read on empty pipe, got {other:?}"),
    };

    // Rebind BEFORE the kernel posts the completion entry.
    server_reg.set_user_key(KEY);

    // Peer write — for a fresh pipe with a pending overlapped read on
    // the server, this completes synchronously on the client side and
    // the server's read finishes asynchronously.
    match client_reg.submit_write(b"PAYLOAD!".to_vec()) {
        Submission::Complete { bytes, .. } => assert_eq!(bytes, 8),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let (res, _) = op.take();
            let n = res.unwrap();
            assert_eq!(n, 8);
        }
        Submission::Failed { error, .. } => panic!("client write failed: {error}"),
    }

    let mut events = Events::new();
    let deadline = Instant::now() + TEST_TIMEOUT;
    let mut matched = false;
    while !matched {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            panic!(
                "timeout waiting for rebound-key event; got {:?}",
                events.iter().collect::<Vec<_>>()
            );
        }
        poller.wait(&mut events, Some(remaining)).unwrap();
        matched = events
            .iter()
            .any(|e| e.key == KEY && e.readable && !e.writable);
        // The sentinel must NOT appear in any drained event.
        assert!(
            !events.iter().any(|e| e.key == SENTINEL && e.readable),
            "set_user_key did not take effect: saw sentinel key in {:?}",
            events.iter().collect::<Vec<_>>()
        );
    }

    assert!(read_op.is_complete());
    let (res, buf) = read_op.take();
    let n = res.unwrap();
    assert_eq!(n, 8);
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    assert_eq!(slice, b"PAYLOAD!");
}

// --- Audit: oversized-capacity rejection (H1) -----------------------
//
// These tests exercise the `cap > u32::MAX` validation. On 32-bit
// targets `usize` is 32 bits, so a `usize` value can never exceed
// `u32::MAX` and the validation branch is unreachable; the tests are
// therefore restricted to 64-bit (or wider) targets.

#[cfg(target_pointer_width = "64")]
/// A `StableBufMut` impl that lies about its capacity in order to
/// exercise the `cap > u32::MAX` validation in `submit_read` /
/// `submit_write`. The mendacious `capacity()` value is returned
/// before any syscall, so the `as_mut_ptr()` / `as_ptr()` pointer is
/// never actually dereferenced through the lying length.
struct OversizedCapBuf {
    inner: Vec<u8>,
}

// SAFETY: `OversizedCapBuf` keeps a stable address while alive (it
// owns a `Vec<u8>`). It is `Send + 'static`.
#[cfg(target_pointer_width = "64")]
unsafe impl polling::os::iocp::StableBuf for OversizedCapBuf {
    fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }
    fn len(&self) -> usize {
        // Lie about length too so `submit_write` sees an oversized
        // value. The validation rejects the submission before any
        // pointer is read for `len` bytes.
        (u32::MAX as usize) + 1
    }
}

// SAFETY: see `StableBuf` impl above. `set_init` is never called by
// these tests because submissions fail before producing an
// `OpHandle`.
#[cfg(target_pointer_width = "64")]
unsafe impl polling::os::iocp::StableBufMut for OversizedCapBuf {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }
    fn capacity(&self) -> usize {
        (u32::MAX as usize) + 1
    }
    unsafe fn set_init(&mut self, _n: usize) {}
}

#[cfg(target_pointer_width = "64")]
#[test]
fn submit_read_rejects_oversized_capacity() {
    skip_on_wine!();
    let (server, _client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    let buf = OversizedCapBuf { inner: Vec::new() };
    match server_reg.submit_read(buf) {
        Submission::Failed { error, .. } => {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidInput,
                "expected InvalidInput, got {error:?}"
            );
        }
        other => panic!("expected Failed for oversized read, got {other:?}"),
    }
}

#[cfg(target_pointer_width = "64")]
#[test]
fn submit_write_rejects_oversized_length() {
    skip_on_wine!();
    let (_server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let buf = OversizedCapBuf { inner: Vec::new() };
    match client_reg.submit_write(buf) {
        Submission::Failed { error, .. } => {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::InvalidInput,
                "expected InvalidInput, got {error:?}"
            );
        }
        other => panic!("expected Failed for oversized write, got {other:?}"),
    }
}
