//! Lifetime / cleanup tests for the v2 IOCP file-handle submission API.
//!
//! Spec: `docs/named-pipe.implement.checklist.md` Step 3.3 / 7.
//!
//! These tests verify the buffer- and packet-ownership invariants from
//! `docs/named-pipe.design.md` §3.4 (kernel-Arc protocol) and
//! §3.7 (deactivation / drain semantics):
//!   - dropping an `OpHandle` while the op is pending is **safe** post
//!     Step 7: the kernel's `Arc` strong ref keeps the allocation
//!     alive, and the eventual completion path drops the buffer
//!     cleanly via `OpInner::Drop`.
//!   - the buffer address is stable across submit / take (Pin invariant);
//!   - dropping the `Poller` and/or the underlying handle while ops are
//!     in flight does not corrupt memory.
//!   - the buffer address is stable across submit / take (Pin invariant);
//!   - dropping the `Poller` and/or the underlying handle while ops are
//!     in flight does not corrupt memory.

#![cfg(windows)]

mod common;

use std::os::windows::io::AsRawHandle;
use std::time::Duration;

use polling::os::iocp::{PollerIocpFileExt, Submission};
use polling::{Events, Poller};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn op_outlives_registered_file_clone() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let read_op = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    drop(server_reg);

    let _ = client_reg.submit_write(b"DATA".to_vec());

    let mut events = Events::new();
    common::wait_for_handle(&read_op, &poller, &mut events, TEST_TIMEOUT);
    let (res, buf) = read_op.take();
    let n = res.unwrap();
    assert_eq!(n, 4);
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    assert_eq!(slice, b"DATA");
}

#[test]
fn submit_after_remove_file_errors() {
    skip_on_wine!();
    let (server, _client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    server_reg.deactivate();

    match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Failed { error, buf } => {
            assert!(!error.to_string().is_empty(), "error message empty");
            assert_eq!(buf.capacity(), 4);
        }
        other => panic!("expected Failed after deactivate, got {other:?}"),
    }
}

#[test]
fn in_flight_op_completes_after_remove_file() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let read_op = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    server_reg.deactivate();

    let _ = client_reg.submit_write(b"PING".to_vec());

    let mut events = Events::new();
    common::wait_for_handle(&read_op, &poller, &mut events, TEST_TIMEOUT);
    let (res, buf) = read_op.take();
    let n = res.unwrap();
    assert_eq!(n, 4);
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    assert_eq!(slice, b"PING");
}

#[test]
fn drop_pending_op_is_safe() {
    skip_on_wine!();
    // Step 7: dropping a pending `OpHandle` is safe. The kernel still
    // holds one `Arc` strong ref (bumped at submit time), so the
    // allocation lives on; the eventual completion path drops it and
    // reclaims the buffer via `OpInner::Drop`. No leak, no UAF.
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let op = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    // Drop the user-side handle while still pending.
    drop(op);

    // Satisfy the read so the kernel posts a completion; the
    // dispatcher reclaims the kernel's Arc and the buffer is freed.
    let _ = client_reg.submit_write(b"DATA".to_vec());

    let mut events = Events::new();
    poller
        .wait(&mut events, Some(Duration::from_millis(200)))
        .unwrap();
}

#[test]
fn poller_dropped_before_op_completion() {
    skip_on_wine!();
    // Submit a pending op, then drop everything (including the
    // OpHandle while still pending) in a controlled order. Per the
    // Step 7 redesign, none of these drops may UAF: the kernel still
    // holds the per-op Arc until `CloseHandle` cancels in-flight ops
    // and posts their completions, at which point the IOCP port
    // (still alive via the OpInner back-ref) reclaims them.
    let (server, _client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    let op = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    drop(server_reg);
    drop(op);
    drop(server); // closes the kernel handle; cancels in-flight ops.
    drop(poller); // dispatcher gone; remaining kernel Arc refs leak the
                  //   per-op allocation, but no UAF can occur because
                  //   the OpInner back-reference holds the IOCP port.
}

#[test]
fn buf_addr_stable_across_submit() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let payload = b"PING".to_vec();
    let original_ptr = payload.as_ptr();

    let returned_ptr = match client_reg.submit_write(payload) {
        Submission::Complete { buf, .. } => buf.as_ptr(),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let (res, buf) = op.take();
            let _ = res.unwrap();
            buf.as_ptr()
        }
        Submission::Failed { error, .. } => panic!("write failed: {error}"),
    };

    assert_eq!(
        original_ptr, returned_ptr,
        "buffer heap address changed across submit"
    );

    // Drain the matching read so the pipe completion isn't left
    // dangling.
    let _ = server_reg.submit_read(Vec::<u8>::with_capacity(4));
    drop(client);
    let _ = poller.wait(&mut Events::new(), Some(Duration::from_millis(50)));
}

#[test]
#[ignore]
fn vec_grown_after_submit_is_safe() {
    skip_on_wine!();
    // The v2 API takes the buffer by value, so the user has no handle
    // to the `Vec` between `submit_*` and `OpHandle::take`. It
    // is impossible to grow / mutate the buffer mid-flight through
    // safe Rust, which is exactly the invariant the design intends.
    //
    // ```compile_fail
    // # use polling::os::iocp::{PollerIocpFileExt, Submission};
    // # use polling::Poller;
    // # use std::os::windows::io::AsRawHandle;
    // # let (s, _c) = polling_test_common::pipe();
    // # let p = Poller::new().unwrap();
    // # let r = unsafe { p.register_file(s.as_raw_handle()).unwrap() };
    // let mut buf = Vec::<u8>::with_capacity(4);
    // let _ = r.submit_write(buf);
    // buf.push(0); // ERROR: `buf` was moved into `submit_write`
    // ```
}
