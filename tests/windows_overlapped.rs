//! Windows IOCP file-handle tests for the `RegisteredFile` submission API.
//!
//! Spec: `docs/named-pipe.implement.checklist.md` Step 4 + 7 +
//! `docs/named-pipe.design.md` §7.
//!
//! Step 7 of the implementation deletes `FileCompletion` entirely; the
//! `OpHandle` returned from `submit_*` now owns the completion
//! lifecycle (`is_complete` / `take`). Step 7b drives those checks
//! by emitting a normal `Event { key, readable, writable }` per
//! completion, so the dispatcher integrates cleanly with reactors.

#![cfg(windows)]

mod common;

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::Duration;

use polling::os::iocp::{PollerIocpFileExt, Submission};
use polling::{Events, Poller};

use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn win32_file_io() {
    skip_on_wine!();
    let poller = Poller::new().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    let fname = file_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();

    let file_handle = unsafe {
        let raw_handle = wfs::CreateFileW(
            fname.as_ptr(),
            wf::GENERIC_WRITE | wf::GENERIC_READ,
            0,
            std::ptr::null_mut(),
            wfs::CREATE_ALWAYS,
            wfs::FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        );
        if raw_handle == wf::INVALID_HANDLE_VALUE {
            panic!("CreateFileW failed: {}", io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(raw_handle as _)
    };

    let reg = unsafe {
        poller
            .register_file(file_handle.as_raw_handle(), 1)
            .unwrap()
    };

    let input_text = "Now is the time for all good men to come to the aid of their party";
    let payload = input_text.as_bytes().to_vec();
    let payload_len = payload.len();

    let written = match reg.submit_write(payload) {
        Submission::Complete { bytes, .. } => bytes,
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            op.take().0.unwrap()
        }
        Submission::Failed { error, .. } => {
            if std::env::var("WINELOADER").is_ok()
                || std::env::var("WINE").is_ok()
                || std::env::var("WINEPREFIX").is_ok()
            {
                println!("Skipping under Wine: {error}");
                return;
            }
            panic!("write failed: {error}");
        }
    };
    assert_eq!(written, payload_len);

    drop(reg);
    drop(file_handle);

    let file_handle = unsafe {
        let raw_handle = wfs::CreateFileW(
            fname.as_ptr(),
            wf::GENERIC_READ | wf::GENERIC_WRITE,
            0,
            std::ptr::null_mut(),
            wfs::OPEN_EXISTING,
            wfs::FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        );
        if raw_handle == wf::INVALID_HANDLE_VALUE {
            panic!("CreateFileW failed: {}", io::Error::last_os_error());
        }
        OwnedHandle::from_raw_handle(raw_handle as _)
    };

    let reg = unsafe {
        poller
            .register_file(file_handle.as_raw_handle(), 1)
            .unwrap()
    };
    let buf = Vec::<u8>::with_capacity(1024);

    let (n, buf) = match reg.submit_read(buf) {
        Submission::Complete { bytes, buf } => (bytes, buf),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            {
                let (r, b) = op.take();
                (r.unwrap(), b)
            }
        }
        Submission::Failed { error, .. } => panic!("read failed: {error}"),
    };
    assert_eq!(n, payload_len);
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    assert_eq!(slice, input_text.as_bytes());
}

#[test]
fn writable_after_register() {
    skip_on_wine!();
    {
        let name = format!(r"\\.\pipe\my-pipe-{}", fastrand::u64(..));
        let client = common::client(&name);
        assert_eq!(client.err().unwrap().kind(), io::ErrorKind::NotFound);
    }

    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let _client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    match server_reg.submit_connect_named_pipe() {
        Submission::Complete { bytes, .. } => assert_eq!(bytes, 0),
        other => panic!("expected sync Complete (pipe pre-connected), got {other:?}"),
    }

    let mut events = Events::new();
    poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(events.iter().count(), 0);

    let (server2, name) = common::server();
    let poller2 = Poller::new().unwrap();
    let _server2_reg = unsafe { poller2.register_file(server2.as_raw_handle(), 3).unwrap() };
    let _client2 = common::client(&name).unwrap();

    let mut events = Events::new();
    poller2
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(events.iter().count(), 0);
}

#[test]
fn write_then_read() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    match client_reg.submit_write(b"1234".to_vec()) {
        Submission::Complete { bytes, .. } => assert_eq!(bytes, 4),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let (res, _) = op.take();
            let n = res.unwrap();
            assert_eq!(n, 4);
        }
        Submission::Failed { error, .. } => panic!("write failed: {error}"),
    }

    let buf = Vec::<u8>::with_capacity(10);
    let (n, buf) = match server_reg.submit_read(buf) {
        Submission::Complete { bytes, buf } => (bytes, buf),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            {
                let (r, b) = op.take();
                (r.unwrap(), b)
            }
        }
        Submission::Failed { error, .. } => panic!("read failed: {error}"),
    };
    assert_eq!(n, 4);
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    assert_eq!(slice, b"1234");
}

#[test]
fn close_before_read_complete() {
    skip_on_wine!();
    let (server, _name) = common::server();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    let op = match server_reg.submit_connect_named_pipe() {
        Submission::Pending(op) => op,
        Submission::Complete { .. } => {
            panic!("expected Pending for connect on a fresh server with no client");
        }
        Submission::Failed { error, .. } => panic!("connect submission failed: {error}"),
    };

    drop(server_reg);
    drop(server);

    let mut events = Events::new();
    common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);

    match op.take() {
        (Ok(0), _) => {}
        (Ok(n), _) => panic!("unexpected success with {n} bytes"),
        (Err(e), _) => {
            let code = e.raw_os_error().unwrap_or(0);
            assert!(
                matches!(
                    code as u32,
                    wf::ERROR_OPERATION_ABORTED
                        | wf::ERROR_BROKEN_PIPE
                        | wf::ERROR_INVALID_HANDLE
                        | wf::ERROR_PIPE_NOT_CONNECTED
                ),
                "unexpected error after handle close: {e} (code {code})"
            );
        }
    }
}

#[test]
fn connect_before_client() {
    skip_on_wine!();
    let (server, name) = common::server();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    let mut events = Events::new();
    poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(events.iter().count(), 0);

    let op = match server_reg.submit_connect_named_pipe() {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    let client = common::client(&name).unwrap();
    let _client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    let mut events = Events::new();
    common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
    let (res, _) = op.take();
    let bytes = res.unwrap();
    assert_eq!(bytes, 0);
}

#[test]
fn write_disconnected() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let _client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    drop(client);

    let mut events = Events::new();
    poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(events.iter().count(), 0);

    match server_reg.submit_write(b"1234".to_vec()) {
        Submission::Failed { error, buf } => {
            let code = error.raw_os_error().map(|c| c as u32).unwrap_or(0);
            assert!(
                matches!(
                    code,
                    wf::ERROR_NO_DATA | wf::ERROR_PIPE_NOT_CONNECTED | wf::ERROR_BROKEN_PIPE
                ),
                "unexpected error: {error} (code {code})"
            );
            assert_eq!(buf.len(), 4);
        }
        other => panic!("expected Failed for write to disconnected pipe, got {other:?}"),
    }

    let mut events = Events::new();
    poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(events.iter().count(), 0);
}

#[test]
fn drop_writer_drain() {
    skip_on_wine!();
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };
    let client_reg = unsafe { poller.register_file(client.as_raw_handle(), 2).unwrap() };

    match client_reg.submit_write(b"1234".to_vec()) {
        Submission::Complete { bytes, .. } => assert_eq!(bytes, 4),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let (res, _) = op.take();
            let n = res.unwrap();
            assert_eq!(n, 4);
        }
        Submission::Failed { error, .. } => panic!("write failed: {error}"),
    }

    drop(client_reg);
    drop(client);

    let buf = Vec::<u8>::with_capacity(10);
    let (n, buf) = match server_reg.submit_read(buf) {
        Submission::Complete { bytes, buf } => (bytes, buf),
        Submission::Pending(op) => {
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            {
                let (r, b) = op.take();
                (r.unwrap(), b)
            }
        }
        Submission::Failed { error, .. } => panic!("read failed: {error}"),
    };
    assert_eq!(n, 4);
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    assert_eq!(slice, b"1234");
}

#[test]
fn connect_twice() {
    skip_on_wine!();
    let (server, name) = common::server();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    let op = match server_reg.submit_connect_named_pipe() {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    let c1 = common::client(&name).unwrap();
    let _c1_reg = unsafe { poller.register_file(c1.as_raw_handle(), 4).unwrap() };

    let mut events = Events::new();
    common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
    let (res, _) = op.take();
    let bytes = res.unwrap();
    assert_eq!(bytes, 0);

    drop(c1);

    match server_reg.submit_connect_named_pipe() {
        Submission::Failed { error, .. } => {
            let code = error.raw_os_error().map(|c| c as u32).unwrap_or(0);
            assert!(
                matches!(
                    code,
                    wf::ERROR_NO_DATA
                        | wf::ERROR_PIPE_CONNECTED
                        | wf::ERROR_BROKEN_PIPE
                        | wf::ERROR_PIPE_NOT_CONNECTED
                ),
                "unexpected error: {error} (code {code})"
            );
        }
        Submission::Complete { .. } => {}
        Submission::Pending(op) => {
            let _ = op.cancel();
            let mut events = Events::new();
            common::wait_for_handle(&op, &poller, &mut events, TEST_TIMEOUT);
            let _ = op.take();
        }
    }
}

#[test]
fn remove_file_before_add_file() {
    skip_on_wine!();
    let (server, _name) = common::server();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe { poller.register_file(server.as_raw_handle(), 1).unwrap() };

    server_reg.deactivate();

    match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Failed { buf, .. } => assert_eq!(buf.capacity(), 4),
        other => panic!("expected Failed after deactivate, got {other:?}"),
    }
    match server_reg.submit_write(b"x".to_vec()) {
        Submission::Failed { buf, .. } => assert_eq!(buf, b"x"),
        other => panic!("expected Failed after deactivate, got {other:?}"),
    }
}

#[test]
fn add_file_different_poll() {
    skip_on_wine!();
    let (server, _) = common::server();
    let poller1 = Poller::new().unwrap();
    let poller2 = Poller::new().unwrap();

    let _reg1 = unsafe { poller1.register_file(server.as_raw_handle(), 1).unwrap() };
    let result = unsafe { poller2.register_file(server.as_raw_handle(), 1) };
    assert!(
        result.is_err(),
        "second register_file must fail when handle already bound"
    );
}

/// Step 7b: the dispatcher emits a normal `Event { key, readable,
/// writable }` per file-op completion, mirroring the registered key
/// and the op's direction. A `submit_read` completion must surface as
/// `(key, readable: true, writable: false)`.
#[test]
fn read_completion_emits_event_with_key_and_direction() {
    skip_on_wine!();
    const SERVER_KEY: usize = 7;
    const CLIENT_KEY: usize = 8;
    let (server, client) = common::pipe();
    let poller = Poller::new().unwrap();
    let server_reg = unsafe {
        poller
            .register_file(server.as_raw_handle(), SERVER_KEY)
            .unwrap()
    };
    let _client_reg = unsafe {
        poller
            .register_file(client.as_raw_handle(), CLIENT_KEY)
            .unwrap()
    };

    let op = match server_reg.submit_read(Vec::<u8>::with_capacity(4)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    op.cancel().unwrap();

    let mut events = Events::new();
    poller.wait(&mut events, Some(TEST_TIMEOUT)).unwrap();

    let matched = events
        .iter()
        .any(|e| e.key == SERVER_KEY && e.readable && !e.writable);
    assert!(
        matched,
        "expected an Event {{ key: {SERVER_KEY}, readable: true, writable: false }}, got {:?}",
        events.iter().collect::<Vec<_>>()
    );
    assert!(op.is_complete());
    let _ = op.take();
}
