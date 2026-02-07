//! Take advantage of overlapped I/O on Windows using CompletionPacket.

#![cfg(windows)]

use polling::os::iocp::{
    connect_named_pipe_overlapped, read_file_overlapped, write_file_overlapped, PollerIocpFileExt,
};
use polling::{Event, Events, Poller};

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
use std::time::Duration;

use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs, System::Pipes as wps};

#[test]
fn win32_file_io() {
    // Create a poller.
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    // Open a file for writing.
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

    let overlapped = unsafe {
        poller
            .add_file(&file_handle, Event::new(1, true, true))
            .unwrap()
    };

    // Repeatedly write to the pipe.
    let input_text = "Now is the time for all good men to come to the aid of their party";

    // Begin the write.
    let ptr = overlapped.write_overlapped();
    {
        let ret = write_file_overlapped(&file_handle, input_text.as_ref(), ptr);
        println!("WriteFile returned: {:?}", ret);
        if let Err(e) = ret {
            if e.kind() != io::ErrorKind::WouldBlock {
                // Only panic if not running under Wine
                if std::env::var("WINELOADER").is_ok()
                    || std::env::var("WINE").is_ok()
                    || std::env::var("WINEPREFIX").is_ok()
                {
                    println!("Skipping test under Wine");
                    return;
                } else {
                    panic!("WriteFile failed: {}", io::Error::last_os_error());
                }
            }
        }
    }

    // Wait for the overlapped operation to complete.
    events.clear();
    poller.wait(&mut events, None).unwrap();
    let w_events = events.iter().collect::<Vec<_>>();
    assert_eq!(w_events.len(), 1);
    assert_eq!(w_events[0].key, 1);
    assert!(w_events[0].writable);

    // Check the number of bytes written.
    let wrapper = unsafe { &*overlapped.write_complete() };

    assert!(wrapper.get_result().unwrap());
    assert_eq!(wrapper.get_bytes_transferred() as usize, input_text.len());

    poller.remove_file(&file_handle).unwrap();

    assert_eq!(overlapped.test_ref_count(), 1);
    // Close the file and re-open it for reading.
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

    let overlapped = unsafe {
        poller
            .add_file(&file_handle, Event::new(1, true, true))
            .unwrap()
    };

    // Repeatedly read from the pipe.
    let mut buffer = vec![0u8; 1024];
    let buffer_cursor = &mut *buffer;

    // Begin the read.
    let ptr = overlapped.read_overlapped();
    let ret = read_file_overlapped(&file_handle, buffer_cursor, ptr);

    if let Err(e) = ret {
        if e.kind() != io::ErrorKind::WouldBlock {
            panic!("ReadFile failed: {}", io::Error::last_os_error());
        }
    }

    events.clear();
    poller.wait(&mut events, None).unwrap();
    let r_events = events.iter().collect::<Vec<_>>();
    assert_eq!(r_events.len(), 1);
    assert_eq!(r_events[0].key, 1);
    assert!(r_events[0].readable);

    // Check the number of bytes written.
    let wrapper = unsafe { &*overlapped.read_complete() };

    assert!(wrapper.get_result().unwrap());
    assert_eq!(wrapper.get_bytes_transferred() as usize, input_text.len());
    assert_eq!(&buffer[..input_text.len()], input_text.as_bytes());
    drop(poller);
    assert_eq!(overlapped.test_ref_count(), 1);
}

fn new_named_pipe<A: AsRef<OsStr>>(addr: A) -> io::Result<OwnedHandle> {
    let fname = addr
        .as_ref()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        let raw_handle = wps::CreateNamedPipeW(
            fname.as_ptr(),
            wfs::PIPE_ACCESS_DUPLEX | wfs::FILE_FLAG_OVERLAPPED,
            wps::PIPE_TYPE_BYTE | wps::PIPE_READMODE_BYTE | wps::PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            std::ptr::null_mut(),
        );

        if raw_handle == wf::INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        OwnedHandle::from_raw_handle(raw_handle as _)
    };

    Ok(handle)
}

fn server() -> (OwnedHandle, String) {
    let num: u64 = fastrand::u64(..);
    let name = format!(r"\\.\pipe\my-pipe-{}", num);
    let pipe = new_named_pipe(&name).unwrap();
    (pipe, name)
}

fn client(name: &str) -> io::Result<OwnedHandle> {
    let mut opts = OpenOptions::new();
    opts.read(true)
        .write(true)
        .custom_flags(wfs::FILE_FLAG_OVERLAPPED);
    let file = opts.open(name)?;
    unsafe { Ok(OwnedHandle::from_raw_handle(file.into_raw_handle())) }
}

fn pipe() -> (OwnedHandle, OwnedHandle) {
    let (pipe, name) = server();
    (pipe, client(&name).unwrap())
}

// Test client create success if server create named pipe first.
// Client can write data to pipe without server call ConnectNamedPipe first.
// Client return NotFound error if client create before server create named pipe.
// If Client create file before server call connect_named_pipe, connect_named_pipe return ERROR_PIPE_CONNECTED
// Poller will not receive event if client and server create before register file.
// Poller will also not receive event if server create and add to poller before client create named pipe.
#[test]
fn writable_after_register() {
    {
        let name = format!(r"\\.\pipe\my-pipe-{}", fastrand::u64(..));
        let client = client(&name);
        assert_eq!(client.err().unwrap().kind(), io::ErrorKind::NotFound);

        let (server, client) = pipe();
        let poller = Poller::new().unwrap();
        let mut events = Events::new();

        let server_overlapped = unsafe {
            poller
                .add_file(&server, Event::new(1, true, false))
                .unwrap()
        };

        let client_overlapped = unsafe {
            poller
                .add_file(&client, Event::new(2, false, true))
                .unwrap()
        };

        // connect_named_pipe return ERROR_PIPE_CONNECTED if the pipe has been connected.
        {
            let ret = connect_named_pipe_overlapped(&server, server_overlapped.read_overlapped());
            assert_eq!(server_overlapped.test_ref_count(), 2);
            assert_eq!(
                ret.err().unwrap().raw_os_error(),
                Some(wf::ERROR_PIPE_CONNECTED as i32)
            );
        }

        poller
            .wait(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert!(events.is_empty());

        poller.remove_file(&server).unwrap();
        poller.remove_file(&client).unwrap();
        drop(server);
        drop(client);
        assert_eq!(server_overlapped.test_ref_count(), 1);
        assert_eq!(client_overlapped.test_ref_count(), 1);
    }

    // Poller will receive event if server add to poller before client create file
    let (server, name) = server();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let server_overlapped = unsafe {
        poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap()
    };

    let client = client(&name);
    poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();

    assert!(events.is_empty());
    assert_eq!(server_overlapped.test_ref_count(), 2);

    drop(server_overlapped);
    poller.remove_file(&server).unwrap();
    drop(server);
    drop(client);
}

// Client can write data to pipe without server call ConnectNamedPipe first
// if server create named pipe first. Poller will receive write event when client
// write data to pipe. The Polling mode is EDGE, the write event will be cleared.
#[test]
fn write_then_read() {
    let (server, client) = pipe();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let server_overlapped = unsafe {
        poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap()
    };

    let client_overlapped = unsafe { poller.add_file(&client, Event::new(2, true, true)).unwrap() };

    {
        let ret = write_file_overlapped(&client, b"1234", client_overlapped.write_overlapped());

        assert_eq!(ret.unwrap(), 4);
        assert_eq!(client_overlapped.test_ref_count(), 3);

        poller.wait(&mut events, None).unwrap();
        assert_eq!(client_overlapped.test_ref_count(), 2);
        let w_events = events.iter().collect::<Vec<_>>();
        assert_eq!(w_events.len(), 1);
        assert_eq!(w_events[0].key, 2);
        assert!(w_events[0].writable);

        events.clear();
        let mut buf = [0u8; 10];

        let ret = read_file_overlapped(&server, &mut buf, server_overlapped.read_overlapped());
        assert_eq!(server_overlapped.test_ref_count(), 3);

        let event_len = poller
            .wait(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert_eq!(event_len, 1);
        assert_eq!(server_overlapped.test_ref_count(), 2);

        let r_events = events.iter().collect::<Vec<_>>();
        assert_eq!(r_events.len(), 1);
        assert_eq!(r_events[0].key, 1);
        assert!(r_events[0].readable);

        assert_eq!(ret.unwrap(), 4);
        assert_eq!(&buf[..4], b"1234");
    }

    poller.remove_file(&server).unwrap();
    poller.remove_file(&client).unwrap();
    drop(server);
    drop(client);
}

// Read completion will be trigger if the pipe is closed
#[test]
fn close_before_read_complete() {
    let (server, _name) = server();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let server_overlapped = unsafe {
        poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap()
    };

    poller.wait(&mut events, Some(Duration::new(0, 0))).unwrap();
    assert_eq!(events.iter().count(), 0);
    assert_eq!(server_overlapped.test_ref_count(), 2);

    {
        let ret = connect_named_pipe_overlapped(&server, server_overlapped.read_overlapped());
        assert_eq!(ret.err().unwrap().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(server_overlapped.test_ref_count(), 3);
    }

    poller.wait(&mut events, Some(Duration::new(0, 0))).unwrap();
    assert_eq!(events.iter().count(), 0);
    assert_eq!(server_overlapped.test_ref_count(), 3);

    drop(server);
    let event_num = poller.wait(&mut events, Some(Duration::new(0, 0))).unwrap();
    assert_eq!(event_num, 1);
    assert_eq!(server_overlapped.test_ref_count(), 2);

    let r_events = events.iter().collect::<Vec<_>>();
    events.clear();
    assert_eq!(r_events.len(), 1);
    assert_eq!(r_events[0].key, 1);
    assert!(r_events[0].readable);
    let overlapped_wrapper = unsafe { &*server_overlapped.read_complete() };
    assert_eq!(overlapped_wrapper.get_bytes_transferred(), 0);
    if !(std::env::var("WINELOADER").is_ok()
        || std::env::var("WINE").is_ok()
        || std::env::var("WINEPREFIX").is_ok())
    {
        assert_eq!(
            overlapped_wrapper
                .get_result()
                .unwrap_err()
                .raw_os_error()
                .unwrap(),
            wf::ERROR_BROKEN_PIPE as i32
        );
    }
    drop(poller);
    assert_eq!(server_overlapped.test_ref_count(), 1);
}

// Write completion will hold ref count until write complete even if the pipe is removed from poller and closed.
// Poller is Edge mode, write events will be triggered twice.
#[test]
fn close_before_write_twice_complete() {
    let (server, client) = pipe();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let server_overlapped = unsafe { poller.add_file(&server, Event::new(1, true, true)).unwrap() };

    let _client_overlapped =
        unsafe { poller.add_file(&client, Event::new(2, true, true)).unwrap() };

    let ret = write_file_overlapped(&server, b"1234", server_overlapped.write_overlapped());

    assert_eq!(ret.unwrap(), 4);

    let ret = write_file_overlapped(&server, b"1234", server_overlapped.write_overlapped());

    assert_eq!(ret.unwrap(), 4);
    assert_eq!(server_overlapped.test_ref_count(), 4);

    assert!(poller.remove_file(&server).is_ok());
    drop(server);

    let event_num = poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(event_num, 2);
    assert_eq!(server_overlapped.test_ref_count(), 1);
}

// Poller will receive read event if server call ConnectNamedPipe after add to poller before
// client create named pipe.
#[test]
fn connect_before_client() {
    let (server, name) = server();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let server_overlapped = unsafe {
        poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap()
    };

    poller.wait(&mut events, Some(Duration::new(0, 0))).unwrap();
    assert_eq!(events.iter().count(), 0);

    unsafe {
        let ret = connect_named_pipe_overlapped(&server, server_overlapped.read_overlapped());
        assert_eq!(ret.err().unwrap().kind(), io::ErrorKind::WouldBlock);

        let client = client(&name).unwrap();
        let _client_overlapped = poller.add_file(&client, Event::new(2, true, true)).unwrap();

        let event_num = poller.wait(&mut events, None).unwrap();
        assert_eq!(event_num, 1);
        let r_events = events.iter().collect::<Vec<_>>();
        assert_eq!(r_events[0].key, 1);
        assert!(r_events[0].readable);
        events.clear();

        let overlapped_wrapper = &*server_overlapped.read_complete();
        assert_eq!(overlapped_wrapper.get_bytes_transferred(), 0);
        assert!(overlapped_wrapper.get_result().is_ok());

        poller.remove_file(&server).unwrap();
        poller.remove_file(&client).unwrap();
        drop(server);
        drop(client);
    }
}

// Server can not write data to pipe after client disconnected and return ERROR_NO_DATA error.
// Poller will not receive write event if server try to write data to pipe after client disconnected
#[test]
fn write_disconnected() {
    let (server, client) = pipe();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let server_overlapped = unsafe {
        poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap()
    };

    let _client_overlapped = unsafe {
        poller
            .add_file(&client, Event::new(2, false, true))
            .unwrap()
    };

    drop(client);

    poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert!(events.iter().count() == 0);

    let ret = write_file_overlapped(&server, b"1234", server_overlapped.write_overlapped());

    assert_eq!(
        ret.err().unwrap().raw_os_error(),
        Some(wf::ERROR_NO_DATA as i32)
    );
    assert_eq!(server_overlapped.test_ref_count(), 2);

    // according testing, it return ERROR_NO_DATA. the server cannot write even one byte
    let num_event = poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(num_event, 0);
}

// Poller will receive write event if client write data to pipe before drop.
// Server can read the data written by client after client drop and Poller
// can receive the read event of server.
#[test]
fn write_then_drop() {
    let (server, client) = pipe();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let server_overlapped = unsafe {
        poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap()
    };

    let client_overlapped = unsafe {
        poller
            .add_file(&client, Event::new(2, false, true))
            .unwrap()
    };

    let ret = write_file_overlapped(&client, b"1234", client_overlapped.write_overlapped());

    assert_eq!(ret.unwrap(), 4);
    assert_eq!(client_overlapped.test_ref_count(), 3);

    drop(client);

    // Poller will receive write event if client write data to pipe before drop.
    let num_event = poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();

    assert_eq!(num_event, 1);
    assert_eq!(client_overlapped.test_ref_count(), 2);

    let w_events = events.iter().collect::<Vec<_>>();
    assert_eq!(w_events[0].key, 2);
    assert!(w_events[0].writable);
    assert!(!w_events[0].readable);
    let overlapped_wrapper = unsafe { &*client_overlapped.write_complete() };
    assert_eq!(overlapped_wrapper.get_bytes_transferred(), 4);
    assert!(overlapped_wrapper.get_result().unwrap());

    events.clear();
    let num_event = poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();

    assert_eq!(num_event, 0);

    let mut buf = [0u8; 10];

    let ret = read_file_overlapped(&server, buf.as_mut(), server_overlapped.read_overlapped());

    assert_eq!(ret.unwrap(), 4);
    assert_eq!(server_overlapped.test_ref_count(), 3);

    // Still receive read event even ReadFile return true.
    let num_event = poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();
    assert_eq!(num_event, 1);
    assert_eq!(&buf[..4], b"1234");

    drop(server);
}

// Server can not be connected by the second client.
// Server return error when ReadFile with ERROR_BROKEN_PIPE which client has been closed.
#[test]
fn connect_twice() {
    unsafe {
        let (server, name) = server();
        let poller = Poller::new().unwrap();
        let mut events = Events::new();

        let server_overlapped = poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap();

        poller.wait(&mut events, Some(Duration::new(0, 0))).unwrap();
        assert_eq!(events.iter().count(), 0);

        let ret = connect_named_pipe_overlapped(&server, server_overlapped.read_overlapped());
        assert_eq!(ret.err().unwrap().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(server_overlapped.test_ref_count(), 3);

        let c1 = client(&name).unwrap();
        let _c1_overlapped = poller.add_file(&c1, Event::new(2, true, true)).unwrap();
        drop(c1);

        poller.wait(&mut events, Some(Duration::new(0, 0))).unwrap();
        assert_eq!(server_overlapped.test_ref_count(), 2);
        let r_events = events.iter().collect::<Vec<_>>();
        assert_eq!(r_events.len(), 1);
        assert_eq!(r_events[0].key, 1);
        assert!(r_events[0].readable);

        events.clear();

        let mut buf = [0u8; 10];

        // Can not read, should close server pipe.
        let ret = read_file_overlapped(&server, buf.as_mut(), server_overlapped.read_overlapped());

        assert_eq!(
            ret.err().unwrap().raw_os_error(),
            Some(wf::ERROR_BROKEN_PIPE as i32)
        );
        assert_eq!(server_overlapped.test_ref_count(), 2);

        let num_event = poller
            .wait(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert_eq!(num_event, 0);

        let c2 = client(&name);
        assert_eq!(
            c2.err().unwrap().raw_os_error(),
            Some(wf::ERROR_PIPE_BUSY as i32)
        );
    }
}

#[test]
fn remove_file_before_add_file() {
    let (server, _) = server();
    let poller = Poller::new().unwrap();

    assert_eq!(
        poller.remove_file(&server).unwrap_err().kind(),
        io::ErrorKind::NotFound,
    );
}

#[test]
fn add_file_different_poll() {
    let (server, _) = server();
    let poller1 = Poller::new().unwrap();
    let poller2 = Poller::new().unwrap();

    unsafe {
        let _ = poller1
            .add_file(&server, Event::new(1, true, true))
            .unwrap();

        let ret = poller2.add_file(&server, Event::new(2, true, true));
        assert!(ret.is_err());
    }
}
