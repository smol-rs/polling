//! Take advantage of overlapped I/O on Windows using CompletionPacket.

#![cfg(windows)]

use polling::os::iocp::{FileOverlappedWrapper, PollerIocpFileExt};
use polling::{Event, Events, Poller};
use windows_sys::Win32::System::IO::OVERLAPPED;

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
use std::time::Duration;

use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs, System::Pipes as wps};

#[test]
fn win32_file_io() {
    // Create a poller.
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    println!("Create a temp file");
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

    println!("file handle: {:?}", file_handle);
    let overlapped = unsafe {
        poller
            .add_file(&file_handle, Event::new(1, true, true))
            .unwrap()
    };

    // Repeatedly write to the pipe.
    let input_text = "Now is the time for all good men to come to the aid of their party";
    let mut len = input_text.len();

    while len > 0 {
        // Begin the write.
        let ptr = overlapped.write_ptr();
        unsafe {
            let ret = wfs::WriteFile(
                file_handle.as_raw_handle() as _,
                input_text.as_ptr() as _,
                len as _,
                std::ptr::null_mut(),
                ptr,
            );
            println!("WriteFile returned: {}, len: {}, ptr: {:p}", ret, len, ptr);
            if ret == 0 && wf::GetLastError() != wf::ERROR_IO_PENDING {
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

        // Wait for the overlapped operation to complete.
        'waiter: loop {
            events.clear();
            println!("Starting wait...");
            poller.wait(&mut events, None).unwrap();
            println!("Got events");

            for event in events.iter() {
                if event.writable && event.key == 1 {
                    break 'waiter;
                }
            }
        }

        // Decrement the length by the number of bytes written.
        let wrapper = unsafe { &*FileOverlappedWrapper::from_overlapped_ptr(ptr) };
        wrapper.get_result().map_or_else(
            |e| {
                match e.kind() {
                    io::ErrorKind::WouldBlock => {
                        // The operation is still pending, we can ignore this error.
                        println!("WriteFile is still pending, continuing...");
                    }
                    _ => panic!("WriteFile failed: {}", e),
                }
            },
            |ret| {
                if !ret {
                    println!("The file handle maybe closed");
                } else {
                    let bytes_written = wrapper.get_bytes_transferred();
                    println!("Bytes written: {}", bytes_written);
                    len -= bytes_written as usize;
                }
            },
        );
    }

    poller.remove_file(&file_handle).unwrap();
    // Close the file and re-open it for reading.
    drop(file_handle);
    println!("file handle dropped");

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

    println!("file handle: {:?}", file_handle);
    let overlapped = unsafe {
        poller
            .add_file(&file_handle, Event::new(1, true, true))
            .unwrap()
    };

    // Repeatedly read from the pipe.
    let mut buffer = vec![0u8; 1024];
    let mut buffer_cursor = &mut *buffer;
    let mut len = 1024;
    let mut bytes_received = 0;

    while bytes_received < input_text.len() {
        // Begin the read.
        let ptr = overlapped.read_ptr();
        unsafe {
            if wfs::ReadFile(
                file_handle.as_raw_handle() as _,
                buffer_cursor.as_mut_ptr() as _,
                len as _,
                std::ptr::null_mut(),
                ptr,
            ) == 0
                && wf::GetLastError() != wf::ERROR_IO_PENDING
            {
                panic!("ReadFile failed: {}", io::Error::last_os_error());
            }
        }

        // Wait for the overlapped operation to complete.
        'waiter: loop {
            events.clear();
            poller.wait(&mut events, None).unwrap();

            for event in events.iter() {
                if event.readable && event.key == 1 {
                    break 'waiter;
                }
            }
        }

        // Increment the cursor and decrement the length by the number of bytes read.
        let bytes_read = input_text.len();
        buffer_cursor = &mut buffer_cursor[bytes_read..];
        len -= bytes_read;
        bytes_received += bytes_read;
    }

    assert_eq!(bytes_received, input_text.len());
    assert_eq!(&buffer[..bytes_received], input_text.as_bytes());
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

unsafe fn connect_named_pipe(
    handle: &impl AsRawHandle,
    overlapped: *mut OVERLAPPED,
) -> io::Result<()> {
    if wps::ConnectNamedPipe(handle.as_raw_handle() as _, overlapped) != 0 {
        // If ConnectNamedPipe returns non-zero, the connection was successful.
        return Ok(());
    }

    let err = io::Error::last_os_error();

    match err.raw_os_error().map(|e| e as u32) {
        Some(wf::ERROR_PIPE_CONNECTED) => Ok(()),
        Some(wf::ERROR_NO_DATA) => Err(io::ErrorKind::WouldBlock.into()),
        Some(wf::ERROR_IO_PENDING) => Err(io::ErrorKind::WouldBlock.into()),
        _ => Err(err),
    }
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
// Client return NotFound error if clinet create before server create named pipe.
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

        let _server_overlapped = unsafe {
            poller
                .add_file(&server, Event::new(1, true, false))
                .unwrap()
        };

        let _client_overlapped = unsafe {
            poller
                .add_file(&client, Event::new(2, false, true))
                .unwrap()
        };

        poller
            .wait(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert!(events.is_empty());

        poller.remove_file(&server).unwrap();
        poller.remove_file(&client).unwrap();
        drop(server);
        drop(client);
    }

    // Poller will receive event if server add to poller before client create file
    let (server, name) = server();
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    let _server_overlapped = unsafe {
        poller
            .add_file(&server, Event::new(1, true, false))
            .unwrap()
    };

    let client = client(&name);
    poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();

    assert!(events.is_empty());

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

    unsafe {
        let mut written = 0u32;
        let ret = wfs::WriteFile(
            client.as_raw_handle(),
            b"1234" as *const u8,
            4,
            (&mut written) as *mut u32,
            client_overlapped.write_ptr(),
        );

        assert!(ret == wf::TRUE && written == 4);

        loop {
            poller.wait(&mut events, None).unwrap();
            let events = events.iter().collect::<Vec<_>>();
            if let Some(event) = events.iter().find(|e| e.key == 2) {
                if event.writable {
                    break;
                }
            }
        }

        events.clear();
        let mut buf = [0u8; 10];

        let mut read = 0u32;
        let ret = wfs::ReadFile(
            server.as_raw_handle(),
            &mut buf as *mut u8,
            10,
            (&mut read) as *mut u32,
            server_overlapped.read_ptr(),
        );

        let event_len = poller
            .wait(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert_eq!(event_len, 1);

        let events = events.iter().collect::<Vec<_>>();
        events.iter().for_each(|e| {
            if e.key == 2 {
                assert!(e.writable);
            }
        });

        assert!(ret == wf::TRUE && read == 4);
        assert_eq!(&buf[..4], b"1234");
    }

    poller.remove_file(&server).unwrap();
    poller.remove_file(&client).unwrap();
    drop(server);
    drop(client);
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
        let ret = connect_named_pipe(&server, server_overlapped.read_ptr());
        assert_eq!(ret.err().unwrap().kind(), io::ErrorKind::WouldBlock);

        let client = client(&name).unwrap();
        let _client_overlapped = poller.add_file(&client, Event::new(2, true, true)).unwrap();

        loop {
            let event_num = poller.wait(&mut events, None).unwrap();
            assert_eq!(event_num, 1);
            let e = events.iter().collect::<Vec<_>>();
            events.clear();
            if let Some(event) = e.iter().find(|e| e.key == 1) {
                if event.readable {
                    let overlapped_wrapper =
                        &*FileOverlappedWrapper::from_overlapped_ptr(server_overlapped.read_ptr());
                    assert_eq!(overlapped_wrapper.get_bytes_transferred(), 0);
                    assert!(overlapped_wrapper.get_result().is_ok());
                    break;
                }
            }
        }

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

    unsafe {
        let mut written = 0u32;
        let ret = wfs::WriteFile(
            server.as_raw_handle(),
            b"1234" as *const u8,
            1,
            (&mut written) as *mut u32,
            server_overlapped.write_ptr(),
        );

        let e = io::Error::last_os_error();

        assert_eq!(ret, wf::FALSE);
        assert_eq!(written, 0);
        assert_eq!(e.raw_os_error(), Some(wf::ERROR_NO_DATA as i32));

        // according testing, it return ERROR_NO_DATA. the server cannot write even one byte
        let num_event = poller
            .wait(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert_eq!(num_event, 0);
    }
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

    unsafe {
        let mut written = 0u32;
        let ret = wfs::WriteFile(
            client.as_raw_handle(),
            b"1234" as *const u8,
            4,
            (&mut written) as *mut u32,
            client_overlapped.write_ptr(),
        );

        assert!(ret == wf::TRUE && written == 4);
    }

    drop(client);

    // Poller will receive write event if client write data to pipe before drop.
    let num_event = poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();

    assert_eq!(num_event, 1);

    unsafe {
        let events = events.iter().collect::<Vec<_>>();
        assert_eq!(events[0].key, 2);
        assert!(events[0].writable);
        assert!(!events[0].readable);
        let overlapped_wrapper =
            &*FileOverlappedWrapper::from_overlapped_ptr(client_overlapped.write_ptr());
        assert_eq!(overlapped_wrapper.get_bytes_transferred(), 4);
        assert!(overlapped_wrapper.get_result().unwrap());
    }

    events.clear();
    let num_event = poller
        .wait(&mut events, Some(Duration::from_millis(10)))
        .unwrap();

    assert_eq!(num_event, 0);

    unsafe {
        let mut buf = [0u8; 10];

        let mut read = 0u32;
        let ret = wfs::ReadFile(
            server.as_raw_handle(),
            &mut buf as *mut u8,
            10,
            (&mut read) as *mut u32,
            server_overlapped.read_ptr(),
        );

        assert_eq!(ret, wf::TRUE);
        assert_eq!(read, 4);

        // Still receive read event even ReadFile return true.
        let num_event = poller
            .wait(&mut events, Some(Duration::from_millis(10)))
            .unwrap();
        assert_eq!(num_event, 1);
        assert_eq!(&buf[..4], b"1234");
    }

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

        let ret = connect_named_pipe(&server, server_overlapped.read_ptr());
        assert_eq!(ret.err().unwrap().kind(), io::ErrorKind::WouldBlock);

        let c1 = client(&name).unwrap();
        let _c1_overlapped = poller.add_file(&c1, Event::new(2, true, true)).unwrap();
        drop(c1);

        poller.wait(&mut events, Some(Duration::new(0, 0))).unwrap();
        let ret_events = events.iter().collect::<Vec<_>>();
        assert_eq!(ret_events.len(), 1);
        assert_eq!(ret_events[0].key, 1);
        assert!(ret_events[0].readable);

        events.clear();

        let mut buf = [0u8; 10];

        let mut read = 0u32;
        // Can not read, should close server pipe.
        let ret = wfs::ReadFile(
            server.as_raw_handle(),
            &mut buf as *mut u8,
            10,
            (&mut read) as *mut u32,
            server_overlapped.read_ptr(),
        );

        let e = io::Error::last_os_error();

        assert_eq!(ret, wf::FALSE);
        assert_eq!(read, 0);
        assert_eq!(e.raw_os_error(), Some(wf::ERROR_BROKEN_PIPE as i32));

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
