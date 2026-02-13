//! Take advantage of overlapped I/O on Windows using CompletionPacket.
#![cfg(windows)]

use polling::os::iocp::CompletionPacket;
use polling::{Event, Events, Poller};

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs, System::IO as wio};

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

    // Associate this file with the poller.
    unsafe {
        let poller_handle = poller.as_raw_handle();
        if wio::CreateIoCompletionPort(
            file_handle.as_raw_handle() as _,
            poller_handle as _,
            1,
            0) == std::ptr::null_mut()
        {
            panic!(
                "CreateIoCompletionPort failed: {}",
                io::Error::last_os_error()
            );
        }
    }

    // Repeatedly write to the pipe.
    let input_text = "Now is the time for all good men to come to the aid of their party";
    let write_buffer : &[u8] = input_text.as_bytes();
    let mut write_buffer_cursor = & *write_buffer;
    let mut len = input_text.len();

    let write_packet = CompletionPacket::new(Event::writable(2));

    while len > 0 {
        // Begin to write.
        // TODO: CompletionPacket is already in use!!!!! But this should be reset
        // once the packet completes. in poller.wait(...)
        let ptr = write_packet.as_ptr() as *mut _;
        unsafe {
            if wfs::WriteFile(
                file_handle.as_raw_handle() as _,
                write_buffer_cursor.as_ptr() as _,
                len as _,
                std::ptr::null_mut(),
                ptr) == 0 && wf::GetLastError() != wf::ERROR_IO_PENDING
            {
                panic!("WriteFile failed: {}", io::Error::last_os_error());
            }
        }


        // Wait for the overlapped operation to complete.
        'waiter: loop {
            events.clear();
            println!("Starting wait...");
            poller.wait(&mut events, None).unwrap();
            println!("Got events");

            for event in events.iter() {
                if event.writable && event.key == 2 {
                    let bytes_written  = event.transferred_bytes();
                    write_buffer_cursor = & write_buffer_cursor[bytes_written as usize..];
                    len -= bytes_written as usize;
                    break 'waiter;

                }
            }
        }
    }

/*
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

    // Associate this file with the poller.
    unsafe {
        let poller_handle = poller.as_raw_handle();
        if wio::CreateIoCompletionPort(
            file_handle.as_raw_handle() as _,
            poller_handle as _,
            2,
            0) == std::ptr::null_mut()
        {
            panic!(
                "CreateIoCompletionPort failed: {}",
                io::Error::last_os_error()
            );
        }
    }

    // Repeatedly read from the pipe.
    let mut buffer = vec![0u8; 1024];
    let mut buffer_cursor = &mut *buffer;
    let mut len = 1024;
    let mut bytes_received = 0;

    let read_packet = CompletionPacket::new(Event::readable(1));
    while bytes_received < input_text.len() {
        // Begin the read.
        let ptr = read_packet.as_ptr().cast();
        unsafe {
            if wfs::ReadFile(
                file_handle.as_raw_handle() as _,
                buffer_cursor.as_mut_ptr() as _,
                len as _,
                std::ptr::null_mut(),
                ptr) == 0 && wf::GetLastError() != wf::ERROR_IO_PENDING
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
                    let bytes_read  = event.transferred_bytes();
                    buffer_cursor = &mut buffer_cursor[bytes_read ..];
                    len -= bytes_read;
                    bytes_received += bytes_read;
                    break 'waiter;
                }
            }
        }
    }

    assert_eq!(bytes_received, input_text.len());
    assert_eq!(&buffer[..bytes_received], input_text.as_bytes());
*/
}
