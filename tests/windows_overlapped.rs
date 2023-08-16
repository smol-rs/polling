//! Take advantage of overlapped I/O on Windows using CompletionPacket.

#![cfg(windows)]

use polling::os::iocp::CompletionPacket;
use polling::{Event, Events, Poller};

use std::io;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::{Storage::FileSystem as wfs, System::IO as wio};

#[test]
fn anonymous_pipe() {
    // Create an anonymous pipe through miow.
    let (read, write) = miow::pipe::anonymous(1024).unwrap();

    // Create two completion packets: one for reading, one for writing.
    let read_packet = CompletionPacket::new(Event::readable(1));
    let write_packet = CompletionPacket::new(Event::writable(2));

    // Create a poller.
    let poller = Poller::new().unwrap();
    let mut events = Events::new();

    // Associate this pipe with the poller.
    unsafe {
        let poller_handle = poller.as_raw_handle();
        if wio::CreateIoCompletionPort(read.as_raw_handle() as _, poller_handle as _, 0, 0) == 0 {
            panic!(
                "CreateIoCompletionPort failed: {}",
                io::Error::last_os_error()
            );
        }
        if wio::CreateIoCompletionPort(write.as_raw_handle() as _, poller_handle as _, 0, 0) == 0 {
            panic!(
                "CreateIoCompletionPort failed: {}",
                io::Error::last_os_error()
            );
        }
    }

    // Repeatedly write to the pipe.
    let input_text = "Now is the time for all good men to come to the aid of their party";
    let mut len = input_text.len();
    let mut bytes_written_or_read = Box::new(0u32);
    while len > 0 {
        // Begin the write.
        unsafe {
            if wfs::WriteFile(
                write.as_raw_handle() as _,
                input_text.as_ptr() as _,
                len as _,
                bytes_written_or_read.as_mut() as *mut _,
                write_packet.as_ptr().cast(),
            ) == 0
            {
                panic!("WriteFile failed: {}", io::Error::last_os_error());
            }
        }

        // Wait for the overlapped operation to complete.
        'waiter: loop {
            events.clear();
            poller.wait(&mut events, None).unwrap();

            for event in events.iter() {
                if event.writable && event.key == 2 {
                    break 'waiter;
                }
            }
        }

        // Decrement the length by the number of bytes written.
        len -= *bytes_written_or_read as usize;
    }

    // Repeatedly read from the pipe.
    let mut buffer = vec![0u8; 1024];
    let mut buffer_cursor = &mut *buffer;
    let mut len = 1024;
    let mut bytes_received = 0;

    while bytes_received < input_text.len() {
        // Begin the read.
        unsafe {
            if wfs::ReadFile(
                read.as_raw_handle() as _,
                buffer_cursor.as_mut_ptr() as _,
                len as _,
                bytes_written_or_read.as_mut() as *mut _,
                read_packet.as_ptr().cast(),
            ) == 0
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
        buffer_cursor = &mut buffer_cursor[*bytes_written_or_read as usize..];
        len -= *bytes_written_or_read as usize;
        bytes_received += *bytes_written_or_read as usize;
    }

    assert_eq!(bytes_received, input_text.len());
    assert_eq!(&buffer[..bytes_received], input_text.as_bytes());
}
