//! Two concurrent reads on a named pipe + cancel demo for the v2
//! IOCP file-handle API.
//!
//! Run with:
//!
//! ```text
//! cargo run --example named_pipe_concurrent
//! ```

#[cfg(not(windows))]
fn main() {
    eprintln!("named_pipe_concurrent example only runs on Windows");
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use polling::os::iocp::{OpHandle, PollerIocpFileExt, Submission};
    use polling::{Events, Poller};

    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::io::{self, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::time::Duration;

    use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs, System::Pipes as wps};

    fn server(name: &str) -> io::Result<OwnedHandle> {
        let wide: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
        let raw = unsafe {
            wps::CreateNamedPipeW(
                wide.as_ptr(),
                wfs::PIPE_ACCESS_DUPLEX | wfs::FILE_FLAG_OVERLAPPED,
                wps::PIPE_TYPE_BYTE | wps::PIPE_READMODE_BYTE | wps::PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                std::ptr::null_mut(),
            )
        };
        if raw == wf::INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(raw as _) })
    }

    fn client(name: &str) -> io::Result<std::fs::File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(wfs::FILE_FLAG_OVERLAPPED)
            .open(name)
    }

    let name = format!(r"\\.\pipe\polling-concurrent-{}", std::process::id());
    let server_h = server(&name)?;
    let mut client_file = client(&name)?;

    let poller = Poller::new()?;
    // SAFETY: `server_h` outlives every `OpHandle` derived from this
    // registration; we drain all completions before returning.
    let server_reg = unsafe { poller.register_file(server_h.as_raw_handle(), 1)? };

    // Submit two concurrent reads.
    let read_a = match server_reg.submit_read(Vec::<u8>::with_capacity(64)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };
    let read_b = match server_reg.submit_read(Vec::<u8>::with_capacity(64)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };

    // A third read that we will cancel before any data arrives.
    let read_c = match server_reg.submit_read(Vec::<u8>::with_capacity(64)) {
        Submission::Pending(op) => op,
        other => panic!("expected Pending, got {other:?}"),
    };
    read_c.cancel()?;

    // Peer writes two distinct messages from a worker thread.
    let writer = std::thread::spawn(move || -> io::Result<()> {
        client_file.write_all(b"first")?;
        client_file.write_all(b"second")?;
        Ok(())
    });

    let mut events = Events::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);

    let mut pending: Vec<Option<OpHandle<Vec<u8>>>> =
        vec![Some(read_a), Some(read_b), Some(read_c)];
    let mut got = 0;
    while got < 3 {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            panic!("timed out waiting for completions");
        }
        poller.wait(&mut events, Some(remaining))?;
        for (idx, slot) in pending.iter_mut().enumerate() {
            let take = slot.as_ref().map(|op| op.is_complete()).unwrap_or(false);
            if !take {
                continue;
            }
            let op = slot.take().unwrap();
            match op.take() {
                (Ok(n), buf) => {
                    let init = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
                    println!(
                        "read #{idx} got {n} bytes: {:?}",
                        std::str::from_utf8(init).unwrap_or("<non-utf8>")
                    );
                }
                (Err(e), _) => println!("read #{idx} aborted: {e}"),
            }
            got += 1;
        }
    }

    writer.join().expect("writer panicked")?;
    drop(server_reg);
    drop(poller);
    drop(server_h);
    Ok(())
}
