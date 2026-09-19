//! Round-trip a small message through a Windows named pipe using the
//! IOCP file-handle support of `polling` (v2 API).
//!
//! Run with:
//!
//! ```text
//! cargo run --example named_pipe
//! ```
//!
//! On non-Windows targets this example is a no-op `main`.

#[cfg(not(windows))]
fn main() {
    eprintln!("named_pipe example only runs on Windows");
}

#[cfg(windows)]
fn main() -> std::io::Result<()> {
    use polling::os::iocp::{OpHandle, PollerIocpFileExt, Submission};
    use polling::{Events, Poller};

    use std::ffi::OsStr;
    use std::fs::OpenOptions;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
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

    fn client(name: &str) -> io::Result<OwnedHandle> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(wfs::FILE_FLAG_OVERLAPPED)
            .open(name)?;
        Ok(unsafe { OwnedHandle::from_raw_handle(file.into_raw_handle()) })
    }

    let name = format!(r"\\.\pipe\polling-example-{}", std::process::id());
    let server_h = server(&name)?;
    let client_h = client(&name)?;

    let poller = Poller::new()?;
    // SAFETY: `server_h` / `client_h` outlive every `OpHandle` produced
    // below (we drain all completions before returning).
    let server_reg = unsafe { poller.register_file(server_h.as_raw_handle(), 1)? };
    let client_reg = unsafe { poller.register_file(client_h.as_raw_handle(), 2)? };

    fn drain<B>(
        op: OpHandle<B>,
        poller: &Poller,
        events: &mut Events,
    ) -> std::io::Result<(usize, B)> {
        while !op.is_complete() {
            poller.wait(events, Some(Duration::from_secs(1)))?;
        }
        let (res, buf) = op.take();
        res.map(|n| (n, buf))
    }

    // Server: complete the connection. The client opened the pipe
    // before we got here, so this typically returns `Complete` (via
    // ERROR_PIPE_CONNECTED) rather than `Pending`.
    match server_reg.submit_connect_named_pipe() {
        Submission::Complete { .. } => {}
        Submission::Pending(op) => {
            let mut events = Events::new();
            let _ = drain(op, &poller, &mut events)?;
        }
        Submission::Failed { error, .. } => return Err(error),
    }

    // Client writes a greeting.
    let msg = b"hello, named pipe".to_vec();
    let written = match client_reg.submit_write(msg) {
        Submission::Complete { bytes, .. } => bytes,
        Submission::Pending(op) => {
            let mut events = Events::new();
            drain(op, &poller, &mut events)?.0
        }
        Submission::Failed { error, .. } => return Err(error),
    };
    println!("client wrote {written} bytes");

    // Server reads it back.
    let buf = Vec::<u8>::with_capacity(64);
    let (n, buf) = match server_reg.submit_read(buf) {
        Submission::Complete { bytes, buf } => (bytes, buf),
        Submission::Pending(op) => {
            let mut events = Events::new();
            drain(op, &poller, &mut events)?
        }
        Submission::Failed { error, .. } => return Err(error),
    };
    let init = unsafe { std::slice::from_raw_parts(buf.as_ptr(), n) };
    println!(
        "server read {n} bytes: {:?}",
        std::str::from_utf8(init).unwrap_or("<non-utf8>")
    );

    drop(server_reg);
    drop(client_reg);
    drop(poller);
    drop(server_h);
    drop(client_h);
    Ok(())
}
