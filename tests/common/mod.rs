//! Shared helpers for Windows IOCP file-handle tests.
//!
//! Copied from `tests/windows_overlapped.rs` so that the new v2 test
//! suite (`tests/file_concurrent.rs`, `tests/file_lifetime.rs`) does
//! not have to depend on the legacy test file. Step 4 of the redesign
//! will delete the duplicates in `windows_overlapped.rs` and switch
//! that file over to `mod common;`.
//!
//! See `docs/named-pipe.implement.checklist.md` Step 3.1.

#![cfg(windows)]
#![allow(dead_code)] // not all helpers are used by every test crate

use std::ffi::OsStr;
use std::fs::OpenOptions;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};

use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs, System::Pipes as wps};

/// Detect whether the test process is running under Wine.
///
/// Wine's IOCP / NtReadFile / NtCancelIoFileEx implementations are not
/// complete enough to drive these tests reliably; the CI `wine` job
/// uses this helper to skip integration tests that depend on the new
/// file-handle API. Returns `true` iff `ntdll.dll!wine_get_version`
/// resolves.
pub fn is_wine() -> bool {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    unsafe {
        let ntdll = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return false;
        }
        GetProcAddress(ntdll, c"wine_get_version".as_ptr().cast()).is_some()
    }
}

/// Skip the current test (return early, printing a notice) when
/// running under Wine.
#[macro_export]
macro_rules! skip_on_wine {
    () => {
        if $crate::common::is_wine() {
            eprintln!("skipping on wine: {}", module_path!());
            return;
        }
    };
}

/// Create a server-side named pipe handle in byte / overlapped mode.
pub fn new_named_pipe<A: AsRef<OsStr>>(addr: A) -> io::Result<OwnedHandle> {
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

/// Allocate a fresh pipe name and create the server end.
pub fn server() -> (OwnedHandle, String) {
    let num: u64 = fastrand::u64(..);
    let name = format!(r"\\.\pipe\my-pipe-{}", num);
    let pipe = new_named_pipe(&name).unwrap();
    (pipe, name)
}

/// Open the client end of an existing named pipe in overlapped mode.
pub fn client(name: &str) -> io::Result<OwnedHandle> {
    let mut opts = OpenOptions::new();
    opts.read(true)
        .write(true)
        .custom_flags(wfs::FILE_FLAG_OVERLAPPED);
    let file = opts.open(name)?;
    unsafe { Ok(OwnedHandle::from_raw_handle(file.into_raw_handle())) }
}

/// Convenience: server + matched client.
pub fn pipe() -> (OwnedHandle, OwnedHandle) {
    let (server, name) = server();
    let client = client(&name).unwrap();
    (server, client)
}

/// Drive `poller.wait` until `handle.is_complete()` reports `true`,
/// or panic if the timeout elapses first.
pub fn wait_for_handle<B>(
    handle: &polling::os::iocp::OpHandle<B>,
    poller: &polling::Poller,
    events: &mut polling::Events,
    timeout: std::time::Duration,
) {
    let deadline = std::time::Instant::now() + timeout;
    while !handle.is_complete() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            panic!("timeout waiting for OpHandle completion");
        }
        poller.wait(events, Some(remaining)).unwrap();
    }
}
