//! Safe wrapper around `NtAssociateWaitCompletionPacket` API series.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::null_mut;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, BOOLEAN, GENERIC_READ, GENERIC_WRITE, HANDLE, NTSTATUS,
    STATUS_CANCELLED, STATUS_PENDING, STATUS_SUCCESS,
};

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateWaitCompletionPacket(
        WaitCompletionPacketHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ) -> NTSTATUS;

    fn NtAssociateWaitCompletionPacket(
        WaitCompletionPacketHandle: HANDLE,
        IoCompletionHandle: HANDLE,
        TargetObjectHandle: HANDLE,
        KeyContext: *mut c_void,
        ApcContext: *mut c_void,
        IoStatus: NTSTATUS,
        IoStatusInformation: usize,
        AlreadySignaled: *mut BOOLEAN,
    ) -> NTSTATUS;

    fn NtCancelWaitCompletionPacket(
        WaitCompletionPacketHandle: HANDLE,
        RemoveSignaledPacket: BOOLEAN,
    ) -> NTSTATUS;
}

/// Wrapper of NT WaitCompletionPacket.
#[derive(Debug)]
pub struct WaitCompletionPacket {
    handle: OwnedHandle,
}

fn check_status(status: NTSTATUS) -> io::Result<()> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(unsafe {
            RtlNtStatusToDosError(status) as _
        }))
    }
}

impl WaitCompletionPacket {
    pub fn new() -> io::Result<Self> {
        let mut handle = 0;
        check_status(unsafe {
            NtCreateWaitCompletionPacket(&mut handle, GENERIC_READ | GENERIC_WRITE, null_mut())
        })?;
        let handle = unsafe { OwnedHandle::from_raw_handle(handle as _) };
        Ok(Self { handle })
    }

    /// Associate waitable object to IOCP. The parameter `info` is the
    /// field `dwNumberOfBytesTransferred` in `OVERLAPPED_ENTRY`
    pub fn associate(
        &mut self,
        port: RawHandle,
        event: RawHandle,
        key: usize,
        info: usize,
    ) -> io::Result<()> {
        check_status(unsafe {
            NtAssociateWaitCompletionPacket(
                self.handle.as_raw_handle() as _,
                port as _,
                event as _,
                key as _,
                null_mut(),
                STATUS_SUCCESS,
                info,
                null_mut(),
            )
        })?;
        Ok(())
    }

    /// Cancels the completion packet. The return value means:
    /// - `Ok(true)`: cancellation is successful.
    /// - `Ok(false)`: cancellation failed, the packet is still in use.
    /// - `Err(e)`: other errors.
    pub fn cancel(&mut self) -> io::Result<bool> {
        let status = unsafe { NtCancelWaitCompletionPacket(self.handle.as_raw_handle() as _, 0) };
        match status {
            STATUS_SUCCESS | STATUS_CANCELLED => Ok(true),
            STATUS_PENDING => Ok(false),
            _ => Err(io::Error::from_raw_os_error(unsafe {
                RtlNtStatusToDosError(status) as _
            })),
        }
    }
}
