//! A safe wrapper around the Windows I/O API.

use crate::iocp::FileCompletionStatus;
use crate::os::iocp::OverlappedInner;

use super::dur2timeout;

use std::fmt;
use std::io;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::pin::Pin;
use std::ptr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::SetFileCompletionNotificationModes;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::WindowsProgramming::FILE_SKIP_SET_EVENT_ON_HANDLE;
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatusEx, PostQueuedCompletionStatus, OVERLAPPED,
    OVERLAPPED_ENTRY,
};

/// A completion block which can be used with I/O completion ports.
///
/// # Safety
///
/// This must be a valid completion block.
pub(super) unsafe trait Completion {
    /// Signal to the completion block that we are about to start an operation.
    fn try_lock(self: Pin<&Self>) -> bool;

    /// Unlock the completion block.
    unsafe fn unlock(self: Pin<&Self>);
}

/// The pointer to a completion block.
///
/// # Safety
///
/// This must be a valid completion block.
pub(super) unsafe trait CompletionHandle: Deref + Sized {
    /// Type of the completion block.
    type Completion: Completion;

    /// Get a pointer to the completion block.
    ///
    /// The pointer is pinned since the underlying object should not be moved
    /// after creation. This prevents it from being invalidated while it's
    /// used in an overlapped operation.
    fn get(&self) -> Pin<&Self::Completion>;

    /// Convert this block into a pointer that can be passed as `*mut OVERLAPPED`.
    fn into_ptr(this: Self) -> *mut OVERLAPPED;

    /// Convert a pointer that was passed as `*mut OVERLAPPED` into a pointer to this block.
    ///
    /// # Safety
    ///
    /// This must be a valid pointer to a completion block.
    unsafe fn from_ptr(ptr: *mut OVERLAPPED) -> Self;

    /// Convert to a pointer without losing ownership.
    fn as_ptr(&self) -> *mut OVERLAPPED;
}

/// Offset that a file read/write overlapped position to the begining of the whole 'IoStatusBlock<T>' block.
///
/// # Safety
///
/// The whole 'IoStatusBlock<T>' block must include file read/write `Overlapped<T>` struct
pub(super) trait FileOverlapped {
    /// Get the offset of the file read overlapped structure to the whole 'IoStatusBlock<T>' block
    fn file_read_offset() -> usize;

    /// Get the offset of the file write overlapped structure to the whole 'IoStatusBlock<T>' block
    fn file_write_offset() -> usize;
}

/// File completion overlapped pointer convert to 'IoStatusBlock<T>'
///
/// # Safety
///
/// The completion overlaped pointer must be valid as part of 'IoStatusBlock<T>'
pub(super) unsafe trait FileCompletionHandle {
    /// file read overlapped pointer convert to 'IoStatusBlock<T>'
    fn file_read_done(entry: &OVERLAPPED_ENTRY) -> Self;

    /// file write overlapped pointer convert to 'IoStatusBlock<T>'
    fn file_write_done(entry: &OVERLAPPED_ENTRY) -> Self;
}

unsafe impl<T: Completion> CompletionHandle for Pin<&T> {
    type Completion = T;

    fn get(&self) -> Pin<&Self::Completion> {
        *self
    }

    fn into_ptr(this: Self) -> *mut OVERLAPPED {
        unsafe { Pin::into_inner_unchecked(this) as *const T as *mut OVERLAPPED }
    }

    unsafe fn from_ptr(ptr: *mut OVERLAPPED) -> Self {
        Pin::new_unchecked(&*(ptr as *const T))
    }

    fn as_ptr(&self) -> *mut OVERLAPPED {
        self.get_ref() as *const T as *mut OVERLAPPED
    }
}

unsafe impl<T: Completion> CompletionHandle for Pin<Arc<T>> {
    type Completion = T;

    fn get(&self) -> Pin<&Self::Completion> {
        self.as_ref()
    }

    fn into_ptr(this: Self) -> *mut OVERLAPPED {
        unsafe { Arc::into_raw(Pin::into_inner_unchecked(this)) as *const T as *mut OVERLAPPED }
    }

    unsafe fn from_ptr(ptr: *mut OVERLAPPED) -> Self {
        Pin::new_unchecked(Arc::from_raw(ptr as *const T))
    }

    fn as_ptr(&self) -> *mut OVERLAPPED {
        self.as_ref().get_ref() as *const T as *mut OVERLAPPED
    }
}

unsafe impl<T: FileOverlapped> FileCompletionHandle for Pin<&T> {
    fn file_read_done(entry: &OVERLAPPED_ENTRY) -> Self {
        let overlapped_ptr = entry.lpOverlapped;
        let offset = T::file_read_offset();
        unsafe { Pin::new_unchecked(&*((overlapped_ptr as *mut u8).sub(offset) as *const T)) }
    }

    fn file_write_done(entry: &OVERLAPPED_ENTRY) -> Self {
        let overlapped_ptr = entry.lpOverlapped;
        let offset = T::file_write_offset();
        unsafe { Pin::new_unchecked(&*((overlapped_ptr as *mut u8).sub(offset) as *const T)) }
    }
}

unsafe impl<T: FileOverlapped> FileCompletionHandle for Pin<Arc<T>> {
    fn file_read_done(entry: &OVERLAPPED_ENTRY) -> Self {
        let overlapped_ptr = entry.lpOverlapped;
        let offset = T::file_read_offset();
        // File completion does not clone the Packet when add the file handle to IOCP
        // So need to clone the Packet to avoid the owner ship lost
        unsafe {
            let inner = Arc::from_raw((overlapped_ptr as *const u8).sub(offset) as *const T);
            assert!(Arc::strong_count(&inner) >= 1, "File has been removed, but still use FileOverlappedWrapper return from add_file function");

            let new_one = Pin::new_unchecked(Arc::clone(&inner));
            let _ = Arc::into_raw(inner); // Prevent Arc from being dropped
            new_one
        }
    }

    fn file_write_done(entry: &OVERLAPPED_ENTRY) -> Self {
        let overlapped_ptr = entry.lpOverlapped;
        let offset = T::file_write_offset();
        unsafe {
            let inner = Arc::from_raw((overlapped_ptr as *const u8).sub(offset) as *const T);
            assert!(Arc::strong_count(&inner) >= 1, "File has been removed, but still use FileOverlappedWrapper return from add_file function");

            let new_one = Pin::new_unchecked(Arc::clone(&inner));
            let _ = Arc::into_raw(inner); // Prevent Arc from being dropped
            new_one
        }
    }
}
/// A handle to the I/O completion port.
pub(super) struct IoCompletionPort<T> {
    /// The underlying handle.
    handle: HANDLE,

    /// We own the status block.
    _marker: PhantomData<T>,
}

impl<T> Drop for IoCompletionPort<T> {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl<T> AsRawHandle for IoCompletionPort<T> {
    fn as_raw_handle(&self) -> RawHandle {
        self.handle as _
    }
}

impl<T> fmt::Debug for IoCompletionPort<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct WriteAsHex(HANDLE);

        impl fmt::Debug for WriteAsHex {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{:010x}", self.0 as usize)
            }
        }

        f.debug_struct("IoCompletionPort")
            .field("handle", &WriteAsHex(self.handle))
            .finish()
    }
}

impl<T: CompletionHandle + FileCompletionHandle> IoCompletionPort<T> {
    /// Create a new I/O completion port.
    pub(super) fn new(threads: usize) -> io::Result<Self> {
        let handle = unsafe {
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                ptr::null_mut(),
                0,
                threads.try_into().expect("too many threads"),
            )
        };

        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self {
                handle,
                _marker: PhantomData,
            })
        }
    }

    /// Register a handle with this I/O completion port.
    pub(super) fn register(
        &self,
        handle: &impl AsRawHandle, // TODO change to AsHandle
        skip_set_event_on_handle: bool,
        kind: CompletionKeyType,
    ) -> io::Result<()> {
        let handle = handle.as_raw_handle();

        let result = unsafe {
            CreateIoCompletionPort(handle as _, self.handle, CompletionKey::new(kind).into(), 0)
        };

        if result.is_null() {
            return Err(io::Error::last_os_error());
        }

        if skip_set_event_on_handle {
            // Set the skip event on handle.
            let result = unsafe {
                SetFileCompletionNotificationModes(handle as _, FILE_SKIP_SET_EVENT_ON_HANDLE as _)
            };

            if result == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    /// Post a completion packet to this port.
    pub(super) fn post(&self, bytes_transferred: usize, id: usize, packet: T) -> io::Result<()> {
        let result = unsafe {
            PostQueuedCompletionStatus(
                self.handle,
                bytes_transferred
                    .try_into()
                    .expect("too many bytes transferred"),
                id,
                T::into_ptr(packet),
            )
        };

        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Wait for completion packets to arrive.
    pub(super) fn wait(
        &self,
        packets: &mut Vec<OverlappedEntry<T>>,
        timeout: Option<Duration>,
    ) -> io::Result<usize> {
        // Drop the current packets.
        packets.clear();

        let mut count = MaybeUninit::<u32>::uninit();
        let timeout = timeout.map_or(INFINITE, dur2timeout);

        let result = unsafe {
            GetQueuedCompletionStatusEx(
                self.handle,
                packets.as_mut_ptr() as _,
                packets.capacity().try_into().expect("too many packets"),
                count.as_mut_ptr(),
                timeout,
                0,
            )
        };

        if result == 0 {
            let io_error = io::Error::last_os_error();
            if io_error.kind() == io::ErrorKind::TimedOut {
                Ok(0)
            } else {
                Err(io_error)
            }
        } else {
            let count = unsafe { count.assume_init() };
            unsafe {
                packets.set_len(count as _);
            }
            Ok(count as _)
        }
    }
}

/// An `OVERLAPPED_ENTRY` resulting from an I/O completion port.
#[repr(transparent)]
pub(super) struct OverlappedEntry<T: CompletionHandle + FileCompletionHandle> {
    /// The underlying entry.
    entry: OVERLAPPED_ENTRY,

    /// We own the status block.
    _marker: PhantomData<T>,
}

impl<T: CompletionHandle + FileCompletionHandle> fmt::Debug for OverlappedEntry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OverlappedEntry { .. }")
    }
}

impl<T: CompletionHandle + FileCompletionHandle> OverlappedEntry<T> {
    /// Convert into the completion packet.
    pub(super) fn into_packet(self) -> T {
        let packet = unsafe { self.packet() };
        std::mem::forget(self);
        packet
    }

    /// Get the number of bytes transferred by the I/O operation.
    pub(super) fn bytes_transferred(&self) -> u32 {
        self.entry.dwNumberOfBytesTransferred
    }

    /// Check if this entry is a file completion packet.
    pub(super) fn is_file_completion(&self) -> bool {
        CompletionKey::from(self.entry.lpCompletionKey).is_file()
    }

    /// Convert into the completion packet through file overlapped pointer which is not the beginning address
    /// of the packet.
    ///
    /// # Safety
    ///
    /// This function should only be called once, since it moves
    /// out the `T` from the `OVERLAPPED_ENTRY`.
    pub(super) fn into_file_packet(self) -> (T, FileCompletionStatus) {
        assert!(
            self.is_file_completion(),
            "This is not a file completion packet"
        );
        let (packet, status) = unsafe { OverlappedInner::<T>::from_entry(&self.entry) };
        std::mem::forget(self);
        (packet, status)
    }

    /// Get the packet reference that this entry refers to.
    ///
    /// # Safety
    ///
    /// This function should only be called once, since it moves
    /// out the `T` from the `OVERLAPPED_ENTRY`.
    unsafe fn packet(&self) -> T {
        let packet = T::from_ptr(self.entry.lpOverlapped);
        packet.get().unlock();
        packet
    }
}

impl<T: CompletionHandle + FileCompletionHandle> Drop for OverlappedEntry<T> {
    fn drop(&mut self) {
        // File packet do not need to Arc::Clone to add or remove from the poller
        // So we can safely drop it without decrease the reference count.
        if !self.is_file_completion() {
            drop(unsafe { self.packet() });
        }
    }
}

/// The type of completion key used to differentiate between different types of completion keys.
/// The completion key type determines how to convert raw address to packet block.
/// [`OverlappedEntry<T>::into_packet`]: create::iocp::OverlappedEntry<T>::into_packet
/// [`OverlappedEntry<T>::into_file_packet`]: create::iocp::OverlappedEntry<T>::into_file_packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompletionKeyType {
    Socket,
    File,
}

/// This is used to differentiate between different types of completion keys.
/// Completion key has not to be unique per handle for IOCP. The `CompletionKey` is used to
/// identify the type of completion key, it assign one key for per handle. But it does not
/// guarantee uniqueness across different handles when the token is overflowed and wrapped back
/// to low value which may be used by existing handle.
/// It is used to differentiate between different types of completion keys.
#[repr(transparent)]
pub(super) struct CompletionKey(usize);

static NEXT_DEFAULT_TOKEN: AtomicUsize = AtomicUsize::new(1); // 0 reserved for default iocp packet
static NEXT_FILE_TOKEN: AtomicUsize = AtomicUsize::new(1usize << (usize::BITS - 1)); // Initialize with high bit set

impl CompletionKey {
    const HIGH_BIT: usize = 1usize << (usize::BITS - 1); // 0x8000_0000_0000_0000 on 64-bit
    const COUNTER_MASK: usize = !Self::HIGH_BIT; // 0x7FFF_FFFF_FFFF_FFFF on 64-bit
    pub(super) fn new(kind: CompletionKeyType) -> Self {
        match kind {
            CompletionKeyType::File => {
                // For file tokens, increment from HIGH_BIT base
                // If it would overflow past HIGH_BIT | COUNTER_MASK, wrap back to HIGH_BIT
                let token = loop {
                    let current = NEXT_FILE_TOKEN.load(std::sync::atomic::Ordering::Relaxed);
                    let next = if current == (Self::HIGH_BIT | Self::COUNTER_MASK) {
                        Self::HIGH_BIT // Wrap back to HIGH_BIT (first file token)
                    } else {
                        current + 1
                    };

                    match NEXT_FILE_TOKEN.compare_exchange_weak(
                        current,
                        next,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    ) {
                        Ok(_) => break current,
                        Err(_) => continue, // Retry if another thread modified it
                    }
                };

                Self(token)
            }
            _ => {
                // For default tokens, we need to ensure the counter never exceeds COUNTER_MASK
                // If it would overflow, wrap back to 0
                let counter = loop {
                    let current = NEXT_DEFAULT_TOKEN.load(std::sync::atomic::Ordering::Relaxed);
                    let next = if current >= Self::COUNTER_MASK {
                        1
                    } else {
                        current + 1
                    };

                    match NEXT_DEFAULT_TOKEN.compare_exchange_weak(
                        current,
                        next,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    ) {
                        Ok(_) => break current,
                        Err(_) => continue, // Retry if another thread modified it
                    }
                };

                // Keep highest bit as 0, counter is already safe
                let token = counter;
                Self(token)
            }
        }
    }

    /// Check if this completion key is for a File type
    pub(super) fn is_file(&self) -> bool {
        (self.0 & Self::HIGH_BIT) != 0
    }
}

impl From<CompletionKey> for usize {
    fn from(key: CompletionKey) -> Self {
        key.0
    }
}

impl From<usize> for CompletionKey {
    fn from(token: usize) -> Self {
        Self(token)
    }
}
