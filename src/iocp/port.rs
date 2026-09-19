//! A safe wrapper around the Windows I/O API.

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

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_FUNCTION, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::SetFileCompletionNotificationModes;
use windows_sys::Win32::System::Threading::INFINITE;
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

/// Byte offset from a per-op `OVERLAPPED` block back to the start of
/// the owning `IoStatusBlock<T>`.
///
/// Used to recover the containing `Packet` from the raw
/// `lpOverlapped` pointer that the kernel places into each
/// `OVERLAPPED_ENTRY`.
pub(super) trait FileOverlapped {
    /// Offset from the per-op `OVERLAPPED` (inside `OpInner.overlapped`)
    /// to the start of `IoStatusBlock<T>` for the `FileOp` variant.
    fn file_op_offset() -> usize;
}

/// Recovers the owning `IoStatusBlock<T>` from a file completion's
/// `OVERLAPPED_ENTRY`.
///
/// # Safety
///
/// The `lpOverlapped` pointer in the entry must point into a valid
/// `IoStatusBlock<T>` that has not been freed.
pub(super) unsafe trait FileCompletionHandle {
    /// Recover the owner from a `FileOp` completion.
    fn file_op_done(entry: &OVERLAPPED_ENTRY) -> Self;
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
    fn file_op_done(entry: &OVERLAPPED_ENTRY) -> Self {
        let overlapped_ptr = entry.lpOverlapped;
        let offset = T::file_op_offset();
        // SAFETY: the `OpInner` whose `OVERLAPPED` produced this entry is
        // held alive by the user's `OpHandle` (or, in the leaked case,
        // outlives the program); the borrow lifetime is the caller's
        // problem.
        unsafe { Pin::new_unchecked(&*((overlapped_ptr as *mut u8).sub(offset) as *const T)) }
    }
}

unsafe impl<T: FileOverlapped> FileCompletionHandle for Pin<Arc<T>> {
    fn file_op_done(entry: &OVERLAPPED_ENTRY) -> Self {
        let overlapped_ptr = entry.lpOverlapped;
        let offset = T::file_op_offset();
        // The submitter (`classify_submission` in `iocp::mod`) bumped the `Arc`
        // strong count via `mem::forget(packet.clone())` when the op
        // entered the `Pending` state, so the kernel logically owns
        // one strong reference. Reclaim that reference here via a
        // plain `Arc::from_raw` (no extra increment). Mirrors the
        // bump/reclaim invariant in `docs/named-pipe.design.md`
        // §3.4.
        unsafe {
            let raw = (overlapped_ptr as *const u8).sub(offset) as *const T;
            Pin::new_unchecked(Arc::from_raw(raw))
        }
    }
}
/// A handle to the I/O completion port.
pub(super) struct IoCompletionPort<T> {
    /// The underlying handle.
    handle: HANDLE,

    /// The completion key generator.
    key_gen: CompletionKeyGenerator,

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
                key_gen: Default::default(),
                _marker: PhantomData,
            })
        }
    }

    /// Register a handle with this I/O completion port.
    ///
    /// `notification_flags` is the value passed to
    /// [`SetFileCompletionNotificationModes`] after registration. Pass `0`
    /// to skip the call entirely. `ERROR_INVALID_FUNCTION` from
    /// `SetFileCompletionNotificationModes` is treated as a non-fatal
    /// no-op (some device types do not support the API).
    pub(super) fn register(
        &self,
        handle: &impl AsRawHandle, // TODO change to AsHandle
        notification_flags: u8,
        kind: CompletionKeyType,
    ) -> io::Result<()> {
        let handle = handle.as_raw_handle();

        let result = unsafe {
            CreateIoCompletionPort(
                handle as _,
                self.handle,
                CompletionKey::new(kind, &self.key_gen).into(),
                0,
            )
        };

        if result.is_null() {
            return Err(io::Error::last_os_error());
        }

        if notification_flags != 0 {
            // SAFETY: `handle` was just successfully attached to an IOCP,
            // so it is a valid open handle for the lifetime of this call.
            let result =
                unsafe { SetFileCompletionNotificationModes(handle as _, notification_flags) };

            if result == 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(ERROR_INVALID_FUNCTION as i32) {
                    return Err(err);
                }
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

    /// Returns `true` if this entry was posted for a file handle
    /// (registered via `register_file`).
    pub(super) fn is_file_completion(&self) -> bool {
        CompletionKey::from(self.entry.lpCompletionKey).is_file()
    }

    /// Read the NTSTATUS code from the embedded `OVERLAPPED.Internal`
    /// field of this completion. The value is meaningful only for file
    /// completions; sockets / waitables encode their status separately.
    ///
    /// # Safety
    ///
    /// The caller must ensure `self.entry.lpOverlapped` points to a live
    /// `OVERLAPPED` block (true for any not-yet-consumed entry).
    pub(super) unsafe fn nt_status_raw(&self) -> i32 {
        // SAFETY: caller-asserted.
        unsafe { (*self.entry.lpOverlapped).Internal as i32 }
    }

    /// Convert into the owning `T` using the `FileOp` offset path.
    ///
    /// Unlike [`into_packet`](Self::into_packet), the `lpOverlapped`
    /// here does **not** point to the start of the packet; it points to
    /// an inner `OVERLAPPED` field inside `OpInner`.
    ///
    /// # Safety
    ///
    /// Must be called at most once per entry. The `lpOverlapped` must
    /// belong to a live `FileOp` packet.
    pub(super) fn into_file_op_packet(self) -> T {
        assert!(
            self.is_file_completion(),
            "This is not a file-op completion packet"
        );
        let packet = T::file_op_done(&self.entry);
        std::mem::forget(self);
        packet
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
        // Both file-op and socket/waitable/wakeup entries transfer one
        // `Arc` strong reference into the kernel at submit time. If the
        // dispatcher consumes the entry through `into_packet` /
        // `into_file_op_packet`, those helpers `mem::forget` the entry
        // and this `Drop` does not run. Otherwise (panic, early
        // return) we reclaim the kernel's ref here so the allocation
        // is not leaked.
        if self.is_file_completion() {
            drop(unsafe { T::file_op_done(&self.entry) });
        } else {
            drop(unsafe { self.packet() });
        }
    }
}

/// Distinguishes the kind of handle a completion key was generated for.
///
/// IOCP itself does not require completion keys to be unique per handle: the
/// real per-completion routing is done through `lpOverlapped` (which points
/// back to the owning `Packet`). We use the high bit of the key purely as a
/// fast classifier so the dispatcher can choose the correct conversion path
/// when a completion arrives:
///
/// - high bit clear → socket / waitable / wakeup completion → recover the
///   `Packet` via `T::from_ptr(lpOverlapped)`.
/// - high bit set   → file-op completion (registered via
///   `register_file`) → recover via the per-op `file_op_offset()`.
///
/// [`OverlappedEntry::into_packet`]: crate::iocp::OverlappedEntry::into_packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompletionKeyType {
    Socket,
    FileOp,
}

/// Per-poller completion key.
///
/// The low 31 (or 63) bits are a monotonically increasing counter that wraps
/// around if exhausted. The counter value is **not used for handle
/// identification**:
///
/// - For sockets and waitables, it is purely informational (handle routing
///   uses `lpOverlapped`). Counter wrap-around is therefore harmless.
/// - For files the counter is also not used for routing, but the **high bit
///   is** — it tells the dispatcher to use the file completion path.
///
/// Key value `0` is reserved for IOCP-internal packets (notify / wakeup /
/// custom user packets posted via `PostQueuedCompletionStatus` with key `0`).
///
/// 31 bits of headroom is more than sufficient on 32-bit Windows, since
/// handle exhaustion will hit long before the counter wraps.
#[repr(transparent)]
struct CompletionKey(usize);

#[derive(Debug)]
struct CompletionKeyGenerator {
    next_default_key: AtomicUsize,
    next_file_key: AtomicUsize,
}

impl Default for CompletionKeyGenerator {
    fn default() -> Self {
        Self {
            next_default_key: AtomicUsize::new(1), // 0 reserved for default iocp packet
            next_file_key: AtomicUsize::new(1usize << (usize::BITS - 1)), // Initialize with high bit set
        }
    }
}

impl CompletionKey {
    const HIGH_BIT: usize = 1usize << (usize::BITS - 1); // 0x8000_0000_0000_0000 on 64-bit
    /// Reserved class bits. Counter values must avoid these.
    const CLASS_MASK: usize = Self::HIGH_BIT;
    const COUNTER_MASK: usize = !Self::CLASS_MASK; // 0x7FFF_FFFF_FFFF_FFFF on 64-bit
    pub(super) fn new(kind: CompletionKeyType, gen: &CompletionKeyGenerator) -> Self {
        match kind {
            CompletionKeyType::FileOp => {
                // FileOp keys live in the HIGH_BIT bucket. The counter
                // portion only needs to be unique \u2014 it's not used for
                // routing. Wraps within the bucket on overflow.
                let key = loop {
                    let current = gen.next_file_key.load(std::sync::atomic::Ordering::Relaxed);
                    let next = if current == (Self::HIGH_BIT | Self::COUNTER_MASK) {
                        Self::HIGH_BIT
                    } else {
                        current + 1
                    };

                    match gen.next_file_key.compare_exchange_weak(
                        current,
                        next,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    ) {
                        Ok(_) => break current,
                        Err(_) => continue,
                    }
                };
                Self(key)
            }
            CompletionKeyType::Socket => {
                // For default keys, ensure the counter never exceeds
                // COUNTER_MASK. If it would overflow, wrap back to 1.
                let key = loop {
                    let current = gen
                        .next_default_key
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let next = if current >= Self::COUNTER_MASK {
                        1
                    } else {
                        current + 1
                    };

                    match gen.next_default_key.compare_exchange_weak(
                        current,
                        next,
                        std::sync::atomic::Ordering::Relaxed,
                        std::sync::atomic::Ordering::Relaxed,
                    ) {
                        Ok(_) => break current,
                        Err(_) => continue,
                    }
                };

                Self(key)
            }
        }
    }

    /// Returns `true` if the key belongs to a file handle (high bit set).
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
    fn from(key: usize) -> Self {
        Self(key)
    }
}
