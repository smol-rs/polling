//! Functionality that is only available for IOCP-based platforms.

pub use crate::iocp::{
    buf::{StableBuf, StableBufMut},
    OpHandle, RegisteredFile, Submission,
};
pub use crate::sys::CompletionPacket;

use super::__private::PollerSealed;
use crate::{Event, PollMode, Poller};

use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::os::windows::prelude::{AsHandle, BorrowedHandle};

/// Extension trait for the [`Poller`] type that provides functionality specific to IOCP-based
/// platforms.
///
/// [`Poller`]: crate::Poller
pub trait PollerIocpExt: PollerSealed {
    /// Post a new [`Event`] to the poller.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use polling::{Poller, Event, Events};
    /// use polling::os::iocp::{CompletionPacket, PollerIocpExt};
    ///
    /// use std::thread;
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// // Spawn a thread to wake us up after 100ms.
    /// let poller = Arc::new(Poller::new()?);
    /// thread::spawn({
    ///     let poller = poller.clone();
    ///     move || {
    ///         let packet = CompletionPacket::new(Event::readable(0));
    ///         thread::sleep(Duration::from_millis(100));
    ///         poller.post(packet).unwrap();
    ///     }
    /// });
    ///
    /// // Wait for the event.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None)?;
    ///
    /// assert_eq!(events.len(), 1);
    /// # Ok(()) }
    /// ```
    fn post(&self, packet: CompletionPacket) -> io::Result<()>;

    /// Add a waitable handle to this poller.
    ///
    /// Some handles in Windows are "waitable", which means that they emit a "readiness" signal
    /// after some event occurs. This function can be used to wait for such events to occur
    /// on a handle. This function can be used in addition to regular socket polling.
    ///
    /// Waitable objects include the following:
    ///
    /// - Console inputs
    /// - Waitable events
    /// - Mutexes
    /// - Processes
    /// - Semaphores
    /// - Threads
    /// - Timer
    ///
    /// Once the object has been signalled, the poller will emit the `interest` event.
    ///
    /// # Safety
    ///
    /// The added handle must not be dropped before it is deleted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::{Poller, Event, Events, PollMode};
    /// use polling::os::iocp::PollerIocpExt;
    ///
    /// use std::process::Command;
    ///
    /// // Spawn a new process.
    /// let mut child = Command::new("echo")
    ///     .arg("Hello, world!")
    ///     .spawn()
    ///     .unwrap();
    ///
    /// // Create a new poller.
    /// let poller = Poller::new().unwrap();
    ///
    /// // Add the child process to the poller.
    /// unsafe {
    ///     poller.add_waitable(&child, Event::all(0), PollMode::Oneshot).unwrap();
    /// }
    ///
    /// // Wait for the child process to exit.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events.iter().next().unwrap(), Event::all(0));
    /// ```
    unsafe fn add_waitable(
        &self,
        handle: impl AsRawWaitable,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()>;

    /// Modify an existing waitable handle.
    ///
    /// This function can be used to change the emitted event and/or mode of an existing waitable
    /// handle. The handle must have been previously added to the poller using [`add_waitable`].
    ///
    /// [`add_waitable`]: Self::add_waitable
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::{Poller, Event, Events, PollMode};
    /// use polling::os::iocp::PollerIocpExt;
    ///
    /// use std::process::Command;
    ///
    /// // Spawn a new process.
    /// let mut child = Command::new("echo")
    ///     .arg("Hello, world!")
    ///     .spawn()
    ///     .unwrap();
    ///
    /// // Create a new poller.
    /// let poller = Poller::new().unwrap();
    ///
    /// // Add the child process to the poller.
    /// unsafe {
    ///     poller.add_waitable(&child, Event::all(0), PollMode::Oneshot).unwrap();
    /// }
    ///
    /// // Wait for the child process to exit.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events.iter().next().unwrap(), Event::all(0));
    ///
    /// // Modify the waitable handle.
    /// poller.modify_waitable(&child, Event::readable(0), PollMode::Oneshot).unwrap();
    /// ```
    fn modify_waitable(
        &self,
        handle: impl AsWaitable,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()>;

    /// Remove a waitable handle from this poller.
    ///
    /// This function can be used to remove a waitable handle from the poller. The handle must
    /// have been previously added to the poller using [`add_waitable`].
    ///
    /// [`add_waitable`]: Self::add_waitable
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::{Poller, Event, Events, PollMode};
    /// use polling::os::iocp::PollerIocpExt;
    ///
    /// use std::process::Command;
    ///
    /// // Spawn a new process.
    /// let mut child = Command::new("echo")
    ///     .arg("Hello, world!")
    ///     .spawn()
    ///     .unwrap();
    ///
    /// // Create a new poller.
    /// let poller = Poller::new().unwrap();
    ///
    /// // Add the child process to the poller.
    /// unsafe {
    ///     poller.add_waitable(&child, Event::all(0), PollMode::Oneshot).unwrap();
    /// }
    ///
    /// // Wait for the child process to exit.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events.iter().next().unwrap(), Event::all(0));
    ///
    /// // Remove the waitable handle.
    /// poller.remove_waitable(&child).unwrap();
    /// ```
    fn remove_waitable(&self, handle: impl AsWaitable) -> io::Result<()>;
}

impl PollerIocpExt for Poller {
    fn post(&self, packet: CompletionPacket) -> io::Result<()> {
        self.poller.post(packet)
    }

    unsafe fn add_waitable(
        &self,
        handle: impl AsRawWaitable,
        event: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        self.poller
            .add_waitable(handle.as_raw_handle(), event, mode)
    }

    fn modify_waitable(
        &self,
        handle: impl AsWaitable,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        self.poller
            .modify_waitable(handle.as_waitable().as_raw_handle(), interest, mode)
    }

    fn remove_waitable(&self, handle: impl AsWaitable) -> io::Result<()> {
        self.poller
            .remove_waitable(handle.as_waitable().as_raw_handle())
    }
}

/// A type that represents a waitable handle.
pub trait AsRawWaitable {
    /// Returns the raw handle of this waitable.
    fn as_raw_handle(&self) -> RawHandle;
}

impl AsRawWaitable for RawHandle {
    fn as_raw_handle(&self) -> RawHandle {
        *self
    }
}

impl<T: AsRawHandle + ?Sized> AsRawWaitable for &T {
    fn as_raw_handle(&self) -> RawHandle {
        AsRawHandle::as_raw_handle(*self)
    }
}

/// A type that represents a waitable handle.
pub trait AsWaitable: AsHandle {
    /// Returns the raw handle of this waitable.
    fn as_waitable(&self) -> BorrowedHandle<'_> {
        self.as_handle()
    }
}

impl<T: AsHandle + ?Sized> AsWaitable for T {}

/// Extension trait for [`Poller`] that adds file-handle support on
/// IOCP-based platforms.
///
/// File handles registered through this trait drive overlapped I/O via
/// the [`RegisteredFile`] / [`OpHandle`] / [`Submission`] surface. See
/// `docs/named-pipe.design.md` for the design rationale.
///
/// [`Poller`]: crate::Poller
pub trait PollerIocpFileExt: PollerSealed {
    /// Register a file handle for IOCP-based overlapped I/O.
    ///
    /// `key` follows the same convention as
    /// [`Poller::add`](crate::Poller::add): it is the user-chosen
    /// identifier mirrored into [`Event::key`] of every completion
    /// emitted for ops on this file. A reactor (e.g. `async-io`) keys
    /// its waker registry by this value.
    ///
    /// The returned [`RegisteredFile`] is cheaply cloneable and is the
    /// entry point for [`RegisteredFile::submit_read`],
    /// [`RegisteredFile::submit_write`] and
    /// [`RegisteredFile::submit_connect_named_pipe`]. Each pending
    /// submission produces an [`OpHandle`] that owns the operation's
    /// lifecycle: drive [`crate::Poller::wait`] until the matching
    /// completion event arrives, then call
    /// [`OpHandle::is_complete`] / [`OpHandle::take`].
    ///
    /// Read submissions emit `Event { key, readable: true, .. }` on
    /// completion; writes emit `writable: true`;
    /// `submit_connect_named_pipe` emits `readable: true` (the typical
    /// follow-up is a server-side read).
    ///
    /// The handle can be any Win32 handle opened with
    /// `FILE_FLAG_OVERLAPPED`, such as files, named/anonymous pipes,
    /// mailslots, serial ports, or other communication devices.
    ///
    /// # Safety
    ///
    /// The caller must uphold all of the following:
    ///
    /// - The handle was opened with `FILE_FLAG_OVERLAPPED`. Submitting
    ///   overlapped I/O against a synchronous handle is undefined
    ///   behaviour at the Win32 layer.
    /// - The handle is not already attached to another
    ///   `IoCompletionPort`. Win32 forbids re-association and the
    ///   second `CreateIoCompletionPort` call will fail; the
    ///   safety hazard is silently sharing completions across two
    ///   pollers.
    /// - The handle outlives every [`OpHandle`] created from this
    ///   registration **and** every in-flight op has produced its
    ///   completion event before the handle is closed. Closing the
    ///   handle while ops are pending in the kernel is sound
    ///   (Windows cancels them and posts completions), but the
    ///   caller must still drain those completions via
    ///   [`crate::Poller::wait`] to release the per-op packet
    ///   allocations.
    ///
    /// # Resource leaks on [`crate::Poller`] drop
    ///
    /// Each pending submission holds a reference-counted packet that
    /// the IOCP dispatcher reclaims when it observes the matching
    /// completion. If the [`crate::Poller`] is dropped while ops are
    /// still pending, the dispatcher never runs again and the
    /// per-op packet (including the user-supplied buffer) leaks.
    /// There is no use-after-free — the kernel still owns a
    /// `Pin<Arc<…>>` strong reference — but the memory is not
    /// recovered. Callers that need clean shutdown should
    /// [`crate::Poller::wait`] until every in-flight op has
    /// completed (typically after closing the underlying handle to
    /// trigger cancellation) before dropping the [`crate::Poller`].
    unsafe fn register_file(
        &self,
        file: impl AsRawFileHandle,
        key: usize,
    ) -> io::Result<RegisteredFile>;
}
/// A type that represents a raw file handle.
pub trait AsRawFileHandle {
    /// Returns the raw handle of this file.
    fn as_raw_handle(&self) -> RawHandle;
}

impl AsRawFileHandle for RawHandle {
    fn as_raw_handle(&self) -> RawHandle {
        *self
    }
}

impl<T: AsRawHandle + ?Sized> AsRawFileHandle for &T {
    fn as_raw_handle(&self) -> RawHandle {
        AsRawHandle::as_raw_handle(*self)
    }
}

/// A type that represents a file handle.
pub trait AsFileHandle: AsHandle {
    /// Returns the raw handle of this file.
    fn as_file(&self) -> BorrowedHandle<'_> {
        self.as_handle()
    }
}

impl<T: AsHandle + ?Sized> AsFileHandle for T {}

impl PollerIocpFileExt for Poller {
    unsafe fn register_file(
        &self,
        file: impl AsRawFileHandle,
        key: usize,
    ) -> io::Result<RegisteredFile> {
        self.poller.register_file(file.as_raw_handle(), key)
    }
}
