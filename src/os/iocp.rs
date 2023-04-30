//! Functionality that is only availale for IOCP-based platforms.

pub use crate::sys::CompletionPacket;

use super::__private::PollerSealed;
use crate::{Event, PollMode, Poller};

use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};

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
    /// use polling::{Poller, Event};
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
    /// let mut events = vec![];
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
    /// # Examples
    ///
    /// ```no_run
    /// use polling::{Poller, Event, PollMode};
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
    /// poller.add_waitable(child, Event::both(0), PollMode::Oneshot).unwrap();
    ///
    /// // Wait for the child process to exit.
    /// let mut events = vec![];
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events[0], Event::both(0));
    /// ```
    fn add_waitable(
        &self,
        handle: impl Waitable,
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
    /// use polling::{Poller, Event, PollMode};
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
    /// poller.add_waitable(child, Event::both(0), PollMode::Oneshot).unwrap();
    ///
    /// // Wait for the child process to exit.
    /// let mut events = vec![];
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events[0], Event::both(0));
    ///
    /// // Modify the waitable handle.
    /// poller.modify_waitable(child, Event::readable(0), PollMode::Oneshot).unwrap();
    /// ```
    fn modify_waitable(
        &self,
        handle: impl Waitable,
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
    /// use polling::{Poller, Event, PollMode};
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
    /// poller.add_waitable(child, Event::both(0), PollMode::Oneshot).unwrap();
    ///
    /// // Wait for the child process to exit.
    /// let mut events = vec![];
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events[0], Event::both(0));
    ///
    /// // Remove the waitable handle.
    /// poller.remove_waitable(child).unwrap();
    /// ```
    fn remove_waitable(&self, handle: impl Waitable) -> io::Result<()>;
}

impl PollerIocpExt for Poller {
    fn post(&self, packet: CompletionPacket) -> io::Result<()> {
        self.poller.post(packet)
    }

    fn add_waitable(&self, handle: impl Waitable, event: Event, mode: PollMode) -> io::Result<()> {
        self.poller
            .add_waitable(handle.as_raw_handle(), event, mode)
    }

    fn modify_waitable(
        &self,
        handle: impl Waitable,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        self.poller
            .modify_waitable(handle.as_raw_handle(), interest, mode)
    }

    fn remove_waitable(&self, handle: impl Waitable) -> io::Result<()> {
        self.poller.remove_waitable(handle.as_raw_handle())
    }
}

/// A type that represents a waitable handle.
pub trait Waitable {
    /// Returns the raw handle of this waitable.
    fn as_raw_handle(&self) -> RawHandle;
}

impl Waitable for RawHandle {
    fn as_raw_handle(&self) -> RawHandle {
        *self
    }
}

impl<T: AsRawHandle + ?Sized> Waitable for &T {
    fn as_raw_handle(&self) -> RawHandle {
        AsRawHandle::as_raw_handle(*self)
    }
}
