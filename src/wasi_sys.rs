//! Bindings to WASI (preview-2).

use std::convert::TryInto;
use std::io;
use std::os::wasi::io::{AsRawFd, RawFd};
use std::ptr;
use std::time::Duration;

#[cfg(not(polling_no_io_safety))]
use std::os::wasi::io::{AsFd, BorrowedFd};

use wasi::wasi_poll::Pollable;

use crate::{Event, PollMode};

/// Interface to epoll.
#[derive(Debug)]
pub struct Poller {}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Self> {
        todo!();
    }

    /// Whether this poller supports level-triggered events.
    pub fn supports_level(&self) -> bool {
        false
    }

    /// Whether the poller supports edge-triggered events.
    pub fn supports_edge(&self) -> bool {
        false
    }

    /// Adds a new file descriptor.
    pub fn add(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        todo!();
    }

    /// Modifies an existing file descriptor.
    pub fn modify(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        todo!();
    }

    /// Deletes a file descriptor.
    pub fn delete(&self, fd: RawFd) -> io::Result<()> {
        todo!();
    }

    /// Waits for I/O events with an optional timeout.
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        todo!();
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        todo!();
    }
}

impl AsRawFd for Poller {
    fn as_raw_fd(&self) -> RawFd {
        todo!();
    }
}

#[cfg(not(polling_no_io_safety))]
impl AsFd for Poller {
    fn as_fd(&self) -> BorrowedFd<'_> {
        todo!();
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        todo!();
    }
}

/// A list of reported I/O events.
pub struct Events {
    list: Box<[libc::epoll_event; 1024]>,
    len: usize,
}

unsafe impl Send for Events {}

impl Events {
    /// Creates an empty list.
    pub fn new() -> Events {
        let ev = libc::epoll_event { events: 0, u64: 0 };
        let list = Box::new([ev; 1024]);
        let len = 0;
        Events { list, len }
    }

    /// Iterates over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.list[..self.len].iter().map(|ev| Event {
            key: ev.u64 as usize,
            readable: (ev.events as libc::c_int & read_flags()) != 0,
            writable: (ev.events as libc::c_int & write_flags()) != 0,
        })
    }
}
