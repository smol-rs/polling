//! Bindings to event port (illumos, Solaris).

use std::io;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::io::{fcntl_getfd, fcntl_setfd, port, FdFlags, PollFlags};

use crate::{Event, PollMode};

/// Interface to event ports.
#[derive(Debug)]
pub struct Poller {
    /// File descriptor for the port instance.
    port_fd: OwnedFd,
}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Poller> {
        let port_fd = port::port_create()?;
        let flags = fcntl_getfd(&port_fd)?;
        fcntl_setfd(&port_fd, flags | FdFlags::CLOEXEC)?;

        tracing::trace!(
            port_fd = ?port_fd.as_raw_fd(),
            "new",
        );

        Ok(Poller { port_fd })
    }

    /// Whether this poller supports level-triggered events.
    pub fn supports_level(&self) -> bool {
        false
    }

    /// Whether this poller supports edge-triggered events.
    pub fn supports_edge(&self) -> bool {
        false
    }

    /// Adds a file descriptor.
    pub fn add(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        // File descriptors don't need to be added explicitly, so just modify the interest.
        self.modify(fd, ev, mode)
    }

    /// Modifies an existing file descriptor.
    pub fn modify(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        let span = tracing::trace_span!(
            "modify",
            port_fd = ?self.port_fd.as_raw_fd(),
            ?fd,
            ?ev,
        );
        let _enter = span.enter();

        let mut flags = PollFlags::empty();
        if ev.readable {
            flags |= read_flags();
        }
        if ev.writable {
            flags |= write_flags();
        }

        if mode != PollMode::Oneshot {
            return Err(crate::unsupported_error(
                "this kind of event is not supported with event ports",
            ));
        }

        unsafe {
            port::port_associate_fd(&self.port_fd, fd, flags, ev.key as _)?;
        }

        Ok(())
    }

    /// Deletes a file descriptor.
    pub fn delete(&self, fd: RawFd) -> io::Result<()> {
        let span = tracing::trace_span!(
            "delete",
            port_fd = ?self.port_fd.as_raw_fd(),
            ?fd,
        );
        let _enter = span.enter();

        let result = unsafe { port::port_dissociate_fd(&self.port_fd, fd) };
        if let Err(e) = result {
            match e {
                rustix::io::Errno::NOENT => return Ok(()),
                _ => return Err(e.into()),
            }
        }

        Ok(())
    }

    /// Waits for I/O events with an optional timeout.
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        let span = tracing::trace_span!(
            "wait",
            port_fd = ?self.port_fd.as_raw_fd(),
            ?timeout,
        );
        let _enter = span.enter();

        // Wait for I/O events.
        let res = port::port_getn(&self.port_fd, &mut events.list, 1, timeout);
        tracing::trace!(
            port_fd = ?self.port_fd,
            res = ?events.list.len(),
            "new events"
        );

        // Event ports sets the return value to -1 and returns ETIME on timer expire. The number of
        // returned events is stored in nget, but in our case it should always be 0 since we set
        // nget to 1 initially.
        if let Err(e) = res {
            match e {
                rustix::io::Errno::TIME => {}
                _ => return Err(e.into()),
            }
        }

        Ok(())
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        const PORT_SOURCE_USER: i32 = 3;

        let span = tracing::trace_span!(
            "notify",
            port_fd = ?self.port_fd.as_raw_fd(),
        );
        let _enter = span.enter();

        // Use port_send to send a notification to the port.
        port::port_send(&self.port_fd, PORT_SOURCE_USER, crate::NOTIFY_KEY as _)?;

        Ok(())
    }
}

impl AsRawFd for Poller {
    fn as_raw_fd(&self) -> RawFd {
        self.port_fd.as_raw_fd()
    }
}

impl AsFd for Poller {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.port_fd.as_fd()
    }
}

/// Poll flags for all possible readability events.
fn read_flags() -> PollFlags {
    PollFlags::IN | PollFlags::HUP | PollFlags::ERR | PollFlags::PRI
}

/// Poll flags for all possible writability events.
fn write_flags() -> PollFlags {
    PollFlags::OUT | PollFlags::HUP | PollFlags::ERR
}

/// A list of reported I/O events.
pub struct Events {
    list: Vec<port::Event>,
}

unsafe impl Send for Events {}

impl Events {
    /// Creates an empty list.
    pub fn new() -> Events {
        Events {
            list: Vec::with_capacity(1024),
        }
    }

    /// Iterates over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.list.iter().map(|ev| Event {
            key: ev.userdata() as usize,
            readable: PollFlags::from_bits_truncate(ev.events() as _).intersects(read_flags()),
            writable: PollFlags::from_bits_truncate(ev.events() as _).intersects(write_flags()),
        })
    }
}
