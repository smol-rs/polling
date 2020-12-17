//! Bindings to poll (VxWorks, Fuchsia, other Unix systems).

use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::sync::Mutex;
use std::time::Duration;

// std::os::unix doesn't exist on Fuchsia
use libc::c_int as RawFd;

use crate::Event;

/// Special value for an fd in a pollfd to signal that it should be removed.
const REMOVE_FD: RawFd = -2;

/// Interface to poll.
#[derive(Debug)]
pub struct Poller {
    /// File descriptors to poll.
    fds: Mutex<Fds>,
    /// The file descriptor of the read half of the notify pipe. This is also stored as the first
    /// file descriptor in `fds.poll_fds`.
    notify_read: RawFd,
    /// The file descriptor of the write half of the notify pipe.
    notify_write: RawFd,
}

/// The file descriptors to poll in a `Poller`.
#[derive(Debug)]
struct Fds {
    /// The list of `pollfds` taken by poll.
    ///
    /// The first file descriptor is always present and is used to notify the poller. It is also
    /// stored in `notify_read`.
    ///
    /// If the fd stored in here is `REMOVE_FD`, it should be removed.
    poll_fds: Vec<libc::pollfd>,
    /// The map of each file descriptor to data associated with it. This does not include the file
    /// descriptors `notify_read` or `notify_write`.
    fd_data: HashMap<RawFd, FdData>,
}

/// Data associated with a file descriptor in a poller.
#[derive(Debug)]
struct FdData {
    /// The index into `poll_fds` this file descriptor is.
    poll_fds_index: usize,
    /// The key of the `Event` associated with this file descriptor.
    key: usize,
}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Poller> {
        // Create the notification pipe.
        let mut notify_pipe = [0; 2];
        syscall!(pipe(notify_pipe.as_mut_ptr()))?;

        // Put the reading side into non-blocking mode.
        let notify_read_flags = syscall!(fcntl(notify_pipe[0], libc::F_GETFL))?;
        syscall!(fcntl(
            notify_pipe[0],
            libc::F_SETFL,
            notify_read_flags | libc::O_NONBLOCK
        ))?;

        Ok(Self {
            fds: Mutex::new(Fds {
                poll_fds: vec![libc::pollfd {
                    fd: notify_pipe[0],
                    events: libc::POLLRDNORM,
                    revents: 0,
                }],
                fd_data: HashMap::new(),
            }),
            notify_read: notify_pipe[0],
            notify_write: notify_pipe[1],
        })
    }

    /// Adds a new file descriptor.
    pub fn add(&self, fd: RawFd, ev: Event) -> io::Result<()> {
        if fd == self.notify_read || fd == self.notify_write {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        let mut fds = self.fds.lock().unwrap();

        if fds.fd_data.contains_key(&fd) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }

        let poll_fds_index = fds.poll_fds.len();
        fds.fd_data.insert(
            fd,
            FdData {
                poll_fds_index,
                key: ev.key,
            },
        );

        fds.poll_fds.push(libc::pollfd {
            fd,
            events: poll_events(ev),
            revents: 0,
        });

        Ok(())
    }

    /// Modifies an existing file descriptor.
    pub fn modify(&self, fd: RawFd, ev: Event) -> io::Result<()> {
        let mut fds = self.fds.lock().unwrap();

        let data = fds.fd_data.get_mut(&fd).ok_or(io::ErrorKind::NotFound)?;
        data.key = ev.key;
        let poll_fds_index = data.poll_fds_index;
        fds.poll_fds[poll_fds_index].events = poll_events(ev);

        Ok(())
    }

    /// Deletes a file descriptor.
    pub fn delete(&self, fd: RawFd) -> io::Result<()> {
        let mut fds = self.fds.lock().unwrap();

        let data = fds.fd_data.remove(&fd).ok_or(io::ErrorKind::NotFound)?;
        fds.poll_fds[data.poll_fds_index].fd = REMOVE_FD;

        Ok(())
    }

    /// Waits for I/O events with an optional timeout.
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        events.inner.clear();

        let timeout_ms = timeout
            .map(|timeout| {
                // Round up to a whole millisecond.
                let mut ms = timeout.as_millis().try_into().unwrap_or(std::u64::MAX);
                if Duration::from_millis(ms) < timeout {
                    ms += 1;
                }
                ms.try_into().unwrap_or(std::i32::MAX)
            })
            .unwrap_or(-1);

        let mut fds = self.fds.lock().unwrap();
        let fds = &mut *fds;

        // Remove all fds that have been marked to be removed.
        fds.poll_fds.retain(|poll_fd| poll_fd.fd != REMOVE_FD);

        let num_events = loop {
            match syscall!(poll(
                fds.poll_fds.as_mut_ptr(),
                fds.poll_fds.len() as u64,
                timeout_ms,
            )) {
                Ok(num_events) => break num_events as usize,
                // EAGAIN is translated into WouldBlock, and EWOULDBLOCK cannot be returned by
                // poll.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            };
        };

        // Store any events that occured and remove interest.
        events.inner.reserve(num_events);
        for fd_data in fds.fd_data.values_mut() {
            let mut poll_fd = fds.poll_fds[fd_data.poll_fds_index];
            if poll_fd.revents != 0 {
                events.inner.push(Event {
                    key: fd_data.key,
                    readable: poll_fd.revents & READ_REVENTS != 0,
                    writable: poll_fd.revents & WRITE_REVENTS != 0,
                });
                poll_fd.events = 0;
            }
        }

        // Read all notifications.
        while syscall!(read(self.notify_read, &mut [0; 64] as *mut _ as *mut _, 64)).is_ok() {}

        Ok(())
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        syscall!(write(self.notify_write, &0_u8 as *const _ as *const _, 1))?;
        Ok(())
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        let _ = syscall!(close(self.notify_read));
        let _ = syscall!(close(self.notify_write));
    }
}

/// Get the input poll events for the given event.
fn poll_events(ev: Event) -> libc::c_short {
    (if ev.readable {
        libc::POLLIN | libc::POLLPRI
    } else {
        0
    }) | (if ev.writable {
        libc::POLLOUT | libc::POLLWRBAND
    } else {
        0
    })
}

/// Returned poll events for reading.
const READ_REVENTS: libc::c_short = libc::POLLIN | libc::POLLPRI | libc::POLLHUP | libc::POLLERR;

/// Returned poll events for writing.
const WRITE_REVENTS: libc::c_short =
    libc::POLLOUT | libc::POLLWRBAND | libc::POLLHUP | libc::POLLERR;

/// A list of reported I/O events.
pub struct Events {
    inner: Vec<Event>,
}

impl Events {
    /// Creates an empty list.
    pub fn new() -> Events {
        Self { inner: Vec::new() }
    }

    /// Iterates over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.inner.iter().copied()
    }
}
