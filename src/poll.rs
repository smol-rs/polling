//! Bindings to poll (VxWorks, Fuchsia, other Unix systems).

use std::collections::HashMap;
use std::convert::TryInto;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::io::{fcntl_getfd, fcntl_setfd, read, write, FdFlags};
use rustix::pipe::{pipe, pipe_with, PipeFlags};

// std::os::unix doesn't exist on Fuchsia
type RawFd = std::os::raw::c_int;

use crate::{Event, PollMode};

/// Interface to poll.
#[derive(Debug)]
pub struct Poller {
    /// File descriptors to poll.
    fds: Mutex<Fds>,

    /// The file descriptor of the read half of the notify pipe. This is also stored as the first
    /// file descriptor in `fds.poll_fds`.
    notify_read: OwnedFd,
    /// The file descriptor of the write half of the notify pipe.
    ///
    /// Data is written to this to wake up the current instance of `wait`, which can occur when the
    /// user notifies it (in which case `notified` would have been set) or when an operation needs
    /// to occur (in which case `waiting_operations` would have been incremented).
    notify_write: OwnedFd,

    /// The number of operations (`add`, `modify` or `delete`) that are currently waiting on the
    /// mutex to become free. When this is nonzero, `wait` must be suspended until it reaches zero
    /// again.
    waiting_operations: AtomicUsize,
    /// Whether `wait` has been notified by the user.
    notified: AtomicBool,
    /// The condition variable that gets notified when `waiting_operations` reaches zero or
    /// `notified` becomes true.
    ///
    /// This is used with the `fds` mutex.
    operations_complete: Condvar,
}

/// The file descriptors to poll in a `Poller`.
#[derive(Debug)]
struct Fds {
    /// The list of `pollfds` taken by poll.
    ///
    /// The first file descriptor is always present and is used to notify the poller. It is also
    /// stored in `notify_read`.
    poll_fds: Vec<PollFd<'static>>,
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
    /// Whether to remove this file descriptor from the poller on the next call to `wait`.
    remove: bool,
}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Poller> {
        // Create the notification pipe.
        let (notify_read, notify_write) = pipe_with(PipeFlags::CLOEXEC).or_else(|_| {
            let (notify_read, notify_write) = pipe()?;
            fcntl_setfd(&notify_read, fcntl_getfd(&notify_read)? | FdFlags::CLOEXEC)?;
            fcntl_setfd(
                &notify_write,
                fcntl_getfd(&notify_write)? | FdFlags::CLOEXEC,
            )?;
            io::Result::Ok((notify_read, notify_write))
        })?;

        // Put the reading side into non-blocking mode.
        fcntl_setfl(&notify_read, fcntl_getfl(&notify_read)? | OFlags::NONBLOCK)?;

        tracing::trace!(?notify_read, ?notify_write, "new");

        Ok(Self {
            fds: Mutex::new(Fds {
                poll_fds: vec![PollFd::from_borrowed_fd(
                    // SAFETY: `read` will remain valid until we drop `self`.
                    unsafe { BorrowedFd::borrow_raw(notify_read.as_raw_fd()) },
                    PollFlags::RDNORM,
                )],
                fd_data: HashMap::new(),
            }),
            notify_read,
            notify_write,
            waiting_operations: AtomicUsize::new(0),
            operations_complete: Condvar::new(),
            notified: AtomicBool::new(false),
        })
    }

    /// Whether this poller supports level-triggered events.
    pub fn supports_level(&self) -> bool {
        true
    }

    /// Whether the poller supports edge-triggered events.
    pub fn supports_edge(&self) -> bool {
        false
    }

    /// Adds a new file descriptor.
    pub fn add(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        if fd == self.notify_read.as_raw_fd() || fd == self.notify_write.as_raw_fd() {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        let span = tracing::trace_span!(
            "add",
            notify_read = ?self.notify_read,
            ?fd,
            ?ev,
        );
        let _enter = span.enter();

        self.modify_fds(|fds| {
            if fds.fd_data.contains_key(&fd) {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }

            let poll_fds_index = fds.poll_fds.len();
            fds.fd_data.insert(
                fd,
                FdData {
                    poll_fds_index,
                    key: ev.key,
                    remove: cvt_mode_as_remove(mode)?,
                },
            );

            fds.poll_fds.push(PollFd::from_borrowed_fd(
                // SAFETY: Until we have I/O safety, assume that `fd` is valid forever.
                unsafe { BorrowedFd::borrow_raw(fd) },
                poll_events(ev),
            ));

            Ok(())
        })
    }

    /// Modifies an existing file descriptor.
    pub fn modify(&self, fd: BorrowedFd<'_>, ev: Event, mode: PollMode) -> io::Result<()> {
        let span = tracing::trace_span!(
            "modify",
            notify_read = ?self.notify_read,
            ?fd,
            ?ev,
        );
        let _enter = span.enter();

        self.modify_fds(|fds| {
            let data = fds
                .fd_data
                .get_mut(&fd.as_raw_fd())
                .ok_or(io::ErrorKind::NotFound)?;
            data.key = ev.key;
            let poll_fds_index = data.poll_fds_index;

            // SAFETY: This is essentially transmuting a `PollFd<'a>` to a `PollFd<'static>`, which
            // only works if it's removed in time with `delete()`.
            fds.poll_fds[poll_fds_index] = PollFd::from_borrowed_fd(
                unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) },
                poll_events(ev),
            );
            data.remove = cvt_mode_as_remove(mode)?;

            Ok(())
        })
    }

    /// Deletes a file descriptor.
    pub fn delete(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let span = tracing::trace_span!(
            "delete",
            notify_read = ?self.notify_read,
            ?fd,
        );
        let _enter = span.enter();

        self.modify_fds(|fds| {
            let data = fds
                .fd_data
                .remove(&fd.as_raw_fd())
                .ok_or(io::ErrorKind::NotFound)?;
            fds.poll_fds.swap_remove(data.poll_fds_index);
            if let Some(swapped_pollfd) = fds.poll_fds.get(data.poll_fds_index) {
                fds.fd_data
                    .get_mut(&swapped_pollfd.as_fd().as_raw_fd())
                    .unwrap()
                    .poll_fds_index = data.poll_fds_index;
            }

            Ok(())
        })
    }

    /// Waits for I/O events with an optional timeout.
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        let span = tracing::trace_span!(
            "wait",
            notify_read = ?self.notify_read,
            ?timeout,
        );
        let _enter = span.enter();

        let deadline = timeout.and_then(|t| Instant::now().checked_add(t));

        events.inner.clear();

        let mut fds = self.fds.lock().unwrap();

        loop {
            // Complete all current operations.
            loop {
                if self.notified.swap(false, Ordering::SeqCst) {
                    // `notify` will have sent a notification in case we were polling. We weren't,
                    // so remove it.
                    return self.pop_notification();
                } else if self.waiting_operations.load(Ordering::SeqCst) == 0 {
                    break;
                }

                fds = self.operations_complete.wait(fds).unwrap();
            }

            // Convert the timeout to milliseconds.
            let timeout_ms = deadline
                .map(|deadline| {
                    let timeout = deadline.saturating_duration_since(Instant::now());

                    // Round up to a whole millisecond.
                    let mut ms = timeout.as_millis().try_into().unwrap_or(std::u64::MAX);
                    if Duration::from_millis(ms) < timeout {
                        ms = ms.saturating_add(1);
                    }
                    ms.try_into().unwrap_or(std::i32::MAX)
                })
                .unwrap_or(-1);

            // Perform the poll.
            let num_events = poll(&mut fds.poll_fds, timeout_ms)?;
            let notified = !fds.poll_fds[0].revents().is_empty();
            let num_fd_events = if notified { num_events - 1 } else { num_events };
            tracing::trace!(?num_events, ?notified, ?num_fd_events, "new events",);

            // Read all notifications.
            if notified {
                while read(&self.notify_read, &mut [0; 64]).is_ok() {}
            }

            // If the only event that occurred during polling was notification and it wasn't to
            // exit, another thread is trying to perform an operation on the fds. Continue the
            // loop.
            if !self.notified.swap(false, Ordering::SeqCst) && num_fd_events == 0 && notified {
                continue;
            }

            // Store the events if there were any.
            if num_fd_events > 0 {
                let fds = &mut *fds;

                events.inner.reserve(num_fd_events);
                for fd_data in fds.fd_data.values_mut() {
                    let poll_fd = &mut fds.poll_fds[fd_data.poll_fds_index];
                    if !poll_fd.revents().is_empty() {
                        // Store event
                        events.inner.push(Event {
                            key: fd_data.key,
                            readable: poll_fd.revents().intersects(read_events()),
                            writable: poll_fd.revents().intersects(write_events()),
                        });
                        // Remove interest if necessary
                        if fd_data.remove {
                            *poll_fd = PollFd::from_borrowed_fd(
                                unsafe { BorrowedFd::borrow_raw(poll_fd.as_fd().as_raw_fd()) },
                                PollFlags::empty(),
                            );
                        }

                        if events.inner.len() == num_fd_events {
                            break;
                        }
                    }
                }
            }

            break;
        }

        Ok(())
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        let span = tracing::trace_span!(
            "notify",
            notify_read = ?self.notify_read,
        );
        let _enter = span.enter();

        if !self.notified.swap(true, Ordering::SeqCst) {
            self.notify_inner()?;
            self.operations_complete.notify_one();
        }

        Ok(())
    }

    /// Perform a modification on `fds`, interrupting the current caller of `wait` if it's running.
    fn modify_fds(&self, f: impl FnOnce(&mut Fds) -> io::Result<()>) -> io::Result<()> {
        self.waiting_operations.fetch_add(1, Ordering::SeqCst);

        // Wake up the current caller of `wait` if there is one.
        let sent_notification = self.notify_inner().is_ok();

        let mut fds = self.fds.lock().unwrap();

        // If there was no caller of `wait` our notification was not removed from the pipe.
        if sent_notification {
            let _ = self.pop_notification();
        }

        let res = f(&mut fds);

        if self.waiting_operations.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.operations_complete.notify_one();
        }

        res
    }

    /// Wake the current thread that is calling `wait`.
    fn notify_inner(&self) -> io::Result<()> {
        write(&self.notify_write, &[0; 1])?;
        Ok(())
    }

    /// Remove a notification created by `notify_inner`.
    fn pop_notification(&self) -> io::Result<()> {
        read(&self.notify_read, &mut [0; 1])?;
        Ok(())
    }
}

/// Get the input poll events for the given event.
fn poll_events(ev: Event) -> PollFlags {
    (if ev.readable {
        PollFlags::IN | PollFlags::PRI
    } else {
        PollFlags::empty()
    }) | (if ev.writable {
        PollFlags::OUT | PollFlags::WRBAND
    } else {
        PollFlags::empty()
    })
}

/// Returned poll events for reading.
fn read_events() -> PollFlags {
    PollFlags::IN | PollFlags::PRI | PollFlags::HUP | PollFlags::ERR
}

/// Returned poll events for writing.
fn write_events() -> PollFlags {
    PollFlags::OUT | PollFlags::WRBAND | PollFlags::HUP | PollFlags::ERR
}

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

fn cvt_mode_as_remove(mode: PollMode) -> io::Result<bool> {
    match mode {
        PollMode::Oneshot => Ok(true),
        PollMode::Level => Ok(false),
        _ => Err(crate::unsupported_error(
            "edge-triggered I/O events are not supported in poll()",
        )),
    }
}
