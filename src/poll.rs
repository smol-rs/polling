//! Bindings to poll (VxWorks, Fuchsia, other Unix systems).

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags};
use rustix::fd::{AsFd, AsRawFd, BorrowedFd};

// std::os::unix doesn't exist on Fuchsia
type RawFd = std::os::raw::c_int;

use crate::{Event, PollMode};

/// Interface to poll.
#[derive(Debug)]
pub struct Poller {
    /// File descriptors to poll.
    fds: Mutex<Fds>,
    /// Notification pipe for waking up the poller.
    ///
    /// On all platforms except ESP IDF, the `pipe` syscall is used.
    /// On ESP IDF, the `eventfd` syscall is used instead.
    notify: notify::Notify,
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
        let notify = notify::Notify::new()?;

        tracing::trace!(?notify, "new");

        Ok(Self {
            fds: Mutex::new(Fds {
                poll_fds: vec![PollFd::from_borrowed_fd(
                    // SAFETY: `notify.fd()` will remain valid until we drop `self`.
                    unsafe { BorrowedFd::borrow_raw(notify.fd().as_raw_fd()) },
                    notify.poll_flags(),
                )],
                fd_data: HashMap::new(),
            }),
            notify,
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
        if self.notify.has_fd(fd) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        let span = tracing::trace_span!(
            "add",
            notify_read = ?self.notify.fd().as_raw_fd(),
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
        if self.notify.has_fd(fd.as_raw_fd()) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        let span = tracing::trace_span!(
            "modify",
            notify_read = ?self.notify.fd().as_raw_fd(),
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
        if self.notify.has_fd(fd.as_raw_fd()) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }

        let span = tracing::trace_span!(
            "delete",
            notify_read = ?self.notify.fd().as_raw_fd(),
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
            notify_read = ?self.notify.fd().as_raw_fd(),
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
                    return self.notify.pop_notification();
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
                self.notify.pop_all_notifications()?;
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
                        let revents = poll_fd.revents();
                        events.inner.push(Event {
                            key: fd_data.key,
                            readable: revents.intersects(read_events()),
                            writable: revents.intersects(write_events()),
                            extra: EventExtra { flags: revents },
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
            notify_read = ?self.notify.fd().as_raw_fd(),
        );
        let _enter = span.enter();

        if !self.notified.swap(true, Ordering::SeqCst) {
            self.notify.notify()?;
            self.operations_complete.notify_one();
        }

        Ok(())
    }

    /// Perform a modification on `fds`, interrupting the current caller of `wait` if it's running.
    fn modify_fds(&self, f: impl FnOnce(&mut Fds) -> io::Result<()>) -> io::Result<()> {
        self.waiting_operations.fetch_add(1, Ordering::SeqCst);

        // Wake up the current caller of `wait` if there is one.
        let sent_notification = self.notify.notify().is_ok();

        let mut fds = self.fds.lock().unwrap();

        // If there was no caller of `wait` our notification was not removed from the pipe.
        if sent_notification {
            let _ = self.notify.pop_notification();
        }

        let res = f(&mut fds);

        if self.waiting_operations.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.operations_complete.notify_one();
        }

        res
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
    pub fn with_capacity(cap: usize) -> Events {
        Self {
            inner: Vec::with_capacity(cap),
        }
    }

    /// Iterates over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.inner.iter().copied()
    }

    /// Clear the list.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Get the capacity of the list.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

/// Extra information associated with an event.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EventExtra {
    /// Flags associated with this event.
    flags: PollFlags,
}

impl EventExtra {
    /// Creates an empty set of extra information.
    #[inline]
    pub const fn empty() -> Self {
        Self {
            flags: PollFlags::empty(),
        }
    }

    /// Set the interrupt flag.
    #[inline]
    pub fn set_hup(&mut self, value: bool) {
        self.flags.set(PollFlags::HUP, value);
    }

    /// Set the priority flag.
    #[inline]
    pub fn set_pri(&mut self, value: bool) {
        self.flags.set(PollFlags::PRI, value);
    }

    /// Is this an interrupt event?
    #[inline]
    pub fn is_hup(&self) -> bool {
        self.flags.contains(PollFlags::HUP)
    }

    /// Is this a priority event?
    #[inline]
    pub fn is_pri(&self) -> bool {
        self.flags.contains(PollFlags::PRI)
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

#[cfg(not(target_os = "espidf"))]
mod notify {
    use std::io;

    use rustix::event::PollFlags;
    use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
    use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
    use rustix::io::{fcntl_getfd, fcntl_setfd, read, write, FdFlags};
    #[cfg(not(target_os = "haiku"))]
    use rustix::pipe::pipe_with;
    use rustix::pipe::{pipe, PipeFlags};

    /// A notification pipe.
    ///
    /// This implementation uses a pipe to send notifications.
    #[derive(Debug)]
    pub(super) struct Notify {
        /// The file descriptor of the read half of the notify pipe. This is also stored as the first
        /// file descriptor in `fds.poll_fds`.
        read_pipe: OwnedFd,
        /// The file descriptor of the write half of the notify pipe.
        ///
        /// Data is written to this to wake up the current instance of `Poller::wait`, which can occur when the
        /// user notifies it (in which case `Poller::notified` would have been set) or when an operation needs
        /// to occur (in which case `Poller::waiting_operations` would have been incremented).
        write_pipe: OwnedFd,
    }

    impl Notify {
        /// Creates a new notification pipe.
        pub(super) fn new() -> io::Result<Self> {
            let fallback_pipe = |_| {
                let (read_pipe, write_pipe) = pipe()?;
                fcntl_setfd(&read_pipe, fcntl_getfd(&read_pipe)? | FdFlags::CLOEXEC)?;
                fcntl_setfd(&write_pipe, fcntl_getfd(&write_pipe)? | FdFlags::CLOEXEC)?;
                io::Result::Ok((read_pipe, write_pipe))
            };

            #[cfg(not(target_os = "haiku"))]
            let (read_pipe, write_pipe) = pipe_with(PipeFlags::CLOEXEC).or_else(fallback_pipe)?;

            #[cfg(target_os = "haiku")]
            let (read_pipe, write_pipe) = fallback_pipe(PipeFlags::CLOEXEC)?;

            // Put the reading side into non-blocking mode.
            fcntl_setfl(&read_pipe, fcntl_getfl(&read_pipe)? | OFlags::NONBLOCK)?;

            Ok(Self {
                read_pipe,
                write_pipe,
            })
        }

        /// Provides the file handle of the read half of the notify pipe that needs to be registered by the `Poller`.
        pub(super) fn fd(&self) -> BorrowedFd<'_> {
            self.read_pipe.as_fd()
        }

        /// Provides the poll flags to be used when registering the read half of the botify pipe with the `Poller`.
        pub(super) fn poll_flags(&self) -> PollFlags {
            PollFlags::RDNORM
        }

        /// Notifies the `Poller` instance via the write half of the notify pipe.
        pub(super) fn notify(&self) -> Result<(), io::Error> {
            write(&self.write_pipe, &[0; 1])?;

            Ok(())
        }

        /// Pops a notification (if any) from the pipe.
        pub(super) fn pop_notification(&self) -> Result<(), io::Error> {
            read(&self.read_pipe, &mut [0; 1])?;

            Ok(())
        }

        /// Pops all notifications from the pipe.
        pub(super) fn pop_all_notifications(&self) -> Result<(), io::Error> {
            while read(&self.read_pipe, &mut [0; 64]).is_ok() {}

            Ok(())
        }

        /// Whether this raw file descriptor is associated with this notifier.
        pub(super) fn has_fd(&self, fd: RawFd) -> bool {
            self.read_pipe.as_raw_fd() == fd || self.write_pipe.as_raw_fd() == fd
        }
    }
}

#[cfg(target_os = "espidf")]
mod notify {
    use std::io;
    use std::mem;

    use rustix::event::PollFlags;
    use rustix::event::{eventfd, EventfdFlags};

    use rustix::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
    use rustix::io::{read, write};

    /// A notification pipe.
    ///
    /// This implementation uses ther `eventfd` syscall to send notifications.
    #[derive(Debug)]
    pub(super) struct Notify {
        /// The file descriptor of the eventfd object. This is also stored as the first
        /// file descriptor in `fds.poll_fds`.
        ///
        /// Data is written to this to wake up the current instance of `Poller::wait`, which can occur when the
        /// user notifies it (in which case `Poller::notified` would have been set) or when an operation needs
        /// to occur (in which case `Poller::waiting_operations` would have been incremented).
        event_fd: OwnedFd,
    }

    impl Notify {
        /// Creates a new notification pipe.
        pub(super) fn new() -> io::Result<Self> {
            // Note that the eventfd() implementation in ESP-IDF deviates from the specification in the following ways:
            // 1) The file descriptor is always in a non-blocking mode, as if EFD_NONBLOCK was passed as a flag;
            //    passing EFD_NONBLOCK or calling fcntl(.., F_GETFL/F_SETFL) on the eventfd() file descriptor is not supported
            // 2) It always returns the counter value, even if it is 0. This is contrary to the specification which mandates
            //    that it should instead fail with EAGAIN
            //
            // (1) is not a problem for us, as we want the eventfd() file descriptor to be in a non-blocking mode anyway
            // (2) is also not a problem, as long as we don't try to read the counter value in an endless loop when we detect being notified

            #[cfg(not(target_os = "espidf"))]
            let flags = EventfdFlags::NONBLOCK;

            #[cfg(target_os = "espidf")]
            let flags = EventfdFlags::empty();

            let event_fd = eventfd(0, flags)?;

            Ok(Self { event_fd })
        }

        /// Provides the eventfd file handle that needs to be registered by the `Poller`.
        pub(super) fn fd(&self) -> BorrowedFd<'_> {
            self.event_fd.as_fd()
        }

        /// Provides the eventfd file handle poll flags to be used when registering it with the `Poller`.
        pub(super) fn poll_flags(&self) -> PollFlags {
            PollFlags::IN
        }

        /// Notifies the `Poller` instance via the eventfd file descriptor.
        pub(super) fn notify(&self) -> Result<(), io::Error> {
            write(&self.event_fd, &1u64.to_ne_bytes())?;

            Ok(())
        }

        /// Pops a notification (if any) from the eventfd file descriptor.
        pub(super) fn pop_notification(&self) -> Result<(), io::Error> {
            read(&self.event_fd, &mut [0; mem::size_of::<u64>()])?;

            Ok(())
        }

        /// Pops all notifications from the eventfd file descriptor.
        /// Since the eventfd object accumulates all writes in a single 64 bit value,
        /// this operation is - in fact - equivalent to `pop_notification`.
        pub(super) fn pop_all_notifications(&self) -> Result<(), io::Error> {
            let _ = self.pop_notification();

            Ok(())
        }

        /// Whether this raw file descriptor is associated with this notifier.
        pub(super) fn has_fd(&self, fd: RawFd) -> bool {
            self.event_fd.as_raw_fd() == fd
        }
    }
}
