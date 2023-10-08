//! Bindings to epoll (Linux, Android).

use std::io;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::time::Duration;

use rustix::event::{epoll, eventfd, EventfdFlags};
use rustix::fd::OwnedFd;
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use rustix::io::{fcntl_getfd, fcntl_setfd, read, write, FdFlags};
use rustix::pipe::{pipe, pipe_with, PipeFlags};
use rustix::time::{
    timerfd_create, timerfd_settime, Itimerspec, TimerfdClockId, TimerfdFlags, TimerfdTimerFlags,
    Timespec,
};

use crate::{Event, PollMode};

/// Interface to epoll.
#[derive(Debug)]
pub struct Poller {
    /// File descriptor for the epoll instance.
    epoll_fd: OwnedFd,

    /// Notifier used to wake up epoll.
    notifier: Notifier,

    /// File descriptor for the timerfd that produces timeouts.
    timer_fd: Option<OwnedFd>,
}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Poller> {
        // Create an epoll instance.
        //
        // Use `epoll_create1` with `EPOLL_CLOEXEC`.
        let epoll_fd = epoll::create(epoll::CreateFlags::CLOEXEC)?;

        // Set up notifier and timerfd.
        let notifier = Notifier::new()?;
        let timer_fd = timerfd_create(
            TimerfdClockId::Monotonic,
            TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
        )
        .ok();

        let poller = Poller {
            epoll_fd,
            notifier,
            timer_fd,
        };

        unsafe {
            if let Some(ref timer_fd) = poller.timer_fd {
                poller.add(
                    timer_fd.as_raw_fd(),
                    Event::none(crate::NOTIFY_KEY),
                    PollMode::Oneshot,
                )?;
            }

            poller.add(
                poller.notifier.as_fd().as_raw_fd(),
                Event::readable(crate::NOTIFY_KEY),
                PollMode::Oneshot,
            )?;
        }

        tracing::trace!(
            epoll_fd = ?poller.epoll_fd.as_raw_fd(),
            notifier = ?poller.notifier,
            timer_fd = ?poller.timer_fd,
            "new",
        );
        Ok(poller)
    }

    /// Whether this poller supports level-triggered events.
    pub fn supports_level(&self) -> bool {
        true
    }

    /// Whether the poller supports edge-triggered events.
    pub fn supports_edge(&self) -> bool {
        true
    }

    /// Adds a new file descriptor.
    ///
    /// # Safety
    ///
    /// The `fd` must be a valid file descriptor. The usual condition of remaining registered in
    /// the `Poller` doesn't apply to `epoll`.
    pub unsafe fn add(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        let span = tracing::trace_span!(
            "add",
            epoll_fd = ?self.epoll_fd.as_raw_fd(),
            ?fd,
            ?ev,
        );
        let _enter = span.enter();

        epoll::add(
            &self.epoll_fd,
            unsafe { rustix::fd::BorrowedFd::borrow_raw(fd) },
            epoll::EventData::new_u64(ev.key as u64),
            epoll_flags(&ev, mode) | ev.extra.flags,
        )?;

        Ok(())
    }

    /// Modifies an existing file descriptor.
    pub fn modify(&self, fd: BorrowedFd<'_>, ev: Event, mode: PollMode) -> io::Result<()> {
        let span = tracing::trace_span!(
            "modify",
            epoll_fd = ?self.epoll_fd.as_raw_fd(),
            ?fd,
            ?ev,
        );
        let _enter = span.enter();

        epoll::modify(
            &self.epoll_fd,
            fd,
            epoll::EventData::new_u64(ev.key as u64),
            epoll_flags(&ev, mode) | ev.extra.flags,
        )?;

        Ok(())
    }

    /// Deletes a file descriptor.
    pub fn delete(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let span = tracing::trace_span!(
            "delete",
            epoll_fd = ?self.epoll_fd.as_raw_fd(),
            ?fd,
        );
        let _enter = span.enter();

        epoll::delete(&self.epoll_fd, fd)?;

        Ok(())
    }

    /// Waits for I/O events with an optional timeout.
    #[allow(clippy::needless_update)]
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        let span = tracing::trace_span!(
            "wait",
            epoll_fd = ?self.epoll_fd.as_raw_fd(),
            ?timeout,
        );
        let _enter = span.enter();

        if let Some(ref timer_fd) = self.timer_fd {
            // Configure the timeout using timerfd.
            let new_val = Itimerspec {
                it_interval: TS_ZERO,
                it_value: match timeout {
                    None => TS_ZERO,
                    Some(t) => {
                        let mut ts = TS_ZERO;
                        ts.tv_sec = t.as_secs() as _;
                        ts.tv_nsec = t.subsec_nanos() as _;
                        ts
                    }
                },
                ..unsafe { std::mem::zeroed() }
            };

            timerfd_settime(timer_fd, TimerfdTimerFlags::empty(), &new_val)?;

            // Set interest in timerfd.
            self.modify(
                timer_fd.as_fd(),
                Event::readable(crate::NOTIFY_KEY),
                PollMode::Oneshot,
            )?;
        }

        // Timeout in milliseconds for epoll.
        let timeout_ms = match (&self.timer_fd, timeout) {
            (_, Some(t)) if t == Duration::from_secs(0) => 0,
            (None, Some(t)) => {
                // Round up to a whole millisecond.
                let mut ms = t.as_millis().try_into().unwrap_or(std::i32::MAX);
                if Duration::from_millis(ms as u64) < t {
                    ms = ms.saturating_add(1);
                }
                ms
            }
            _ => -1,
        };

        // Wait for I/O events.
        epoll::wait(&self.epoll_fd, &mut events.list, timeout_ms)?;
        tracing::trace!(
            epoll_fd = ?self.epoll_fd.as_raw_fd(),
            res = ?events.list.len(),
            "new events",
        );

        // Clear the notification (if received) and re-register interest in it.
        self.notifier.clear();
        self.modify(
            self.notifier.as_fd(),
            Event::readable(crate::NOTIFY_KEY),
            PollMode::Oneshot,
        )?;
        Ok(())
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        let span = tracing::trace_span!(
            "notify",
            epoll_fd = ?self.epoll_fd.as_raw_fd(),
            notifier = ?self.notifier,
        );
        let _enter = span.enter();

        self.notifier.notify();
        Ok(())
    }
}

impl AsRawFd for Poller {
    fn as_raw_fd(&self) -> RawFd {
        self.epoll_fd.as_raw_fd()
    }
}

impl AsFd for Poller {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.epoll_fd.as_fd()
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        let span = tracing::trace_span!(
            "drop",
            epoll_fd = ?self.epoll_fd.as_raw_fd(),
            notifier = ?self.notifier,
            timer_fd = ?self.timer_fd
        );
        let _enter = span.enter();

        if let Some(timer_fd) = self.timer_fd.take() {
            let _ = self.delete(timer_fd.as_fd());
        }
        let _ = self.delete(self.notifier.as_fd());
    }
}

/// `timespec` value that equals zero.
const TS_ZERO: Timespec = unsafe { std::mem::transmute([0u8; std::mem::size_of::<Timespec>()]) };

/// Get the EPOLL flags for the interest.
fn epoll_flags(interest: &Event, mode: PollMode) -> epoll::EventFlags {
    let mut flags = match mode {
        PollMode::Oneshot => epoll::EventFlags::ONESHOT,
        PollMode::Level => epoll::EventFlags::empty(),
        PollMode::Edge => epoll::EventFlags::ET,
        PollMode::EdgeOneshot => epoll::EventFlags::ET | epoll::EventFlags::ONESHOT,
    };
    if interest.readable {
        flags |= read_flags();
    }
    if interest.writable {
        flags |= write_flags();
    }
    flags
}

/// Epoll flags for all possible readability events.
fn read_flags() -> epoll::EventFlags {
    use epoll::EventFlags as Epoll;
    Epoll::IN | Epoll::HUP | Epoll::ERR | Epoll::PRI
}

/// Epoll flags for all possible writability events.
fn write_flags() -> epoll::EventFlags {
    use epoll::EventFlags as Epoll;
    Epoll::OUT | Epoll::HUP | Epoll::ERR
}

/// A list of reported I/O events.
pub struct Events {
    list: epoll::EventVec,
}

unsafe impl Send for Events {}

impl Events {
    /// Creates an empty list.
    pub fn with_capacity(cap: usize) -> Events {
        Events {
            list: epoll::EventVec::with_capacity(cap),
        }
    }

    /// Iterates over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.list.iter().map(|ev| {
            let flags = ev.flags;
            Event {
                key: ev.data.u64() as usize,
                readable: flags.intersects(read_flags()),
                writable: flags.intersects(write_flags()),
                extra: EventExtra { flags },
            }
        })
    }

    /// Clear the list.
    pub fn clear(&mut self) {
        self.list.clear();
    }

    /// Get the capacity of the list.
    pub fn capacity(&self) -> usize {
        self.list.capacity()
    }
}

/// Extra information about this event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventExtra {
    flags: epoll::EventFlags,
}

impl EventExtra {
    /// Create an empty version of the data.
    #[inline]
    pub const fn empty() -> EventExtra {
        EventExtra {
            flags: epoll::EventFlags::empty(),
        }
    }

    /// Add the interrupt flag to this event.
    #[inline]
    pub fn set_hup(&mut self, active: bool) {
        self.flags.set(epoll::EventFlags::HUP, active);
    }

    /// Add the priority flag to this event.
    #[inline]
    pub fn set_pri(&mut self, active: bool) {
        self.flags.set(epoll::EventFlags::PRI, active);
    }

    /// Tell if the interrupt flag is set.
    #[inline]
    pub fn is_hup(&self) -> bool {
        self.flags.contains(epoll::EventFlags::HUP)
    }

    /// Tell if the priority flag is set.
    #[inline]
    pub fn is_pri(&self) -> bool {
        self.flags.contains(epoll::EventFlags::PRI)
    }
}

/// The notifier for Linux.
///
/// Certain container runtimes do not expose eventfd to the client, as it relies on the host and
/// can be used to "escape" the container under certain conditions. Gramine is the prime example,
/// see [here](gramine). In this case, fall back to using a pipe.
///
/// [gramine]: https://gramine.readthedocs.io/en/stable/manifest-syntax.html#allowing-eventfd
#[derive(Debug)]
enum Notifier {
    /// The primary notifier, using eventfd.
    EventFd(OwnedFd),

    /// The fallback notifier, using a pipe.
    Pipe {
        /// The read end of the pipe.
        read_pipe: OwnedFd,

        /// The write end of the pipe.
        write_pipe: OwnedFd,
    },
}

impl Notifier {
    /// Create a new notifier.
    fn new() -> io::Result<Self> {
        // Skip eventfd for testing if necessary.
        if !cfg!(polling_test_epoll_pipe) {
            // Try to create an eventfd.
            match eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK) {
                Ok(fd) => {
                    tracing::trace!("created eventfd for notifier");
                    return Ok(Notifier::EventFd(fd));
                }

                Err(err) => {
                    tracing::warn!(
                        "eventfd() failed with error ({}), falling back to pipe",
                        err
                    );
                }
            }
        }

        let (read, write) = pipe_with(PipeFlags::CLOEXEC).or_else(|_| {
            let (read, write) = pipe()?;
            fcntl_setfd(&read, fcntl_getfd(&read)? | FdFlags::CLOEXEC)?;
            fcntl_setfd(&write, fcntl_getfd(&write)? | FdFlags::CLOEXEC)?;
            io::Result::Ok((read, write))
        })?;

        fcntl_setfl(&read, fcntl_getfl(&read)? | OFlags::NONBLOCK)?;
        Ok(Notifier::Pipe {
            read_pipe: read,
            write_pipe: write,
        })
    }

    /// The file descriptor to register in the poller.
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Notifier::EventFd(fd) => fd.as_fd(),
            Notifier::Pipe {
                read_pipe: read, ..
            } => read.as_fd(),
        }
    }

    /// Notify the poller.
    fn notify(&self) {
        match self {
            Self::EventFd(fd) => {
                let buf: [u8; 8] = 1u64.to_ne_bytes();
                let _ = write(fd, &buf);
            }

            Self::Pipe { write_pipe, .. } => {
                write(write_pipe, &[0; 1]).ok();
            }
        }
    }

    /// Clear the notification.
    fn clear(&self) {
        match self {
            Self::EventFd(fd) => {
                let mut buf = [0u8; 8];
                let _ = read(fd, &mut buf);
            }

            Self::Pipe { read_pipe, .. } => while read(read_pipe, &mut [0u8; 1024]).is_ok() {},
        }
    }
}
