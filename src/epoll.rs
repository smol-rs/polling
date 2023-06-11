//! Bindings to epoll (Linux, Android).

use std::convert::TryInto;
use std::io;
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::time::Duration;

use rustix::fd::OwnedFd;
use rustix::io::{epoll, eventfd, read, write, EventfdFlags};
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
    /// File descriptor for the eventfd that produces notifications.
    event_fd: OwnedFd,
    /// File descriptor for the timerfd that produces timeouts.
    timer_fd: Option<OwnedFd>,
}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Poller> {
        // Create an epoll instance.
        //
        // Use `epoll_create1` with `EPOLL_CLOEXEC`.
        let epoll_fd = epoll::epoll_create(epoll::CreateFlags::CLOEXEC)?;

        // Set up eventfd and timerfd.
        let event_fd = eventfd(0, EventfdFlags::CLOEXEC | EventfdFlags::NONBLOCK)?;
        let timer_fd = timerfd_create(
            TimerfdClockId::Monotonic,
            TimerfdFlags::CLOEXEC | TimerfdFlags::NONBLOCK,
        )
        .ok();

        let poller = Poller {
            epoll_fd,
            event_fd,
            timer_fd,
        };

        if let Some(ref timer_fd) = poller.timer_fd {
            poller.add(
                timer_fd.as_raw_fd(),
                Event::none(crate::NOTIFY_KEY),
                PollMode::Oneshot,
            )?;
        }

        poller.add(
            poller.event_fd.as_raw_fd(),
            Event {
                key: crate::NOTIFY_KEY,
                readable: true,
                writable: false,
            },
            PollMode::Oneshot,
        )?;

        log::trace!(
            "new: epoll_fd={}, event_fd={}, timer_fd={:?}",
            poller.epoll_fd.as_raw_fd(),
            poller.event_fd.as_raw_fd(),
            poller.timer_fd
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
    pub fn add(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        log::trace!(
            "add: epoll_fd={}, fd={}, ev={:?}",
            self.epoll_fd.as_raw_fd(),
            fd,
            ev
        );

        epoll::epoll_add(
            &self.epoll_fd,
            unsafe { rustix::fd::BorrowedFd::borrow_raw(fd) },
            ev.key as u64,
            epoll_flags(&ev, mode),
        )?;

        Ok(())
    }

    /// Modifies an existing file descriptor.
    pub fn modify(&self, fd: RawFd, ev: Event, mode: PollMode) -> io::Result<()> {
        log::trace!(
            "modify: epoll_fd={}, fd={}, ev={:?}",
            self.epoll_fd.as_raw_fd(),
            fd,
            ev
        );

        epoll::epoll_mod(
            &self.epoll_fd,
            unsafe { rustix::fd::BorrowedFd::borrow_raw(fd) },
            ev.key as u64,
            epoll_flags(&ev, mode),
        )?;

        Ok(())
    }

    /// Deletes a file descriptor.
    pub fn delete(&self, fd: RawFd) -> io::Result<()> {
        log::trace!("remove: epoll_fd={}, fd={}", self.epoll_fd.as_raw_fd(), fd);

        epoll::epoll_del(&self.epoll_fd, unsafe {
            rustix::fd::BorrowedFd::borrow_raw(fd)
        })?;

        Ok(())
    }

    /// Waits for I/O events with an optional timeout.
    #[allow(clippy::needless_update)]
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        log::trace!(
            "wait: epoll_fd={}, timeout={:?}",
            self.epoll_fd.as_raw_fd(),
            timeout
        );

        if let Some(ref timer_fd) = self.timer_fd {
            // Configure the timeout using timerfd.
            let new_val = Itimerspec {
                it_interval: TS_ZERO,
                it_value: match timeout {
                    None => TS_ZERO,
                    Some(t) => {
                        let mut ts = TS_ZERO;
                        ts.tv_sec = t.as_secs() as libc::time_t;
                        ts.tv_nsec = (t.subsec_nanos() as libc::c_long).into();
                        ts
                    }
                },
                ..unsafe { std::mem::zeroed() }
            };

            timerfd_settime(timer_fd, TimerfdTimerFlags::empty(), &new_val)?;

            // Set interest in timerfd.
            self.modify(
                timer_fd.as_raw_fd(),
                Event {
                    key: crate::NOTIFY_KEY,
                    readable: true,
                    writable: false,
                },
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
        epoll::epoll_wait(&self.epoll_fd, &mut events.list, timeout_ms)?;
        log::trace!(
            "new events: epoll_fd={}, res={}",
            self.epoll_fd.as_raw_fd(),
            events.list.len()
        );

        // Clear the notification (if received) and re-register interest in it.
        let mut buf = [0u8; 8];
        let _ = read(&self.event_fd, &mut buf);
        self.modify(
            self.event_fd.as_raw_fd(),
            Event {
                key: crate::NOTIFY_KEY,
                readable: true,
                writable: false,
            },
            PollMode::Oneshot,
        )?;
        Ok(())
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        log::trace!(
            "notify: epoll_fd={}, event_fd={}",
            self.epoll_fd.as_raw_fd(),
            self.event_fd.as_raw_fd()
        );

        let buf: [u8; 8] = 1u64.to_ne_bytes();
        let _ = write(&self.event_fd, &buf);
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
        log::trace!(
            "drop: epoll_fd={}, event_fd={}, timer_fd={:?}",
            self.epoll_fd.as_raw_fd(),
            self.event_fd.as_raw_fd(),
            self.timer_fd
        );

        if let Some(timer_fd) = self.timer_fd.take() {
            let _ = self.delete(timer_fd.as_raw_fd());
        }
        let _ = self.delete(self.event_fd.as_raw_fd());
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
    pub fn new() -> Events {
        Events {
            list: epoll::EventVec::with_capacity(1024),
        }
    }

    /// Iterates over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.list.iter().map(|(flags, data)| Event {
            key: data as usize,
            readable: flags.intersects(read_flags()),
            writable: flags.intersects(write_flags()),
        })
    }
}
