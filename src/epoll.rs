//! Bindings to epoll (Linux, Android).

use std::convert::TryInto;
use std::io;
use std::os::unix::io::RawFd;
use std::ptr;
use std::time::Duration;
use std::usize;

use crate::Event;

/// Interface to epoll.
#[derive(Debug)]
pub struct Poller {
    /// File descriptor for the epoll instance.
    epoll_fd: RawFd,
    /// File descriptor for the eventfd that produces notifications.
    event_fd: RawFd,
}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Poller> {
        // According to libuv, `EPOLL_CLOEXEC` is not defined on Android API < 21.
        // But `EPOLL_CLOEXEC` is an alias for `O_CLOEXEC` on that platform, so we use it instead.
        #[cfg(target_os = "android")]
        const CLOEXEC: libc::c_int = libc::O_CLOEXEC;
        #[cfg(not(target_os = "android"))]
        const CLOEXEC: libc::c_int = libc::EPOLL_CLOEXEC;

        // Create an epoll instance.
        let epoll_fd = unsafe {
            // Check if the `epoll_create1` symbol is available on this platform.
            let ptr = libc::dlsym(
                libc::RTLD_DEFAULT,
                "epoll_create1\0".as_ptr() as *const libc::c_char,
            );

            if ptr.is_null() {
                // If not, use `epoll_create` and manually set `CLOEXEC`.
                let fd = match libc::epoll_create(1024) {
                    -1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                };
                let flags = libc::fcntl(fd, libc::F_GETFD);
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
                fd
            } else {
                // Use `epoll_create1` with `CLOEXEC`.
                let epoll_create1 = std::mem::transmute::<
                    *mut libc::c_void,
                    unsafe extern "C" fn(libc::c_int) -> libc::c_int,
                >(ptr);
                match epoll_create1(CLOEXEC) {
                    -1 => return Err(io::Error::last_os_error()),
                    fd => fd,
                }
            }
        };

        // Set up eventfd.
        let event_fd = syscall!(eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK))?;
        let poller = Poller { epoll_fd, event_fd };
        poller.insert(event_fd)?;
        poller.interest(
            event_fd,
            Event {
                key: NOTIFY_KEY,
                readable: true,
                writable: false,
            },
        )?;

        Ok(poller)
    }

    /// Inserts a file descriptor.
    pub fn insert(&self, fd: RawFd) -> io::Result<()> {
        // Put the file descriptor in non-blocking mode.
        let flags = syscall!(fcntl(fd, libc::F_GETFL))?;
        syscall!(fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK))?;

        // Register the file descriptor in epoll.
        let mut ev = libc::epoll_event {
            events: 0,
            u64: 0u64,
        };
        syscall!(epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut ev))?;

        Ok(())
    }

    /// Sets interest in a read/write event on a file descriptor and associates a key with it.
    pub fn interest(&self, fd: RawFd, ev: Event) -> io::Result<()> {
        let mut flags = libc::EPOLLONESHOT;
        if ev.readable {
            flags |= read_flags();
        }
        if ev.writable {
            flags |= write_flags();
        }

        let mut ev = libc::epoll_event {
            events: flags as _,
            u64: ev.key as u64,
        };
        syscall!(epoll_ctl(self.epoll_fd, libc::EPOLL_CTL_MOD, fd, &mut ev))?;

        Ok(())
    }

    /// Removes a file descriptor.
    pub fn remove(&self, fd: RawFd) -> io::Result<()> {
        syscall!(epoll_ctl(
            self.epoll_fd,
            libc::EPOLL_CTL_DEL,
            fd,
            ptr::null_mut()
        ))?;
        Ok(())
    }

    /// Waits for I/O events with an optional timeout.
    ///
    /// Returns the number of processed I/O events.
    ///
    /// If a notification occurs, the notification event will be included in the `events` list
    /// identifiable by key `usize::MAX`.
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        // Convert the timeout to milliseconds.
        let timeout_ms = timeout
            .map(|t| {
                if t == Duration::from_millis(0) {
                    t
                } else {
                    // Non-zero duration must be at least 1ms.
                    t.max(Duration::from_millis(1))
                }
            })
            .and_then(|t| t.as_millis().try_into().ok())
            .unwrap_or(-1);

        // Wait for I/O events.
        let res = syscall!(epoll_wait(
            self.epoll_fd,
            events.list.as_mut_ptr() as *mut libc::epoll_event,
            events.list.len() as libc::c_int,
            timeout_ms as libc::c_int,
        ))?;
        events.len = res as usize;

        // Clear the notification (if received) and re-register interest in it.
        let mut buf = [0u8; 8];
        let _ = syscall!(read(
            self.event_fd,
            &mut buf[0] as *mut u8 as *mut libc::c_void,
            buf.len()
        ));
        self.interest(
            self.event_fd,
            Event {
                key: NOTIFY_KEY,
                readable: true,
                writable: false,
            },
        )?;

        Ok(events.len)
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        let buf: [u8; 8] = 1u64.to_ne_bytes();
        let _ = syscall!(write(
            self.event_fd,
            &buf[0] as *const u8 as *const libc::c_void,
            buf.len()
        ));
        Ok(())
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        let _ = self.remove(self.event_fd);
        let _ = syscall!(close(self.event_fd));
        let _ = syscall!(close(self.epoll_fd));
    }
}

/// Key associated with the eventfd for producing notifications.
const NOTIFY_KEY: usize = usize::MAX;

/// Epoll flags for all possible readability events.
fn read_flags() -> libc::c_int {
    libc::EPOLLIN | libc::EPOLLRDHUP | libc::EPOLLHUP | libc::EPOLLERR | libc::EPOLLPRI
}

/// Epoll flags for all possible writability events.
fn write_flags() -> libc::c_int {
    libc::EPOLLOUT | libc::EPOLLHUP | libc::EPOLLERR
}

/// A list of reported I/O events.
pub struct Events {
    list: Box<[libc::epoll_event]>,
    len: usize,
}

unsafe impl Send for Events {}

impl Events {
    /// Creates an empty list.
    pub fn new() -> Events {
        let ev = libc::epoll_event { events: 0, u64: 0 };
        let list = vec![ev; 1000].into_boxed_slice();
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
