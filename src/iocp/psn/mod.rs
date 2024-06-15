//! Bindings to Windows IOCP with `ProcessSocketNotifications` and
//! `NtAssociateWaitCompletionPacket` support.
//!
//! `ProcessSocketNotifications` is a new Windows API after 21H1. It is much like kqueue,
//! and support edge triggers. The implementation is easier to be adapted to the crate's API.
//! However, there are some behaviors different from other platforms:
//! - The `psn` poller distingushes "disabled" state and "removed" state. When the registration
//!   disabled, the notifications won't be queued to the poller.
//! - The edge trigger only triggers condition changes after it is enabled. You cannot expect
//!   an event coming if you change the condition before registering the notification.
//! - A socket can be registered to only one IOCP at a time.
//!
//! `NtAssociateWaitCompletionPacket` is an undocumented API and it's the back of thread pool
//! APIs like `RegisterWaitForSingleObject`. We use it to avoid starting thread pools. It only
//! supports `Oneshot` mode.

mod wait;

use std::collections::HashMap;
use std::io;
use std::mem::MaybeUninit;
use std::os::windows::io::{
    AsHandle, AsRawHandle, AsRawSocket, BorrowedHandle, BorrowedSocket, FromRawHandle, OwnedHandle,
    RawHandle, RawSocket,
};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use wait::WaitCompletionPacket;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::Networking::WinSock::{
    ProcessSocketNotifications, SOCK_NOTIFY_EVENT_ERR, SOCK_NOTIFY_EVENT_HANGUP,
    SOCK_NOTIFY_EVENT_IN, SOCK_NOTIFY_EVENT_OUT, SOCK_NOTIFY_EVENT_REMOVE, SOCK_NOTIFY_OP_DISABLE,
    SOCK_NOTIFY_OP_ENABLE, SOCK_NOTIFY_OP_REMOVE, SOCK_NOTIFY_REGISTER_EVENT_HANGUP,
    SOCK_NOTIFY_REGISTER_EVENT_IN, SOCK_NOTIFY_REGISTER_EVENT_NONE, SOCK_NOTIFY_REGISTER_EVENT_OUT,
    SOCK_NOTIFY_REGISTRATION, SOCK_NOTIFY_TRIGGER_EDGE, SOCK_NOTIFY_TRIGGER_LEVEL,
    SOCK_NOTIFY_TRIGGER_ONESHOT, SOCK_NOTIFY_TRIGGER_PERSISTENT,
};
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, PostQueuedCompletionStatus, OVERLAPPED, OVERLAPPED_ENTRY,
};

use super::dur2timeout;
use crate::{Event, PollMode, NOTIFY_KEY};

/// Macro to lock and ignore lock poisoning.
macro_rules! lock {
    ($lock_result:expr) => {{
        $lock_result.unwrap_or_else(|e| e.into_inner())
    }};
}

/// Interface to kqueue.
#[derive(Debug)]
pub struct Poller {
    /// The I/O completion port.
    port: Arc<OwnedHandle>,

    /// The state of the sources registered with this poller.
    ///
    /// Each source is keyed by its raw socket ID.
    sources: RwLock<HashMap<RawSocket, usize>>,

    /// The state of the waitable handles registered with this poller.
    waitables: Mutex<HashMap<RawHandle, WaitableAttr>>,
}

/// A waitable object with key and [`WaitCompletionPacket`].
///
/// [`WaitCompletionPacket`]: wait::WaitCompletionPacket
#[derive(Debug)]
struct WaitableAttr {
    key: usize,
    packet: wait::WaitCompletionPacket,
}

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Self> {
        let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0) };
        if handle == 0 {
            return Err(io::Error::last_os_error());
        }

        tracing::trace!(port = ?handle, "new");
        let port = Arc::new(unsafe { OwnedHandle::from_raw_handle(handle as _) });
        Ok(Poller {
            port,
            sources: RwLock::default(),
            waitables: Mutex::default(),
        })
    }

    /// Whether this poller supports level-triggered events.
    pub fn supports_level(&self) -> bool {
        true
    }

    /// Whether this poller supports edge-triggered events.
    pub fn supports_edge(&self) -> bool {
        true
    }

    /// Adds a new socket.
    ///
    /// # Safety
    ///
    /// The socket must be valid and it must last until it is deleted.
    pub unsafe fn add(&self, socket: RawSocket, interest: Event, mode: PollMode) -> io::Result<()> {
        let span = tracing::trace_span!(
            "add",
            handle = ?self.port,
            sock = ?socket,
            ev = ?interest,
        );
        let _enter = span.enter();

        let mut sources = lock!(self.sources.write());
        if sources.contains_key(&socket) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }
        sources.insert(socket, interest.key);

        let info = create_registration(socket, interest, mode, true);
        self.update_source(info)
    }

    /// Modifies an existing socket.
    pub fn modify(
        &self,
        socket: BorrowedSocket<'_>,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        let span = tracing::trace_span!(
            "modify",
            handle = ?self.port,
            sock = ?socket,
            ev = ?interest,
        );
        let _enter = span.enter();

        let socket = socket.as_raw_socket();

        let sources = lock!(self.sources.read());
        let oldkey = sources
            .get(&socket)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

        if oldkey != &interest.key {
            // To change the key, remove the old registration and wait for REMOVE event.
            let info = create_registration(socket, Event::none(*oldkey), PollMode::Oneshot, false);
            self.update_and_wait_for_remove(info, *oldkey)?;
        }
        let info = create_registration(socket, interest, mode, true);
        self.update_source(info)
    }

    /// Deletes a socket.
    pub fn delete(&self, socket: BorrowedSocket<'_>) -> io::Result<()> {
        let span = tracing::trace_span!(
            "delete",
            handle = ?self.port,
            sock = ?socket
        );
        let _enter = span.enter();

        let socket = socket.as_raw_socket();

        let key = lock!(self.sources.write())
            .remove(&socket)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let info = create_registration(socket, Event::none(key), PollMode::Oneshot, false);
        self.update_and_wait_for_remove(info, key)
    }

    /// Add a new waitable to the poller.
    pub(crate) fn add_waitable(
        &self,
        handle: RawHandle,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        tracing::trace!(
            "add_waitable: handle={:?}, waitable={:p}, ev={:?}",
            self.port,
            handle,
            interest
        );

        if !matches!(mode, PollMode::Oneshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only support oneshot events",
            ));
        }

        let key = interest.key;

        let mut waitables = lock!(self.waitables.lock());
        if waitables.contains_key(&handle) {
            return Err(io::Error::from(io::ErrorKind::AlreadyExists));
        }

        let mut packet = wait::WaitCompletionPacket::new()?;
        packet.associate(
            self.port.as_raw_handle(),
            handle,
            key,
            interest_to_events(&interest) as _,
        )?;
        waitables.insert(handle, WaitableAttr { key, packet });
        Ok(())
    }

    /// Update a waitable in the poller.
    pub(crate) fn modify_waitable(
        &self,
        waitable: RawHandle,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        tracing::trace!(
            "modify_waitable: handle={:?}, waitable={:p}, ev={:?}",
            self.port,
            waitable,
            interest
        );

        if !matches!(mode, PollMode::Oneshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only support oneshot events",
            ));
        }

        let mut waitables = lock!(self.waitables.lock());
        let WaitableAttr { key, packet } = waitables
            .get_mut(&waitable)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

        let cancelled = packet.cancel()?;
        if !cancelled {
            // The packet could not be reused, create a new one.
            *packet = WaitCompletionPacket::new()?;
        }
        packet.associate(
            self.port.as_raw_handle(),
            waitable,
            *key,
            interest_to_events(&interest) as _,
        )
    }

    /// Delete a waitable from the poller.
    pub(crate) fn remove_waitable(&self, waitable: RawHandle) -> io::Result<()> {
        tracing::trace!("remove: handle={:?}, waitable={:p}", self.port, waitable);

        let WaitableAttr { mut packet, .. } = lock!(self.waitables.lock())
            .remove(&waitable)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;

        packet.cancel()?;
        Ok(())
    }

    /// Add or modify the registration.
    fn update_source(&self, mut reg: SOCK_NOTIFY_REGISTRATION) -> io::Result<()> {
        let res = unsafe {
            ProcessSocketNotifications(
                self.port.as_raw_handle() as _,
                1,
                &mut reg,
                0,
                0,
                null_mut(),
                null_mut(),
            )
        };
        if res == ERROR_SUCCESS {
            if reg.registrationResult == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(reg.registrationResult as _))
            }
        } else {
            Err(io::Error::from_raw_os_error(res as _))
        }
    }

    /// Attempt to remove a registration, and wait for the `SOCK_NOTIFY_EVENT_REMOVE` event.
    fn update_and_wait_for_remove(
        &self,
        mut reg: SOCK_NOTIFY_REGISTRATION,
        key: usize,
    ) -> io::Result<()> {
        debug_assert_eq!(reg.operation, SOCK_NOTIFY_OP_REMOVE as _);
        let mut received = 0;
        let mut entry: MaybeUninit<OVERLAPPED_ENTRY> = MaybeUninit::uninit();

        let repost = |entry: OVERLAPPED_ENTRY| {
            self.post_raw(
                entry.dwNumberOfBytesTransferred,
                entry.lpCompletionKey,
                entry.lpOverlapped,
            )
        };

        // Update the registration and wait for the event in the same time.
        // However, the returned completion entry may not be the wanted REMOVE event.
        let res = unsafe {
            ProcessSocketNotifications(
                self.port.as_raw_handle() as _,
                1,
                &mut reg,
                0,
                1,
                entry.as_mut_ptr().cast(),
                &mut received,
            )
        };
        match res {
            ERROR_SUCCESS | WAIT_TIMEOUT => {
                if reg.registrationResult != ERROR_SUCCESS {
                    // If the registration is not successful, the received entry should be reposted.
                    if received == 1 {
                        repost(unsafe { entry.assume_init() })?;
                    }
                    return Err(io::Error::from_raw_os_error(reg.registrationResult as _));
                }
            }
            _ => return Err(io::Error::from_raw_os_error(res as _)),
        }
        if received == 1 {
            // The registration is successful, and check the received entry.
            let entry = unsafe { entry.assume_init() };
            if entry.lpCompletionKey == key {
                // If the entry is current key but not the remove event, just ignore it.
                if (entry.dwNumberOfBytesTransferred & SOCK_NOTIFY_EVENT_REMOVE) != 0 {
                    return Ok(());
                }
            } else {
                repost(entry)?;
            }
        }

        // No wanted event, start a loop to wait for it.
        // TODO: any better solutions?
        loop {
            let res = unsafe {
                ProcessSocketNotifications(
                    self.port.as_raw_handle() as _,
                    0,
                    null_mut(),
                    0,
                    1,
                    entry.as_mut_ptr().cast(),
                    &mut received,
                )
            };
            match res {
                ERROR_SUCCESS => {
                    debug_assert_eq!(received, 1);
                    let entry = unsafe { entry.assume_init() };
                    if entry.lpCompletionKey == key {
                        if (entry.dwNumberOfBytesTransferred & SOCK_NOTIFY_EVENT_REMOVE) != 0 {
                            return Ok(());
                        }
                    } else {
                        repost(entry)?;
                    }
                }
                WAIT_TIMEOUT => {}
                _ => return Err(io::Error::from_raw_os_error(res as _)),
            }
        }
    }

    /// Waits for I/O events with an optional timeout.
    pub fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<()> {
        let span = tracing::trace_span!(
            "wait",
            handle = ?self.port,
            ?timeout,
        );
        let _enter = span.enter();

        let timeout = timeout.map_or(INFINITE, dur2timeout);
        let spare_entries = events.list.spare_capacity_mut();
        let mut received = 0;
        let res = unsafe {
            ProcessSocketNotifications(
                self.port.as_raw_handle() as _,
                0,
                null_mut(),
                timeout,
                spare_entries.len() as _,
                spare_entries.as_mut_ptr().cast(),
                &mut received,
            )
        };

        if res == ERROR_SUCCESS {
            tracing::trace!(
                handle = ?self.port,
                received,
                "new events",
            );
            unsafe { events.list.set_len(events.list.len() + received as usize) };
            Ok(())
        } else if res == WAIT_TIMEOUT {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(res as _))
        }
    }

    /// Sends a notification to wake up the current or next `wait()` call.
    pub fn notify(&self) -> io::Result<()> {
        self.post(CompletionPacket::new(Event::none(NOTIFY_KEY)))
    }

    /// Push an IOCP packet into the queue.
    pub fn post(&self, packet: CompletionPacket) -> io::Result<()> {
        let span = tracing::trace_span!(
            "post",
            handle = ?self.port,
            key = ?packet.0.key,
        );
        let _enter = span.enter();

        let event = packet.event();
        self.post_raw(interest_to_events(event), event.key, null_mut())
    }

    fn post_raw(
        &self,
        transferred: u32,
        key: usize,
        overlapped: *mut OVERLAPPED,
    ) -> io::Result<()> {
        let res = unsafe {
            PostQueuedCompletionStatus(self.port.as_raw_handle() as _, transferred, key, overlapped)
        };
        if res == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl AsRawHandle for Poller {
    fn as_raw_handle(&self) -> RawHandle {
        self.port.as_raw_handle()
    }
}

impl AsHandle for Poller {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        self.port.as_handle()
    }
}

unsafe impl Send for Poller {}
unsafe impl Sync for Poller {}

/// A list of reported I/O events.
pub struct Events {
    list: Vec<OVERLAPPED_ENTRY>,
}

unsafe impl Send for Events {}

impl Events {
    /// Creates an empty list.
    pub fn with_capacity(cap: usize) -> Events {
        Events {
            list: Vec::with_capacity(cap),
        }
    }

    /// Iterates over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.list.iter().map(|ev| {
            let events = ev.dwNumberOfBytesTransferred;
            Event {
                key: ev.lpCompletionKey,
                readable: (events & SOCK_NOTIFY_EVENT_IN) != 0,
                writable: (events & SOCK_NOTIFY_EVENT_OUT) != 0,
                extra: EventExtra {
                    hup: (events & SOCK_NOTIFY_EVENT_HANGUP) != 0,
                    err: (events & SOCK_NOTIFY_EVENT_ERR) != 0,
                },
            }
        })
    }

    /// Clears the list.
    pub fn clear(&mut self) {
        self.list.clear();
    }

    /// Get the capacity of the list.
    pub fn capacity(&self) -> usize {
        self.list.capacity()
    }
}

/// Extra information associated with an event.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EventExtra {
    hup: bool,
    err: bool,
}

impl EventExtra {
    /// Create a new, empty version of this struct.
    #[inline]
    pub const fn empty() -> EventExtra {
        EventExtra {
            hup: false,
            err: false,
        }
    }

    /// Set the interrupt flag.
    #[inline]
    pub fn set_hup(&mut self, value: bool) {
        self.hup = value;
    }

    /// Set the priority flag.
    #[inline]
    pub fn set_pri(&mut self, _value: bool) {
        // No-op.
    }

    /// Is the interrupt flag set?
    #[inline]
    pub fn is_hup(&self) -> bool {
        self.hup
    }

    /// Is the priority flag set?
    #[inline]
    pub fn is_pri(&self) -> bool {
        false
    }

    #[inline]
    pub fn is_connect_failed(&self) -> Option<bool> {
        None
    }

    #[inline]
    pub fn is_err(&self) -> Option<bool> {
        Some(self.err)
    }
}

/// A packet used to wake up the poller with an event.
#[derive(Debug, Clone)]
pub struct CompletionPacket(Event);

impl CompletionPacket {
    /// Create a new completion packet with a custom event.
    pub fn new(event: Event) -> Self {
        Self(event)
    }

    /// Get the event associated with this packet.
    pub fn event(&self) -> &Event {
        &self.0
    }
}

pub(crate) fn interest_to_filter(interest: &Event) -> u16 {
    let mut filter = SOCK_NOTIFY_REGISTER_EVENT_NONE;
    if interest.readable {
        filter |= SOCK_NOTIFY_REGISTER_EVENT_IN;
    }
    if interest.writable {
        filter |= SOCK_NOTIFY_REGISTER_EVENT_OUT;
    }
    if interest.extra.hup {
        filter |= SOCK_NOTIFY_REGISTER_EVENT_HANGUP;
    }
    filter as _
}

pub(crate) fn interest_to_events(interest: &Event) -> u32 {
    let mut events = 0;
    if interest.readable {
        events |= SOCK_NOTIFY_EVENT_IN;
    }
    if interest.writable {
        events |= SOCK_NOTIFY_EVENT_OUT;
    }
    if interest.extra.hup {
        events |= SOCK_NOTIFY_EVENT_HANGUP;
    }
    if interest.extra.err {
        events |= SOCK_NOTIFY_EVENT_ERR;
    }
    events
}

pub(crate) fn mode_to_flags(mode: PollMode) -> u8 {
    let flags = match mode {
        PollMode::Oneshot => SOCK_NOTIFY_TRIGGER_ONESHOT | SOCK_NOTIFY_TRIGGER_LEVEL,
        PollMode::Level => SOCK_NOTIFY_TRIGGER_PERSISTENT | SOCK_NOTIFY_TRIGGER_LEVEL,
        PollMode::Edge => SOCK_NOTIFY_TRIGGER_PERSISTENT | SOCK_NOTIFY_TRIGGER_EDGE,
        PollMode::EdgeOneshot => SOCK_NOTIFY_TRIGGER_ONESHOT | SOCK_NOTIFY_TRIGGER_EDGE,
    };
    flags as u8
}

pub(crate) fn create_registration(
    socket: RawSocket,
    interest: Event,
    mode: PollMode,
    enable: bool,
) -> SOCK_NOTIFY_REGISTRATION {
    let filter = interest_to_filter(&interest);
    SOCK_NOTIFY_REGISTRATION {
        socket: socket as _,
        completionKey: interest.key as _,
        eventFilter: filter,
        operation: if enable {
            if filter == SOCK_NOTIFY_REGISTER_EVENT_NONE as _ {
                SOCK_NOTIFY_OP_DISABLE as _
            } else {
                SOCK_NOTIFY_OP_ENABLE as _
            }
        } else {
            SOCK_NOTIFY_OP_REMOVE as _
        },
        triggerFlags: mode_to_flags(mode),
        registrationResult: 0,
    }
}
