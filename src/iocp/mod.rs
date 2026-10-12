//! Bindings to Windows I/O Completion Ports.
//!
//! I/O Completion Ports is a completion-based API rather than a polling-based API, like
//! epoll or kqueue. Therefore, we have to adapt the IOCP API to the crate's API.
//!
//! WinSock is powered by the Auxiliary Function Driver (AFD) subsystem, which can be
//! accessed directly by using unstable `ntdll` functions. AFD exposes features that are not
//! available through the normal WinSock interface, such as IOCTL_AFD_POLL. This function is
//! similar to the exposed `WSAPoll` method. However, once the targeted socket is "ready",
//! a completion packet is queued to an I/O completion port.
//!
//! We take advantage of IOCTL_AFD_POLL to "translate" this crate's polling-based API
//! to the one Windows expects. When a device is added to the `Poller`, an IOCTL_AFD_POLL
//! operation is started and queued to the IOCP. To modify a currently registered device
//! (e.g. with `modify()` or `delete()`), the ongoing POLL is cancelled and then restarted
//! with new parameters. When the POLL eventually completes, the packet is posted to the IOCP.
//! From here it's a simple matter of using `GetQueuedCompletionStatusEx` to read the packets
//! from the IOCP and react accordingly. Notifying the poller is trivial, because we can
//! simply post a packet to the IOCP to wake it up.
//!
//! The main disadvantage of this strategy is that it relies on unstable Windows APIs.
//! However, as `libuv` (the backing I/O library for Node.JS) relies on the same unstable
//! AFD strategy, it is unlikely to be broken without plenty of advanced warning.
//!
//! Previously, this crate used the `wepoll` library for polling. `wepoll` uses a similar
//! AFD-based strategy for polling.

mod afd;
pub(crate) mod buf;
pub(crate) mod ntdll;
mod port;

use afd::{base_socket, Afd, AfdPollInfo, AfdPollMask, HasAfdInfo, IoStatusBlock};
use port::{IoCompletionPort, OverlappedEntry};

use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, ERROR_IO_PENDING, STATUS_CANCELLED};
use windows_sys::Win32::System::Threading::{
    RegisterWaitForSingleObject, UnregisterWait, INFINITE, WT_EXECUTELONGFUNCTION,
    WT_EXECUTEONLYONCE,
};
use windows_sys::Win32::System::WindowsProgramming::{
    FILE_SKIP_COMPLETION_PORT_ON_SUCCESS, FILE_SKIP_SET_EVENT_ON_HANDLE,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::iocp::port::FileOverlapped;
use crate::{Event, PollMode};

use concurrent_queue::ConcurrentQueue;
use pin_project_lite::pin_project;

use std::cell::UnsafeCell;
use std::collections::hash_map::{Entry, HashMap};
use std::ffi::c_void;
use std::marker::PhantomPinned;
use std::mem::{forget, MaybeUninit};
use std::os::windows::io::{
    AsHandle, AsRawHandle, AsRawSocket, BorrowedHandle, BorrowedSocket, RawHandle, RawSocket,
};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};
use std::{fmt, io};

/// Macro to lock and ignore lock poisoning.
macro_rules! lock {
    ($lock_result:expr) => {{
        $lock_result.unwrap_or_else(|e| e.into_inner())
    }};
}

/// Interface to I/O completion ports.
#[derive(Debug)]
pub(super) struct Poller {
    /// The I/O completion port.
    port: Arc<IoCompletionPort<Packet>>,

    /// List of currently active AFD instances.
    ///
    /// AFD acts as the actual source of the socket events. It's essentially running `WSAPoll` on
    /// the sockets and then posting the events to the IOCP.
    ///
    /// AFD instances can be keyed to an unlimited number of sockets. However, each AFD instance
    /// polls their sockets linearly. Therefore, it is best to limit the number of sockets each AFD
    /// instance is responsible for. The limit of 32 is chosen because that's what `wepoll` uses.
    ///
    /// Weak references are kept here so that the AFD handle is automatically dropped when the last
    /// associated socket is dropped.
    afd: Mutex<Vec<Weak<Afd<Packet>>>>,

    /// The state of the sources registered with this poller.
    ///
    /// Each source is keyed by its raw socket ID.
    sources: RwLock<HashMap<RawSocket, Packet>>,

    /// The state of the waitable handles registered with this poller.
    waitables: RwLock<HashMap<RawHandle, Packet>>,

    /// Sockets with pending updates.
    ///
    /// This list contains packets with sockets that need to have their AFD state adjusted by
    /// calling the `update()` function on them. It's best to queue up packets as they need to
    /// be updated and then run all of the updates before we start waiting on the IOCP, rather than
    /// updating them as we come. If we're waiting on the IOCP updates should be run immediately.
    pending_updates: ConcurrentQueue<Packet>,

    /// Are we currently polling?
    ///
    /// This indicates whether or not we are blocking on the IOCP, and is used to determine
    /// whether pending updates should be run immediately or queued.
    polling: AtomicBool,

    /// The packet used to notify the poller.
    ///
    /// This is a special-case packet that is used to wake up the poller when it is waiting.
    notifier: Packet,
}

unsafe impl Send for Poller {}
unsafe impl Sync for Poller {}

impl Poller {
    /// Creates a new poller.
    pub(super) fn new() -> io::Result<Self> {
        // Make sure AFD is able to be used.
        if let Err(e) = ntdll::NtdllImports::force_load() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                AfdError::new("failed to initialize unstable Windows functions", e),
            ));
        }

        // Create and destroy a single AFD to test if we support it.
        Afd::<Packet>::new().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                AfdError::new("failed to initialize \\Device\\Afd", e),
            )
        })?;

        let port = IoCompletionPort::new(0)?;
        #[cfg(feature = "tracing")]
        tracing::trace!(handle = ?port, "new");

        Ok(Poller {
            #[allow(clippy::arc_with_non_send_sync)]
            port: Arc::new(port),
            afd: Mutex::new(vec![]),
            sources: RwLock::new(HashMap::new()),
            waitables: RwLock::new(HashMap::new()),
            pending_updates: ConcurrentQueue::bounded(1024),
            polling: AtomicBool::new(false),
            notifier: Arc::pin(
                PacketInner::Wakeup {
                    _pinned: PhantomPinned,
                }
                .into(),
            ),
        })
    }

    /// Whether this poller supports level-triggered events.
    pub(super) fn supports_level(&self) -> bool {
        true
    }

    /// Whether this poller supports edge-triggered events.
    pub(super) fn supports_edge(&self) -> bool {
        false
    }

    /// Add a new source to the poller.
    ///
    /// # Safety
    ///
    /// The socket must be a valid socket and must last until it is deleted.
    pub(super) unsafe fn add(
        &self,
        socket: RawSocket,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        let span = tracing::trace_span!(
            "add",
            handle = ?self.port,
            sock = ?socket,
            ev = ?interest,
        );
        #[cfg(feature = "tracing")]
        let _enter = span.enter();

        // We don't support edge-triggered events.
        if matches!(mode, PollMode::Edge | PollMode::EdgeOneshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "edge-triggered events are not supported",
            ));
        }

        // Create a new packet.
        let socket_state = {
            // Create a new socket state and assign an AFD handle to it.
            let state = SocketState {
                socket,
                base_socket: base_socket(socket)?,
                interest,
                interest_error: true,
                afd: self.afd_handle()?,
                mode,
                waiting_on_delete: false,
                status: SocketStatus::Idle,
            };

            // We wrap this socket state in a Packet so the IOCP can use it.
            Arc::pin(IoStatusBlock::from(PacketInner::Socket {
                packet: UnsafeCell::new(AfdPollInfo::default()),
                socket: Mutex::new(state),
            }))
        };

        // Keep track of the source in the poller.
        {
            let mut sources = lock!(self.sources.write());

            match sources.entry(socket) {
                Entry::Vacant(v) => {
                    v.insert(Pin::<Arc<_>>::clone(&socket_state));
                }

                Entry::Occupied(_) => {
                    return Err(io::Error::from(io::ErrorKind::AlreadyExists));
                }
            }
        }

        // Update the packet.
        self.update_packet(socket_state)
    }

    /// Update a source in the poller.
    pub(super) fn modify(
        &self,
        socket: BorrowedSocket<'_>,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        let span = tracing::trace_span!(
            "modify",
            handle = ?self.port,
            sock = ?socket,
            ev = ?interest,
        );
        #[cfg(feature = "tracing")]
        let _enter = span.enter();

        // We don't support edge-triggered events.
        if matches!(mode, PollMode::Edge | PollMode::EdgeOneshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "edge-triggered events are not supported",
            ));
        }

        // Get a reference to the source.
        let source = {
            let sources = lock!(self.sources.read());

            sources
                .get(&socket.as_raw_socket())
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        };

        // Set the new event.
        if source.as_ref().set_events(interest, mode) {
            // The packet needs to be updated.
            self.update_packet(source)?;
        }

        Ok(())
    }

    /// Delete a source from the poller.
    pub(super) fn delete(&self, socket: BorrowedSocket<'_>) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        let span = tracing::trace_span!(
            "remove",
            handle = ?self.port,
            sock = ?socket,
        );
        #[cfg(feature = "tracing")]
        let _enter = span.enter();

        // Remove the source from our associative map.
        let source = {
            let mut sources = lock!(self.sources.write());

            match sources.remove(&socket.as_raw_socket()) {
                Some(s) => s,
                None => {
                    // If the source wasn't recognized then we must return a NotFound error.
                    return Err(io::ErrorKind::NotFound.into());
                }
            }
        };

        // Indicate to the source that it is being deleted.
        // This cancels any ongoing AFD_IOCTL_POLL operations.
        source.begin_delete()
    }

    /// Add a new waitable to the poller.
    pub(super) fn add_waitable(
        &self,
        handle: RawHandle,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            "add_waitable: handle={:?}, waitable={:p}, ev={:?}",
            self.port,
            handle,
            interest
        );

        // We don't support edge-triggered events.
        if matches!(mode, PollMode::Edge | PollMode::EdgeOneshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "edge-triggered events are not supported",
            ));
        }

        // Create a new packet.
        let handle_state = {
            let state = WaitableState {
                handle,
                port: Arc::downgrade(&self.port),
                interest,
                mode,
                status: WaitableStatus::Idle,
            };

            Arc::pin(IoStatusBlock::from(PacketInner::Waitable {
                handle: Mutex::new(state),
            }))
        };

        // Keep track of the source in the poller.
        {
            let mut sources = lock!(self.waitables.write());

            match sources.entry(handle) {
                Entry::Vacant(v) => {
                    v.insert(Pin::<Arc<_>>::clone(&handle_state));
                }

                Entry::Occupied(_) => {
                    return Err(io::Error::from(io::ErrorKind::AlreadyExists));
                }
            }
        }

        // Update the packet.
        self.update_packet(handle_state)
    }

    /// Update a waitable in the poller.
    pub(crate) fn modify_waitable(
        &self,
        waitable: RawHandle,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        tracing::trace!(
            "modify_waitable: handle={:?}, waitable={:p}, ev={:?}",
            self.port,
            waitable,
            interest
        );

        // We don't support edge-triggered events.
        if matches!(mode, PollMode::Edge | PollMode::EdgeOneshot) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "edge-triggered events are not supported",
            ));
        }

        // Get a reference to the source.
        let source = {
            let sources = lock!(self.waitables.read());

            sources
                .get(&waitable)
                .cloned()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
        };

        // Set the new event.
        if source.as_ref().set_events(interest, mode) {
            self.update_packet(source)?;
        }

        Ok(())
    }

    /// Delete a waitable from the poller.
    pub(super) fn remove_waitable(&self, waitable: RawHandle) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        tracing::trace!("remove: handle={:?}, waitable={:p}", self.port, waitable);

        // Get a reference to the source.
        let source = {
            let mut sources = lock!(self.waitables.write());

            match sources.remove(&waitable) {
                Some(s) => s,
                None => {
                    // If the source has already been removed, then we can just return.
                    return Ok(());
                }
            }
        };

        // Indicate to the source that it is being deleted.
        // This cancels any ongoing AFD_IOCTL_POLL operations.
        source.begin_delete()
    }

    /// Register a file handle for the `submit_*` API.
    ///
    /// `key` is the same kind of value passed to
    /// [`Poller::add`](crate::Poller::add): it is mirrored into
    /// [`Event::key`] of every completion this file emits, so a
    /// reactor (e.g. `async-io`) can route the completion to the
    /// correct source via its key-indexed waker registry.
    ///
    /// Each [`RegisteredFile`] is its own self-managed registration;
    /// per-op packets carry their own Arc lifetimes.
    pub(super) fn register_file(
        &self,
        handle: RawHandle,
        key: usize,
    ) -> io::Result<RegisteredFile> {
        struct H(RawHandle);
        impl AsRawHandle for H {
            fn as_raw_handle(&self) -> RawHandle {
                self.0
            }
        }

        // Attach the handle to this IOCP and request the sync-success
        // fast-path flags; ERROR_INVALID_FUNCTION is treated as a
        // non-fatal no-op inside `register`.
        self.port.register(
            &H(handle),
            (FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS) as u8,
            port::CompletionKeyType::FileOp,
        )?;

        Ok(RegisteredFile {
            inner: Arc::new(RegisteredFileInner {
                handle,
                port: Arc::clone(&self.port),
                active: AtomicBool::new(true),
                user_key: AtomicUsize::new(key),
            }),
        })
    }

    /// Wait for events.
    pub(super) fn wait_deadline(
        &self,
        events: &mut Events,
        deadline: Option<Instant>,
    ) -> io::Result<()> {
        #[cfg(feature = "tracing")]
        let span = tracing::trace_span!(
            "wait",
            handle = ?self.port,
            ?deadline,
        );
        #[cfg(feature = "tracing")]
        let _enter = span.enter();

        let mut notified = false;

        loop {
            let mut new_events = 0;

            // Indicate that we are now polling.
            let was_polling = self.polling.swap(true, Ordering::SeqCst);
            debug_assert!(!was_polling);

            // Even if we panic, we want to make sure we indicate that polling has stopped.
            let guard = CallOnDrop(|| {
                let was_polling = self.polling.swap(false, Ordering::SeqCst);
                debug_assert!(was_polling);
            });

            // Process every entry in the queue before we start polling.
            self.drain_update_queue(false)?;

            // Get the time to wait for.
            let timeout = deadline.map(|t| t.saturating_duration_since(Instant::now()));

            // Wait for I/O events.
            let _len = self.port.wait(&mut events.completions, timeout)?;
            #[cfg(feature = "tracing")]
            tracing::trace!(
                handle = ?self.port,
                res = ?_len,
                "new events");

            // We are no longer polling.
            drop(guard);

            // Process all of the events.
            for entry in events.completions.drain(..) {
                let result = if entry.is_file_completion() {
                    let bytes = entry.bytes_transferred();
                    // SAFETY: the entry is fresh from
                    // `GetQueuedCompletionStatusEx`, so its
                    // `lpOverlapped` points to a live `OVERLAPPED`.
                    let nt_status = unsafe { entry.nt_status_raw() };
                    // Reclaim the kernel's `Arc` strong reference (bumped
                    // at submit time in `classify_submission`) and
                    // publish the completion fields. The packet is
                    // dropped at the end of this scope, releasing that
                    // strong ref. If the user already dropped their
                    // `OpHandle`, the allocation is freed here and
                    // `OpInner::Drop` reclaims the buffer.
                    let packet = entry.into_file_op_packet();
                    if let PacketInnerProj::FileOp { op } = packet.as_ref().data().project_ref() {
                        let op = op.get_ref();
                        // Order matters: the user-visible state must
                        // be Released BEFORE we push the Event, so
                        // that a task woken by its reactor sees
                        // `Completed` on its Acquire-load of `state`.
                        op.bytes_transferred.store(bytes, Ordering::Release);
                        // Translate the NTSTATUS to a Win32 error
                        // here so consumers (`OpHandle::take`) can
                        // hand the value straight to
                        // `io::Error::from_raw_os_error`.
                        // `STATUS_BUFFER_OVERFLOW` translates to
                        // `ERROR_MORE_DATA`, which `take_inner`
                        // treats as success-with-remaining-data so
                        // the partial buffer is not lost.
                        let dos = match ntdll::NtdllImports::get() {
                            // SAFETY: pure translation, no
                            // preconditions on `Status`.
                            Ok(ntdll) => unsafe { ntdll.RtlNtStatusToDosError(nt_status) },
                            // ntdll failed to load — extremely
                            // unlikely (the rest of this module
                            // already requires it). Fall back to a
                            // generic Win32 error so the user still
                            // sees a non-zero failure.
                            Err(_) => ERROR_INVALID_HANDLE,
                        };
                        op.dos_error.store(dos, Ordering::Release);
                        // Unconditionally publish Completed. If the user
                        // pre-cancelled (state = Cancelled), the kernel
                        // still posted a completion entry (typically
                        // with STATUS_CANCELLED in `nt_status`), and the
                        // outcome is encoded in `nt_status` rather than
                        // the lifecycle state.
                        op.state.store(OpState::Completed as u8, Ordering::Release);
                        // Emit a normal Event so the reactor (e.g.
                        // `async-io`) can wake the task that owns the
                        // matching source via its key-indexed waker
                        // registry. The op carries its own
                        // direction-of-interest, mirrored here.
                        let interest = op.interest;
                        // Acquire pairs with the `Release` store in
                        // `RegisteredFile::set_user_key`. Reading
                        // `user_key` *after* the `state` Release store
                        // above is intentional: a concurrent
                        // `set_user_key` either lands before this load
                        // (event carries the new key) or after it
                        // (event carries the old key). Both outcomes
                        // are documented as acceptable — `set_user_key`
                        // is best-effort for in-flight ops.
                        let key = op
                            .file
                            .as_ref()
                            .expect("submitted op has back-ref to its RegisteredFile")
                            .user_key
                            .load(Ordering::Acquire);
                        let event = Event {
                            key,
                            readable: interest.readable,
                            writable: interest.writable,
                            extra: crate::sys::EventExtra::empty(),
                        };
                        events.packets.push(event);
                        new_events += 1;
                    }
                    Ok::<_, io::Error>(FeedEventResult::NoEvent)
                } else {
                    let packet = entry.into_packet();
                    packet.feed_event(self)
                };

                // Feed the event into the packet.
                match result? {
                    FeedEventResult::NoEvent => {}
                    FeedEventResult::Event(event) => {
                        events.packets.push(event);
                        new_events += 1;
                    }
                    FeedEventResult::Notified => {
                        notified = true;
                    }
                }
            }

            // Break if there was a notification or at least one event, or if deadline is reached.
            let timeout_is_empty = timeout.is_some_and(|t| t.is_zero());
            if notified || new_events > 0 || timeout_is_empty {
                break;
            }

            #[cfg(feature = "tracing")]
            tracing::trace!("wait: no events found, re-entering polling loop");
        }

        Ok(())
    }

    /// Notify this poller.
    pub(super) fn notify(&self) -> io::Result<()> {
        // Push the notify packet into the IOCP.
        self.port.post(0, 0, self.notifier.clone())
    }

    /// Push an IOCP packet into the queue.
    pub(super) fn post(&self, packet: CompletionPacket) -> io::Result<()> {
        self.port.post(0, 0, packet.0)
    }

    /// Run an update on a packet.
    fn update_packet(&self, mut packet: Packet) -> io::Result<()> {
        loop {
            // If we are currently polling, we need to update the packet immediately.
            if self.polling.load(Ordering::Acquire) {
                packet.update()?;
                return Ok(());
            }

            // Try to queue the update.
            match self.pending_updates.push(packet) {
                Ok(()) => return Ok(()),
                Err(p) => packet = p.into_inner(),
            }

            // If we failed to queue the update, we need to drain the queue first.
            self.drain_update_queue(true)?;

            // Loop back and try again.
        }
    }

    /// Drain the update queue.
    fn drain_update_queue(&self, limit: bool) -> io::Result<()> {
        // Determine how many packets to process.
        let max = if limit {
            // Only drain the queue's capacity, since this could in theory run forever.
            self.pending_updates.capacity().unwrap()
        } else {
            // Less of a concern if we're draining the queue prior to a poll operation.
            usize::MAX
        };

        self.pending_updates
            .try_iter()
            .take(max)
            .try_for_each(|packet| packet.update())
    }

    /// Get a handle to the AFD reference.
    ///
    /// This finds an AFD handle with less than 32 associated sockets, or creates a new one if
    /// one does not exist.
    fn afd_handle(&self) -> io::Result<Arc<Afd<Packet>>> {
        const AFD_MAX_SIZE: usize = 32;

        // Crawl the list and see if there are any existing AFD instances that we can use.
        // While we're here, remove any unused AFD pointers.
        let mut afd_handles = lock!(self.afd.lock());
        let mut i = 0;
        while i < afd_handles.len() {
            // Get the reference count of the AFD instance.
            let refcount = Weak::strong_count(&afd_handles[i]);

            match refcount {
                0 => {
                    // Prune the AFD pointer if it has no references.
                    afd_handles.swap_remove(i);
                }

                refcount if refcount >= AFD_MAX_SIZE => {
                    // Skip this one, since it is already at the maximum size.
                    i += 1;
                }

                _ => {
                    // We can use this AFD instance.
                    match afd_handles[i].upgrade() {
                        Some(afd) => return Ok(afd),
                        None => {
                            // The last socket dropped the AFD before we could acquire it.
                            // Prune the AFD pointer and continue.
                            afd_handles.swap_remove(i);
                        }
                    }
                }
            }
        }

        // No available handles, create a new AFD instance.
        #[allow(clippy::arc_with_non_send_sync)]
        let afd = Arc::new(Afd::new()?);

        // Register the AFD instance with the I/O completion port.
        self.port.register(
            &*afd,
            FILE_SKIP_SET_EVENT_ON_HANDLE as u8,
            port::CompletionKeyType::Socket,
        )?;

        // Insert a weak pointer to the AFD instance into the list for other sockets.
        afd_handles.push(Arc::downgrade(&afd));

        Ok(afd)
    }
}

impl AsRawHandle for Poller {
    fn as_raw_handle(&self) -> RawHandle {
        self.port.as_raw_handle()
    }
}

impl AsHandle for Poller {
    fn as_handle(&self) -> BorrowedHandle<'_> {
        unsafe { BorrowedHandle::borrow_raw(self.as_raw_handle()) }
    }
}

/// The container for events.
pub(super) struct Events {
    /// List of IOCP packets.
    packets: Vec<Event>,

    /// Buffer for completion packets.
    completions: Vec<OverlappedEntry<Packet>>,
}

unsafe impl Send for Events {}

impl Events {
    /// Creates an empty list of events.
    pub fn with_capacity(cap: usize) -> Events {
        Events {
            packets: Vec::with_capacity(cap),
            completions: Vec::with_capacity(cap),
        }
    }

    /// Iterate over I/O events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.packets.iter().copied()
    }

    /// Clear the list of events.
    pub fn clear(&mut self) {
        self.packets.clear();
    }

    /// The capacity of the list of events.
    pub fn capacity(&self) -> usize {
        self.packets.capacity()
    }
}

/// Extra information about an event.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct EventExtra {
    /// Flags associated with this event.
    flags: AfdPollMask,
}

impl EventExtra {
    /// Create a new, empty version of this struct.
    #[inline]
    pub const fn empty() -> EventExtra {
        EventExtra {
            flags: AfdPollMask::empty(),
        }
    }

    /// Is this a HUP event?
    #[inline]
    pub fn is_hup(&self) -> bool {
        self.flags.intersects(AfdPollMask::ABORT)
    }

    /// Is this a PRI event?
    #[inline]
    pub fn is_pri(&self) -> bool {
        self.flags.intersects(AfdPollMask::RECEIVE_EXPEDITED)
    }

    /// Set up a listener for HUP events.
    #[inline]
    pub fn set_hup(&mut self, active: bool) {
        self.flags.set(AfdPollMask::ABORT, active);
    }

    /// Set up a listener for PRI events.
    #[inline]
    pub fn set_pri(&mut self, active: bool) {
        self.flags.set(AfdPollMask::RECEIVE_EXPEDITED, active);
    }

    /// Check if TCP connect failed. Deprecated.
    #[inline]
    pub fn is_connect_failed(&self) -> Option<bool> {
        Some(self.flags.intersects(AfdPollMask::CONNECT_FAIL))
    }

    /// Check if TCP connect failed.
    #[inline]
    pub fn is_err(&self) -> Option<bool> {
        Some(self.flags.intersects(AfdPollMask::CONNECT_FAIL))
    }
}

/// A packet used to wake up the poller with an event.
#[derive(Debug, Clone)]
pub struct CompletionPacket(Packet);

impl CompletionPacket {
    /// Create a new completion packet with a custom event.
    pub fn new(event: Event) -> Self {
        Self(Arc::pin(IoStatusBlock::from(PacketInner::Custom { event })))
    }

    /// Get the event associated with this packet.
    pub fn event(&self) -> &Event {
        let data = self.0.as_ref().data().project_ref();

        match data {
            PacketInnerProj::Custom { event } => event,
            _ => unreachable!(),
        }
    }
}

/// The type of our completion packet.
///
/// It needs to be pinned, since it contains data that is expected by IOCP not to be moved.
type Packet = Pin<Arc<PacketUnwrapped>>;
type PacketUnwrapped = IoStatusBlock<PacketInner>;

pin_project! {
    /// The inner type of the packet.
    #[project_ref = PacketInnerProj]
    #[project = PacketInnerProjMut]
    enum PacketInner {
        // A packet for a socket.
        Socket {
            // The AFD packet state.
            #[pin]
            packet: UnsafeCell<AfdPollInfo>,

            // The socket state.
            socket: Mutex<SocketState>
        },

        /// A packet for a waitable handle.
        Waitable {
            handle: Mutex<WaitableState>
        },

        /// A single overlapped file operation with owned buffer.
        ///
        /// Per-op allocation: one [`OVERLAPPED`] per outstanding op.
        /// See `docs/named-pipe.design.md` §3.1.
        FileOp {
            #[pin]
            op: OpInner,
        },

        /// A custom event sent by the user.
        Custom {
            event: Event,
        },

        // A packet used to wake up the poller.
        Wakeup { #[pin] _pinned: PhantomPinned },
    }
}

/// Lifecycle state of a single [`OpInner`] operation.
///
/// Stored as an `AtomicU8` so the completion path and a concurrent
/// `cancel()` can race on the transition without a lock.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OpState {
    Submitted = 0,
    Completed = 1,
    Cancelled = 2,
}

/// VTable for type-erased buffer storage inside [`OpInner`].
///
/// The concrete buffer type `B` is recovered at the typed `OpHandle<B>`
/// layer.
struct OpVTable {
    /// Drop the buffer in place.
    pub drop_buf: unsafe fn(*mut u8),
}

/// Type-erased buffer slot embedded in [`OpInner`].
///
/// A fixed 32-byte, 8-byte-aligned blob large enough to hold the
/// buffer wrapper types the [`buf::StableBuf`] / [`buf::StableBufMut`]
/// machinery stores — typically a `(ptr, len, cap)` triple for
/// `Vec<u8>`, a `(ptr, len)` pair for `Box<[u8]>`, or similar.
#[repr(C, align(8))]
pub(crate) struct ErasedBuf([u8; 32]);

/// No-op vtable used while the buffer slot is empty (e.g. for the
/// bare `OpInner::new` constructor used by tests).
static NOOP_VTABLE: OpVTable = OpVTable {
    drop_buf: noop_drop_buf,
};

unsafe fn noop_drop_buf(_: *mut u8) {}

/// Kernel-visible per-operation block.
///
/// `#[repr(C)]` with the `OVERLAPPED` block at offset 0 so the
/// `lpOverlapped` pointer the kernel writes into a completion entry
/// can be cast straight back to `*mut OpInner` (after the file-op
/// classifier has identified it as a file packet).
///
/// Buffer storage is type-erased; [`OpInner::vtable`] knows how to
/// drop or move it. The concrete buffer type is recovered at the typed
/// `OpHandle<B>` layer.
///
/// The struct is `!Unpin` (via [`PhantomPinned`]) because the kernel
/// holds a raw pointer into the embedded [`OVERLAPPED`] for the
/// duration of the operation; moving the payload after submission
/// would invalidate that pointer.
#[repr(C)]
pub(crate) struct OpInner {
    /// `OVERLAPPED` MUST be the first field. The kernel writes the
    /// completion status into it.
    overlapped: UnsafeCell<OVERLAPPED>,
    /// Lifecycle state of this operation.
    state: AtomicU8,
    /// Bytes transferred, written by the completion path.
    bytes_transferred: AtomicU32,
    /// Win32 error reaped from the completion entry, already
    /// translated from NTSTATUS via `ntdll!RtlNtStatusToDosError`
    /// inside the dispatcher; `0` (= success) until set. `OpHandle`
    /// consumers feed this straight into
    /// [`io::Error::from_raw_os_error`] without ever touching the
    /// raw NTSTATUS.
    dos_error: AtomicU32,
    /// `true` after `OpHandle::take` (or sync-success classification)
    /// extracts the buffer; the in-place destructor in `Drop for
    /// OpInner` then becomes a no-op.
    taken: AtomicBool,
    /// Type-erased buffer storage.
    buf_storage: UnsafeCell<MaybeUninit<ErasedBuf>>,
    /// VTable that knows how to drop / move the contents of
    /// [`OpInner::buf_storage`].
    vtable: &'static OpVTable,
    /// Back-reference to the owning [`RegisteredFile`]. `None` when the
    /// op is built from the bare `OpInner::new` constructor used by
    /// internal unit tests; `Some(_)` for every `submit_*`-issued op.
    file: Option<Arc<RegisteredFileInner>>,
    /// Direction of interest for this op. The dispatcher emits an
    /// `Event { key, readable, writable }` mirroring this on
    /// completion, so a reactor (e.g. `async-io`) can wake the right
    /// task via its key-indexed waker registry.
    interest: OpInterest,
    /// Marks the struct as `!Unpin`: the kernel holds a raw pointer
    /// into `overlapped`, so the payload must never be moved.
    _pinned: PhantomPinned,
}

/// Direction of interest for a single in-flight op.
///
/// Mirrored into the `Event { readable, writable }` the dispatcher
/// emits on completion. Reads (and `ConnectNamedPipe`) set
/// `readable = true`; writes set `writable = true`.
#[derive(Copy, Clone, Debug)]
pub(crate) struct OpInterest {
    pub readable: bool,
    pub writable: bool,
}

// Safety: the kernel holds a raw pointer into `OpInner` (specifically
// into `overlapped`) but never reads or writes through any of the
// Rust-side fields concurrently with the user; the typed `OpHandle<B>`
// layer owns the synchronisation discipline for the buffer slot.
unsafe impl Send for OpInner {}
unsafe impl Sync for OpInner {}

impl OpInner {
    /// Construct a fresh `OpInner` in the [`OpState::Submitted`] state
    /// with an empty buffer slot and the [`NOOP_VTABLE`].
    ///
    /// Used by internal layout / unit tests; production submission
    /// sites build `OpInner` inline inside `make_op_packet` so the
    /// buffer / vtable / file back-reference can be set in one move.
    fn new() -> Self {
        Self {
            overlapped: UnsafeCell::new(OVERLAPPED::default()),
            state: AtomicU8::new(OpState::Submitted as u8),
            bytes_transferred: AtomicU32::new(0),
            dos_error: AtomicU32::new(0),
            taken: AtomicBool::new(false),
            buf_storage: UnsafeCell::new(MaybeUninit::zeroed()),
            vtable: &NOOP_VTABLE,
            file: None,
            interest: OpInterest {
                readable: false,
                writable: false,
            },
            _pinned: PhantomPinned,
        }
    }
}

impl Drop for OpInner {
    fn drop(&mut self) {
        // Drop the buffer in place via the type-erased vtable, unless it
        // was already extracted by `OpHandle::take` / sync-success.
        if !self.taken.load(Ordering::Acquire) {
            // SAFETY: `buf_storage` was either initialised by the
            // `submit_*` helper (in which case `vtable.drop_buf` is a
            // typed `drop_in_place::<B>`), or remained zeroed with
            // [`NOOP_VTABLE`] (in which case `drop_buf` is a no-op).
            unsafe {
                (self.vtable.drop_buf)(self.buf_storage.get() as *mut u8);
            }
        }
    }
}

unsafe impl Send for PacketInner {}
unsafe impl Sync for PacketInner {}

impl fmt::Debug for PacketInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wakeup { .. } => f.write_str("Wakeup { .. }"),
            Self::Custom { event } => f.debug_struct("Custom").field("event", event).finish(),
            Self::Socket { socket, .. } => f
                .debug_struct("Socket")
                .field("packet", &"..")
                .field("socket", socket)
                .finish(),
            Self::Waitable { handle } => {
                f.debug_struct("Waitable").field("handle", handle).finish()
            }
            Self::FileOp { .. } => f.write_str("FileOp { .. }"),
        }
    }
}

impl HasAfdInfo for PacketInner {
    fn afd_info(self: Pin<&Self>) -> Pin<&UnsafeCell<AfdPollInfo>> {
        match self.project_ref() {
            PacketInnerProj::Socket { packet, .. } => packet,
            _ => unreachable!(),
        }
    }
}

/// Cached offset of the `FileOp` variant payload inside [`PacketInner`].
///
/// `std::mem::offset_of!` does not yet support enum variants on stable
/// (tracking issue rust-lang/rust#120141), so the variant offset is
/// computed once at runtime.
static FILE_OP_VARIANT_OFFSET: OnceLock<usize> = OnceLock::new();

impl FileOverlapped for PacketInner {
    fn file_op_offset() -> usize {
        // `OpInner.overlapped` is at offset 0 of `OpInner`, so the offset
        // from the `OVERLAPPED` back to the start of `PacketInner` equals
        // the `FileOp` variant offset (no further intra-struct add).
        PacketInner::file_op_variant_offset()
    }
}

impl PacketInner {
    /// Compute (and cache) the offset of the `FileOp` variant payload
    /// (i.e. the embedded `OpInner`) inside `PacketInner`.
    fn file_op_variant_offset() -> usize {
        *FILE_OP_VARIANT_OFFSET.get_or_init(|| {
            let packet = PacketInner::FileOp { op: OpInner::new() };
            let base = &packet as *const _ as *const u8;
            let op_ptr = match &packet {
                PacketInner::FileOp { op } => op as *const _ as *const u8,
                _ => unreachable!(),
            };
            unsafe { op_ptr.offset_from(base) as usize }
        })
    }
}

impl PacketUnwrapped {
    /// Set the new events that this socket is waiting on.
    ///
    /// Returns `true` if we need to be updated.
    fn set_events(self: Pin<&Self>, interest: Event, mode: PollMode) -> bool {
        match self.data().project_ref() {
            PacketInnerProj::Socket { socket, .. } => {
                let mut socket = lock!(socket.lock());
                socket.interest = interest;
                socket.mode = mode;
                socket.interest_error = true;

                // If there was a change, indicate that we need an update.
                match socket.status {
                    SocketStatus::Polling { flags } => {
                        let our_flags = event_to_afd_mask(socket.interest, socket.interest_error);
                        our_flags != flags
                    }
                    _ => true,
                }
            }
            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());

                // Set the new interest.
                handle.interest = interest;
                handle.mode = mode;

                // Update if there is no ongoing wait.
                handle.status.is_idle()
            }
            PacketInnerProj::FileOp { .. } => {
                // One-shot per-op packet: no readiness reconfiguration.
                false
            }
            _ => true,
        }
    }

    /// Update the socket and install the new status in AFD.
    ///
    /// This function does one of the following:
    ///
    /// - Nothing, if the packet is waiting on being dropped anyways.
    /// - Cancels the ongoing poll, if we want to poll for different events than we are currently
    ///   polling for.
    /// - Starts a new AFD_POLL operation, if we are not currently polling.
    fn update(self: Pin<Arc<Self>>) -> io::Result<()> {
        let mut socket = match self.as_ref().data().project_ref() {
            PacketInnerProj::Socket { socket, .. } => lock!(socket.lock()),
            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());

                // If there is no interests, or if we have been cancelled, we don't need to update.
                if !handle.interest.readable && !handle.interest.writable {
                    return Ok(());
                }

                // If we are idle, we need to update.
                if !handle.status.is_idle() {
                    return Ok(());
                }

                // Start a new wait.
                let packet = self.clone();
                let wait_handle = WaitHandle::new(
                    handle.handle,
                    move || {
                        let mut handle = match packet.as_ref().data().project_ref() {
                            PacketInnerProj::Waitable { handle } => lock!(handle.lock()),
                            _ => unreachable!(),
                        };

                        // Try to get the IOCP.
                        let iocp = match handle.port.upgrade() {
                            Some(iocp) => iocp,
                            None => return,
                        };

                        // Set us back into the idle state.
                        handle.status = WaitableStatus::Idle;

                        // Push this packet.
                        drop(handle);
                        if let Err(_e) = iocp.post(0, 0, packet) {
                            #[cfg(feature = "tracing")]
                            tracing::error!("failed to post completion packet: {}", _e);
                        }
                    },
                    None,
                    false,
                )?;

                // Set the new status.
                handle.status = WaitableStatus::Waiting(wait_handle);

                return Ok(());
            }
            PacketInnerProj::FileOp { .. } => {
                // One-shot per-op packet: nothing to update.
                return Ok(());
            }
            _ => return Err(io::Error::other("invalid socket state")),
        };

        // If we are waiting on a delete, just return, dropping the packet.
        if socket.waiting_on_delete {
            return Ok(());
        }

        // Check the current status.
        match socket.status {
            SocketStatus::Polling { flags } => {
                // If we need to poll for events aside from what we are currently polling, we need
                // to update the packet. Cancel the ongoing poll.
                let our_flags = event_to_afd_mask(socket.interest, socket.interest_error);
                if our_flags != flags {
                    return self.cancel(socket);
                }

                // All events that we are currently waiting on are accounted for.
                Ok(())
            }

            SocketStatus::Cancelled => {
                // The ongoing operation was cancelled, and we're still waiting for it to return.
                // For now, wait until the top-level loop calls feed_event().
                Ok(())
            }

            SocketStatus::Idle => {
                // Start a new poll.
                let mask = event_to_afd_mask(socket.interest, socket.interest_error);
                let result = socket.afd.poll(self.clone(), socket.base_socket, mask);

                match result {
                    Ok(()) => {}

                    Err(err)
                        if err.raw_os_error() == Some(ERROR_IO_PENDING as i32)
                            || err.kind() == io::ErrorKind::WouldBlock =>
                    {
                        // The operation is pending.
                    }

                    Err(err) if err.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) => {
                        // The socket was closed. We need to delete it.
                        // This should happen after we drop it here.
                    }

                    Err(err) => return Err(err),
                }

                // We are now polling for the current events.
                socket.status = SocketStatus::Polling { flags: mask };

                Ok(())
            }
        }
    }

    /// This socket state was notified; see if we need to update it.
    ///
    /// This indicates that this packet was indicated as "ready" by the IOCP and needs to be
    /// processed.
    fn feed_event(self: Pin<Arc<Self>>, poller: &Poller) -> io::Result<FeedEventResult> {
        let inner = self.as_ref().data().project_ref();

        let (afd_info, socket) = match inner {
            PacketInnerProj::Socket { packet, socket } => (packet, socket),
            PacketInnerProj::Custom { event } => {
                // This is a custom event.
                return Ok(FeedEventResult::Event(*event));
            }
            PacketInnerProj::Wakeup { .. } => {
                // The poller was notified.
                return Ok(FeedEventResult::Notified);
            }
            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());
                let event = handle.interest;

                // Clear the events if we are in one-shot mode.
                if matches!(handle.mode, PollMode::Oneshot) {
                    handle.interest = Event::none(handle.interest.key);
                }

                // Submit for an update.
                drop(handle);
                poller.update_packet(self)?;

                return Ok(FeedEventResult::Event(event));
            }
            PacketInnerProj::FileOp { .. } => {
                unreachable!(
                    "FileOp packets are dispatched inline in `wait_deadline` and never reach `feed_event`"
                )
            }
        };

        let mut socket_state = lock!(socket.lock());
        let mut event = Event::none(socket_state.interest.key);

        // Put ourselves into the idle state.
        socket_state.status = SocketStatus::Idle;

        // If we are waiting to be deleted, just return and let the drop handler do their thing.
        if socket_state.waiting_on_delete {
            return Ok(FeedEventResult::NoEvent);
        }

        unsafe {
            // SAFETY: The packet is not in transit.
            let iosb = &mut *self.as_ref().iosb().get();

            // Check the status.
            match iosb.Anonymous.Status {
                STATUS_CANCELLED => {
                    // Poll request was cancelled.
                }

                status if status < 0 => {
                    // There was an error, so we signal both ends.
                    event.readable = true;
                    event.writable = true;
                }

                _ => {
                    // Check in on the AFD data.
                    let afd_data = &*afd_info.get();

                    // There was at least one event.
                    if afd_data.handle_count() >= 1 {
                        let events = afd_data.events();

                        // If we closed the socket, remove it from being polled.
                        if events.intersects(AfdPollMask::LOCAL_CLOSE) {
                            let source = lock!(poller.sources.write())
                                .remove(&socket_state.socket)
                                .unwrap();
                            return source.begin_delete().map(|()| FeedEventResult::NoEvent);
                        }

                        // Report socket-related events.
                        let (readable, writable) = afd_mask_to_event(events);
                        event.readable = readable;
                        event.writable = writable;
                        event.extra.flags = events;
                    }
                }
            }
        }

        // Filter out events that the user didn't ask for.
        event.readable &= socket_state.interest.readable;
        event.writable &= socket_state.interest.writable;

        // If this event doesn't have anything that interests us, don't return or
        // update the oneshot state.
        let return_value = if event.readable
            || event.writable
            || event
                .extra
                .flags
                .intersects(socket_state.interest.extra.flags)
        {
            // If we are in oneshot mode, remove the interest.
            if matches!(socket_state.mode, PollMode::Oneshot) {
                socket_state.interest = Event::none(socket_state.interest.key);
                socket_state.interest_error = false;
            }

            FeedEventResult::Event(event)
        } else {
            FeedEventResult::NoEvent
        };

        // Put ourselves in the update queue.
        drop(socket_state);
        poller.update_packet(self)?;

        // Return the event.
        Ok(return_value)
    }

    /// Begin deleting this socket.
    fn begin_delete(self: Pin<Arc<Self>>) -> io::Result<()> {
        // If we aren't already being deleted, start deleting.
        let mut socket = match self.as_ref().data().project_ref() {
            PacketInnerProj::Socket { socket, .. } => lock!(socket.lock()),
            PacketInnerProj::Waitable { handle } => {
                let mut handle = lock!(handle.lock());

                // Set the status to be cancelled. This drops the wait handle and prevents
                // any further updates.
                handle.status = WaitableStatus::Cancelled;

                return Ok(());
            }
            _ => panic!("can't delete packet that doesn't belong to a socket"),
        };
        if !socket.waiting_on_delete {
            socket.waiting_on_delete = true;

            if matches!(socket.status, SocketStatus::Polling { .. }) {
                // Cancel the ongoing poll.
                self.cancel(socket)?;
            }
        }

        // Either drop it now or wait for it to be dropped later.
        Ok(())
    }

    fn cancel(self: &Pin<Arc<Self>>, mut socket: MutexGuard<'_, SocketState>) -> io::Result<()> {
        assert!(matches!(socket.status, SocketStatus::Polling { .. }));

        // Send the cancel request.
        unsafe {
            socket.afd.cancel(self)?;
        }

        // Move state to cancelled.
        socket.status = SocketStatus::Cancelled;

        Ok(())
    }
}

/// Per-socket state.
#[derive(Debug)]
struct SocketState {
    /// The raw socket handle.
    socket: RawSocket,

    /// The base socket handle.
    base_socket: RawSocket,

    /// The event that this socket is currently waiting on.
    interest: Event,

    /// Whether to listen for error events.
    interest_error: bool,

    /// The current poll mode.
    mode: PollMode,

    /// The AFD instance that this socket is registered with.
    afd: Arc<Afd<Packet>>,

    /// Whether this socket is waiting to be deleted.
    waiting_on_delete: bool,

    /// The current status of the socket.
    status: SocketStatus,
}

/// The mode that a socket can be in.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum SocketStatus {
    /// We are currently not polling.
    Idle,

    /// We are currently polling these events.
    Polling {
        /// The flags we are currently polling for.
        flags: AfdPollMask,
    },

    /// The last poll operation was cancelled, and we're waiting for it to
    /// complete.
    Cancelled,
}

/// Per-waitable handle state.
#[derive(Debug)]
struct WaitableState {
    /// The handle that this state is for.
    handle: RawHandle,

    /// The IO completion port that this handle is registered with.
    port: Weak<IoCompletionPort<Packet>>,

    /// The event that this handle will report.
    interest: Event,

    /// The current poll mode.
    mode: PollMode,

    /// The status of this waitable.
    status: WaitableStatus,
}

#[derive(Debug)]
enum WaitableStatus {
    /// We are not polling.
    Idle,

    /// We are waiting on this handle to become signaled.
    Waiting(#[allow(dead_code)] WaitHandle),

    /// This handle has been cancelled.
    Cancelled,
}

impl WaitableStatus {
    fn is_idle(&self) -> bool {
        matches!(self, WaitableStatus::Idle)
    }
}

/// The result of calling `feed_event`.
#[derive(Debug)]
enum FeedEventResult {
    /// No event was yielded.
    NoEvent,

    /// An event was yielded.
    Event(Event),

    /// The poller has been notified.
    Notified,
}

/// A handle for an ongoing wait operation.
#[derive(Debug)]
struct WaitHandle(RawHandle);

impl Drop for WaitHandle {
    fn drop(&mut self) {
        unsafe {
            UnregisterWait(self.0 as _);
        }
    }
}

impl WaitHandle {
    /// Wait for a waitable handle to become signaled.
    fn new<F>(
        handle: RawHandle,
        callback: F,
        timeout: Option<Duration>,
        long_wait: bool,
    ) -> io::Result<Self>
    where
        F: FnOnce() + Send + Sync + 'static,
    {
        // Make sure a panic in the callback doesn't propagate to the OS.
        struct AbortOnDrop;

        impl Drop for AbortOnDrop {
            fn drop(&mut self) {
                std::process::abort();
            }
        }

        unsafe extern "system" fn wait_callback<F: FnOnce() + Send + Sync + 'static>(
            context: *mut c_void,
            _timer_fired: bool,
        ) {
            let _guard = AbortOnDrop;
            let callback = Box::from_raw(context as *mut F);
            callback();

            // We executed without panicking, so don't abort.
            forget(_guard);
        }

        let mut wait_handle = MaybeUninit::<RawHandle>::uninit();

        let mut flags = WT_EXECUTEONLYONCE;
        if long_wait {
            flags |= WT_EXECUTELONGFUNCTION;
        }

        let res = unsafe {
            RegisterWaitForSingleObject(
                wait_handle.as_mut_ptr().cast::<_>(),
                handle as _,
                Some(wait_callback::<F>),
                Box::into_raw(Box::new(callback)) as _,
                timeout.map_or(INFINITE, dur2timeout),
                flags,
            )
        };

        if res == 0 {
            return Err(io::Error::last_os_error());
        }

        let wait_handle = unsafe { wait_handle.assume_init() };
        Ok(Self(wait_handle))
    }
}

/// Translate an event to the mask expected by AFD.
#[inline]
fn event_to_afd_mask(event: Event, error: bool) -> afd::AfdPollMask {
    event_properties_to_afd_mask(event.readable, event.writable, error) | event.extra.flags
}

/// Translate an event to the mask expected by AFD.
#[inline]
fn event_properties_to_afd_mask(readable: bool, writable: bool, error: bool) -> afd::AfdPollMask {
    use afd::AfdPollMask as AfdPoll;

    let mut mask = AfdPoll::empty();

    if error || readable || writable {
        mask |= AfdPoll::ABORT | AfdPoll::CONNECT_FAIL;
    }

    if readable {
        mask |=
            AfdPoll::RECEIVE | AfdPoll::ACCEPT | AfdPoll::DISCONNECT | AfdPoll::RECEIVE_EXPEDITED;
    }

    if writable {
        mask |= AfdPoll::SEND;
    }

    mask
}

/// Convert the mask reported by AFD to an event.
#[inline]
fn afd_mask_to_event(mask: afd::AfdPollMask) -> (bool, bool) {
    use afd::AfdPollMask as AfdPoll;

    let mut readable = false;
    let mut writable = false;

    if mask.intersects(
        AfdPoll::RECEIVE | AfdPoll::ACCEPT | AfdPoll::DISCONNECT | AfdPoll::RECEIVE_EXPEDITED,
    ) {
        readable = true;
    }

    if mask.intersects(AfdPoll::SEND) {
        writable = true;
    }

    if mask.intersects(AfdPoll::ABORT | AfdPoll::CONNECT_FAIL) {
        readable = true;
        writable = true;
    }

    (readable, writable)
}

// Implementation taken from https://github.com/rust-lang/rust/blob/db5476571d9b27c862b95c1e64764b0ac8980e23/src/libstd/sys/windows/mod.rs
fn dur2timeout(dur: Duration) -> u32 {
    // Note that a duration is a (u64, u32) (seconds, nanoseconds) pair, and the
    // timeouts in windows APIs are typically u32 milliseconds. To translate, we
    // have two pieces to take care of:
    //
    // * Nanosecond precision is rounded up
    // * Greater than u32::MAX milliseconds (50 days) is rounded up to INFINITE
    //   (never time out).
    dur.as_secs()
        .checked_mul(1000)
        .and_then(|ms| ms.checked_add((dur.subsec_nanos() as u64) / 1_000_000))
        .and_then(|ms| {
            if dur.subsec_nanos() % 1_000_000 > 0 {
                ms.checked_add(1)
            } else {
                Some(ms)
            }
        })
        .and_then(|x| u32::try_from(x).ok())
        .unwrap_or(INFINITE)
}

/// An error type that wraps around failing to open AFD.
struct AfdError {
    /// String description of what happened.
    description: &'static str,

    /// The underlying system error.
    system: io::Error,
}

impl AfdError {
    #[inline]
    fn new(description: &'static str, system: io::Error) -> Self {
        Self {
            description,
            system,
        }
    }
}

impl fmt::Debug for AfdError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AfdError")
            .field("description", &self.description)
            .field("system", &self.system)
            .field("note", &"probably caused by old Windows or Wine")
            .finish()
    }
}

impl fmt::Display for AfdError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}\nThis error is usually caused by running on old Windows or Wine",
            self.description, self.system
        )
    }
}

impl std::error::Error for AfdError {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.system)
    }
}

struct CallOnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for CallOnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// Inner, Arc-shared state of a [`RegisteredFile`].
///
/// Held behind an [`Arc`] so each in-flight [`OpHandle`] can keep the
/// registration alive independently of the user-facing
/// [`RegisteredFile`] handle.
#[derive(Debug)]
pub(crate) struct RegisteredFileInner {
    /// Raw handle, used by `CancelIoEx` and submission helpers.
    /// Borrowed; never closed by us.
    handle: RawHandle,
    /// Back-reference to the IOCP port. Each in-flight Op holds an
    /// `Arc<RegisteredFileInner>`, so the port stays alive at least as
    /// long as any Op needs to deliver a completion to it.
    #[allow(dead_code)] // Holds the port alive; consulted only by Drop chain.
    port: Arc<IoCompletionPort<Packet>>,
    /// `false` after `RegisteredFile::deactivate`. New `submit_*` calls
    /// are rejected.
    active: AtomicBool,
    /// User-chosen key, mirrored into the `Event::key` of every
    /// completion this file emits. Same convention as
    /// `Poller::add(socket, Event::none(key))` — it identifies the
    /// reactor-side source for an external waker registry.
    ///
    /// Stored atomically so reactors that allocate the key after
    /// constructing the [`RegisteredFile`] (e.g. `async-io`'s
    /// `Slab<Source>` indexing) can rebind it via
    /// [`RegisteredFile::set_user_key`]. The dispatcher reads with
    /// `Acquire`; `set_user_key` writes with `Release`.
    user_key: AtomicUsize,
}

// SAFETY: `RawHandle` is `*mut c_void`; we never dereference it
// concurrently with the kernel except via `ReadFile`/`WriteFile`/
// `CancelIoEx`, which are themselves thread-safe.
unsafe impl Send for RegisteredFileInner {}
unsafe impl Sync for RegisteredFileInner {}

// =====================================================================
// File-handle submission API.
// =====================================================================

use crate::iocp::buf::{StableBuf, StableBufMut};

use std::marker::PhantomData;
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_PIPE_CONNECTED, FALSE};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::IO::CancelIoEx;

/// A long-lived registration token for the IOCP file submission API.
///
/// Cloning is cheap (it bumps an internal `Arc` refcount). All
/// clones submit to the same kernel handle.
#[derive(Clone, Debug)]
pub struct RegisteredFile {
    inner: Arc<RegisteredFileInner>,
}

/// Result of a `RegisteredFile::submit_*` call.
pub enum Submission<B> {
    /// Synchronous success: the kernel processed the I/O immediately
    /// and (because of `FILE_SKIP_COMPLETION_PORT_ON_SUCCESS`) will
    /// not post a completion. The buffer is returned together with
    /// the byte count.
    Complete {
        /// Number of bytes transferred.
        bytes: usize,
        /// The buffer handed back to the caller.
        buf: B,
    },
    /// `ERROR_IO_PENDING` was returned and the completion will arrive
    /// on the poller. Drive [`crate::Poller::wait`] until the
    /// returned [`OpHandle`] reports [`OpHandle::is_complete`], then
    /// call [`OpHandle::take`].
    Pending(OpHandle<B>),
    /// The syscall failed before reaching the kernel queue. The
    /// buffer is handed back together with the error.
    Failed {
        /// The error reported by the syscall.
        error: io::Error,
        /// The buffer handed back to the caller.
        buf: B,
    },
}

impl<B> std::fmt::Debug for Submission<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Submission::Complete { bytes, .. } => f
                .debug_struct("Complete")
                .field("bytes", bytes)
                .finish_non_exhaustive(),
            Submission::Pending(_) => f.write_str("Pending(..)"),
            Submission::Failed { error, .. } => f
                .debug_struct("Failed")
                .field("error", error)
                .finish_non_exhaustive(),
        }
    }
}

impl<B> Submission<B> {
    /// Returns `true` for the `Complete` variant.
    pub fn is_complete(&self) -> bool {
        matches!(self, Submission::Complete { .. })
    }
    /// Returns `true` for the `Pending` variant.
    pub fn is_pending(&self) -> bool {
        matches!(self, Submission::Pending(_))
    }
}

/// Typed handle for one outstanding file operation.
///
/// Holds the per-op packet allocation. The buffer lives inside the
/// allocation; recover it by calling [`OpHandle::take`] once
/// [`OpHandle::is_complete`] reports `true`.
pub struct OpHandle<B> {
    packet: Packet,
    _marker: PhantomData<B>,
}

impl<B> std::fmt::Debug for OpHandle<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpHandle").finish_non_exhaustive()
    }
}

// SAFETY: `OpHandle<B>` exposes only `&self` cancel access, and the
// kernel completion path serialises with the user via atomic state.
// The packet itself is `Send + Sync` (its `Pin<Arc<…>>` wraps a
// `Send + Sync` `IoStatusBlock<PacketInner>`).
unsafe impl<B: Send> Send for OpHandle<B> {}
unsafe impl<B: Sync> Sync for OpHandle<B> {}

impl<B> OpHandle<B> {
    /// Issue [`CancelIoEx`] for this op.
    ///
    /// If the op already completed, this is a no-op (`Ok(())`).
    /// Otherwise the kernel best-effort aborts the op; the user
    /// must still drain the completion via [`crate::Poller::wait`]
    /// before calling [`OpHandle::take`].
    ///
    /// # Why this takes `&self` and does not return `B`
    ///
    /// `CancelIoEx` is asynchronous: it only *requests* cancellation.
    /// The kernel may still be reading from / writing into the buffer
    /// at the moment `cancel` returns, and a final completion packet
    /// (either a late `Ok(n)` or `Err(ERROR_OPERATION_ABORTED)`) is
    /// delivered to the IOCP some time later. The buffer must remain
    /// pinned at its original address until that completion is observed,
    /// otherwise the kernel would write into freed or reused memory.
    ///
    /// Consequently `cancel` does *not* consume `self` and does *not*
    /// hand back `B`. The buffer is reclaimed through the normal path:
    /// poll until [`OpHandle::is_complete`] returns `true`, then call
    /// [`OpHandle::take`] (or [`OpHandle::try_take`]) — both now return
    /// `B` on every path, including the cancelled / errored case.
    ///
    /// This mirrors `compio`'s cancellation contract, where the buffer
    /// is also returned via the awaited completion rather than from the
    /// cancel call itself.
    pub fn cancel(&self) -> io::Result<()> {
        let op = self.op_ref();
        // Fast path: already completed.
        if op.state.load(Ordering::Acquire) == OpState::Completed as u8 {
            return Ok(());
        }
        // CAS Submitted -> Cancelled (idempotent on already-Cancelled).
        let _ = op.state.compare_exchange(
            OpState::Submitted as u8,
            OpState::Cancelled as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );

        let file = op
            .file
            .as_ref()
            .expect("submitted op must have a back-ref to its RegisteredFile");
        let overlapped = op.overlapped.get() as *mut OVERLAPPED;
        // SAFETY: `file.handle` is the kernel handle the op was
        // submitted against; `overlapped` is the per-op `OVERLAPPED`
        // the kernel currently knows about.
        let r = unsafe { CancelIoEx(file.handle as _, overlapped) };
        if r == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    /// Returns `true` once the IOCP completion dispatcher has
    /// observed this op's completion entry.
    pub fn is_complete(&self) -> bool {
        self.op_ref().state.load(Ordering::Acquire) == OpState::Completed as u8
    }

    /// If [`is_complete`](Self::is_complete) reports `true`, consume
    /// `self` and return the I/O result paired with the buffer;
    /// otherwise hand `self` back unchanged.
    ///
    /// On error, the buffer is still returned alongside the
    /// `io::Error` — the caller decides whether to drop it or
    /// resubmit. The shape mirrors compio's `BufResult<T, B>`
    /// (which is `From<(io::Result<T>, B)>`).
    pub fn try_take(self) -> Result<(io::Result<usize>, B), Self> {
        if self.is_complete() {
            Ok(self.take_inner())
        } else {
            Err(self)
        }
    }

    /// Consume `self` and return the I/O result paired with the
    /// buffer.
    ///
    /// On error, the buffer is still returned — see
    /// [`try_take`](Self::try_take) for the rationale.
    ///
    /// # Panics
    ///
    /// Panics if [`is_complete`](Self::is_complete) is `false`.
    /// Use [`try_take`](Self::try_take) for the non-panicking
    /// variant. Drive [`crate::Poller::wait`] until the
    /// completion `Event` for this op's key arrives — see the
    /// `key` argument to [`crate::os::iocp::PollerIocpFileExt::register_file`].
    pub fn take(self) -> (io::Result<usize>, B) {
        assert!(
            self.is_complete(),
            "OpHandle::take called on a not-yet-completed op",
        );
        self.take_inner()
    }

    fn take_inner(self) -> (io::Result<usize>, B) {
        let inner = self.op_ref();
        let bytes = inner.bytes_transferred.load(Ordering::Acquire) as usize;
        let dos_error = inner.dos_error.load(Ordering::Acquire);

        // Take the buffer out of `buf_storage` via a raw read; mark
        // taken so `OpInner::Drop` does not double-free.
        //
        // SAFETY: `buf_storage` was initialised by the matching
        // `submit_*` helper with a `B`. State is `Completed`, so
        // the kernel no longer references the buffer and the
        // dispatcher has already released its `Arc` strong ref.
        let buf: B = unsafe { ptr::read(inner.buf_storage.get() as *const B) };
        inner.taken.store(true, Ordering::Release);

        // `self` is dropped at end of scope; with `taken == true`
        // and refcount now 1 (kernel ref already reclaimed), the
        // allocation is freed without re-running the buffer
        // destructor.
        drop(self);

        // `ERROR_MORE_DATA` is the Win32 translation of
        // `STATUS_BUFFER_OVERFLOW` — a message-mode pipe read filled
        // the user buffer while more data is queued. Byte count and
        // buffer contents are valid; surface as success so the
        // partial data is not lost.
        let res = if dos_error == 0 || dos_error == ERROR_MORE_DATA {
            Ok(bytes)
        } else {
            Err(io::Error::from_raw_os_error(dos_error as i32))
        };
        (res, buf)
    }

    fn op_ref(&self) -> &OpInner {
        match self.packet.as_ref().data().project_ref() {
            PacketInnerProj::FileOp { op } => op.get_ref(),
            _ => unreachable!("OpHandle wraps a FileOp packet"),
        }
    }
}

// No custom `Drop` for `OpHandle`. The default `Pin<Arc<…>>` drop
// is correct:
//   - Op already completed: refcount drops to 0, `OpInner::Drop`
//     reclaims the buffer (unless `take()` already took it).
//   - Op still pending: the kernel still holds one strong ref
//     (bumped at submit time in `classify_submission`), so the
//     allocation lives on. The eventual completion dispatcher
//     reclaims that ref, decrements to 0, and `OpInner::Drop`
//     reclaims the buffer.

/// `ERROR_MORE_DATA` (Win32 234) — translation of
/// `STATUS_BUFFER_OVERFLOW`. A message-mode pipe read filled the
/// user buffer while more data is queued. `OpHandle::take_inner`
/// treats this as success so the partial result is not dropped.
const ERROR_MORE_DATA: u32 = 234;

/// VTable factory: produces a per-`B` `OpVTable` whose `drop_buf`
/// runs `ptr::drop_in_place::<B>`.
fn vtable_for<B>() -> &'static OpVTable {
    struct VTableHolder<B>(PhantomData<B>);
    impl<B> VTableHolder<B> {
        const VTABLE: OpVTable = OpVTable {
            drop_buf: drop_buf_typed::<B>,
        };
    }
    unsafe fn drop_buf_typed<B>(p: *mut u8) {
        // SAFETY: callers (`OpInner::Drop`) only invoke this on
        // storage that was initialised with a `B` via `ptr::write`
        // and not yet taken (`taken == false`).
        unsafe { ptr::drop_in_place(p as *mut B) }
    }
    &VTableHolder::<B>::VTABLE
}

/// Construct a fresh `Pin<Arc<…>>` packet wrapping a `FileOp` op.
///
/// The buffer `B` is moved into the type-erased slot; the chosen
/// vtable knows how to drop / take it.
fn make_op_packet<B>(
    file: Arc<RegisteredFileInner>,
    buf: B,
    interest: OpInterest,
) -> Result<Packet, (B, io::Error)> {
    // Compile-time would be nicer, but we already enforce these
    // dynamically when the slot is dimensioned (Step 1 sized it at
    // 32 bytes). If a future buffer type overflows the slot, we
    // hand it back as a `Failed` instead of UB.
    if std::mem::size_of::<B>() > std::mem::size_of::<ErasedBuf>()
        || std::mem::align_of::<B>() > std::mem::align_of::<ErasedBuf>()
    {
        return Err((
            buf,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer type exceeds the OpInner slot (size or alignment)",
            ),
        ));
    }

    let op = OpInner {
        overlapped: UnsafeCell::new(OVERLAPPED::default()),
        state: AtomicU8::new(OpState::Submitted as u8),
        bytes_transferred: AtomicU32::new(0),
        dos_error: AtomicU32::new(0),
        taken: AtomicBool::new(false),
        buf_storage: UnsafeCell::new(MaybeUninit::zeroed()),
        vtable: vtable_for::<B>(),
        file: Some(file),
        interest,
        _pinned: PhantomPinned,
    };

    // Move the buffer into the type-erased slot.
    // SAFETY: `buf_storage` is a `MaybeUninit<ErasedBuf>` sized to
    // hold `B` (verified above). We own `op` exclusively.
    unsafe {
        ptr::write(op.buf_storage.get() as *mut B, buf);
    }

    Ok(Arc::pin(IoStatusBlock::from(PacketInner::FileOp { op })))
}

/// Helpers to access the `OpInner` inside a freshly-built `Packet`
/// without going through the projection machinery (we need a
/// `*mut OVERLAPPED` and the buffer back when classifying a sync
/// success).
fn op_in(packet: &Packet) -> &OpInner {
    match packet.as_ref().data().project_ref() {
        PacketInnerProj::FileOp { op } => op.get_ref(),
        _ => unreachable!(),
    }
}

impl RegisteredFile {
    /// Mark the registration inactive; in-flight ops continue to
    /// drive completions, but new `submit_*` calls error.
    pub fn deactivate(&self) {
        self.inner.active.store(false, Ordering::Release);
    }

    /// Rebind the user-visible event key.
    ///
    /// Intended for reactors that allocate the event key after
    /// constructing the [`RegisteredFile`] — for example
    /// [`async-io`](https://docs.rs/async-io)'s `Slab<Source>`
    /// indexing (see `docs/named-pipe.design.md` §5.2).
    ///
    /// The new key applies to every completion the dispatcher emits
    /// **after** the dispatcher's `Acquire` load of `user_key`
    /// observes this `Release` store. There is no synchronisation
    /// with completions already dequeued from the IOCP, nor with
    /// completions whose `user_key` load happens-before the store;
    /// those carry the previous key. Callers that need a strict
    /// hand-off should drain pending events from
    /// [`crate::Poller::wait`] before calling `set_user_key`.
    pub fn set_user_key(&self, key: usize) {
        self.inner.user_key.store(key, Ordering::Release);
    }

    /// Submit a `ReadFile` op. See module docs.
    pub fn submit_read<B: StableBufMut>(&self, mut buf: B) -> Submission<B> {
        if !self.inner.active.load(Ordering::Acquire) {
            return Submission::Failed {
                error: io::Error::new(io::ErrorKind::InvalidInput, "file removed from poller"),
                buf,
            };
        }
        let cap = buf.capacity();
        // Win32 `ReadFile` takes a `u32` byte count. Reject buffers
        // larger than `u32::MAX` early so the truncation does not
        // silently short-read.
        if cap > u32::MAX as usize {
            return Submission::Failed {
                error: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer capacity exceeds u32::MAX",
                ),
                buf,
            };
        }
        let ptr = buf.as_mut_ptr();
        let packet = match make_op_packet::<B>(
            Arc::clone(&self.inner),
            buf,
            OpInterest {
                readable: true,
                writable: false,
            },
        ) {
            Ok(p) => p,
            Err((buf, error)) => return Submission::Failed { error, buf },
        };
        let overlapped = op_in(&packet).overlapped.get() as *mut OVERLAPPED;
        let mut bytes_returned: u32 = 0;
        // SAFETY: `self.inner.handle` is the kernel handle bound at
        // registration time; `ptr` / `cap` describe the buffer we
        // just moved into the packet (so it stays at this address
        // for the kernel's use); `overlapped` is the per-op block.
        let r = unsafe {
            ReadFile(
                self.inner.handle as _,
                ptr,
                cap as u32,
                &mut bytes_returned as *mut _,
                overlapped,
            )
        };
        classify_submission::<B>(packet, r != FALSE, bytes_returned as usize)
    }

    /// Submit a `WriteFile` op. See module docs.
    pub fn submit_write<B: StableBuf>(&self, buf: B) -> Submission<B> {
        if !self.inner.active.load(Ordering::Acquire) {
            return Submission::Failed {
                error: io::Error::new(io::ErrorKind::InvalidInput, "file removed from poller"),
                buf,
            };
        }
        let len = buf.len();
        // Win32 `WriteFile` takes a `u32` byte count. Reject buffers
        // larger than `u32::MAX` early so the truncation does not
        // silently short-write.
        if len > u32::MAX as usize {
            return Submission::Failed {
                error: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer length exceeds u32::MAX",
                ),
                buf,
            };
        }
        let ptr = buf.as_ptr();
        let packet = match make_op_packet::<B>(
            Arc::clone(&self.inner),
            buf,
            OpInterest {
                readable: false,
                writable: true,
            },
        ) {
            Ok(p) => p,
            Err((buf, error)) => return Submission::Failed { error, buf },
        };
        let overlapped = op_in(&packet).overlapped.get() as *mut OVERLAPPED;
        let mut bytes_returned: u32 = 0;
        // SAFETY: see `submit_read`.
        let r = unsafe {
            WriteFile(
                self.inner.handle as _,
                ptr,
                len as u32,
                &mut bytes_returned as *mut _,
                overlapped,
            )
        };
        classify_submission::<B>(packet, r != FALSE, bytes_returned as usize)
    }

    /// Submit a `ConnectNamedPipe` op. See module docs.
    pub fn submit_connect_named_pipe(&self) -> Submission<()> {
        if !self.inner.active.load(Ordering::Acquire) {
            return Submission::Failed {
                error: io::Error::new(io::ErrorKind::InvalidInput, "file removed from poller"),
                buf: (),
            };
        }
        // ConnectNamedPipe is the server-side accept; the typical
        // follow-up is a `ReadFile`, so we mark it readable-only.
        let packet = match make_op_packet::<()>(
            Arc::clone(&self.inner),
            (),
            OpInterest {
                readable: true,
                writable: false,
            },
        ) {
            Ok(p) => p,
            Err((buf, error)) => return Submission::Failed { error, buf },
        };
        let overlapped = op_in(&packet).overlapped.get() as *mut OVERLAPPED;
        // SAFETY: see `submit_read`.
        let r = unsafe { ConnectNamedPipe(self.inner.handle as _, overlapped) };
        if r != FALSE {
            // Sync success. No completion will arrive.
            return finish_sync_success::<()>(packet, 0);
        }
        // ConnectNamedPipe quirk: returns FALSE + ERROR_PIPE_CONNECTED
        // when the client had already connected before the call.
        let err = io::Error::last_os_error();
        match err.raw_os_error().map(|e| e as u32) {
            Some(ERROR_IO_PENDING) => {
                // SAFETY: see `classify_submission`; the kernel
                // owns one `Arc` strong ref for the lifetime of
                // the in-flight op, reclaimed by the dispatcher.
                std::mem::forget(packet.clone());
                Submission::Pending(into_op_handle::<()>(packet))
            }
            Some(ERROR_PIPE_CONNECTED) => finish_sync_success::<()>(packet, 0),
            _ => finish_sync_failure::<()>(packet, err),
        }
    }
}

fn classify_submission<B>(packet: Packet, sync_ok: bool, bytes: usize) -> Submission<B> {
    if sync_ok {
        return finish_sync_success::<B>(packet, bytes);
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error().map(|e| e as u32) {
        Some(ERROR_IO_PENDING) => {
            // SAFETY: the kernel kept our `OVERLAPPED` pointer (the
            // syscall returned `ERROR_IO_PENDING`). We bump the
            // packet `Arc` strong count here so the kernel
            // logically owns one strong reference for the lifetime
            // of the in-flight op. The IOCP completion dispatcher
            // in `Poller::wait_deadline` reclaims that reference
            // via `OverlappedEntry::into_file_op_packet` (which
            // calls `Arc::from_raw` on the recovered packet
            // pointer). The bump and the reclaim are paired one
            // for one: every `Pending` submission produces exactly
            // one completion entry.
            std::mem::forget(packet.clone());
            Submission::Pending(into_op_handle::<B>(packet))
        }
        _ => finish_sync_failure::<B>(packet, err),
    }
}

fn into_op_handle<B>(packet: Packet) -> OpHandle<B> {
    OpHandle {
        packet,
        _marker: PhantomData,
    }
}

fn finish_sync_success<B>(packet: Packet, bytes: usize) -> Submission<B> {
    // Take the buffer back out and discard the empty packet.
    let buf = unsafe { take_buf_unchecked::<B>(&packet) };
    Submission::Complete { bytes, buf }
}

fn finish_sync_failure<B>(packet: Packet, error: io::Error) -> Submission<B> {
    let buf = unsafe { take_buf_unchecked::<B>(&packet) };
    Submission::Failed { error, buf }
}

/// SAFETY: caller must ensure the buffer at `buf_storage` is still
/// initialised (i.e. `taken == false`) and that no concurrent
/// reader is racing on it (true for sync paths inside `submit_*`).
unsafe fn take_buf_unchecked<B>(packet: &Packet) -> B {
    let op = op_in(packet);
    // SAFETY: see fn doc.
    let buf: B = unsafe { ptr::read(op.buf_storage.get() as *const B) };
    op.taken.store(true, Ordering::Release);
    buf
}

#[cfg(test)]
mod op_tests {
    use super::*;

    /// `OVERLAPPED` (the inner kernel block) must live at offset 0 of
    /// `OpInner` so the kernel-written `lpOverlapped` pointer can be
    /// cast straight back to `*mut OpInner`.
    #[test]
    fn op_inner_overlapped_at_offset_zero() {
        assert_eq!(std::mem::offset_of!(OpInner, overlapped), 0);
    }

    /// Smoke test that an `OpInner` can be pinned in an `Arc` and the
    /// raw-pointer round trip through `Pin::into_inner_unchecked` /
    /// re-pinning works. `OpInner` is `!Unpin` (via `PhantomPinned`),
    /// which is what we actually rely on.
    #[test]
    fn op_inner_round_trips_through_pinned_arc() {
        let arc: Pin<Arc<OpInner>> = Arc::pin(OpInner::new());
        // Round-trip via the unchecked pin API the IOCP path uses.
        let raw = unsafe { Pin::into_inner_unchecked(arc) };
        let _re_pinned: Pin<Arc<OpInner>> = unsafe { Pin::new_unchecked(raw) };
    }

    /// Calling `NOOP_VTABLE.drop_buf` on a zeroed buffer must be a
    /// no-op and not panic.
    #[test]
    fn noop_vtable_drop_is_safe() {
        let mut buf = [0u8; 32];
        unsafe {
            (NOOP_VTABLE.drop_buf)(buf.as_mut_ptr());
        }
    }
}
