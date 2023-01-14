//! Bindings to I/O Completion Ports (Windows).
//!
//! I/O Completion Ports are an API in Windows that enables asynchronous I/O. However, this interface
//! is completion-based, not event based. This is incompatible with the event-based interface
//! of `polling`. However, Windows exposes an undocumented, unstable interface called '\Device\Afd'
//! that emits I/O completion events when readiness signals are available. This module uses that
//! interface to emulate event-based I/O.
//!
//! There is little danger of this interface changing, since it is also used by Node.js.
//! (Recommendation: It may be wise to monitor `libuv` in case any changes do become necessary.)
//!
//! Previously, this crate used `wepoll`, which also used this strategy.

/// Safe bindings to the Windows API.
mod syscalls {
    use async_lock::OnceCell;

    use std::cell::UnsafeCell;
    use std::fmt;
    use std::io;
    use std::marker::{PhantomData, PhantomPinned};
    use std::mem::{self, MaybeUninit};
    use std::os::windows::prelude::{AsRawHandle, RawHandle, RawSocket};
    use std::pin::Pin;
    use std::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::Foundation::{HANDLE, HINSTANCE, NTSTATUS, UNICODE_STRING};
    use windows_sys::Win32::Foundation::{
        INVALID_HANDLE_VALUE, STATUS_CANCELLED, STATUS_NOT_FOUND, STATUS_PENDING, STATUS_SUCCESS,
    };

    use windows_sys::Win32::Networking::WinSock::WSAIoctl;
    use windows_sys::Win32::Networking::WinSock::{
        INVALID_SOCKET, SIO_BASE_HANDLE, SIO_BSP_HANDLE_POLL, SOCKET_ERROR, WSAENOTSOCK,
    };

    use windows_sys::Win32::Storage::FileSystem::SetFileCompletionNotificationModes;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_OPEN, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };

    use windows_sys::Win32::System::IO::OVERLAPPED_ENTRY;
    use windows_sys::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatusEx, PostQueuedCompletionStatus,
    };

    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    use windows_sys::Win32::System::WindowsProgramming::FILE_SKIP_SET_EVENT_ON_HANDLE;
    use windows_sys::Win32::System::WindowsProgramming::{
        IO_STATUS_BLOCK, OBJECT_ATTRIBUTES, PIO_APC_ROUTINE,
    };

    pub(super) use windows_sys::Win32::System::WindowsProgramming::INFINITE;

    #[allow(clippy::upper_case_acronyms)]
    pub(super) type ULONG = u32;

    /// Macro for defining a structure that contains function pointers to the unsafe Win32 functions.
    macro_rules! ntdll_import {
        ($(
            $(#[$meta:meta])*
            fn $name:ident($($arg:ident: $arg_ty:ty),* $(,)?) -> $ret:ty;
        )*) => {
            #[allow(non_snake_case)]
            struct NtdllImports {
                $(
                    $(#[$meta])*
                    $name: unsafe extern "system" fn($($arg_ty),*) -> $ret
                ),*
            }

            #[allow(non_snake_case, clippy::too_many_arguments)]
            impl NtdllImports {
                unsafe fn load(handle: HINSTANCE) -> io::Result<Self> {
                    Ok(Self {
                        $(
                            $name: {
                                // Create the C name by concatenating the Rust name with a null byte.
                                let name = {
                                    let s = concat!(stringify!($name), "\0");
                                    s.as_ptr() as *const _
                                };

                                // Get the address of the function.
                                let addr = unsafe { GetProcAddress(handle, name) };
                                if addr.is_none() {
                                    return Err(io::Error::last_os_error());
                                }

                                // Transmute to a function pointer.
                                unsafe { mem::transmute(addr) }
                            },
                        )*
                    })
                }

                $(
                    $(#[$meta])*
                    unsafe fn $name(&self, $($arg: $arg_ty),*) -> $ret {
                        (self.$name)($($arg),*)
                    }
                )*
            }
        }
    }

    ntdll_import! {
        /// Cancel an ongoing file operation.
        fn NtCancelIoFileEx(
            FileHandle: HANDLE,
            IoRequestToCancel: *mut IO_STATUS_BLOCK,
            IoStatusBlock: *mut IO_STATUS_BLOCK,
        ) -> NTSTATUS;

        /// Create a new file handle.
        fn NtCreateFile(
            FileHandle: *mut HANDLE,
            DesiredAccess: u32,
            ObjectAttributes: *mut OBJECT_ATTRIBUTES,
            IoStatusBlock: *mut IO_STATUS_BLOCK,
            AllocationSize: *mut (),
            FileAttributes: ULONG,
            ShareAccess: ULONG,
            CreateDisposition: ULONG,
            CreateOptions: ULONG,
            EaBuffer: *mut (),
            EaLength: ULONG,
        ) -> NTSTATUS;

        /// Call a command associated with a file.
        ///
        /// This is similar to Linux's `ioctl` function.
        fn NtDeviceIoControlFile(
            FileHandle: HANDLE,
            Event: HANDLE,
            ApcRoutine: PIO_APC_ROUTINE,
            ApcContext: *mut (),
            IoStatusBlock: *mut IO_STATUS_BLOCK,
            IoControlCode: ULONG,
            InputBuffer: *mut (),
            InputBufferLength: ULONG,
            OutputBuffer: *mut (),
            OutputBufferLength: ULONG,
        ) -> NTSTATUS;

        /// Convert an `NTSTATUS` to a Win32 error code.
        fn RtlNtStatusToDosError(
            Status: NTSTATUS,
        ) -> ULONG;
    }

    impl NtdllImports {
        /// Get the global instance of `NtdllImports`.
        fn get() -> io::Result<&'static NtdllImports> {
            static NTDLL_IMPORTS: OnceCell<NtdllImports> = OnceCell::new();

            NTDLL_IMPORTS.get_or_try_init_blocking(|| unsafe {
                // Get a handle to ntdll.dll.
                let ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const _);
                if ntdll == 0 {
                    return Err(io::Error::last_os_error());
                }

                // Load the imports.
                NtdllImports::load(ntdll)
            })
        }
    }

    /// Get the last Win32 error.
    pub(super) fn last_error() -> u32 {
        unsafe { GetLastError() }
    }

    /// Get the base socket for a `BorrowedSocket` type.
    ///
    /// The AFD driver only operates on base sockets, so we need to convert the socket to a base
    /// socket before we can use it.
    ///
    /// # I/O Safety
    ///
    /// `sock` must be a valid socket.
    fn base_socket(sock: RawSocket) -> io::Result<RawSocket> {
        // Try to get the base socket.
        if let Ok(base) = unsafe { try_ioctl(sock, SIO_BASE_HANDLE) } {
            return Ok(base);
        }

        if last_error() == WSAENOTSOCK as _ {
            return Err(io::Error::from_raw_os_error(WSAENOTSOCK));
        }

        // Some buggy systems handle SIO_BASE_HANDLE improperly. However, we can try to get at
        // the base socket by bypassing the current layer with SIO_BSP_HANDLE_POLL, and then
        // getting the base handle of that.
        let poll_handle = unsafe { try_ioctl(sock, SIO_BSP_HANDLE_POLL)? };
        if poll_handle == sock {
            return Err(io::Error::last_os_error());
        }

        // Try again.
        unsafe { try_ioctl(poll_handle, SIO_BASE_HANDLE) }
    }

    /// Run the IOCTL on a socket.
    ///
    /// # Safety
    ///
    /// The IOCTL must return a socket.
    unsafe fn try_ioctl(sock: RawSocket, ioctl: u32) -> io::Result<RawSocket> {
        let mut socket: MaybeUninit<RawSocket> = MaybeUninit::uninit();
        let mut bytes: MaybeUninit<u32> = MaybeUninit::uninit();

        let result = unsafe {
            WSAIoctl(
                sock as _,
                ioctl,
                ptr::null_mut(),
                0,
                socket.as_mut_ptr() as *mut _,
                mem::size_of::<RawSocket>() as u32,
                bytes.as_mut_ptr(),
                ptr::null_mut(),
                None,
            )
        };

        if result == SOCKET_ERROR {
            Err(io::Error::last_os_error())
        } else {
            let socket = unsafe { socket.assume_init() };

            // Also check for invalid sockets.
            if socket == INVALID_SOCKET as _ || socket == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(socket)
            }
        }
    }

    // Various AFD constants.
    pub(super) const AFD_POLL_RECEIVE: ULONG = 0x0001;
    pub(super) const AFD_POLL_RECEIVE_EXPEDITED: ULONG = 0x0002;
    pub(super) const AFD_POLL_SEND: ULONG = 0x0004;
    pub(super) const AFD_POLL_DISCONNECT: ULONG = 0x0008;
    pub(super) const AFD_POLL_ABORT: ULONG = 0x0010;
    pub(super) const AFD_POLL_LOCAL_CLOSE: ULONG = 0x0020;
    pub(super) const AFD_POLL_ACCEPT: ULONG = 0x0080;
    pub(super) const AFD_POLL_CONNECT_FAIL: ULONG = 0x0100;

    /// The poll handle structure the AFD expects.
    #[repr(C)]
    pub(super) struct AfdPollHandleInfo {
        handle: RawSocket,
        events: ULONG,
        status: NTSTATUS,
    }

    /// The poll info structure the AFD expects.
    #[repr(C)]
    pub(super) struct AfdPollInfo {
        timeout: i64,
        number_of_handles: ULONG,
        exclusive: i8,
        handles: [AfdPollHandleInfo; 1],
    }

    pin_project_lite::pin_project! {
        /// A wrapper around AFD information.
        pub struct AfdInfo {
            // AFD polling info.
            //
            // This is wrapped in `UnsafeCell` to indicate that it may be changed outside of Rust's
            // control, so alias optimizations should not apply.
            #[pin]
            poll_info: UnsafeCell<AfdPollInfo>,

            // The raw base socket.
            //
            // Since this belongs (strangely) to another socket, we shouldn't close it.
            base_socket: RawSocket,

            // This type needs to be `!Unpin`, since it contains data that is invalidated on move.
            #[pin]
            _pinned: PhantomPinned,
        }
    }

    unsafe impl Send for AfdInfo {}
    unsafe impl Sync for AfdInfo {}

    impl AfdInfo {
        /// Create a new `AfdInfo` for a socket type.
        pub(super) fn new(socket: RawSocket) -> io::Result<Self> {
            // Get the base socket.
            let base_socket = base_socket(socket)?;

            // Create the poll info.
            let poll_info = AfdPollInfo {
                timeout: i64::MAX,
                number_of_handles: 1,
                exclusive: false as _,
                handles: [AfdPollHandleInfo {
                    handle: base_socket,
                    events: 0,
                    status: 0,
                }],
            };

            Ok(Self {
                poll_info: UnsafeCell::new(poll_info),
                base_socket,
                _pinned: PhantomPinned,
            })
        }

        /// Get the AFD handle.
        ///
        /// # Safety
        ///
        /// An operation must not be in progress.
        pub(super) unsafe fn afd_handle(self: Pin<&Self>) -> &AfdPollInfo {
            &*self.poll_info.get()
        }

        /// Replenish the AFD poll info structure in preparation for another poll.
        ///
        /// # Safety
        ///
        /// An operation must not be in progress.
        pub(super) unsafe fn replenish(&self, events: ULONG) {
            let poll_info = &mut *self.poll_info.get();

            *poll_info = AfdPollInfo {
                exclusive: false as _,
                number_of_handles: 1,
                timeout: i64::MAX,
                handles: [AfdPollHandleInfo {
                    handle: self.base_socket,
                    events,
                    status: 0,
                }],
            };
        }

        /// Get a raw pointer to the AFD information.
        ///
        /// Since we are `Pin`ned, we shouldn't be able to move, so the pointer should never be
        /// invalidated mid operation.
        fn afd_info(self: Pin<&Self>) -> *mut AfdPollInfo {
            self.project_ref().poll_info.get()
        }
    }

    /// A type that contains an AFD poll info structure.
    ///
    /// This is used to allow types with other external data to be used with AFD.
    pub(super) trait AfdCompatible {
        /// Get the AFD poll info structure.
        fn afd_info(self: Pin<&Self>) -> Pin<&AfdInfo>;

        /// The AFD events that we want to poll.
        fn afd_events(&self) -> ULONG;
    }

    /// Wrapper around the `\Device\Afd` device.
    ///
    /// The '\Device\Afd' device is used to poll sockets for events. By submitting a poll operation,
    /// we can wait for a socket to become readable or writable using IOCP.
    ///
    /// This is an unstable system API. However, the only other alternative is to either a). rewrite
    /// futures to use a completion model or b). have a fleet of threads that are each dedicated to
    /// `poll`ing one single socket. Neither of these options are particularly appealing; however,
    /// in the future we may want to add the second one as an alternative for users who don't want to
    /// rely on unstable APIs, or are using platforms without AFD available (Windows XP?).
    pub(super) struct Afd<T> {
        /// Handle to the AFD device.
        handle: HANDLE,

        /// Capture the `T` generic.
        _marker: PhantomData<Pin<Arc<T>>>,
    }

    impl<T> Drop for Afd<T> {
        fn drop(&mut self) {
            // Ignore errors.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    impl<T> fmt::Debug for Afd<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.pad("Afd { .. }")
        }
    }

    impl<T> AsRawHandle for Afd<T> {
        fn as_raw_handle(&self) -> RawHandle {
            self.handle as _
        }
    }

    impl<T> Afd<T> {
        /// Create a new instance of `Afd`.
        pub(super) fn new() -> io::Result<Self> {
            macro_rules! b {
                ($e:expr) => {{
                    $e as _
                }};
            }

            // \Device\Afd\Smol
            const AFD_NAME: &[u16] = &[
                b!('\\'),
                b!('D'),
                b!('e'),
                b!('v'),
                b!('i'),
                b!('c'),
                b!('e'),
                b!('\\'),
                b!('A'),
                b!('f'),
                b!('d'),
                b!('\\'),
                b!('S'),
                b!('m'),
                b!('o'),
                b!('l'),
                b!('\0'),
            ];

            let mut name = UNICODE_STRING {
                Length: (AFD_NAME.len() - 1) as _,
                MaximumLength: AFD_NAME.len() as _,
                Buffer: AFD_NAME.as_ptr() as _,
            };

            // Define the attributes of the file.
            let mut object_attribute = OBJECT_ATTRIBUTES {
                Length: mem::size_of::<OBJECT_ATTRIBUTES>() as _,
                RootDirectory: 0,
                ObjectName: &mut name,
                Attributes: 0,
                SecurityDescriptor: ptr::null_mut(),
                SecurityQualityOfService: ptr::null_mut(),
            };

            // Create the file handle.
            let mut handle: MaybeUninit<HANDLE> = MaybeUninit::uninit();
            let mut status_block: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

            // Creating a file handle without any extended attributes (using `NtCreateFile`) allows
            // us to open a handle for communication with the AFD driver.
            let status = unsafe {
                NtdllImports::get()?.NtCreateFile(
                    handle.as_mut_ptr() as *mut _,
                    SYNCHRONIZE,
                    &mut object_attribute,
                    status_block.as_mut_ptr(),
                    ptr::null_mut(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    FILE_OPEN,
                    0,
                    ptr::null_mut(),
                    0,
                )
            };

            if status != STATUS_SUCCESS {
                // Convert the error code.
                return Err(convert_ntstatus(status));
            }

            Ok(Self {
                handle: unsafe { handle.assume_init() },
                _marker: PhantomData,
            })
        }

        /// Begin polling the provided AFD info structure on this AFD.
        ///
        /// This clones the `iosb` and uses its pointer as an IOSB submission.
        pub(super) fn poll(&self, iosb: &StatusBlock<T>) -> io::Result<()>
        where
            T: AfdCompatible,
        {
            const IOCTL_AFD_POLL: ULONG = 0x00012024;

            let mut current_status: IosbState = iosb.0.state.load(Ordering::Acquire).into();
            loop {
                // Make sure we're not polling the same AFD info structure twice.
                if let IosbState::Pending = current_status {
                    return Err(io::Error::new(io::ErrorKind::Other, "already polling"));
                }

                // Indicate that we are now pending.
                match iosb.0.state.compare_exchange(
                    current_status.into(),
                    IosbState::Pending.into(),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(status) => current_status = status.into(),
                }
            }

            // Clear out state in the IOSB.
            // SAFETY:
            //  - Since we are now "pending", other users won't access the raw IOSB's fields.
            //  - We haven't begun an operation yet, so we can access the raw AFD fields.
            let iosb = iosb.clone();
            unsafe {
                iosb.user_data()
                    .afd_info()
                    .replenish(iosb.user_data().afd_events());
                let iosb = &mut *iosb.status_block().get();
                iosb.Anonymous.Status = STATUS_PENDING;
            }

            let poll_info = iosb.user_data().afd_info().afd_info();

            // Poll the AFD using the IOCTL_AFD_POLL control.
            let status = unsafe {
                NtdllImports::get()?.NtDeviceIoControlFile(
                    self.handle,
                    0,
                    None,
                    ptr::null_mut(),
                    iosb.into_ptr() as _,
                    IOCTL_AFD_POLL,
                    poll_info as _,
                    mem::size_of::<AfdPollInfo>() as _,
                    poll_info as _,
                    mem::size_of::<AfdPollInfo>() as _,
                )
            };

            // SAFETY: The reference to the IOSB is now held by AFD; into_ptr prevents refcount from dropping.

            match status {
                STATUS_SUCCESS => Ok(()),
                STATUS_PENDING => Err(io::Error::from(io::ErrorKind::WouldBlock)),
                status => {
                    // Convert the error code.
                    Err(convert_ntstatus(status))
                }
            }
        }

        /// Cancel the pending operation on this AFD.
        ///
        /// This function will raise an error if the operation is not pending, or if the
        /// operation is not registered in this AFD.
        pub(super) fn cancel(&self, iosb: &StatusBlock<T>) -> io::Result<()>
        where
            T: AfdCompatible,
        {
            // If the status is not pending, then it's been completed.
            match iosb.0.state.compare_exchange(
                IosbState::Pending.into(),
                IosbState::Cancelled.into(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => (),
                Err(_) => return Err(io::Error::new(io::ErrorKind::Other, "not pending")),
            }

            if unsafe { (*iosb.status_block().get()).Anonymous.Status } != STATUS_PENDING {
                return Err(io::Error::new(io::ErrorKind::Other, "not pending"));
            }

            // Cancel the operation.
            let mut cancel_iosb = MaybeUninit::uninit();
            let status = unsafe {
                NtdllImports::get()?.NtCancelIoFileEx(
                    self.handle,
                    iosb.status_block().get(),
                    cancel_iosb.as_mut_ptr(),
                )
            };

            if let STATUS_SUCCESS | STATUS_NOT_FOUND = status {
                Ok(())
            } else {
                // Convert the error code.
                Err(convert_ntstatus(status))
            }
        }
    }

    /// Wrapper around an I/O completion port.
    ///
    /// I/O completion ports are the standard way of polling operations in Windows.
    pub(super) struct IoCompletionPort<T> {
        /// The handle to the I/O completion port.
        handle: HANDLE,

        /// Captures the `T` type parameter.
        _marker: PhantomData<T>,
    }

    impl<T> Drop for IoCompletionPort<T> {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }

    impl<T> fmt::Debug for IoCompletionPort<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            struct DebugHandle(HANDLE);

            impl fmt::Debug for DebugHandle {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "{:#010x}", self.0)
                }
            }

            f.debug_tuple("IoCompletionPort")
                .field(&DebugHandle(self.handle))
                .finish()
        }
    }

    impl<T> IoCompletionPort<T> {
        /// Create a new I/O completion port.
        pub(super) fn new() -> io::Result<Self> {
            // Create the I/O completion port.
            let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0) };

            if handle == 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(Self {
                handle,
                _marker: PhantomData,
            })
        }

        /// Register a handle with the I/O completion port.
        pub(super) fn register(
            &self,
            handle: &impl AsRawHandle,
            skip_set_event: bool,
        ) -> io::Result<()> {
            // Register the handle.
            let raw = handle.as_raw_handle() as _;
            let handle = unsafe { CreateIoCompletionPort(raw, self.handle, 0, 0) };

            if handle == 0 {
                return Err(io::Error::last_os_error());
            }

            if skip_set_event {
                let res = unsafe {
                    SetFileCompletionNotificationModes(raw, FILE_SKIP_SET_EVENT_ON_HANDLE as _)
                };

                if res == 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            Ok(())
        }

        /// Post a new completion packet to the I/O completion port.
        pub(super) fn post(&self, sb: &StatusBlock<T>) -> io::Result<()> {
            let sb = sb.clone();

            // Post the completion packet.
            let status =
                unsafe { PostQueuedCompletionStatus(self.handle, 0, 0, sb.into_ptr() as _) };

            if status == 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }

        /// Get the next completion packets from the I/O completion port.
        ///
        /// `timeout` is in milliseconds. Returns the number of entries initialized.
        pub(super) fn wait(
            &self,
            entries: &mut OverlappedBuffer<T>,
            timeout: u32,
        ) -> io::Result<usize> {
            // Wait for the completion packets.
            let mut num_entries = MaybeUninit::uninit();

            let status = unsafe {
                GetQueuedCompletionStatusEx(
                    self.handle,
                    entries.as_mut_ptr() as _,
                    entries.capacity() as _,
                    num_entries.as_mut_ptr(),
                    timeout,
                    false as _,
                )
            };

            // If the status is false, then we have an error.
            if status == 0 {
                return Err(io::Error::last_os_error());
            }

            // Update the number of entries.
            let num_entries = unsafe { num_entries.assume_init() as usize };
            unsafe {
                entries.entries.set_len(num_entries);
            }
            Ok(num_entries)
        }
    }

    impl<T> AsRawHandle for IoCompletionPort<T> {
        fn as_raw_handle(&self) -> RawHandle {
            self.handle as _
        }
    }

    /// An `IO_STATUS_BLOCK` entry combined with a user data type.
    ///
    /// This type is a reference counted heap allocation. During I/O operations, it is actively
    /// owned by the I/O completion port. When the I/O operation completes, the I/O completion port
    /// will return a reference to the `StatusBlock` to the caller through the `OverlappedBuffer`.
    pub(super) struct StatusBlock<T>(Pin<Arc<IosbInner<T>>>);

    impl<T: fmt::Debug> fmt::Debug for StatusBlock<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("StatusBlock")
                .field("state", &self.state())
                .field("user_data", &self.user_data())
                .finish()
        }
    }

    impl<T> Clone for StatusBlock<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }

    pin_project_lite::pin_project! {
        #[repr(C)]
        struct IosbInner<T> {
            // The `IO_STATUS_BLOCK` structure.
            //
            // This needs to come first so that we can cast a pointer to this. It's wrapped in an
            // `UnsafeCell` so Rust understands not to alias to it, since it may be modified
            // outside of Rust's control.
            #[pin]
            iosb: UnsafeCell<IO_STATUS_BLOCK>,

            // The current state of the I/O operation.
            //
            // This is used to track whether the I/O operation has completed or not.
            state: AtomicUsize,

            // Associated user data.
            #[pin]
            data: T,

            // This structure cannot be moved.
            #[pin]
            _pin: PhantomPinned,
        }
    }

    // SAFETY: All access to `UnsafeCell` is synchronized.
    unsafe impl<T: Send + Sync> Send for IosbInner<T> {}
    unsafe impl<T: Send + Sync> Sync for IosbInner<T> {}

    /// The current state of the I/O operation.
    #[repr(usize)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub(super) enum IosbState {
        /// The I/O operation has completed.
        Idle = 0,

        /// The I/O operation is pending.
        Pending = 1,

        /// The last I/O operation was cancelled.
        Cancelled = 2,
    }

    impl From<usize> for IosbState {
        fn from(value: usize) -> Self {
            match value {
                0 => Self::Idle,
                1 => Self::Pending,
                2 => Self::Cancelled,
                _ => unreachable!(),
            }
        }
    }

    impl From<IosbState> for usize {
        fn from(value: IosbState) -> Self {
            value as usize
        }
    }

    /// The result of an IOSB operation.
    pub(super) enum IosbResult {
        /// The operation completed successfully.
        Success,

        /// The operation was cancelled.
        Cancelled,

        /// The operation is still pending.
        Pending,
    }

    impl<T> StatusBlock<T> {
        /// Create a new `StatusBlock` with the given user data.
        pub(super) fn new(data: T) -> Self {
            Self(Arc::pin(IosbInner {
                iosb: unsafe {
                    let mut iosb: IO_STATUS_BLOCK = mem::zeroed();
                    iosb.Anonymous.Status = STATUS_PENDING;
                    UnsafeCell::new(iosb)
                },
                state: AtomicUsize::new(IosbState::Idle.into()),
                data,
                _pin: PhantomPinned,
            }))
        }

        /// Get the current state of the I/O operation.
        pub(super) fn state(&self) -> IosbState {
            self.0.state.load(Ordering::Acquire).into()
        }

        /// Get the status block's I/O result.
        ///
        /// # Panics
        ///
        /// If the operation is still pending, this function will panic.
        pub(super) fn result(&self) -> io::Result<IosbResult> {
            assert_ne!(self.state(), IosbState::Pending);

            unsafe {
                // SAFETY: Our toes are not being stepped on.
                let iosb = self.0.iosb.get();
                let status = (*iosb).Anonymous.Status;

                match status {
                    STATUS_SUCCESS => Ok(IosbResult::Success),
                    STATUS_CANCELLED => Ok(IosbResult::Cancelled),
                    STATUS_PENDING => Ok(IosbResult::Pending),
                    err => Err(io::Error::from_raw_os_error(err as _)),
                }
            }
        }

        fn into_ptr(self) -> *const IO_STATUS_BLOCK {
            unsafe { Arc::into_raw(Pin::into_inner_unchecked(self.0)) as _ }
        }

        fn from_ptr(ptr: *const IO_STATUS_BLOCK) -> Self {
            Self(unsafe { Pin::new_unchecked(Arc::from_raw(ptr as _)) })
        }

        fn status_block(&self) -> &UnsafeCell<IO_STATUS_BLOCK> {
            &self.0.iosb
        }

        /// Get the user data associated with this `StatusBlock`.
        pub(super) fn user_data(&self) -> Pin<&T> {
            self.0.as_ref().project_ref().data
        }

        /// Are two `StatusBlock` instances equal?
        pub(super) fn ptr_eq(a: &Self, b: &Self) -> bool {
            unsafe {
                Arc::ptr_eq(
                    &*(a as *const _ as *const Arc<IosbInner<T>>),
                    &*(b as *const _ as *const Arc<IosbInner<T>>),
                )
            }
        }
    }

    impl<T: AfdCompatible> StatusBlock<T> {
        /// Get the AFD block associated with this `StatusBlock`.
        fn afd_block(&self) -> &AfdPollInfo {
            assert_ne!(self.state(), IosbState::Pending);

            unsafe { self.user_data().afd_info().afd_handle() }
        }

        /// Get the `number_of_handles` field of the AFD block.
        pub(super) fn number_of_handles(&self) -> u32 {
            self.afd_block().number_of_handles
        }

        /// Get the `events` field of the AFD block.
        pub(super) fn events(&self) -> u32 {
            self.afd_block().handles[0].events
        }
    }

    /// A buffer for `OVERLAPPED_ENTRY` structures.
    ///
    /// This is used to hold the result of an I/O completion port wait operation.
    pub(super) struct OverlappedBuffer<T> {
        /// Unmovable vector of `OVERLAPPED_ENTRY` structures.
        ///
        /// The capacity of this vector must never be changed, or else the pointers to the
        /// `OVERLAPPED_ENTRY` structures will become invalid.
        entries: Vec<OVERLAPPED_ENTRY>,

        /// `OVERLAPPED_ENTRY` contains several `Arc<T>`'s.
        _marker: PhantomData<Vec<StatusBlock<T>>>,
    }

    unsafe impl<T: Send + Sync> Send for OverlappedBuffer<T> {}
    unsafe impl<T: Send + Sync> Sync for OverlappedBuffer<T> {}

    impl<T> OverlappedBuffer<T> {
        /// Create a new `OverlappedBuffer` with the given capacity.
        pub(super) fn new(capacity: usize) -> Self {
            Self {
                entries: Vec::with_capacity(capacity),
                _marker: PhantomData,
            }
        }

        /// Get a mutable pointer to the `OVERLAPPED_ENTRY` structure.
        fn as_mut_ptr(&mut self) -> *mut OVERLAPPED_ENTRY {
            self.entries.as_mut_ptr()
        }

        /// Get the total capacity of the buffer.
        fn capacity(&self) -> usize {
            self.entries.capacity()
        }

        /// Get the number of entries in the buffer.
        pub(super) fn len(&self) -> usize {
            self.entries.len()
        }

        /// Clear the buffer.
        pub(super) fn clear(&mut self) {
            self.entries.drain(..).for_each(|entry| {
                let ptr = entry.lpOverlapped as *const IO_STATUS_BLOCK;
                drop(StatusBlock::<T>::from_ptr(ptr));
            });
        }

        /// Drain the `StatusBlock` entries from the buffer.
        pub(super) fn drain(&mut self) -> impl ExactSizeIterator<Item = StatusBlock<T>> + '_ {
            self.entries.drain(..).map(|entry| {
                let ptr = entry.lpOverlapped as *const IO_STATUS_BLOCK;
                let iosb = StatusBlock::<T>::from_ptr(ptr);

                // Mark the I/O operation as completed.
                iosb.0
                    .state
                    .store(IosbState::Idle.into(), Ordering::Release);

                iosb
            })
        }
    }

    impl<T> Drop for OverlappedBuffer<T> {
        fn drop(&mut self) {
            // Make sure to drop all `StatusBlock` entries.
            self.clear();
        }
    }

    /// Convert an `NTSTATUS` to an I/O error.
    fn convert_ntstatus(status: NTSTATUS) -> io::Error {
        // Convert the error code.
        let dll = match NtdllImports::get() {
            Ok(dll) => dll,
            Err(e) => {
                // This branch should never be triggered, since another DLL function has to be loaded
                // to call this function.
                return e;
            }
        };

        let error = unsafe { dll.RtlNtStatusToDosError(status) };
        io::Error::from_raw_os_error(error as _)
    }
}

use crate::{Event, PollMode};

use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle, RawSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use syscalls::{
    Afd, AfdCompatible, AfdInfo, IoCompletionPort, IosbResult, IosbState, OverlappedBuffer,
};
use windows_sys::Win32::Foundation::ERROR_INVALID_HANDLE;

/// Interface to IOCP.
#[derive(Debug)]
pub(crate) struct Poller {
    /// The IOCP handle.
    iocp: IoCompletionPort<Notification>,

    /// The status block for `notify`ing the poller.
    notify_status_block: StatusBlock,

    /// The list of AFD handles we're using to poll sockets.
    ///
    /// Each AFD handle has a limited number of sockets that can be polled at once, so we need to
    /// create multiple AFD handles to poll more sockets.
    afd_handles: Mutex<Vec<Arc<Afd<Notification>>>>,

    /// Map between the raw sockets and their associated completion handles.
    ///
    /// Handles not in this map may still be being actively polled.
    socket_map: Mutex<HashMap<RawSocket, StatusBlock>>,

    /// Queue of sockets waiting to be updated.
    update_queue: Mutex<VecDeque<StatusBlock>>,

    /// The number of concurrent polling operations that currently exist on this poller.
    wait_count: AtomicUsize,
}

impl AsRawHandle for Poller {
    fn as_raw_handle(&self) -> RawHandle {
        self.iocp.as_raw_handle()
    }
}

#[cfg(not(polling_no_io_safety))]
impl std::os::windows::io::AsHandle for Poller {
    fn as_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(self.iocp.as_raw_handle()) }
    }
}

/// The maximum number of sockets that can be registered to one AFD handle at once.
const MAX_SOCKETS_PER_AFD: usize = 32;

impl Poller {
    /// Creates a new poller.
    pub fn new() -> io::Result<Poller> {
        // Create the IOCP handle.
        let iocp = IoCompletionPort::new().map_err(|e| {
            // Return a more descriptive error message for Wine users.
            crate::unsupported_error(
                format!(
                    "Failed to initialize polling: {}\nThis usually only happens for old Windows or Wine.",
                    e
                )
            )
        })?;

        log::trace!("new: iocp={:?}", &iocp);

        Ok(Self {
            iocp,
            notify_status_block: StatusBlock::new(Notification::Notify { _private: () }),
            afd_handles: Mutex::new(Vec::new()),
            socket_map: Mutex::new(HashMap::new()),
            update_queue: Mutex::new(VecDeque::new()),
            wait_count: AtomicUsize::new(0),
        })
    }

    /// Whether this poller supports level-triggered events.
    pub fn supports_level(&self) -> bool {
        true
    }

    /// Whether this poller supports edge-triggered events.
    pub fn supports_edge(&self) -> bool {
        // If we had control over the I/O operations, it would be possible to support edge
        // triggered mode. The idea would be:
        //  - When we receive an event, clear that event and only that event from the interest.
        //  - When the I/O encounters `WouldBlock`, set the event back to the interest.
        // This would also be possible to do with the `poll()` backend.
        false
    }

    /// Adds a socket.
    pub fn add(&self, socket: RawSocket, interest: Event, mode: PollMode) -> io::Result<()> {
        log::trace!("add_socket: socket={:?}, mode={:?}", socket, mode);

        // Get the AFD handle.
        let afd = self.afd_handle()?;

        // Create the status block.
        let status_block = StatusBlock::new(Notification::Socket {
            sock: SocketState {
                raw: socket,
                afd_poll: AfdInfo::new(socket)?,
                afd_handle: afd,
                events: Mutex::new(EventState {
                    interest,
                    read_pending: false,
                    write_pending: false,
                    mode,
                }),
                delete: AtomicBool::new(false),
                _pinned: core::marker::PhantomPinned,
            },
        });

        // Add it to the update queue.
        self.update_queue
            .lock()
            .unwrap()
            .push_back(status_block.clone());

        // Add the socket to the socket map.
        self.socket_map.lock().unwrap().insert(socket, status_block);

        // Update it now if we're mid-poll.
        self.update_if_polling()?;

        Ok(())
    }

    /// Modifies a socket.
    pub fn modify(&self, socket: RawSocket, interest: Event, mode: PollMode) -> io::Result<()> {
        log::trace!("modify_socket: socket={:?}, mode={:?}", socket, mode);

        let socket_map = self.socket_map.lock().unwrap();
        if let Some(status_block) = socket_map.get(&socket) {
            // Update the socket state.
            status_block.set_interest(interest, self, mode)?;
        }

        self.update_if_polling()?;

        Ok(())
    }

    /// Removes a socket.
    pub fn delete(&self, socket: RawSocket) -> io::Result<()> {
        log::trace!("delete_socket: socket={:?}", socket);

        let mut socket_map = self.socket_map.lock().unwrap();
        if let Some(status_block) = socket_map.remove(&socket) {
            // Queue for deletion.
            status_block.delete(self)?;
        }

        self.update_if_polling()?;

        Ok(())
    }

    /// Waits for I/O events with an optional timeout.
    ///
    /// Returns the number of processed I/O events.
    ///
    /// If a notification occurs, this method will return but the notification event will not be
    /// included in the `events` list nor contribute to the returned count.
    pub(crate) fn wait(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        log::trace!("wait: iocp={:?}, timeout={:?}", &self.iocp, timeout);
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));

        // Update the sockets before we start polling.
        self.update_sockets()?;

        // We are currently waiting; indicate as such.
        self.wait_count.fetch_add(1, Ordering::Relaxed);
        let _poll_guard = CallOnDrop(|| {
            // Drop the guard; we are no longer waiting.
            self.wait_count.fetch_sub(1, Ordering::Release);
        });

        loop {
            // Convert the timeout to milliseconds.
            let timeout_ms = match deadline {
                Some(deadline) => {
                    // Get the milliseconds until the deadline.
                    let timeout = deadline.saturating_duration_since(Instant::now());

                    // Round up to the next millisecond.
                    let mut ms = timeout.as_millis().try_into().unwrap_or(std::u64::MAX);
                    if Duration::from_millis(ms) > timeout {
                        ms = ms.saturating_add(1);
                    }
                    ms.try_into().unwrap_or(syscalls::INFINITE)
                }
                None => syscalls::INFINITE,
            };

            // Wait for an event.
            let Events { buffer, events } = events;
            let num_events = self.iocp.wait(buffer, timeout_ms)?;

            // Feed events to the sockets.
            let mut notified = false;
            events.reserve(buffer.len());
            for status in buffer.drain() {
                match status.on_event(self)? {
                    OnEventResult::NoEvents => {}
                    OnEventResult::Notification => {
                        // We got a notification; don't return it.
                        notified = true;
                    }
                    OnEventResult::OneEvent(event) => events.push(event),
                }
            }

            // If we had any events, or if we can't wait anymore, return.
            if num_events > 0 || timeout_ms == 0 || notified {
                return Ok(num_events);
            }
        }
    }

    /// Notify the poller.
    pub fn notify(&self) -> io::Result<()> {
        // Post a notification to the IOCP.
        self.iocp.post(&self.notify_status_block)
    }

    /// Run updates for every socket that is waiting to be updated.
    fn update_sockets(&self) -> io::Result<()> {
        // Take out the update queue to prevent mutex contention.
        let mut update_queue = std::mem::take(&mut *self.update_queue.lock().unwrap());

        // Poll every socket.
        let result = update_queue
            .drain(..)
            .try_for_each(|status_block| status_block.update(self));

        // Reuse capacity if possible.
        if let Ok(mut lock) = self.update_queue.try_lock() {
            let mut new_updates = std::mem::replace(&mut *lock, update_queue);

            if !new_updates.is_empty() {
                lock.append(&mut new_updates);
            }
        }

        result
    }

    /// Run updates for the sockets if we are in the middle of polling.
    #[inline]
    fn update_if_polling(&self) -> io::Result<()> {
        if self.wait_count.load(Ordering::Relaxed) > 0 {
            self.update_sockets()?;
        }

        Ok(())
    }

    /// Get an AFD handle that can be used to poll sockets.
    fn afd_handle(&self) -> io::Result<Arc<Afd<Notification>>> {
        let mut afd_handles = self.afd_handles.lock().unwrap();

        // Try to find an AFD that has some space left.
        if let Some(afd) = afd_handles.iter().find(|afd| {
            // Minus one, since we keep a reference to it.
            let num_sockets = Arc::strong_count(afd) - 1;
            num_sockets < MAX_SOCKETS_PER_AFD
        }) {
            return Ok(afd.clone());
        }

        // Otherwise, make a new handle.
        let afd = {
            let afd = Afd::new().map_err(|e| {
                // Return a more descriptive error message for Wine users.
                crate::unsupported_error(
                    format!(
                        "Failed to initialize polling: {}\nThis usually only happens for old Windows or Wine.",
                        e
                    )
                )
            })?;

            Arc::new(afd)
        };

        // Register it in our IOCP.
        self.iocp.register(&*afd, true)?;

        // Add it to the list.
        afd_handles.push(afd.clone());

        Ok(afd)
    }
}

/// Buffer for events.
pub(crate) struct Events {
    /// The buffer for `OVERLAPPED_ENTRY` structures.
    buffer: OverlappedBuffer<Notification>,

    /// The actual events.
    events: Vec<Event>,
}

impl Events {
    /// Create a new `Events` buffer.
    pub fn new() -> Events {
        Events {
            buffer: OverlappedBuffer::new(1024),
            events: Vec::new(),
        }
    }

    /// Get the events.
    pub fn iter(&self) -> impl Iterator<Item = Event> + '_ {
        self.events.iter().copied()
    }
}

type StatusBlock = syscalls::StatusBlock<Notification>;

pin_project_lite::pin_project! {
    /// The result of a notification.
    #[project_ref = NotificationProj]
    #[derive(Debug)]
    enum Notification {
        // This notification comes from a `notify` call.
        Notify { _private: () },

        // This notification comes from a socket.
        Socket { #[pin] sock: SocketState },
    }
}

pin_project_lite::pin_project! {
    /// State associated with a socket.
    struct SocketState {
        // The raw socket handle.
        raw: RawSocket,

        // Information used by the AFD backend for polling.
        #[pin]
        afd_poll: AfdInfo,

        // The AFD handle used to poll the socket.
        afd_handle: Arc<Afd<Notification>>,

        // State of the socket's events.
        events: Mutex<EventState>,

        // Whether this socket should be deleted once it is no longer in use.
        delete: AtomicBool,

        // Make sure we're pinned.
        #[pin]
        _pinned: std::marker::PhantomPinned,
    }
}

impl fmt::Debug for SocketState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SocketState { .. }")
    }
}

impl AfdCompatible for Notification {
    fn afd_info(self: Pin<&Self>) -> Pin<&AfdInfo> {
        match self.project_ref() {
            NotificationProj::Notify { .. } => unreachable!("cannot AFD poll a notification"),
            NotificationProj::Socket { sock } => sock.project_ref().afd_poll,
        }
    }

    fn afd_events(&self) -> syscalls::ULONG {
        match self {
            Notification::Notify { .. } => unreachable!("cannot AFD poll a notification"),
            Notification::Socket { sock } => {
                let mut events = 0;
                let state = sock.events.lock().unwrap();

                if state.interest.readable {
                    events |= AFD_READ_EVENTS;
                }

                if state.interest.writable {
                    events |= AFD_WRITE_EVENTS;
                }

                events
            }
        }
    }
}

impl StatusBlock {
    /// Set the interest of this status block.
    fn set_interest(&self, interest: Event, poller: &Poller, mode: PollMode) -> io::Result<()> {
        match self.user_data().project_ref() {
            NotificationProj::Notify { .. } => {
                unreachable!("cannot set interest of a notification")
            }
            NotificationProj::Socket { sock } => {
                let mut state = sock.events.lock().unwrap();

                state.mode = mode;
                if state.interest != interest {
                    state.interest = interest;

                    // If the socket is registered, we need to update it.
                    if (state.interest.readable && !state.read_pending)
                        || (state.interest.writable && !state.write_pending)
                    {
                        // We need to update the socket.
                        poller.update_queue.lock().unwrap().push_back(self.clone());
                    }
                }

                Ok(())
            }
        }
    }

    /// Update this status block's events and registration.
    fn update(&self, poller: &Poller) -> io::Result<()> {
        let socket = match self.user_data().project_ref() {
            NotificationProj::Notify { .. } => unreachable!("cannot update a notification"),
            NotificationProj::Socket { sock } => sock,
        };

        match self.state() {
            IosbState::Pending => {
                // There is still a pending operation. Cancel it if necessary.
                let event_state = socket.events.lock().unwrap();

                // It needs to be cancelled and updated if the pending events don't match the
                // incoming events.
                if (event_state.interest.readable && !event_state.read_pending)
                    || (event_state.interest.writable && !event_state.write_pending)
                {
                    // Cancel the pending operation.
                    drop(event_state);
                    self.cancel()?;
                }
            }

            IosbState::Cancelled => {
                // Do nothing, since we're waiting for it to return.
            }

            IosbState::Idle => {
                // There is no polling operation, start one.
                let result = socket.afd_handle.poll(self);

                if let Err(e) = result {
                    match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            // The socket is not ready yet, so we'll just wait for the next event.
                        }
                        _ if syscalls::last_error() == ERROR_INVALID_HANDLE => {
                            // Remove the socket from the poller.
                            poller.socket_map.lock().unwrap().remove(&socket.raw);
                            return Ok(());
                        }
                        _ => {
                            // Return as normal.
                            return Err(e);
                        }
                    }
                }

                // Operation was submitted; update pending events.
                let mut event_state = socket.events.lock().unwrap();
                event_state.read_pending = event_state.interest.readable;
                event_state.write_pending = event_state.interest.writable;
            }
        }

        Ok(())
    }

    /// An IOCP event has occurred involving this socket; update it accordingly.
    #[allow(clippy::never_loop)]
    fn on_event(&self, poller: &Poller) -> io::Result<OnEventResult> {
        let socket_state = match self.user_data().project_ref() {
            NotificationProj::Notify { .. } => {
                // Got a notification; indicate as such.
                return Ok(OnEventResult::Notification);
            }
            NotificationProj::Socket { sock } => sock,
        };

        let mut event_state = socket_state.events.lock().unwrap();

        // Clear the pending events.
        // State is already set to idle in the "drain" method.
        event_state.read_pending = false;
        event_state.write_pending = false;

        // See if we're about to be deleted; don't return if we do, and just quietly drop.
        if socket_state.delete.load(Ordering::SeqCst) {
            return Ok(OnEventResult::NoEvents);
        }

        // Request to be updated again.
        poller.update_queue.lock().unwrap().push_back(self.clone());

        // Figure out what events we got.
        let event = loop {
            // Check the IOSB status to see what happened.
            match self.result() {
                Ok(IosbResult::Cancelled) => {
                    // The operation was cancelled.
                    return Ok(OnEventResult::NoEvents);
                }
                Ok(IosbResult::Pending) => unreachable!("I/O operation is still pending"),
                Ok(IosbResult::Success) => {}
                Err(_) => {
                    // An error occurred.
                    break Event::all(event_state.interest.key);
                }
            }

            // If no socket events were reported, we received no events.
            if self.number_of_handles() == 0 {
                return Ok(OnEventResult::NoEvents);
            }

            let afd_events = self.events();
            if afd_events & syscalls::AFD_POLL_LOCAL_CLOSE != 0 {
                // The handle was closed; remove it from the poller.
                self.delete(poller)?;
                return Ok(OnEventResult::NoEvents);
            }

            // Convert AFD events to polling events, and make sure we only use events that the
            // user asked for.
            let mut interest = Event::none(event_state.interest.key);

            if afd_events & AFD_READ_EVENTS != 0 && event_state.interest.readable {
                interest.readable = true;
            }

            if afd_events & AFD_WRITE_EVENTS != 0 && event_state.interest.writable {
                interest.writable = true;
            }

            // Connect failure triggers both events.
            if afd_events & syscalls::AFD_POLL_CONNECT_FAIL != 0 {
                if event_state.interest.readable {
                    interest.readable = true;
                }

                if event_state.interest.writable {
                    interest.writable = true;
                }
            }

            break interest;
        };

        if !event.readable && !event.writable {
            // No events occurred.
            return Ok(OnEventResult::NoEvents);
        }

        // For oneshot mode, remove the event from the interest set.
        if event_state.mode == PollMode::Oneshot {
            event_state.interest.readable = false;
            event_state.interest.writable = false;
        }

        Ok(OnEventResult::OneEvent(event))
    }

    /// Cancel this status block's operations.
    fn cancel(&self) -> io::Result<()> {
        let state = match self.user_data().project_ref() {
            NotificationProj::Notify { .. } => return Ok(()),
            NotificationProj::Socket { sock } => sock,
        };

        // Cancel the AFD operation.
        state.afd_handle.cancel(self)?;
        Ok(())
    }

    /// Queue this socket for deletion.
    fn delete(&self, poller: &Poller) -> io::Result<()> {
        // Indicate that we're about to be deleted.
        let state = match self.user_data().project_ref() {
            NotificationProj::Notify { .. } => return Ok(()),
            NotificationProj::Socket { sock } => sock,
        };
        state.delete.store(true, Ordering::Release);

        // Cancel any pending I/O operations, if any.
        if self.state() == IosbState::Pending {
            self.cancel()?;
        }

        // Remove ourselves from the poller's socket map.
        poller.socket_map.lock().unwrap().remove(&state.raw);

        // Remove this socket from the update list.
        poller
            .update_queue
            .lock()
            .unwrap()
            .retain(|x| !StatusBlock::ptr_eq(self, x));

        Ok(())
    }
}

/// The result of polling a single socket for events.
enum OnEventResult {
    /// We yielded no events.
    NoEvents,

    /// We yielded one event.
    OneEvent(Event),

    /// We yielded a notification.
    Notification,
}

/// Event-related state for a socket.
struct EventState {
    /// The event that the user is interested in.
    interest: Event,

    /// Whether we have pending read operations.
    read_pending: bool,

    /// Whether we have pending write operations.
    write_pending: bool,

    /// The poll mode to emulate.
    mode: PollMode,
}

/// Events we poll for no matter what.
const AFD_UNIVERSAL_EVENTS: u32 = syscalls::AFD_POLL_LOCAL_CLOSE;
/// Read-related events.
const AFD_READ_EVENTS: u32 = AFD_UNIVERSAL_EVENTS
    | syscalls::AFD_POLL_RECEIVE
    | syscalls::AFD_POLL_RECEIVE_EXPEDITED
    | syscalls::AFD_POLL_ACCEPT
    | syscalls::AFD_POLL_DISCONNECT
    | syscalls::AFD_POLL_ABORT
    | syscalls::AFD_POLL_CONNECT_FAIL;
/// Write-related events.
const AFD_WRITE_EVENTS: u32 = AFD_UNIVERSAL_EVENTS | syscalls::AFD_POLL_SEND;

/// Call this closure on drop.
struct CallOnDrop<F: Fn()>(F);

impl<F: Fn()> Drop for CallOnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}
