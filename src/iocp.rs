//! Bindings to IOCP (Windows).

/// Safe bindings to the Windows API.
mod syscalls {
    use async_lock::OnceCell;
    use io_lifetimes::{
        AsHandle, AsSocket, BorrowedHandle, BorrowedSocket, OwnedHandle, OwnedSocket,
    };

    use std::cell::{Cell, UnsafeCell};
    use std::fmt;
    use std::io;
    use std::marker::{PhantomData, PhantomPinned};
    use std::mem::{self, MaybeUninit};
    use std::os::windows::prelude::{AsRawHandle, AsRawSocket, FromRawHandle, RawSocket, RawHandle};
    use std::pin::Pin;
    use std::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use windows_sys::Win32::Foundation::DuplicateHandle;
    use windows_sys::Win32::Foundation::{HANDLE, HINSTANCE, NTSTATUS, UNICODE_STRING};
    use windows_sys::Win32::Foundation::{
        INVALID_HANDLE_VALUE, STATUS_CANCELLED, STATUS_NOT_FOUND, STATUS_PENDING, STATUS_SUCCESS,
    };

    use windows_sys::Win32::Networking::WinSock::WSAIoctl;
    use windows_sys::Win32::Networking::WinSock::{SIO_BASE_HANDLE, SOCKET_ERROR};

    use windows_sys::Win32::Storage::FileSystem::SetFileCompletionNotificationModes;
    use windows_sys::Win32::Storage::FileSystem::NT_CREATE_FILE_DISPOSITION;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_OPEN, FILE_SHARE_READ, FILE_SHARE_WRITE, SYNCHRONIZE,
    };

    use windows_sys::Win32::System::IO::{
        CreateIoCompletionPort, GetQueuedCompletionStatusEx, PostQueuedCompletionStatus,
    };
    use windows_sys::Win32::System::IO::{OVERLAPPED, OVERLAPPED_ENTRY};

    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    use windows_sys::Win32::System::WindowsProgramming::FILE_SKIP_SET_EVENT_ON_HANDLE;
    use windows_sys::Win32::System::WindowsProgramming::{
        IO_STATUS_BLOCK, OBJECT_ATTRIBUTES, PIO_APC_ROUTINE,
    };

    pub(super) use windows_sys::Win32::System::WindowsProgramming::INFINITE;

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
        fn NtCancelIoFileEx(
            FileHandle: HANDLE,
            IoRequestToCancel: *mut IO_STATUS_BLOCK,
            IoStatusBlock: *mut IO_STATUS_BLOCK,
        ) -> NTSTATUS;

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

        fn RtlNtStatusToDosError(
            Status: NTSTATUS,
        ) -> ULONG;
    }

    impl NtdllImports {
        /// Get the global instance of `NtdllImports`.
        fn get() -> io::Result<&'static NtdllImports> {
            static NTDLL_IMPORTS: OnceCell<Result<NtdllImports, io::Error>> = OnceCell::new();

            let result = NTDLL_IMPORTS.get_or_init_blocking(|| unsafe {
                // Get a handle to ntdll.dll.
                let ntdll = GetModuleHandleA("ntdll.dll\0".as_ptr() as *const _);
                if ntdll == 0 {
                    return Err(io::Error::last_os_error());
                }

                // Load the imports.
                NtdllImports::load(ntdll)
            });

            match result {
                Ok(imports) => Ok(imports),
                Err(e) => Err(io::Error::from(e.kind())),
            }
        }
    }

    /// Get the base socket for a `BorrowedSocket` type.
    fn base_socket(sock: BorrowedSocket<'_>) -> io::Result<RawSocket> {
        let mut socket: MaybeUninit<RawSocket> = MaybeUninit::uninit();
        let mut bytes: MaybeUninit<u32> = MaybeUninit::uninit();

        let result = unsafe {
            WSAIoctl(
                sock.as_raw_socket() as _,
                SIO_BASE_HANDLE,
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
            Ok(unsafe { socket.assume_init() })
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
        pub(super) handle: RawSocket,
        pub(super) events: ULONG,
        pub(super) status: NTSTATUS,
    }

    /// The poll info structure the AFD expects.
    #[repr(C)]
    pub(super) struct AfdPollInfo {
        pub(super) timeout: i64,
        pub(super) number_of_handles: ULONG,
        pub(super) exclusive: i8,
        pub(super) handles: [AfdPollHandleInfo; 1],
    }

    pin_project_lite::pin_project! {
        /// A type that contains an AFD poll info structure.
        pub struct AfdWrapper {
            // AFD polling info.
            //
            // This is wrapped in `UnsafeCell` to indicate that it may be changed outside of Rust's
            // control, so alias optimizations should not apply.
            #[pin]
            poll_info: UnsafeCell<AfdPollInfo>,

            // The raw base socket.
            base_socket: RawSocket,
        }
    }

    impl AfdWrapper {
        /// Create a new `AfdWrapper` around a socket type.
        pub(super) fn new(socket: &impl AsSocket) -> io::Result<Self> {
            // Get the base socket.
            let base_socket = base_socket(socket.as_socket())?;

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

        /// Replenish the AFD poll info structure.
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

        fn afd_info(self: Pin<&Self>) -> *mut AfdPollInfo {
            self.project_ref().poll_info.get()
        }
    }

    /// A type that contains an AFD poll info structure.
    pub(super) trait AfdCompatible {
        /// Get the AFD poll info structure.
        fn afd_info(self: Pin<&Self>) -> Pin<&AfdWrapper>;

        /// The AFD events that we want to poll.
        fn afd_events(&self) -> ULONG;
    }

    /// Wrapper around the `\Device\Afd` device.
    pub(super) struct Afd<T> {
        /// Handle to the AFD device.
        handle: OwnedHandle,

        /// Capture the `T` generic.
        _marker: PhantomData<Pin<Arc<T>>>,
    }

    impl<T> fmt::Debug for Afd<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.pad("Afd { .. }")
        }
    }

    impl<T> AsHandle for Afd<T> {
        fn as_handle(&self) -> BorrowedHandle<'_> {
            self.handle.as_handle()
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
            let mut handle: MaybeUninit<OwnedHandle> = MaybeUninit::uninit();
            let mut status_block: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();

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
            unsafe {
                iosb.user_data().afd_info().replenish(iosb.user_data().afd_events());
                let iosb = &mut *iosb.status_block().get();
                iosb.Anonymous.Status = STATUS_PENDING;
            }

            let poll_info = iosb.user_data().afd_info().afd_info();

            // Poll the AFD.
            let status = unsafe {
                NtdllImports::get()?.NtDeviceIoControlFile(
                    self.handle.as_raw_handle() as HANDLE,
                    0,
                    None,
                    ptr::null_mut(),
                    iosb.status_block().get(),
                    IOCTL_AFD_POLL,
                    poll_info as _,
                    mem::size_of::<AfdPollInfo>() as _,
                    poll_info as _,
                    mem::size_of::<AfdPollInfo>() as _,
                )
            };

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
        /// # Safety
        ///
        /// `iosb` must be an `IO_STATUS_BLOCK` structure that was passed to `poll`.
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
                    self.handle.as_raw_handle() as HANDLE,
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
    pub(super) struct IoCompletionPort<T> {
        /// The handle to the I/O completion port.
        handle: OwnedHandle,

        /// Captures the `T` type parameter.
        _marker: PhantomData<T>,
    }

    impl<T> fmt::Debug for IoCompletionPort<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            struct DebugHandle<'a>(BorrowedHandle<'a>);

            impl fmt::Debug for DebugHandle<'_> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    fmt::Pointer::fmt(&self.0.as_raw_handle(), f)
                }
            }

            f.debug_tuple("IoCompletionPort")
                .field(&DebugHandle(self.handle.as_handle()))
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
                handle: unsafe { OwnedHandle::from_raw_handle(handle as _) },
                _marker: PhantomData,
            })
        }

        /// Register a handle with the I/O completion port.
        pub(super) fn register(
            &self,
            handle: &impl AsHandle,
            skip_set_event: bool,
        ) -> io::Result<()> {
            // Register the handle.
            let raw = handle.as_handle().as_raw_handle() as _;
            let handle =
                unsafe { CreateIoCompletionPort(raw, self.handle.as_raw_handle() as _, 0, 0) };

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
        pub(super) fn post(&self, sb: StatusBlock<T>) -> io::Result<()> {
            // Post the completion packet.
            let status = unsafe {
                PostQueuedCompletionStatus(
                    self.handle.as_raw_handle() as _,
                    0,
                    0,
                    sb.status_block().get() as _,
                )
            };

            if status == 0 {
                return Err(io::Error::last_os_error());
            }

            Ok(())
        }

        /// Get the next completion packets from the I/O completion port.
        pub(super) fn wait(
            &self,
            entries: &mut OverlappedBuffer<T>,
            timeout: u32,
        ) -> io::Result<usize> {
            // Wait for the completion packets.
            let mut num_entries = 0;

            let status = unsafe {
                GetQueuedCompletionStatusEx(
                    self.handle.as_raw_handle() as _,
                    entries.as_mut_ptr() as _,
                    entries.capacity() as _,
                    &mut num_entries,
                    timeout,
                    false as _,
                )
            };

            // If the status is false, then we have an error.
            if status == 0 {
                return Err(io::Error::last_os_error());
            }

            // Update the number of entries.
            unsafe {
                entries.entries.set_len(num_entries as _);
            }
            Ok(num_entries as _)
        }
    }

    impl<T> AsRawHandle for IoCompletionPort<T> {
        fn as_raw_handle(&self) -> RawHandle {
            self.handle.as_raw_handle()
        }
    }

    impl<T> AsHandle for IoCompletionPort<T> {
        fn as_handle(&self) -> BorrowedHandle<'_> {
            self.handle.as_handle()
        }
    }

    /// An `IO_STATUS_BLOCK` entry combined with a user data type.
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

    #[repr(usize)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub(super) enum IosbState {
        /// The I/O operation has completed.
        Completed = 0,

        /// The I/O operation is pending.
        Pending = 1,

        /// The last I/O operation was cancelled.
        Cancelled = 2,
    }

    impl From<usize> for IosbState {
        fn from(value: usize) -> Self {
            match value {
                0 => Self::Completed,
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

    impl<T> StatusBlock<T> {
        /// Create a new `StatusBlock` with the given user data.
        pub(super) fn new(data: T) -> Self {
            Self(Arc::pin(IosbInner {
                iosb: unsafe {
                    let mut iosb: IO_STATUS_BLOCK = mem::zeroed();
                    iosb.Anonymous.Status = STATUS_PENDING;
                    UnsafeCell::new(iosb)
                },
                state: AtomicUsize::new(IosbState::Completed.into()),
                data,
                _pin: PhantomPinned,
            }))
        }

        /// Get the current state of the I/O operation.
        pub(super) fn state(&self) -> IosbState {
            self.0.state.load(Ordering::Acquire).into()
        }

        /// Was this block cancelled in its last operation?
        pub(super) fn cancelled(&self) -> bool {
            assert_eq!(self.state(), IosbState::Completed);

            unsafe {
                let iosb = self.0.iosb.get();
                (*iosb).Anonymous.Status == STATUS_CANCELLED
            }
        }

        /// Did this block have an error?
        pub(super) fn error(&self) -> bool {
            assert_eq!(self.state(), IosbState::Completed);

            unsafe {
                let iosb = self.0.iosb.get();
                (*iosb).Anonymous.Status != STATUS_SUCCESS
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
    }

    impl<T: AfdCompatible> StatusBlock<T> {
        /// Get the AFD block associated with this `StatusBlock`.
        pub(super) fn afd_block(&self) -> &AfdPollInfo{
            assert_eq!(self.state(), IosbState::Completed);

            unsafe { self.user_data().afd_info().afd_handle() }
        }
    }

    /// A buffer for `OVERLAPPED_ENTRY` structures.
    pub(super) struct OverlappedBuffer<T> {
        /// Unmovable vector of `OVERLAPPED_ENTRY` structures.
        ///
        /// The capacity of this vector must never be changed, or else the pointers to the
        /// `OVERLAPPED_ENTRY` structures will become invalid.
        entries: Vec<OVERLAPPED_ENTRY>,

        /// `OVERLAPPED_ENTRY` contains several `Arc<T>`'s.
        _marker: PhantomData<Vec<Pin<Arc<T>>>>,
    }

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
                    .store(IosbState::Completed.into(), Ordering::Release);

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

use io_lifetimes::BorrowedSocket;
use slab::Slab;

use std::collections::{HashMap, VecDeque};
use std::convert::TryInto;
use std::io;
use std::fmt;
use std::os::windows::io::{RawSocket, AsRawHandle};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use syscalls::{Afd, AfdCompatible, AfdWrapper, IoCompletionPort, OverlappedBuffer};
use windows_sys::Win32::Foundation::{STATUS_SUCCESS, GetLastError, ERROR_INVALID_HANDLE};

use self::syscalls::{IosbState, AFD_POLL_LOCAL_CLOSE};

/// Interface to IOCP.
#[derive(Debug)]
pub(crate) struct Poller {
    /// The IOCP handle.
    iocp: IoCompletionPort<Notification>,

    /// The status block for `notify`ing the poller.
    notify_status_block: StatusBlock,

    /// The list of AFD handles we're using to poll sockets.
    afd_handles: Mutex<Vec<Arc<Afd<Notification>>>>,

    /// Map between the raw sockets and their associated completion handles.
    socket_map: Mutex<HashMap<RawSocket, StatusBlock>>,

    /// Queue of sockets waiting to be updated.
    update_queue: Mutex<VecDeque<StatusBlock>>,

    /// List of sockets waiting to be deleted.
    waiting_for_delete: Mutex<Slab<StatusBlock>>,

    /// The number of concurrent polling operations that currently exist on this poller.
    wait_count: AtomicUsize,
}

impl AsRawHandle for Poller {
    fn as_raw_handle(&self) -> std::os::windows::io::RawHandle {
        todo!()
    }
}

#[cfg(not(polling_no_io_safety))]
impl std::os::windows::io::AsHandle for Poller {
    fn as_handle(&self) -> std::os::windows::io::BorrowedHandle<'_> {
        self.iocp.as_handle()
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
            waiting_for_delete: Mutex::new(Slab::new()),
            wait_count: AtomicUsize::new(0),
        })
    }

    /// Whether this poller supports level-triggered events.
    pub fn supports_level(&self) -> bool {
        true
    }

    /// Whether this poller supports edge-triggered events.
    pub fn supports_edge(&self) -> bool {
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
                afd_poll: AfdWrapper::new(&unsafe { BorrowedSocket::borrow_raw(socket) })?,
                afd_handle: afd,
                events: Mutex::new(EventState {
                    interest,
                    read_pending: false,
                    write_pending: false,
                    mode,
                }),
                deletion_index: AtomicUsize::new(usize::MAX),
                _pinned: core::marker::PhantomPinned
            }
        });

        // Add it to the update queue.
        self.update_queue.lock().unwrap().push_back(status_block.clone());

        // Add the socket to the socket map.
        self.socket_map
            .lock()
            .unwrap()
            .insert(socket, status_block);

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
            let index = self.waiting_for_delete.lock().unwrap().insert(status_block.clone());

            match status_block.user_data().project_ref() {
                NotificationProj::Socket { sock } => {
                    sock.deletion_index.store(index, Ordering::SeqCst);
                }
                _ => unreachable!(),
            }
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
        self.wait_count.fetch_add(1, Ordering::SeqCst);
        let _poll_guard = CallOnDrop(|| {
            // Drop the guard; we are no longer waiting.
            self.wait_count.fetch_sub(1, Ordering::SeqCst);
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
        self.iocp.post(self.notify_status_block.clone())
    }

    /// Run updates for every socket that is waiting to be updated.
    fn update_sockets(&self) -> io::Result<()> {
        self.update_queue
            .lock()
            .unwrap()
            .drain(..)
            .try_for_each(|status_block| status_block.update(self))
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

        // Otherwise, make a new one.
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

    /// Clear the events.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.events.clear();
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
        afd_poll: AfdWrapper,

        // The AFD handle used to poll the socket.
        afd_handle: Arc<Afd<Notification>>,

        // State of the socket's events.
        events: Mutex<EventState>,

        // The index in the deletion list we're at, or `MAX` if we're not in the deletion list.
        deletion_index: AtomicUsize,

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
    fn afd_info(self: Pin<&Self>) -> Pin<&AfdWrapper> {
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
                let mut state = sock.events.lock().unwrap();

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
            NotificationProj::Notify { .. } => unreachable!("cannot set interest of a notification"),
            NotificationProj::Socket { sock } => {
                let mut state = sock.events.lock().unwrap();

                state.mode = mode;
                if state.interest != interest {
                    state.interest = interest;

                    // If the socket is registered, we need to update it.
                    if (state.interest.readable && !state.read_pending) || (
                        state.interest.writable && !state.write_pending
                    ) {
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

            IosbState::Completed => {
                // There is no polling operation, start one.
                let result = socket.afd_handle.poll(self);

                if let Err(e) = result {
                    match e.kind() {
                        io::ErrorKind::WouldBlock => {
                            // The socket is not ready yet, so we'll just wait for the next event.
                        }
                        _ if unsafe { GetLastError() } == ERROR_INVALID_HANDLE => {
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

                // Update pending events.
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
        let user_data = self.user_data().project_ref();

        let socket_state = match user_data {
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

        // See if we're about to be deleted; if so, delete us from the list.
        let deleted_index = socket_state.deletion_index.load(Ordering::Acquire);
        if deleted_index != std::usize::MAX {
            let mut deleted = poller.waiting_for_delete.lock().unwrap();
            deleted.remove(deleted_index);
            return Ok(OnEventResult::NoEvents);
        }

        // Request to be added again.
        poller.update_queue.lock().unwrap().push_back(self.clone());

        // Figure out what events we got.
        let event = loop {
            // If we were cancelled, we received no events.
            if self.cancelled() {
                return Ok(OnEventResult::NoEvents);
            }

            // If there was an error, report it.
            if self.error() {
                break Event::all(event_state.interest.key);
            }

            // Get the AFD block.
            let afd_block = self.afd_block();

            // If no socket events were reported, we received no events.
            if afd_block.number_of_handles == 0 { 
                return Ok(OnEventResult::NoEvents);
            }

            let afd_events = afd_block.handles[0].events;
            if afd_events & syscalls::AFD_POLL_LOCAL_CLOSE != 0 {
                // We need to remove this block.
                poller.socket_map.lock().unwrap().remove(&socket_state.raw);
                return Ok(OnEventResult::NoEvents);
            }

            // Convert AFD events to polling events.
            let mut interest = Event::none(event_state.interest.key);

            if afd_events & AFD_READ_EVENTS != 0 {
                interest.readable = true;
            }

            if afd_events & AFD_WRITE_EVENTS != 0 {
                interest.writable = true;
            }

            break interest;
        };

        if !event.readable && !event.writable {
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
}

enum OnEventResult {
    /// We yielded no events.
    NoEvents,

    /// We yielded one event.
    OneEvent(Event),

    /// We yielded a notification.
    Notification,
}

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

const AFD_UNIVERSAL_EVENTS: u32 = syscalls::AFD_POLL_LOCAL_CLOSE;
const AFD_READ_EVENTS: u32 = AFD_UNIVERSAL_EVENTS
    | syscalls::AFD_POLL_RECEIVE
    | syscalls::AFD_POLL_RECEIVE_EXPEDITED
    | syscalls::AFD_POLL_ACCEPT
    | syscalls::AFD_POLL_DISCONNECT
    | syscalls::AFD_POLL_ABORT
    | syscalls::AFD_POLL_CONNECT_FAIL;
const AFD_WRITE_EVENTS: u32 = AFD_UNIVERSAL_EVENTS | syscalls::AFD_POLL_SEND;

/// Call this closure on drop.
struct CallOnDrop<F: Fn()>(F);

impl<F: Fn()> Drop for CallOnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}
