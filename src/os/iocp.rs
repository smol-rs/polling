//! Functionality that is only available for IOCP-based platforms.

use windows_sys::Win32::Foundation as wf;
use windows_sys::Win32::System::IO::{OVERLAPPED, OVERLAPPED_ENTRY};

use crate::iocp::ntdll::NtdllImports;
use crate::iocp::FileCompletionStatus;
pub use crate::iocp::FileOverlappedWrapper;
pub use crate::sys::CompletionPacket;

use super::__private::PollerSealed;
use crate::{Event, PollMode, Poller};

use std::cell::UnsafeCell;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::os::windows::prelude::{AsHandle, BorrowedHandle};
use std::ptr::NonNull;

/// Extension trait for the [`Poller`] type that provides functionality specific to IOCP-based
/// platforms.
///
/// [`Poller`]: crate::Poller
pub trait PollerIocpExt: PollerSealed {
    /// Post a new [`Event`] to the poller.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use polling::{Poller, Event, Events};
    /// use polling::os::iocp::{CompletionPacket, PollerIocpExt};
    ///
    /// use std::thread;
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// // Spawn a thread to wake us up after 100ms.
    /// let poller = Arc::new(Poller::new()?);
    /// thread::spawn({
    ///     let poller = poller.clone();
    ///     move || {
    ///         let packet = CompletionPacket::new(Event::readable(0));
    ///         thread::sleep(Duration::from_millis(100));
    ///         poller.post(packet).unwrap();
    ///     }
    /// });
    ///
    /// // Wait for the event.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None)?;
    ///
    /// assert_eq!(events.len(), 1);
    /// # Ok(()) }
    /// ```
    fn post(&self, packet: CompletionPacket) -> io::Result<()>;

    /// Add a waitable handle to this poller.
    ///
    /// Some handles in Windows are "waitable", which means that they emit a "readiness" signal
    /// after some event occurs. This function can be used to wait for such events to occur
    /// on a handle. This function can be used in addition to regular socket polling.
    ///
    /// Waitable objects include the following:
    ///
    /// - Console inputs
    /// - Waitable events
    /// - Mutexes
    /// - Processes
    /// - Semaphores
    /// - Threads
    /// - Timer
    ///
    /// Once the object has been signalled, the poller will emit the `interest` event.
    ///
    /// # Safety
    ///
    /// The added handle must not be dropped before it is deleted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::{Poller, Event, Events, PollMode};
    /// use polling::os::iocp::PollerIocpExt;
    ///
    /// use std::process::Command;
    ///
    /// // Spawn a new process.
    /// let mut child = Command::new("echo")
    ///     .arg("Hello, world!")
    ///     .spawn()
    ///     .unwrap();
    ///
    /// // Create a new poller.
    /// let poller = Poller::new().unwrap();
    ///
    /// // Add the child process to the poller.
    /// unsafe {
    ///     poller.add_waitable(&child, Event::all(0), PollMode::Oneshot).unwrap();
    /// }
    ///
    /// // Wait for the child process to exit.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events.iter().next().unwrap(), Event::all(0));
    /// ```
    unsafe fn add_waitable(
        &self,
        handle: impl AsRawWaitable,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()>;

    /// Modify an existing waitable handle.
    ///
    /// This function can be used to change the emitted event and/or mode of an existing waitable
    /// handle. The handle must have been previously added to the poller using [`add_waitable`].
    ///
    /// [`add_waitable`]: Self::add_waitable
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::{Poller, Event, Events, PollMode};
    /// use polling::os::iocp::PollerIocpExt;
    ///
    /// use std::process::Command;
    ///
    /// // Spawn a new process.
    /// let mut child = Command::new("echo")
    ///     .arg("Hello, world!")
    ///     .spawn()
    ///     .unwrap();
    ///
    /// // Create a new poller.
    /// let poller = Poller::new().unwrap();
    ///
    /// // Add the child process to the poller.
    /// unsafe {
    ///     poller.add_waitable(&child, Event::all(0), PollMode::Oneshot).unwrap();
    /// }
    ///
    /// // Wait for the child process to exit.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events.iter().next().unwrap(), Event::all(0));
    ///
    /// // Modify the waitable handle.
    /// poller.modify_waitable(&child, Event::readable(0), PollMode::Oneshot).unwrap();
    /// ```
    fn modify_waitable(
        &self,
        handle: impl AsWaitable,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()>;

    /// Remove a waitable handle from this poller.
    ///
    /// This function can be used to remove a waitable handle from the poller. The handle must
    /// have been previously added to the poller using [`add_waitable`].
    ///
    /// [`add_waitable`]: Self::add_waitable
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::{Poller, Event, Events, PollMode};
    /// use polling::os::iocp::PollerIocpExt;
    ///
    /// use std::process::Command;
    ///
    /// // Spawn a new process.
    /// let mut child = Command::new("echo")
    ///     .arg("Hello, world!")
    ///     .spawn()
    ///     .unwrap();
    ///
    /// // Create a new poller.
    /// let poller = Poller::new().unwrap();
    ///
    /// // Add the child process to the poller.
    /// unsafe {
    ///     poller.add_waitable(&child, Event::all(0), PollMode::Oneshot).unwrap();
    /// }
    ///
    /// // Wait for the child process to exit.
    /// let mut events = Events::new();
    /// poller.wait(&mut events, None).unwrap();
    ///
    /// assert_eq!(events.len(), 1);
    /// assert_eq!(events.iter().next().unwrap(), Event::all(0));
    ///
    /// // Remove the waitable handle.
    /// poller.remove_waitable(&child).unwrap();
    /// ```
    fn remove_waitable(&self, handle: impl AsWaitable) -> io::Result<()>;
}

impl PollerIocpExt for Poller {
    fn post(&self, packet: CompletionPacket) -> io::Result<()> {
        self.poller.post(packet)
    }

    unsafe fn add_waitable(
        &self,
        handle: impl AsRawWaitable,
        event: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        self.poller
            .add_waitable(handle.as_raw_handle(), event, mode)
    }

    fn modify_waitable(
        &self,
        handle: impl AsWaitable,
        interest: Event,
        mode: PollMode,
    ) -> io::Result<()> {
        self.poller
            .modify_waitable(handle.as_waitable().as_raw_handle(), interest, mode)
    }

    fn remove_waitable(&self, handle: impl AsWaitable) -> io::Result<()> {
        self.poller
            .remove_waitable(handle.as_waitable().as_raw_handle())
    }
}

/// A type that represents a waitable handle.
pub trait AsRawWaitable {
    /// Returns the raw handle of this waitable.
    fn as_raw_handle(&self) -> RawHandle;
}

impl AsRawWaitable for RawHandle {
    fn as_raw_handle(&self) -> RawHandle {
        *self
    }
}

impl<T: AsRawHandle + ?Sized> AsRawWaitable for &T {
    fn as_raw_handle(&self) -> RawHandle {
        AsRawHandle::as_raw_handle(*self)
    }
}

/// A type that represents a waitable handle.
pub trait AsWaitable: AsHandle {
    /// Returns the raw handle of this waitable.
    fn as_waitable(&self) -> BorrowedHandle<'_> {
        self.as_handle()
    }
}

impl<T: AsHandle + ?Sized> AsWaitable for T {}

/// Overlapped structure owned by the poller and returned to the caller when calling [`add_file`].
/// The caller must use this structure to get read overlapped ptr or write overlapped ptr as parameter
/// in ReadFile/WriteFile APIs. Otherwise, the behavior is undefined.
///
/// The overlapped ptr can be safely converted to 'FileOverlappedWrapper' to check result.
///
/// [`add_file`]: crate::os::iocp::PollerIocpFileExt::add_file
#[derive(Debug, Clone, Copy)]
pub struct IocpFilePacket {
    /// read pointer to the overlapped structure
    read: NonNull<OVERLAPPED>,
    /// write pointer to the overlapped structure
    write: NonNull<OVERLAPPED>,
}

impl IocpFilePacket {
    /// Create a new `IocpFilePacket` with the given `OVERLAPPED` pointer.
    pub(crate) fn new(read: *mut OVERLAPPED, write: *mut OVERLAPPED) -> Self {
        Self {
            read: NonNull::new(read).unwrap(),
            write: NonNull::new(write).unwrap(),
        }
    }

    /// Get the raw read overlapped pointer to the `OVERLAPPED` structure.
    pub fn read_ptr(&self) -> *mut OVERLAPPED {
        self.read.as_ptr()
    }

    /// Get the raw write overlapped pointer to the `OVERLAPPED` structure.
    pub fn write_ptr(&self) -> *mut OVERLAPPED {
        self.write.as_ptr()
    }
}

/// Extension trait for the [`Poller`] type that provides file specific functionality to IOCP-based
/// platforms.
///
/// [`Poller`]: crate::Poller
pub trait PollerIocpFileExt: PollerSealed {
    /// Add a file handle to this poller.
    ///
    /// File handle can be used in file read/write operation such as: [`ReadFile`], [`WriteFile`], etc API.
    /// Those APIs have LPOVERLAPPED as parameter which will be reutrned in IOCP port polling.
    ///
    /// [`ReadFile`]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
    /// [`WriteFile`]: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
    ///
    /// File handle could be used with various types of handles, including:
    /// - **File Handles**
    ///   - Regular files - Created with CreateFile
    ///   - Directories - For writing directory entries (limited scenarios)
    ///   - Physical disks and volumes - Raw disk access
    /// - **Communication Handles**
    ///   - Named pipes - Both client and server sides
    ///   - Anonymous pipes - For inter-process communication
    ///   - Mailslots - For one-to-many communication
    /// - **Device Handles**
    ///   - Serial ports (COM ports)
    ///   - Parallel ports (LPT ports)
    ///   - Console output
    ///   - Tape drives
    ///   - CD-ROM/DVD drives (for raw access)
    /// - **Network Handles**
    ///   - Sockets - Though send() is typically preferred for sockets
    /// - **Special Handles**
    ///   - Memory-mapped files - When accessed as file handles
    ///   - Virtual files - Some virtual file systems
    ///
    /// The returned [`IocpFilePacket`] provide read/write overlapped pointer used in ReadFile/WriteFile as overlapped pointer parameter.
    /// Once the read/write operation is called with this function readed overlapped pointer, the poller will emit the `interest` event
    /// when the operation is completed. The overlapped pointer can be safely converted to [`FileOverlappedWrapper`] to check result.
    ///
    /// File handle work on PollMode::Edge mode. The IOCP continue to poll the events unitl
    /// the file is closed. The caller must use the overlapped pointer return in IocpFilePacket
    /// as overlapped paramter for I/O operation. The Packet do not need to increase Arc count because
    /// the call can trigger events through I/O operation without update intrest events as long as the
    /// file handle has been registered with the IOCP. So the Packet lifetime is ended with calling [`remove_file`].
    /// Any I/O operation using returned overlapped pointer in IocpFilePacket is undefined behavior.
    ///
    /// IocpFilePacket will return both read and write overlapped pointer no matter what intrest events are.
    /// The caller need to use the correct overlapped pointer for I/O operation. Such as: the read overlapped
    /// pointer can be used for read operations, and the write overlapped pointer can be used for write operations.
    ///
    /// # Safety
    ///
    /// The added handle must not be dropped before it is deleted.
    /// The returned [`IocpFilePacket`] must not be used after [`remove_file`] is called.
    ///
    /// [`remove_file`]: crate::os::iocp::PollerIocpFileExt::remove_file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::os::iocp::{FileOverlappedWrapper, Overlapped, PollerIocpFileExt};
    /// use polling::{Event, Events, Poller};
    /// use windows_sys::Win32::System::IO::OVERLAPPED;
    ///
    /// use std::ffi::OsStr;
    /// use std::fs::OpenOptions;
    /// use std::io;
    /// use std::os::windows::ffi::OsStrExt;
    /// use std::os::windows::fs::OpenOptionsExt;
    /// use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
    /// use std::time::Duration;
    ///
    /// use windows_sys::Win32::{
    ///     Foundation as wf, Storage::FileSystem as wfs, System::Pipes as wps, System::IO as wio,
    /// };
    ///
    /// fn new_named_pipe<A: AsRef<OsStr>>(addr: A) -> io::Result<OwnedHandle> {
    ///    let fname = addr
    ///        .as_ref()
    ///        .encode_wide()
    ///        .chain(Some(0))
    ///        .collect::<Vec<_>>();
    ///    let handle = unsafe {
    ///        let raw_handle = wps::CreateNamedPipeW(
    ///            fname.as_ptr(),
    ///            wfs::PIPE_ACCESS_DUPLEX | wfs::FILE_FLAG_OVERLAPPED,
    ///            wps::PIPE_TYPE_BYTE | wps::PIPE_READMODE_BYTE | wps::PIPE_WAIT,
    ///            1,
    ///            4096,
    ///            4096,
    ///            0,
    ///            std::ptr::null_mut(),
    ///        );
    ///
    ///        if raw_handle == wf::INVALID_HANDLE_VALUE {
    ///            return Err(io::Error::last_os_error());
    ///        }
    ///
    ///        OwnedHandle::from_raw_handle(raw_handle as _)
    ///    };
    ///
    ///    Ok(handle)
    /// }
    ///
    /// fn server() -> (OwnedHandle, String) {
    ///     let num: u64 = fastrand::u64(..);
    ///     let name = format!(r"\\.\pipe\my-pipe-{}", num);
    ///     let pipe = new_named_pipe(&name).unwrap();
    ///     (pipe, name)
    /// }
    ///
    /// fn client(name: &str) -> io::Result<OwnedHandle> {
    ///     let mut opts = OpenOptions::new();
    ///     opts.read(true)
    ///         .write(true)
    ///         .custom_flags(wfs::FILE_FLAG_OVERLAPPED);
    ///     let file = opts.open(name)?;
    ///     unsafe { Ok(OwnedHandle::from_raw_handle(file.into_raw_handle())) }
    /// }
    ///
    /// fn pipe() -> (OwnedHandle, OwnedHandle) {
    ///     let (pipe, name) = server();
    ///     (pipe, client(&name).unwrap())
    /// }
    ///
    /// fn write_then_read() {
    ///     unsafe {
    ///         let (server, client) = pipe();
    ///         let poller = Poller::new().unwrap();
    ///         let mut events = Events::new();
    ///
    ///         let server_overlapped = unsafe {
    ///             poller
    ///                 .add_file(&server, Event::new(1, true, false))
    ///                 .unwrap()
    ///         };
    ///
    ///         let client_overlapped = poller.add_file(&client, Event::new(2, true, true)).unwrap();
    ///
    ///         let mut written = 0u32;
    ///         let ret = wfs::WriteFile(
    ///             client.as_raw_handle(),
    ///             b"1234" as *const u8,
    ///             4,
    ///             (&mut written) as *mut u32,
    ///             client_overlapped.write_ptr(),
    ///         );
    ///
    ///         assert!(ret == wf::TRUE && written == 4);
    ///
    ///         loop {
    ///             poller.wait(&mut events, None).unwrap();
    ///             let events = events.iter().collect::<Vec<_>>();
    ///             if let Some(event) = events.iter().find(|e| e.key == 2) {
    ///                 if event.writable {
    ///                     break;
    ///                 }
    ///             }
    ///         }
    ///
    ///         events.clear();
    ///         let mut buf = [0u8; 10];
    ///
    ///         let mut read = 0u32;
    ///         let ret = wfs::ReadFile(
    ///             server.as_raw_handle(),
    ///             &mut buf as *mut u8,
    ///             10,
    ///             (&mut read) as *mut u32,
    ///             server_overlapped.read_ptr(),
    ///         );
    ///
    ///         let event_len = poller
    ///             .wait(&mut events, Some(Duration::from_millis(10)))
    ///             .unwrap();
    ///         assert_eq!(event_len, 1);
    ///
    ///         let events = events.iter().collect::<Vec<_>>();
    ///         events.iter().for_each(|e| {
    ///             if e.key == 2 {
    ///                 assert_eq!(e.writable, true);
    ///             }
    ///         });
    ///
    ///         assert!(ret == wf::TRUE && read == 4);
    ///         assert_eq!(&buf[..4], b"1234");
    ///
    ///         poller.remove_file(&server).unwrap();
    ///         poller.remove_file(&client).unwrap();
    ///         drop(server);
    ///         drop(client);
    ///     }
    /// }
    /// ```
    unsafe fn add_file(&self, file: &impl AsRawHandle, event: Event) -> io::Result<IocpFilePacket>;

    /// Remove a file handle from this poller.
    ///
    /// This function can be used to remove a file handle from the poller. The handle must
    /// have been previously added to the poller using [`add_file`].
    ///
    /// [`add_file`]: Self::add_file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::os::iocp::{FileOverlappedWrapper, Overlapped, PollerIocpFileExt};
    /// use polling::{Event, Events, Poller};
    /// use windows_sys::Win32::System::IO::OVERLAPPED;
    ///
    /// use std::ffi::OsStr;
    /// use std::fs::OpenOptions;
    /// use std::io;
    /// use std::os::windows::ffi::OsStrExt;
    /// use std::os::windows::fs::OpenOptionsExt;
    /// use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
    /// use std::time::Duration;
    ///
    /// use windows_sys::Win32::{
    ///     Foundation as wf, Storage::FileSystem as wfs, System::Pipes as wps, System::IO as wio,
    /// };
    ///
    /// // Create a poller.
    /// let poller = Poller::new().unwrap();
    /// let mut events = Events::new();
    /// println!("Create a temp file");
    /// // Open a file for writing.
    /// let dir = tempfile::tempdir().unwrap();
    /// let file_path = dir.path().join("test.txt");
    /// let fname = file_path
    ///     .as_os_str()
    ///     .encode_wide()
    ///     .chain(Some(0))
    ///     .collect::<Vec<_>>();
    /// let file_handle = unsafe {
    ///     let raw_handle = wfs::CreateFileW(
    ///         fname.as_ptr(),
    ///         wf::GENERIC_WRITE | wf::GENERIC_READ,
    ///         0,
    ///         std::ptr::null_mut(),
    ///         wfs::CREATE_ALWAYS,
    ///         wfs::FILE_FLAG_OVERLAPPED,
    ///         std::ptr::null_mut(),
    ///     );
    ///     if raw_handle == wf::INVALID_HANDLE_VALUE {
    ///         panic!("CreateFileW failed: {}", io::Error::last_os_error());
    ///     }
    ///     OwnedHandle::from_raw_handle(raw_handle as _)
    /// };
    /// println!("file handle: {:?}", file_handle);
    /// let overlapped = unsafe {
    ///     poller
    ///         .add_file(&file_handle, Event::new(1, true, true))
    ///         .unwrap()
    /// };
    ///
    /// // Repeatedly write to the pipe.
    /// let input_text = "Now is the time for all good men to come to the aid of their party";
    /// let mut len = input_text.len();
    /// while len > 0 {
    ///     // Begin the write.
    ///     let ptr = overlapped.write_ptr();
    ///     unsafe {
    ///         let ret = wfs::WriteFile(
    ///             file_handle.as_raw_handle() as _,
    ///             input_text.as_ptr() as _,
    ///             len as _,
    ///             std::ptr::null_mut(),
    ///             ptr,
    ///         );
    ///         println!("WriteFile returned: {}, len: {}, ptr: {:p}", ret, len, ptr);
    ///         if ret == 0 && wf::GetLastError() != wf::ERROR_IO_PENDING {
    ///             panic!("WriteFile failed: {}", io::Error::last_os_error());
    ///         }
    ///     }
    ///     // Wait for the overlapped operation to complete.
    ///     'waiter: loop {
    ///         events.clear();
    ///         println!("Starting wait...");
    ///         poller.wait(&mut events, None).unwrap();
    ///         println!("Got events");
    ///         for event in events.iter() {
    ///             if event.writable && event.key == 1 {
    ///                 break 'waiter;
    ///             }
    ///         }
    ///     }
    ///     // Decrement the length by the number of bytes written.
    ///     let wrapper = unsafe { &*FileOverlappedWrapper::from_overlapped_ptr(ptr) };
    ///     wrapper.get_result().map_or_else(
    ///         |e| {
    ///             match e.kind() {
    ///                 io::ErrorKind::WouldBlock => {
    ///                     // The operation is still pending, we can ignore this error.
    ///                     println!("WriteFile is still pending, continuing...");
    ///                 }
    ///                 _ => panic!("WriteFile failed: {}", e),
    ///             }
    ///         },
    ///         |ret| {
    ///             if (!ret) {
    ///                 println!("The file handle maybe closed");
    ///             }
    ///             else {
    ///                 let bytes_written = wrapper.get_bytes_transferred();
    ///                 println!("Bytes written: {}", bytes_written);
    ///                 len -= bytes_written as usize;
    ///             }
    ///         },
    ///     );
    /// }
    /// poller.remove_file(&file_handle).unwrap();
    /// ```
    fn remove_file(&self, file: &impl AsRawHandle) -> io::Result<()>;
}

impl PollerIocpFileExt for Poller {
    unsafe fn add_file(&self, file: &impl AsRawHandle, event: Event) -> io::Result<IocpFilePacket> {
        self.poller.add_file(file.as_raw_handle(), event)
    }

    fn remove_file(&self, file: &impl AsRawHandle) -> io::Result<()> {
        self.poller.remove_file(file.as_raw_handle())
    }
}

/// Overlapped structure is part data block of [`IoStatusBlock<PacketInner>`] owned by poller.
/// It is same as Overlapped<T>, but used by poller internal to update status of I/O operations.
///
/// [`IoStatusBlock<PacketInner>`]: crate::iocp::IoStatusBlock<PacketInner>
#[repr(C)]
pub(crate) struct OverlappedInner<T> {
    /// OVERLAPPED structure used for I/O operation
    inner: UnsafeCell<OVERLAPPED>,
    /// bytes transferred when iocp event happens.
    bytes_transferred: u32,
    /// Callback function used to covert to the whole [`IoStatusBlock<PacketInner>`] block
    callback: unsafe fn(&OVERLAPPED_ENTRY) -> (T, FileCompletionStatus),
}

impl<T> OverlappedInner<T> {
    pub(crate) fn new(callback: unsafe fn(&OVERLAPPED_ENTRY) -> (T, FileCompletionStatus)) -> Self {
        Self {
            inner: UnsafeCell::new(OVERLAPPED::default()),
            bytes_transferred: 0,
            callback,
        }
    }

    /// Convert from OVERLAPPED_ENTRY.lpOverlapped back to OverlappedInner<T>
    ///
    /// # Safety
    ///
    /// The overlapped_ptr must point to the `inner` field of a valid OverlappedInner<T> instance
    pub(crate) unsafe fn from_overlapped_ptr(overlapped_ptr: *mut OVERLAPPED) -> *mut Self {
        // Calculate offset of 'inner' field within OverlappedInner<T>
        let offset = std::mem::offset_of!(OverlappedInner<T>, inner);

        // Get pointer to the containing Overlapped<T> struct
        (overlapped_ptr as *mut u8).sub(offset) as *mut OverlappedInner<T>
    }

    /// Convert and call the callback
    ///
    /// # Safety
    ///
    /// The entry.lpOverlapped must point to the `inner` field of a valid OverlappedInner<T> instance
    pub(crate) unsafe fn from_entry(entry: &OVERLAPPED_ENTRY) -> (T, FileCompletionStatus) {
        let overlapped_ptr = Self::from_overlapped_ptr(entry.lpOverlapped);
        let overlapped_ref = &*overlapped_ptr;
        (overlapped_ref.callback)(entry)
    }

    /// Get a raw pointer to the OVERLAPPED structure
    pub(crate) fn as_ptr(&self) -> *mut OVERLAPPED {
        self.inner.get()
    }

    /// Set the number of bytes transferred by the I/O operation
    pub(crate) fn set_bytes_transferred(&mut self, bytes: u32) {
        self.bytes_transferred = bytes;
    }
}

impl<T> Drop for OverlappedInner<T> {
    fn drop(&mut self) {
        // Safety: The OVERLAPPED structure belongs to the Packet. It will be released with Packet
    }
}

/// [`IocpFilePacket`] read/write pointer can safety convert to this structure to check I/O operation
/// results. [`FileOverlappedWrapper`] is alise for access convinence.
/// # Examples
///
/// ```no_run
/// use polling::os::iocp::{FileOverlappedWrapper, IocpFilePacket};
/// use std::io;
///
/// # fn example(overlapped: IocpFilePacket, mut len: usize) {
/// let ptr = overlapped.write_ptr();
/// let wrapper = unsafe { &*FileOverlappedWrapper::from_overlapped_ptr(ptr) };
/// println!("bytes transferred: {}", wrapper.get_bytes_transferred());
/// wrapper.get_result().map_or_else(
///     |e| {
///         match e.kind() {
///             io::ErrorKind::WouldBlock => {
///                 // The operation is still pending, we can ignore this error.
///                 println!("WriteFile is still pending, continuing...");
///             }
///             _ => panic!("WriteFile failed: {}", e),
///         }
///     },
///     |ret| {
///         if (!ret) {
///             println!("The file handle maybe closed");
///         }
///         else {
///             let bytes_written = wrapper.get_bytes_transferred();
///             println!("Bytes written: {}", bytes_written);
///             len -= bytes_written as usize;
///         }
///     },
/// );
/// # }
/// ```
/// [`FileOverlappedWrapper`]: crate::iocp::FileOverlappedWrapper
#[derive(Debug)]
#[repr(C)]
pub struct Overlapped<T> {
    inner: UnsafeCell<OVERLAPPED>,
    bytes_transferred: u32,
    callback: unsafe fn(&OVERLAPPED_ENTRY) -> (T, FileCompletionStatus),
}

impl<T> Overlapped<T> {
    /// Convert from OVERLAPPED_ENTRY.lpOverlapped back to Overlapped<T>
    ///
    /// # Safety
    ///
    /// The overlapped_ptr must point to the `inner` field of a valid Overlapped<T> instance
    pub unsafe fn from_overlapped_ptr(overlapped_ptr: *mut OVERLAPPED) -> *mut Self {
        // Calculate offset of 'inner' field within Overlapped<T>
        let offset = std::mem::offset_of!(Overlapped<T>, inner);

        // Get pointer to the containing Overlapped<T> struct
        (overlapped_ptr as *mut u8).sub(offset) as *mut Overlapped<T>
    }

    /// Get number of bytes transferred by the I/O operation
    pub fn get_bytes_transferred(&self) -> u32 {
        self.bytes_transferred
    }

    /// Get the result of the I/O operation. It returns:
    /// - Ok(true) if the operation was successful
    /// - Ok(false) if there was no data which may means the handle has been closed
    /// - Err(io::ErrorKind::WouldBlock) if the operation is still pending
    /// - Err(io::Error) for any other error
    pub fn get_result(&self) -> io::Result<bool> {
        let nt_status = unsafe { (*self.inner.get()).Internal };
        let ntdll = NtdllImports::get()?;
        let os_error_code = unsafe { ntdll.RtlNtStatusToDosError(nt_status as _) };

        match os_error_code {
            wf::ERROR_SUCCESS => Ok(true),
            wf::ERROR_NO_DATA => Ok(false),
            wf::ERROR_IO_PENDING => Err(io::ErrorKind::WouldBlock.into()),
            error => Err(io::Error::from_raw_os_error(error as _)),
        }
    }

    /// Clear the state of the I/O operation before take the next I/O operation
    pub fn zeroed(&mut self) {
        *self.inner.get_mut() = OVERLAPPED::default();
        self.bytes_transferred = 0;
    }
}

impl<T> Drop for Overlapped<T> {
    fn drop(&mut self) {
        // Safety: The type is not the owner of the struct which is owned by the Packet
    }
}
