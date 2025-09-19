//! Functionality that is only available for IOCP-based platforms.

use windows_sys::Win32::System::IO::{OVERLAPPED, OVERLAPPED_ENTRY};
use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wsf, System::Pipes as wsp};

use crate::iocp::ntdll::NtdllImports;
use crate::iocp::{FileCompletionStatus, PacketWrapper};
pub use crate::iocp::{FileOverlappedConverter, FileOverlappedWrapper};
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
/// The caller must use this structure to get read overlapped converter or write overlapped converter
/// as parameter in [`read_file_overlapped`] or [`write_file_overlapped`] methods which help avoid memory leak
/// instead of using raw Windows ReadFile/WriteFile APIs. Otherwise, the behavior is undefined.
///
/// [`add_file`]: crate::os::iocp::PollerIocpFileExt::add_file
#[derive(Debug, Clone)]
pub struct IocpFilePacket {
    /// read pointer to the overlapped structure
    read: NonNull<OVERLAPPED>,
    /// write pointer to the overlapped structure
    write: NonNull<OVERLAPPED>,
    packet: PacketWrapper,
}

impl IocpFilePacket {
    /// Create a new `IocpFilePacket` with the given `OVERLAPPED` pointer.
    pub(crate) fn new(
        read: *mut OVERLAPPED,
        write: *mut OVERLAPPED,
        packet: PacketWrapper,
    ) -> Self {
        Self {
            read: NonNull::new(read).unwrap(),
            write: NonNull::new(write).unwrap(),
            packet,
        }
    }

    /// Get the raw read overlapped wrapper to the `OVERLAPPED` structure.
    pub fn read_complete(&self) -> *mut FileOverlappedWrapper {
        unsafe { FileOverlappedWrapper::from_overlapped_ptr(self.read.as_ptr()) }
    }

    /// Get the raw write overlapped wrapper to the `OVERLAPPED` structure.
    pub fn write_complete(&self) -> *mut FileOverlappedWrapper {
        unsafe { FileOverlappedWrapper::from_overlapped_ptr(self.write.as_ptr()) }
    }

    /// Get the read overlapped converter which can be used in read_file_overlapped method.
    pub fn read_overlapped(&self) -> FileOverlappedConverter {
        FileOverlappedConverter::new(self.read.as_ptr(), self.packet.clone())
    }

    /// Get the write overlapped converter which can be used in write_file_overlapped method.
    pub fn write_overlapped(&self) -> FileOverlappedConverter {
        FileOverlappedConverter::new(self.write.as_ptr(), self.packet.clone())
    }

    /// Get the reference count of the internal packet for testing purpose.
    #[doc(hidden)]
    pub fn test_ref_count(&self) -> usize {
        self.packet.test_ref_count()
    }
}

/// Helper function to perform a file operation with an overlapped converter to avoid memory leak.
pub fn file_op_overlapped<F>(mut overlapped: FileOverlappedConverter, f: F) -> io::Result<usize>
where
    F: FnOnce(&mut FileOverlappedConverter) -> io::Result<usize>,
{
    let ret = f(&mut overlapped);
    match ret {
        Ok(size) => Ok(size),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
        Err(e) => {
            overlapped.reclaim();
            Err(e)
        }
    }
}

/// Wrapper for ConnectNamedPipe API with an overlapped converter to avoid memory leak.
pub fn connect_named_pipe_overlapped(
    handle: &impl AsHandle,
    overlapped: FileOverlappedConverter,
) -> io::Result<()> {
    let ret = file_op_overlapped(overlapped, |overlapped| {
        let ret = unsafe {
            wsp::ConnectNamedPipe(
                handle.as_handle().as_raw_handle() as _,
                overlapped
                    .as_ptr()
                    .expect("The overlaped pointer may have been used for I/O operation"),
            )
        };
        if ret != wf::FALSE {
            Ok(0)
        } else {
            let err = io::Error::last_os_error();
            match err.raw_os_error().map(|e| e as u32) {
                Some(wf::ERROR_IO_PENDING) => Err(io::ErrorKind::WouldBlock.into()),
                _ => Err(err),
            }
        }
    });

    match ret {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Wrapper for ReadFile API with an overlapped converter to avoid memory leak.
pub fn read_file_overlapped(
    handle: &impl AsHandle,
    buf: &mut [u8],
    overlapped: FileOverlappedConverter,
) -> io::Result<usize> {
    file_op_overlapped(overlapped, |overlapped| {
        let mut read = 0u32;
        // Safety: syscall
        if unsafe {
            wsf::ReadFile(
                handle.as_handle().as_raw_handle() as _,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut read as *mut _,
                overlapped
                    .as_ptr()
                    .expect("The overlapped pointer may have been used for I/O operation"),
            )
        } != wf::FALSE
        {
            return Ok(read as usize);
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error().map(|e| e as u32) {
            Some(wf::ERROR_IO_PENDING) => Err(io::ErrorKind::WouldBlock.into()),
            _ => Err(err),
        }
    })
}

/// Wrapper for WriteFile API with an overlapped converter to avoid memory leak.
pub fn write_file_overlapped(
    handle: &impl AsHandle,
    buf: &[u8],
    overlapped: FileOverlappedConverter,
) -> io::Result<usize> {
    file_op_overlapped(overlapped, |overlapped| {
        let mut write = 0u32;
        // Safety: syscall
        if unsafe {
            wsf::WriteFile(
                handle.as_handle().as_raw_handle() as _,
                buf.as_ptr(),
                buf.len() as u32,
                &mut write as *mut _,
                overlapped
                    .as_ptr()
                    .expect("The overlapped pointer may have been used for I/O operation"),
            )
        } != wf::FALSE
        {
            return Ok(write as usize);
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error().map(|e| e as u32) {
            Some(wf::ERROR_IO_PENDING) => Err(io::ErrorKind::WouldBlock.into()),
            _ => Err(err),
        }
    })
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
    /// use polling::os::iocp::{read_file_overlapped, write_file_overlapped, PollerIocpFileExt};
    /// use polling::{Event, Events, Poller};
    ///
    /// use std::ffi::OsStr;
    /// use std::fs::OpenOptions;
    /// use std::io;
    /// use std::os::windows::ffi::OsStrExt;
    /// use std::os::windows::fs::OpenOptionsExt;
    /// use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
    /// use std::time::Duration;
    ///
    /// use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs, System::Pipes as wps};
    ///
    /// fn new_named_pipe<A: AsRef<OsStr>>(addr: A) -> io::Result<OwnedHandle> {
    ///     let fname = addr
    ///         .as_ref()
    ///         .encode_wide()
    ///         .chain(Some(0))
    ///         .collect::<Vec<_>>();
    ///     let handle = unsafe {
    ///         let raw_handle = wps::CreateNamedPipeW(
    ///             fname.as_ptr(),
    ///             wfs::PIPE_ACCESS_DUPLEX | wfs::FILE_FLAG_OVERLAPPED,
    ///             wps::PIPE_TYPE_BYTE | wps::PIPE_READMODE_BYTE | wps::PIPE_WAIT,
    ///             1,
    ///             4096,
    ///             4096,
    ///             0,
    ///             std::ptr::null_mut(),
    ///         );
    ///
    ///         if raw_handle == wf::INVALID_HANDLE_VALUE {
    ///             return Err(io::Error::last_os_error());
    ///         }
    ///
    ///         OwnedHandle::from_raw_handle(raw_handle as _)
    ///     };
    ///
    ///     Ok(handle)
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
    ///         let ret = write_file_overlapped(&client, b"1234", client_overlapped.write_overlapped());
    ///
    ///         assert_eq!(ret.unwrap(), 4);
    ///
    ///         poller.wait(&mut events, None).unwrap();
    ///
    ///         let w_events = events.iter().collect::<Vec<_>>();
    ///         assert_eq!(w_events.len(), 1);
    ///         assert_eq!(w_events[0].key, 2);
    ///         assert!(w_events[0].writable);
    ///
    ///         events.clear();
    ///         let mut buf = [0u8; 10];
    ///
    ///         let mut read = 0u32;
    ///         let ret = read_file_overlapped(&server, &mut buf, server_overlapped.read_overlapped());
    ///
    ///         let event_len = poller
    ///             .wait(&mut events, Some(Duration::from_millis(10)))
    ///             .unwrap();
    ///         assert_eq!(event_len, 1);
    ///
    ///         let r_events = events.iter().collect::<Vec<_>>();
    ///         assert_eq!(r_events.len(), 1);
    ///         assert_eq!(r_events[0].key, 1);
    ///         assert!(r_events[0].readable);
    ///         assert_eq!(ret.unwrap(), 4);
    ///         assert_eq!(&buf[..4], b"1234");
    ///
    ///         poller.remove_file(&server).unwrap();
    ///         poller.remove_file(&client).unwrap();
    ///         drop(server);
    ///         drop(client);
    ///     }
    /// }
    /// ```
    unsafe fn add_file(
        &self,
        file: impl AsRawFileHandle,
        event: Event,
    ) -> io::Result<IocpFilePacket>;

    /// Modifies the interest in a file handle.
    ///
    /// This method has the same behavior as [`add_file()`][`Poller::add_file()`] except it modifies the
    /// interest of a previously added file handle. The `file` parameter must impl AsFileHandle trait
    /// to ensure the handle is not closed before remove_file is called.
    ///
    /// To use this method with a file handle, you must first add it using
    /// [`add_file()`][`Poller::add_file()`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::os::iocp::PollerIocpFileExt;
    /// use polling::{Event, Poller};
    /// use std::fs::OpenOptions;
    /// use std::io;
    /// use std::os::windows::fs::OpenOptionsExt;
    /// use std::os::windows::io::{FromRawHandle, IntoRawHandle, OwnedHandle};
    /// use windows_sys::Win32::Storage::FileSystem as wfs;
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
    /// # fn main() -> io::Result<()> {
    ///     static PIPE_NUM: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    ///     let num = PIPE_NUM.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    ///     let name = format!(r"\\.\pipe\my-pipe-{}", num);
    ///     let client = client(&name).unwrap();
    ///     let poller = Poller::new().unwrap();
    ///     let key = 2;
    ///     let _client_overlapped = unsafe { poller.add_file(&client, Event::none(key)).unwrap() };
    ///     poller.modify_file(&client, Event::writable(key))?;
    ///     poller.remove_file(&client)
    /// # }
    /// ```
    fn modify_file(&self, handle: impl AsFileHandle, interest: Event) -> io::Result<()>;

    /// Remove a file handle from this poller.
    ///
    /// This function can be used to remove a file handle from the poller. The handle must
    /// have been previously added to the poller using [`add_file`]. The `file` parameter must impl
    /// AsFileHandle trait to ensure the handle is not closed before remove_file is called.
    ///
    ///
    /// [`add_file`]: Self::add_file
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use polling::os::iocp::{
    ///     write_file_overlapped, PollerIocpFileExt,
    /// };
    /// use polling::{Event, Events, Poller};
    ///
    /// use std::io;
    /// use std::os::windows::ffi::OsStrExt;
    /// use std::os::windows::io::{FromRawHandle, OwnedHandle};
    ///
    /// use windows_sys::Win32::{Foundation as wf, Storage::FileSystem as wfs};
    ///
    /// # fn main() {
    ///     // Create a poller.
    ///     let poller = Poller::new().unwrap();
    ///     let mut events = Events::new();
    ///     println!("Create a temp file");
    ///     // Open a file for writing.
    ///     let dir = tempfile::tempdir().unwrap();
    ///     let file_path = dir.path().join("test.txt");
    ///     let fname = file_path
    ///         .as_os_str()
    ///         .encode_wide()
    ///         .chain(Some(0))
    ///         .collect::<Vec<_>>();
    ///     let file_handle = unsafe {
    ///         let raw_handle = wfs::CreateFileW(
    ///             fname.as_ptr(),
    ///             wf::GENERIC_WRITE | wf::GENERIC_READ,
    ///             0,
    ///             std::ptr::null_mut(),
    ///             wfs::CREATE_ALWAYS,
    ///             wfs::FILE_FLAG_OVERLAPPED,
    ///             std::ptr::null_mut(),
    ///         );
    ///         if raw_handle == wf::INVALID_HANDLE_VALUE {
    ///             panic!("CreateFileW failed: {}", io::Error::last_os_error());
    ///         }
    ///         OwnedHandle::from_raw_handle(raw_handle as _)
    ///     };
    ///     println!("file handle: {:?}", file_handle);
    ///     let overlapped = unsafe {
    ///         poller
    ///             .add_file(&file_handle, Event::new(1, true, true))
    ///             .unwrap()
    ///     };
    ///
    ///     // Repeatedly write to the pipe.
    ///     let input_text = "Now is the time for all good men to come to the aid of their party";
    ///     let mut len = input_text.len();
    ///     while len > 0 {
    ///         // Begin the write.
    ///         let ret = write_file_overlapped(&file_handle, b"1234", overlapped.write_overlapped());
    ///         let _ = ret.map_err(|e| {
    ///             if e.kind() != io::ErrorKind::WouldBlock {
    ///                 panic!("WriteFile failed: {}", e);
    ///             }
    ///         });
    ///         // Wait for the overlapped operation to complete.
    ///         'waiter: loop {
    ///             events.clear();
    ///             println!("Starting wait...");
    ///             poller.wait(&mut events, None).unwrap();
    ///             println!("Got events");
    ///             for event in events.iter() {
    ///                 if event.writable && event.key == 1 {
    ///                     break 'waiter;
    ///                 }
    ///             }
    ///         }
    ///         // Decrement the length by the number of bytes written.
    ///         let wrapper = unsafe { &*overlapped.write_complete() };
    ///         wrapper.get_result().map_or_else(
    ///             |e| {
    ///                 match e.kind() {
    ///                     io::ErrorKind::WouldBlock => {
    ///                         // The operation is still pending, we can ignore this error.
    ///                         println!("WriteFile is still pending, continuing...");
    ///                     }
    ///                     _ => panic!("WriteFile failed: {}", e),
    ///                 }
    ///             },
    ///             |ret| {
    ///                 if (!ret) {
    ///                     println!("The file handle maybe closed");
    ///                 } else {
    ///                     let bytes_written = wrapper.get_bytes_transferred();
    ///                     println!("Bytes written: {}", bytes_written);
    ///                     len -= bytes_written as usize;
    ///                 }
    ///             },
    ///         );
    ///     }
    ///     poller.remove_file(file_handle).unwrap();
    /// # }
    /// ```
    fn remove_file(&self, file: impl AsFileHandle) -> io::Result<()>;
}

/// A type that represents a raw file handle.
pub trait AsRawFileHandle {
    /// Returns the raw handle of this file.
    fn as_raw_handle(&self) -> RawHandle;
}

impl AsRawFileHandle for RawHandle {
    fn as_raw_handle(&self) -> RawHandle {
        *self
    }
}

impl<T: AsRawHandle + ?Sized> AsRawFileHandle for &T {
    fn as_raw_handle(&self) -> RawHandle {
        AsRawHandle::as_raw_handle(*self)
    }
}

/// A type that represents a file handle.
pub trait AsFileHandle: AsHandle {
    /// Returns the raw handle of this file.
    fn as_file(&self) -> BorrowedHandle<'_> {
        self.as_handle()
    }
}

impl<T: AsHandle + ?Sized> AsFileHandle for T {}

impl PollerIocpFileExt for Poller {
    unsafe fn add_file(
        &self,
        file: impl AsRawFileHandle,
        event: Event,
    ) -> io::Result<IocpFilePacket> {
        self.poller.add_file(file.as_raw_handle(), event)
    }

    fn modify_file(&self, handle: impl AsFileHandle, interest: Event) -> io::Result<()> {
        self.poller
            .modify_file(handle.as_file().as_raw_handle(), interest)
    }

    fn remove_file(&self, file: impl AsFileHandle) -> io::Result<()> {
        self.poller.remove_file(file.as_file().as_raw_handle())
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
///
/// # Examples
///
/// ```no_run
/// use polling::os::iocp::IocpFilePacket;
/// use std::io;
///
/// fn write_all(overlapped: IocpFilePacket, mut len: usize) {
///     let wrapper = unsafe { &*overlapped.write_complete() };
///     println!("bytes transferred: {}", wrapper.get_bytes_transferred());
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
///             if !ret {
///                 println!("The file handle maybe closed");
///             } else {
///                 let bytes_written = wrapper.get_bytes_transferred();
///                 println!("Bytes written: {}", bytes_written);
///                 len -= bytes_written as usize;
///             }
///         },
///     );
/// }
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
    /// Convert from OVERLAPPED_ENTRY.lpOverlapped back to `Overlapped<T>`
    ///
    /// # Safety
    ///
    /// The overlapped_ptr must point to the `inner` field of a valid `Overlapped<T>` instance
    /// Normally, the call should be made through [`IocpFilePacket::read_complete`] or [`IocpFilePacket::write_complete`]
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
