//! ntdll library bindings
use std::{io, mem::transmute, sync::OnceLock};

use windows_sys::{
    Wdk::Foundation::OBJECT_ATTRIBUTES,
    Win32::{
        Foundation::{HANDLE, HMODULE, NTSTATUS},
        System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            IO::IO_STATUS_BLOCK,
        },
    },
};

macro_rules! define_ntdll_import {
    (
        $(
            $(#[$attr:meta])*
            fn $name:ident($($arg:ident: $arg_ty:ty),*) -> $ret:ty;
        )*
    ) => {
        /// Imported functions from ntdll.dll.
        #[allow(non_snake_case)]
        pub(crate) struct NtdllImports {
            $(
                $(#[$attr])*
                pub(super) $name: unsafe extern "system" fn($($arg_ty),*) -> $ret,
            )*
        }

        #[allow(non_snake_case)]
        impl NtdllImports {
            unsafe fn load(ntdll: HMODULE) -> io::Result<Self> {
                $(
                    #[allow(clippy::missing_transmute_annotations)]
                    let $name = {
                        const NAME: &str = concat!(stringify!($name), "\0");
                        let addr = GetProcAddress(ntdll, NAME.as_ptr() as *const _);

                        let addr = match addr {
                            Some(addr) => addr,
                            None => {
                                #[cfg(feature = "tracing")]
                                tracing::error!("Failed to load ntdll function {}", NAME);
                                return Err(io::Error::last_os_error());
                            },
                        };

                        transmute::<_, unsafe extern "system" fn($($arg_ty),*) -> $ret>(addr)
                    };
                )*

                Ok(Self {
                    $(
                        $name,
                    )*
                })
            }

            $(
                $(#[$attr])*
                pub(crate) unsafe fn $name(&self, $($arg: $arg_ty),*) -> $ret {
                    (self.$name)($($arg),*)
                }
            )*
        }
    };
}

define_ntdll_import! {
    /// Cancels an ongoing I/O operation.
    fn NtCancelIoFileEx(
        FileHandle: HANDLE,
        IoRequestToCancel: *mut IO_STATUS_BLOCK,
        IoStatusBlock: *mut IO_STATUS_BLOCK
    ) -> NTSTATUS;

    /// Opens or creates a file handle.
    #[allow(clippy::too_many_arguments)]
    fn NtCreateFile(
        FileHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        AllocationSize: *mut i64,
        FileAttributes: u32,
        ShareAccess: u32,
        CreateDisposition: u32,
        CreateOptions: u32,
        EaBuffer: *mut (),
        EaLength: u32
    ) -> NTSTATUS;

    /// Runs an I/O control on a file handle.
    ///
    /// Practically equivalent to `ioctl`.
    #[allow(clippy::too_many_arguments)]
    fn NtDeviceIoControlFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: *mut (),
        ApcContext: *mut (),
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        IoControlCode: u32,
        InputBuffer: *mut (),
        InputBufferLength: u32,
        OutputBuffer: *mut (),
        OutputBufferLength: u32
    ) -> NTSTATUS;

    /// Converts `NTSTATUS` to a DOS error code.
    fn RtlNtStatusToDosError(
        Status: NTSTATUS
    ) -> u32;
}

impl NtdllImports {
    pub(crate) fn get() -> io::Result<&'static Self> {
        macro_rules! s {
            ($e:expr) => {{
                $e as u16
            }};
        }

        // ntdll.dll
        static NTDLL_NAME: &[u16] = &[
            s!('n'),
            s!('t'),
            s!('d'),
            s!('l'),
            s!('l'),
            s!('.'),
            s!('d'),
            s!('l'),
            s!('l'),
            s!('\0'),
        ];
        static NTDLL_IMPORTS: OnceLock<io::Result<NtdllImports>> = OnceLock::new();

        NTDLL_IMPORTS
            .get_or_init(|| unsafe {
                let ntdll = GetModuleHandleW(NTDLL_NAME.as_ptr() as *const _);

                if ntdll.is_null() {
                    #[cfg(feature = "tracing")]
                    tracing::error!("Failed to load ntdll.dll");
                    return Err(io::Error::last_os_error());
                }

                NtdllImports::load(ntdll)
            })
            .as_ref()
            .map_err(|e| io::Error::from(e.kind()))
    }

    pub(super) fn force_load() -> io::Result<()> {
        Self::get()?;
        Ok(())
    }
}
