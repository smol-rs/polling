//! Owned-buffer traits for the IOCP file-handle submission API.
//!
//! The completion-based `RegisteredFile::submit_*` API requires the buffer
//! to outlive the kernel-visible pointer it hands to `ReadFile` /
//! `WriteFile`. Buffers therefore must:
//!
//! - have a stable address (no growing `Vec` reallocations after submit),
//! - be `'static` (no borrowed lifetimes — the kernel may complete the I/O
//!   long after the `submit_*` call returns),
//! - be `Send` (completions are delivered on the thread that calls
//!   [`Poller::wait`], which may differ from the submitter).
//!
//! See `docs/named-pipe.design.md` §3.2.

/// A byte region with a stable address until the value is dropped.
///
/// # Safety
///
/// Implementors must guarantee that [`StableBuf::as_ptr`] returns the same
/// address for the lifetime of `self`. Moving `self` is permitted only as
/// long as the pointer has not been observed externally — which the
/// `OpInner` allocation guarantees by pinning the wrapping `Pin<Arc<…>>`.
pub unsafe trait StableBuf: Send + 'static {
    /// Returns a pointer to the start of the byte region.
    fn as_ptr(&self) -> *const u8;
    /// Returns the number of initialised bytes the region currently holds.
    fn len(&self) -> usize;
    /// Returns `true` if [`StableBuf::len`] is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A mutable byte region with a stable address until the value is dropped.
///
/// # Safety
///
/// In addition to [`StableBuf`]'s contract, implementors must guarantee
/// that [`StableBufMut::as_mut_ptr`] returns the same address for the
/// lifetime of `self`, that the region is writable up to
/// [`StableBufMut::capacity`] bytes, and that
/// [`StableBufMut::set_init`] is sound for any `n in 0..=capacity()`.
pub unsafe trait StableBufMut: StableBuf {
    /// Returns a mutable pointer to the start of the byte region.
    fn as_mut_ptr(&mut self) -> *mut u8;
    /// Returns the total writable capacity in bytes.
    fn capacity(&self) -> usize;
    /// Marks the first `n` bytes of the region as initialised after the
    /// kernel reported `n` bytes were written into the buffer.
    ///
    /// # Safety
    ///
    /// `n` must satisfy `n <= capacity()` and the first `n` bytes of the
    /// region must actually be initialised by the kernel before the call.
    unsafe fn set_init(&mut self, n: usize);
}

// SAFETY: `Vec<u8>` keeps its underlying allocation at a stable address as
// long as no method that may reallocate is called. The `submit_*` API
// takes ownership of the `Vec` (so no concurrent code can grow it) and
// only releases it back to the user via `FileCompletion::take` after the
// kernel completion has fired.
unsafe impl StableBuf for Vec<u8> {
    fn as_ptr(&self) -> *const u8 {
        <[u8]>::as_ptr(self)
    }
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

// SAFETY: see `StableBuf for Vec<u8>`. `set_init` upholds `Vec::set_len`'s
// invariants because the caller of `set_init` (the v2 completion path)
// has already verified that the kernel wrote `n` initialised bytes into
// the buffer and that `n <= self.capacity()`.
unsafe impl StableBufMut for Vec<u8> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        <[u8]>::as_mut_ptr(self)
    }
    fn capacity(&self) -> usize {
        Vec::capacity(self)
    }
    unsafe fn set_init(&mut self, n: usize) {
        // SAFETY: Caller contract guarantees `n <= capacity()` and that
        // the first `n` bytes are initialised.
        unsafe {
            self.set_len(n);
        }
    }
}

// SAFETY: `Box<[u8]>` allocates a fixed-size heap region whose address
// does not change for the lifetime of the box.
unsafe impl StableBuf for Box<[u8]> {
    fn as_ptr(&self) -> *const u8 {
        <[u8]>::as_ptr(self)
    }
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

// SAFETY: see `StableBuf for Box<[u8]>`. The slice's length equals its
// capacity, so `set_init` is a no-op.
unsafe impl StableBufMut for Box<[u8]> {
    fn as_mut_ptr(&mut self) -> *mut u8 {
        <[u8]>::as_mut_ptr(self)
    }
    fn capacity(&self) -> usize {
        <[u8]>::len(self)
    }
    unsafe fn set_init(&mut self, _n: usize) {
        // No-op: a `Box<[u8]>` has no separate length field.
    }
}

// SAFETY: a `'static` byte slice points to memory that lives for the
// entire program, so the address is trivially stable.
unsafe impl StableBuf for &'static [u8] {
    fn as_ptr(&self) -> *const u8 {
        <[u8]>::as_ptr(self)
    }
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

// SAFETY: `()` carries no buffer; implementing `StableBuf` for it lets
// `submit_connect_named_pipe` reuse the same `Submission<B>` machinery.
unsafe impl StableBuf for () {
    fn as_ptr(&self) -> *const u8 {
        std::ptr::NonNull::<u8>::dangling().as_ptr()
    }
    fn len(&self) -> usize {
        0
    }
}
