# Windows Named Pipe / File Handle Overlapped I/O — Design

> Companion document:
> [`named-pipe.implement.checklist.md`](./named-pipe.implement.checklist.md)
> tracks the step-by-step implementation history.

This document describes the **current** IOCP file-handle support shipped
on the `kail/windows_file` branch (PR
[smol-rs/polling#248](https://github.com/smol-rs/polling/pull/248)).
It is the canonical design reference: the rationale for the chosen
shape, the alternatives that were rejected, and the invariants the
implementation relies on are all captured here.

The branch adds first-class support for arbitrary Windows overlapped
file handles (regular files, named pipes, anonymous pipes, mailslots,
serial ports, …) to the IOCP backend, in addition to the existing
socket and waitable handle support, via a small completion-based
`RegisteredFile` / `OpHandle<B>` / `Submission<B>` surface.

---

## 1. Overview

### 1.1 Files

| File | Role |
|------|------|
| [Cargo.toml](../Cargo.toml) | MSRV 1.77 (for `offset_of!`); adds `Win32_System_Pipes`; dev-dep `tempfile`. |
| [src/iocp/ntdll.rs](../src/iocp/ntdll.rs) | `NtdllImports` (incl. `RtlNtStatusToDosError`), shared with `port.rs`. |
| [src/iocp/buf.rs](../src/iocp/buf.rs) | `StableBuf` / `StableBufMut` traits and blanket impls (`Vec<u8>`, `Box<[u8]>`, `&'static [u8]`, `()`). |
| [src/iocp/port.rs](../src/iocp/port.rs) | `FileOverlapped` / `FileCompletionHandle` traits, dual-namespace `CompletionKey`, file-vs-socket completion routing. |
| [src/iocp/mod.rs](../src/iocp/mod.rs) | `PacketInner::FileOp { op: OpInner }`, `RegisteredFileInner`, `Poller::register_file`, `RegisteredFile` / `OpHandle<B>` / `Submission<B>`, dispatcher event-emission for file ops. |
| [src/os/iocp.rs](../src/os/iocp.rs) | Public `PollerIocpFileExt::register_file` and re-exports of `RegisteredFile`, `OpHandle`, `Submission`, `StableBuf`, `StableBufMut`. |
| [tests/windows_overlapped.rs](../tests/windows_overlapped.rs), [tests/file_concurrent.rs](../tests/file_concurrent.rs), [tests/file_lifetime.rs](../tests/file_lifetime.rs) | Integration tests; helpers in [tests/common/mod.rs](../tests/common/mod.rs). |
| [examples/named_pipe.rs](../examples/named_pipe.rs), [examples/named_pipe_concurrent.rs](../examples/named_pipe_concurrent.rs) | End-to-end usage examples. |

### 1.2 Public API

```rust
use polling::os::iocp::{
    PollerIocpFileExt, RegisteredFile, OpHandle, Submission,
    StableBuf, StableBufMut,
};

trait PollerIocpFileExt {
    /// Attach `file` to the IOCP and return a long-lived registration
    /// token. `key` is mirrored into `Event::key` of every completion
    /// this file emits.
    unsafe fn register_file(
        &self,
        file: impl AsRawFileHandle,
        key: usize,
    ) -> io::Result<RegisteredFile>;
}

impl RegisteredFile {
    fn submit_read<B: StableBufMut>(&self, buf: B) -> Submission<B>;
    fn submit_write<B: StableBuf>(&self, buf: B) -> Submission<B>;
    fn submit_connect_named_pipe(&self) -> Submission<()>;
    fn deactivate(&self);
    fn set_user_key(&self, key: usize);
}

enum Submission<B> {
    Complete { bytes: usize, buf: B },
    Pending(OpHandle<B>),
    Failed { error: io::Error, buf: B },
}

impl<B> OpHandle<B> {
    fn is_complete(&self) -> bool;
    fn try_take(self) -> Result<(io::Result<usize>, B), Self>;
    fn take(self) -> (io::Result<usize>, B);     // panics if not complete
    fn cancel(&self) -> io::Result<()>;          // CancelIoEx
}
```

`take` / `try_take` always return the buffer alongside the result so the
caller can reclaim or drop it on either path. The shape mirrors
`compio::BufResult<T, B>` (a tuple of `io::Result<T>` and `B`), which makes
adapting these primitives into compio-style traits in downstream crates
(e.g. `async-io`) straightforward. `cancel` takes `&self`; the buffer is
recovered by the subsequent `take`/`try_take` call.

`cancel` deliberately does **not** return `B`. `CancelIoEx` is asynchronous
— it only *requests* cancellation, and the kernel may still be touching the
buffer when `cancel` returns. The final completion packet (a late `Ok(n)`
or `Err(ERROR_OPERATION_ABORTED)`) arrives on the IOCP some time later, and
the buffer must stay pinned at its original address until that completion
is observed; releasing `B` from `cancel` would risk a use-after-free. The
caller therefore drives the same drain path on cancel as on normal
completion: wait for `is_complete`, then `take`/`try_take` to recover `B`
together with the final result. This matches `compio`'s cancellation
contract.

The `unsafe` on `register_file` mirrors the existing `Poller::add` and
`add_waitable` contract: the caller is responsible for keeping the
underlying handle alive until every `OpHandle` produced from this
registration has been drained. `polling` never closes the handle.

`PollMode` is implicitly **edge-triggered duplex** — every successful
overlapped call produces exactly one completion, so there is no
level/oneshot state machine to maintain.

---

## 2. Why not readiness?

A readiness-style file API (returning `Event { readable, writable }`
flags from `Poller::wait` and letting the user issue `ReadFile` /
`WriteFile` afterwards) was the original shape on this branch and was
discarded. Four issues made it untenable for IOCP file handles:

### 2.1 Buffer lifetime

A readiness API takes `&mut [u8]` at submit time. When `ReadFile`
returns `ERROR_IO_PENDING`, the kernel keeps the buffer pointer until
the operation completes — but the borrow on `&mut [u8]` ends as soon
as the function returns. Nothing in the type system stops the caller
from dropping, moving, or aliasing the buffer while the kernel is
still writing into it. That is undefined behaviour.

The `RegisteredFile::submit_*` API takes ownership of an
`impl StableBuf{,Mut}` and returns it to the caller via
`Submission::Complete { buf }` / `OpHandle::take() -> (usize, B)`, so
the type system enforces that the buffer lives until the kernel is
done with it.

### 2.2 Concurrent ops

A readiness API has one `OVERLAPPED` per direction per handle. Reusing
a single `OVERLAPPED` for two simultaneous reads on the same handle is
undefined behaviour on Windows: the kernel writes the status into the
same block twice and the two completions become indistinguishable.

Named pipes are full-duplex *and* often pipelined; HTTP/2-style
servers and AFD-backed sockets routinely keep several reads queued
behind a single handle. The 1-op-per-direction restriction made the
readiness API unusable for those workloads.

The completion API allocates a fresh `OpInner` per `submit_*` call,
so any number of reads and writes can be in flight simultaneously
without aliasing.

### 2.3 Cancellation

`CancelIoEx` is per-`(handle, OVERLAPPED)`. Without an op-scoped
`OVERLAPPED`, a readiness API can only cancel *all* I/O on the handle,
never a single read or write. And `CancelIoEx` followed by buffer drop
is racy unless the buffer is owned until the completion is dequeued —
which §2.1 already rules out.

`OpHandle::cancel` calls `CancelIoEx` against that specific op's
`OVERLAPPED`, leaving sibling ops on the same handle untouched.

### 2.4 Sync fast path

When a `ReadFile` / `WriteFile` returns `TRUE` synchronously, IOCP
still posts a completion packet that the caller's `Poller::wait` must
dequeue and discard. Windows lets us opt out of that by passing
`FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE`
to `SetFileCompletionNotificationModes`. `compio` sets these flags
unconditionally; the readiness shape never set them and so paid the
cost on every successful sync op.

The current API sets both flags on `register_file` and surfaces sync
success as `Submission::Complete { bytes, buf }` directly, with no
IOCP packet to drain.

---

## 3. Architecture

### 3.1 Type system

```text
┌──────────────────────────────────────────────────────────────────┐
│ User code                                                        │
│   let rf = unsafe { poller.register_file(handle, key)? };        │
│   match rf.submit_read(vec![0u8; 4096]) {                        │
│       Submission::Complete { bytes, buf } => …,                  │
│       Submission::Pending(op)             => …,                  │
│       Submission::Failed   { error, buf } => …,                  │
│   }                                                              │
└──────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ RegisteredFile  → Arc<RegisteredFileInner>                       │
│   { handle, port, active: AtomicBool, user_key: AtomicUsize }    │
└──────────────────────────────────────────────────────────────────┘
                                  │ submit_*
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ OpHandle<B>     → Pin<Arc<IoStatusBlock<PacketInner::FileOp>>>   │
│   PhantomData<B> tracks the user-supplied buffer type            │
└──────────────────────────────────────────────────────────────────┘
                                  │ kernel-Arc bumped on Pending
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ IoCompletionPort<Packet>                                         │
│   high-bit-of-key classifier → file vs socket/waitable           │
└──────────────────────────────────────────────────────────────────┘
                                  │ GetQueuedCompletionStatusEx
                                  ▼
┌──────────────────────────────────────────────────────────────────┐
│ Poller::wait_deadline                                            │
│   reclaim Arc, publish bytes / nt_status / state, push Event     │
└──────────────────────────────────────────────────────────────────┘
```

`RegisteredFileInner` holds:

- `handle: RawHandle` — borrowed; never closed by us. Used by
  `CancelIoEx` and the submission helpers.
- `port: Arc<IoCompletionPort<Packet>>` — keeps the IOCP alive at
  least as long as any in-flight op needs to deliver a completion.
- `active: AtomicBool` — flipped to `false` by
  `RegisteredFile::deactivate`. Subsequent `submit_*` calls return
  `Failed { error: InvalidInput, buf }`.
- `user_key: AtomicUsize` — written by `set_user_key` (Release), read
  by the dispatcher (Acquire). Mirrored into every `Event` this file
  emits.

`OpInner` is the kernel-visible per-op block:

```rust
#[repr(C)]
pub(crate) struct OpInner {
    overlapped: UnsafeCell<OVERLAPPED>,        // first field — kernel writes here
    state: AtomicU8,                           // Submitted | Completed | Cancelled
    bytes_transferred: AtomicU32,
    nt_status: AtomicI32,
    taken: AtomicBool,                         // OpHandle::take has consumed buf
    buf_storage: UnsafeCell<MaybeUninit<ErasedBuf>>,
    vtable: &'static OpVTable,                 // drop_buf for the actual B
    file: Option<Arc<RegisteredFileInner>>,    // back-reference; Some(_) for submit_*-issued ops
    interest: OpInterest,                      // direction this op cares about
    _pinned: PhantomPinned,                    // kernel holds raw &overlapped
}
```

The `OVERLAPPED` lives at offset 0, so `lpOverlapped` in the
completion entry can be cast straight back to `*mut OpInner` after
the file-op classifier has identified the entry. `OpInner` is plugged
into the existing `Packet = Pin<Arc<IoStatusBlock<PacketInner>>>`
dispatch type as a new variant `PacketInner::FileOp { #[pin] op: OpInner }`,
so `IoCompletionPort::wait` and the rest of the dispatcher do not
need to be generic over two unrelated packet types.

`OpHandle<B>` is a thin `Pin<Arc<…>>` wrapper that remembers `B` only
in the type system — the runtime type tag is `OpInner::vtable`,
which knows how to `drop_in_place::<B>` the type-erased
`buf_storage` slot.

### 3.2 `StableBuf` / `StableBufMut`

The buffer trait is deliberately minimal:

```rust
pub unsafe trait StableBuf: Send + 'static {
    fn as_ptr(&self)  -> *const u8;
    fn len(&self)     -> usize;
}

pub unsafe trait StableBufMut: StableBuf {
    fn as_mut_ptr(&mut self) -> *mut u8;
    fn capacity(&self)        -> usize;
}
```

Blanket impls cover `Vec<u8>` and `Box<[u8]>` for the mutable side,
plus `&'static [u8]` and `()` (for `submit_connect_named_pipe`) for
the immutable side. Ownership is `'static` (no borrowed lifetimes) —
the only way to enforce §2.1 in the type system. Crates that already
do their own lifetime accounting are expected to wrap a raw region
in their own `StableBuf` newtype and uphold the safety contract.

The `OpInner::buf_storage` slot is dimensioned for buffer wrapper
types up to 32 bytes / 8-byte aligned (concretely: a `Vec<u8>`'s
`(ptr, len, cap)` triple, a `Box<[u8]>`'s `(ptr, len)` pair, etc.).
Buffers exceeding the slot are rejected synchronously as
`Submission::Failed { error: InvalidInput, buf }` — never UB.

### 3.3 Submission classification

Every `submit_*` call funnels through a classifier that maps the
syscall result to one of three `Submission` variants:

| Kernel return         | `Submission` variant                          | Kernel Arc bump? |
|-----------------------|-----------------------------------------------|------------------|
| `TRUE`                | `Complete { bytes, buf }` (sync fast path)    | no               |
| `FALSE` + `ERROR_IO_PENDING` | `Pending(OpHandle<B>)`                 | **yes**          |
| `FALSE` + other err   | `Failed { error, buf }`                       | no               |

`submit_connect_named_pipe` adds a fourth case for the
`ConnectNamedPipe` quirk: `FALSE + ERROR_PIPE_CONNECTED` (the client
had already connected before the call) is treated as sync success.

Sync-success and sync-failure both reclaim the buffer immediately
via a raw `ptr::read` out of `buf_storage`, mark `taken = true`, and
hand the buffer back to the caller. The packet is dropped at the end
of the classifier; `OpInner::Drop` sees `taken == true` and skips the
type-erased `vtable.drop_buf`.

### 3.4 Kernel-Arc protocol (bump on Pending, reclaim in dispatcher)

The single most important invariant in the file API:

> Every `Pending` submission bumps the packet's `Arc` strong count
> by exactly one (via `mem::forget(packet.clone())`). The IOCP
> completion dispatcher reclaims that bump exactly once, via
> `Arc::from_raw` inside `OverlappedEntry::into_file_op_packet`. Sync
> success and sync failure must NOT bump — they leave the Arc
> reference balanced.

`FILE_SKIP_COMPLETION_PORT_ON_SUCCESS` (set in `register_file`)
guarantees that sync success will not produce an IOCP entry, so there
is no completion path that could spuriously reclaim.

The bump/reclaim pairing means:

- A `Pending` `OpHandle` may be dropped immediately. The kernel still
  holds one strong reference, so the buffer stays alive at the
  registered address. When the completion eventually arrives, the
  dispatcher reclaims the kernel's Arc, drops the last reference, and
  `OpInner::Drop` runs the `vtable.drop_buf` to release the buffer.
  No use-after-free, no leak — but no way to recover the buffer
  either.
- If the completion arrives *after* `OpHandle::take`, the dispatcher's
  `Arc::from_raw` decrements the count to zero (the user handle is
  already gone). `OpInner::Drop` sees `taken == true` and skips the
  buffer destructor.

### 3.5 Cancellation

`OpHandle::cancel(&self)` is best-effort:

1. If `state == Completed` already, return `Ok(())`.
2. CAS `state: Submitted → Cancelled` (no-op if already cancelled).
3. Issue `CancelIoEx(file.handle, &op.overlapped)`. `ERROR_NOT_FOUND`
   is treated as `Ok(())` (the kernel had already completed or
   delivered the op).

`Cancelled` is a hint for tracing; it is **not** load-bearing.
Whether the op was racing the kernel or already in flight, the
kernel will eventually post one completion entry (typically with
`STATUS_CANCELLED`). The dispatcher unconditionally publishes
`Completed` and lets the `nt_status` field encode the outcome —
`OpHandle::take` then surfaces `Err(ERROR_OPERATION_ABORTED)`.

### 3.6 Sync fast path

`register_file` calls `IoCompletionPort::register` with the flag set

```text
FILE_SKIP_SET_EVENT_ON_HANDLE | FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
```

`ERROR_INVALID_FUNCTION` (the device does not support the modes) is
treated as a non-fatal no-op. Successful sync ops therefore never
produce an IOCP packet, and `Submission::Complete` is the
zero-syscall-after-submit path.

### 3.7 Deactivation and the drain dance

`RegisteredFile::deactivate` flips the `active` flag to `false` and
returns immediately. Three invariants govern the surrounding state:

1. The kernel must never write into a freed `OVERLAPPED`.
2. The user must always be able to recover their buffers eventually.
3. After `deactivate`, no *new* ops may be submitted.

What `deactivate` does:

- Subsequent `submit_*` calls return
  `Submission::Failed { error: InvalidInput, .. }`.
- **No `CancelIoEx` is issued automatically.** The caller may have
  legitimate in-flight ops they want to keep running.
- The user's `HANDLE` is not closed; `polling` never owned it.
- In-flight `OpHandle<B>`s keep working. Each holds a kernel-bumped
  `Arc<Packet>` that transitively keeps the `IoCompletionPort` alive,
  so the eventual completion still has a live destination. The user
  must continue calling `Poller::wait` until every outstanding op has
  drained.

For "I want to abort *now*" the caller does the explicit dance:

```rust
rf.deactivate();                             // stop accepting new ops
for op in &in_flight {
    let _ = op.cancel();                     // CancelIoEx per op
}
while !in_flight.is_empty() {
    poller.wait(&mut events, None)?;
    for ev in events.iter() {
        if let Some(op) = in_flight.take_matching(ev.key) {
            // Result will typically be Err(ERROR_OPERATION_ABORTED).
            let _ = op.take();
        }
    }
}
// Now safe to drop / close the HANDLE.
drop(handle);
```

This dance is the same one Mio, tokio-uring, and compio require.
`polling` does not try to hide it inside `deactivate` because the set
of in-flight ops is owned by the user (not by the poller, which
cannot iterate them) and a blocking "wait until drained" inside
`deactivate` would invert control flow and break callers that share
the poller across threads.

**Misuse — dropping a pending `OpHandle`:** safe and silent. The
kernel still holds one strong ref via the bump in §3.4, so the
`OpInner` allocation (and the buffer it owns) survive until the
completion arrives. The dispatcher's `Arc::from_raw` then drops the
last reference, `OpInner::Drop` runs `vtable.drop_buf`, and the
buffer is released. Sound, but the buffer is unrecoverable — the
future-cancellation pattern is `op.cancel()` followed by `op.take()`
after the completion is observed.

---

## 4. Completion delivery

### 4.1 Dispatcher write order (load-bearing)

For each FileOp completion entry pulled from
`GetQueuedCompletionStatusEx`, the dispatcher in
`Poller::wait_deadline` does:

```text
1. let packet = entry.into_file_op_packet();    // Arc::from_raw — reclaim kernel ref
2. op.bytes_transferred.store(entry.dwNumberOfBytesTransferred, Release)
3. op.nt_status.store(entry.nt_status_raw(),                     Release)
4. op.state.store(OpState::Completed as u8,                      Release)
5. let interest = op.interest;
6. let key      = op.file.as_ref().unwrap().user_key.load(Acquire);
7. events.packets.push(Event { key, readable: interest.readable, writable: interest.writable, .. })
8. drop(packet);                                // last Arc — runs OpInner::Drop if user already dropped OpHandle
```

Step 4 must release-store **before** step 7 pushes the event, so the
Acquire-load on `state` performed by `OpHandle::is_complete()` (which
the woken future will call after its reactor wakes it) sees
`Completed`. Re-ordering 4 and 7 would allow the woken task to
observe a stale `Submitted` and re-park, losing the wake.

### 4.2 `OpInterest` and event direction

`OpInterest { readable, writable }` is set once per op at submit time
and read once by the dispatcher when constructing the event:

| `submit_*`                  | `event.readable` | `event.writable` |
|-----------------------------|------------------|------------------|
| `submit_read`               | `true`           | `false`          |
| `submit_write`              | `false`          | `true`           |
| `submit_connect_named_pipe` | `true`           | `false`          |

Connect maps to readable-only because the typical pattern is "server
submits `connect`, then submits `read` once a client is attached" —
wakers parked on the readable direction are the natural audience.

### 4.3 `set_user_key` contract

`RegisteredFile::set_user_key(key)` rebinds the user-visible event
key for all *future* completions emitted by this file. Reactors that
allocate the event key after constructing the `RegisteredFile` (e.g.
[`async-io`](https://docs.rs/async-io)'s `Slab<Source>` indexing —
see §5) call `set_user_key` once with the slab slot's index.

The store is `Release`; the dispatcher's load is `Acquire`. A
`set_user_key` racing with the dispatcher either lands before the
load (event carries the new key) or after it (event carries the old
key). Both outcomes are documented as acceptable — `set_user_key` is
best-effort for in-flight ops and exact for ops submitted after the
call returns.

---

## 5. Async-io integration

### 5.1 Why Shape A (key per `RegisteredFile`)

Three shapes were considered for how a readiness-style reactor learns
about file-op completions:

| Shape | Key granularity        | Waker storage              | Layering |
|-------|------------------------|----------------------------|----------|
| A     | one per `RegisteredFile` | reactor's existing `Source` | clean    |
| B     | one per `OpHandle`       | per-file `Slab<Waker>`      | leaky    |
| C     | none                   | `AtomicWaker` on `OpInner` | broken — `polling` would have to call `Waker::wake` itself |

Shape A is what we ship, for three reasons:

- **Same convention as sockets / waitables.** `register_file(handle, key)`
  mirrors `Poller::add(socket, Event::none(key))`. The reactor's
  `Slab<Source>` indexes the key the same way for every kind of
  source.
- **Zero new mutexes inside `polling`.** `OpInner` is lock-free;
  `RegisteredFileInner` only adds an `AtomicBool` and an `AtomicUsize`.
- **Reactor never sees `OpHandle`.** `OpHandle` is the user's
  per-future state; the reactor only reacts to "something happened
  on this key" and wakes the bound wakers.

### 5.2 Proposed `Registration::File` variant

In `async-io`'s `Registration` enum (`src/reactor/windows.rs`):

```rust
pub enum Registration {
    Socket(RawSocket),
    Handle(RawHandle),                        // existing waitable
    File(Arc<polling::RegisteredFile>),       // NEW
}

impl Registration {
    fn add(&self, poller: &Poller, key: usize) -> io::Result<()> {
        match self {
            Self::File(rf) => { rf.set_user_key(key); Ok(()) }
            // … existing Socket / Handle arms unchanged
        }
    }
    fn modify(&self, poller: &Poller, _interest: Event) -> io::Result<()> {
        match self {
            // File ops carry their own per-op interest; no modify needed.
            Self::File(_) => Ok(()),
            // … existing Socket / Handle arms unchanged
        }
    }
    fn delete(&self, poller: &Poller) -> io::Result<()> {
        match self {
            Self::File(rf) => { rf.deactivate(); Ok(()) }
            // … existing Socket / Handle arms unchanged
        }
    }
}
```

The variant carries `Arc<RegisteredFile>` (not `RawHandle`) because
`RegisteredFile` is the only legal way to submit ops on the handle,
and the handle is registered with the IOCP at construction time —
the reactor must not re-register or it would collide with the
existing kernel binding.

### 5.3 `Async<NamedPipe>` sketch

```rust
pub struct AsyncNamedPipe {
    source: Arc<Source>,                      // async-io's Source
    file:   Arc<polling::RegisteredFile>,
}

impl AsyncNamedPipe {
    pub async fn read(&self, buf: Vec<u8>) -> io::Result<(usize, Vec<u8>)> {
        match self.file.submit_read(buf) {
            Submission::Complete { bytes, buf }   => Ok((bytes, buf)),
            Submission::Failed   { error, buf: _ } => Err(error),
            Submission::Pending(handle) => ReadFut { handle: Some(handle), source: &self.source }.await,
        }
    }
}

struct ReadFut<'a, B> { handle: Option<OpHandle<B>>, source: &'a Arc<Source> }

impl<'a, B: Unpin> Future for ReadFut<'a, B> {
    type Output = io::Result<(usize, B)>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let h = self.handle.as_ref().unwrap();
        if h.is_complete() {
            return Poll::Ready(self.handle.take().unwrap().take());
        }
        ready!(self.source.poll_readable(cx))?;
        if h.is_complete() {
            return Poll::Ready(self.handle.take().unwrap().take());
        }
        Poll::Pending
    }
}
```

The future owns its `OpHandle` exclusively; cancel-on-drop is
available via `handle.cancel()` in a `Drop` impl. `source.poll_readable(cx)`
is the *same* method `Async<TcpStream>` uses — no new reactor surface.

### 5.4 Spurious wake budget

A `RegisteredFile` can have any number of in-flight `OpHandle`s of
either direction. When *any* one of them completes, every waker bound
to the file's key in the matching direction is woken. Each woken
future then:

1. Calls `OpHandle::is_complete()` on its own handle (one Acquire load).
2. If `false`: re-registers its waker and returns `Poll::Pending`.
3. If `true`: calls `OpHandle::take()` and returns `Poll::Ready`.

Cost per completion: O(in-flight ops on this file in this direction).
This matches edge-triggered epoll semantics. For pathological
multi-op-per-file workloads, a future revision could add a per-file
`Slab<Waker>` keyed by `Arc<OpInner>` identity inside `async-io`,
but this is **not** part of the v1 contract.

---

## 6. Cross-platform considerations (io_uring)

The shape is deliberately such that a Linux io_uring backend can live
behind the same public types:

| Concept              | IOCP                              | io_uring                            |
| -------------------- | --------------------------------- | ----------------------------------- |
| `RegisteredFile`     | handle + IOCP attach + flags      | fd (no per-fd state needed)         |
| `OpInner`            | `OVERLAPPED` + buf + state        | `user_data` ptr to buf + state      |
| `submit_read`        | `ReadFile(.., &op.overlapped)`    | sqe `IORING_OP_READ`                |
| `Submission` variant | `TRUE` / `IO_PENDING` / err       | always `Pending` (or sqe-full err)  |
| `cancel`             | `CancelIoEx`                      | `IORING_OP_ASYNC_CANCEL`            |
| completion delivery  | `OVERLAPPED_ENTRY.lpOverlapped`   | `cqe.user_data`                     |

The only API-visible difference is that io_uring has no native
sync-success short-cut — `Submission::Complete` would simply never
be produced on Linux, only `Pending`. Quality-of-implementation
difference, not an API difference.

`StableBuf` / `StableBufMut` are exactly what io_uring requires
(the kernel polls memory at the registered address while the sqe is
in flight), so no extra abstraction layer is needed.

---

## 7. Test coverage

| Test file | Coverage |
|-----------|----------|
| [tests/windows_overlapped.rs](../tests/windows_overlapped.rs) | Happy-path round-trips, single-op semantics, `register_file` collisions, drop ordering. |
| [tests/file_concurrent.rs](../tests/file_concurrent.rs) | Multiple concurrent reads / writes, mixed read+write, per-op cancellation. |
| [tests/file_lifetime.rs](../tests/file_lifetime.rs) | `OpHandle` outliving `RegisteredFile`, `OpHandle` outliving `Poller`, `deactivate` semantics, in-flight ops across deactivation. |
| [tests/common/mod.rs](../tests/common/mod.rs) | Shared helpers: `new_named_pipe`, `server`, `client`, `pipe`, Wine-skip predicate, generous `wait_for_event` polling. |

Build / test gates (run by CI and on every commit on this branch):

```pwsh
cargo check --target x86_64-pc-windows-msvc --tests --examples
cargo test  --target x86_64-pc-windows-msvc
$env:RUSTDOCFLAGS="-D warnings"; cargo doc --no-deps --target x86_64-pc-windows-msvc
```

---

## 8. Open questions

1. **`Submission` ergonomics.** Three variants is the right shape for
   the kernel's actual outcomes, but most callers only branch on
   `Pending` vs not. A `Result<Either<…>, …>` or a small helper like
   `Submission::into_pending(self) -> io::Result<Option<OpHandle<B>>>`
   may read better in `async` glue code.
2. **Multishot reads.** io_uring supports `IORING_OP_RECV` in
   multishot mode (one submission, many completions). IOCP has no
   equivalent. Out of scope for v1.
3. **Scatter/gather (`ReadFileScatter` / `WriteFileGather`).** Likely
   v2; the buffer trait would gain `as_iovec` / `as_iovec_mut`.
4. **Buffer pools / registered buffers
   (`IORING_REGISTER_BUFFERS`, `RIO_*`).** Out of scope for v1.
5. **`async-io` cancel-on-drop policy.** `polling` defaults to
   "silent drop = leak the `OpHandle` but keep the kernel Arc; buffer
   is reclaimed on completion." Whether `async-io`'s per-op future
   should call `handle.cancel()` on drop to bound the in-flight
   buffer count is an open item for the follow-up `async-io` PR.

### 8.1 Out of scope

Deliberately not addressed in v1, in addition to the items above:

- Async/await wrappers around `OpHandle`. Downstream crates do this.
- Buffer pools / registered buffers (`IORING_REGISTER_BUFFERS`,
  `RIO_*` for sockets).
- AFD socket completions (already supported by `polling` separately).
- Replacing the readiness side of `polling` — this design only
  changes the file-handle corner.
