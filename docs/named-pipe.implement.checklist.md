# Named-Pipe Redesign — Implementation Checklist

Tracks step-by-step implementation of the design described in
[`named-pipe.design.md`](./named-pipe.design.md). Each item maps
back to a section in that doc. Mark items `[x]` as they land.

Build/test gate between every step:

```pwsh
cargo check
cargo test
$env:RUSTDOCFLAGS="-D warnings"; cargo doc --no-deps
```

---

## Step 1 — Internal: replace `FileFields` with `OpInner` (no public API change)

Goal: introduce the per-op kernel-visible block alongside the existing
file path. Old API still compiles.

- [x] 1.1 Add `OpInner` struct in `src/iocp/mod.rs`:
  - [x] `#[repr(C)]`, `OVERLAPPED` at offset 0
  - [x] `state: AtomicU8` (`Submitted | Completed | Cancelled`)
  - [x] `bytes_transferred: AtomicU32`
  - [x] type-erased buffer slot (`UnsafeCell<MaybeUninit<ErasedBuf>>`)
  - [x] `vtable: &'static OpVTable` (`drop_buf`, `take_buf`)
  - [ ] `file: Arc<RegisteredFile>` back-reference (forward decl ok) — *deferred to Step 2 (RegisteredFile not yet defined)*
- [x] 1.2 Add `PacketInner::FileOp { #[pin] op: OpInner }` variant
  alongside existing `PacketInner::File`.
- [x] 1.3 Extend `wait_deadline` completion loop: `is_file_completion()`
  routes to either `File` (old) or `FileOp` (new) without breaking
  socket / waitable / custom paths.
- [x] 1.4 Unit-test the vtable: construct an `OpInner` for `Vec<u8>`,
  drop it, ensure no leak (Miri). *(3 tests in `iocp::op_tests`)*
- [x] 1.5 `cargo test` — existing `tests/windows_overlapped.rs` still
  green.

---

## Step 2 — New submission API behind a feature flag

 Submission::Pending(handle) k Submission::Pending(handle)
> **Refined by Step 7** — items 2.9–2.11 below describe the original
> `FileCompletion` token + `Events::iter_file_completions` channel.
> That design was replaced by `OpHandle::{is_complete, try_take, take,
> register_waker}`. See Step 7 for the final shape.

Goal: ship `RegisteredFile` / `OpHandle<B>` / `Submission<B>` in
parallel with the old API. Gate behind `#[doc(hidden)]` or
`feature = "iocp-file-v2"`.

- [x] 2.1 Add `StableBuf` / `StableBufMut` traits (minimal surface,
  `# Safety` doc per §3.2). *(in `src/iocp/buf.rs`)*
  - [x] Blanket impls: `Vec<u8>`, `Box<[u8]>`, `&'static [u8]`
  - [ ] (Optional) `bytes::Bytes` / `BytesMut` behind a `bytes` feature — *deferred; not required for v1*
- [x] 2.2 Add `RegisteredFile` (Clone, Arc-backed):
  - [x] `handle: RawHandle`, `port: Arc<IoCompletionPort<…>>`,
    `active: AtomicBool` *(in `RegisteredFileInner`)*
  - [x] Internal ctor invoked from `Poller::register_file`
    (separate from legacy `add_file` per design)
- [x] 2.3 Add `OpHandle<B>` typed wrapper over
  `Pin<Arc<IoStatusBlock<PacketInner>>>` + `PhantomData<B>`.
- [x] 2.4 Add `Submission<B>` enum: `Complete { bytes, buf } |
  Pending(OpHandle<B>) | Failed { error, buf }`.
- [x] 2.5 Implement `RegisteredFile::submit_read<B: StableBufMut>`:
  - [x] Allocate `Pin<Arc<IoStatusBlock<PacketInner::FileOp>>>`
  - [x] Stash buffer via vtable
  - [x] Call `ReadFile`, classify return into the three variants
  - [x] On failure path, reclaim Arc and return buffer
- [x] 2.6 Implement `RegisteredFile::submit_write<B: StableBuf>`
  (symmetric).
- [x] 2.7 Implement `RegisteredFile::submit_connect_named_pipe()
  -> Submission<()>`.
- [x] 2.8 Implement `OpHandle::cancel(&self) -> io::Result<()>`
  (`CancelIoEx(handle, &op.overlapped)`).
- [x] 2.9 Implement `OpHandle::take` *via* `FileCompletion` (see 2.11):
  vtable extracts buffer, returns `(usize, B)` or `io::Error`.
- [x] 2.10 Implement "leak buffer on premature drop" rule
  (§6a.3 *Misuse*): `OpHandle::Drop` leaks the packet `Arc` when
  `state != Completed`.
- [x] 2.11 Add `FileCompletion<'a>` token + `Events::iter_file_completions`.
  Existing `Events::iter()` continues to skip file completions.
- [x] 2.12 Wire `register_file` to call
  `SetFileCompletionNotificationModes(handle,
  FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)`.
  Tolerate `ERROR_INVALID_FUNCTION`. *(legacy `add_file` does NOT set
  these flags — it would break tests that depend on sync-success
  completions arriving)*
- [x] 2.13 Wire sync-success branch in `submit_*` to return
  `Submission::Complete` (the IOCP packet is suppressed by 2.12).
- [x] 2.14 `cargo doc --no-deps -D warnings` clean for new public items
  (with and without `--features iocp-file-v2`).

---

## Step 3 — Tests for the new API

> **Refined by Step 7** — tests originally written against
> `FileCompletion` / `Events::drain_file_completions` were rewritten to
> drive `OpHandle::is_complete` + `OpHandle::take`.

- [x] 3.1 Create `tests/common/mod.rs` with named-pipe helpers
  (`new_named_pipe`, `server`, `client`, `pipe`) extracted from
  `windows_overlapped.rs`.
- [x] 3.2 Create `tests/file_concurrent.rs`:
  - [x] `two_concurrent_writes_distinguish_completions`
  - [x] `two_concurrent_reads_dispatch_correctly`
  - [x] `mixed_read_write_concurrent`
  - [x] `cancel_pending_read_returns_aborted`
  - [x] `cancel_after_completion_is_noop`
  - [x] `cancel_one_of_many_does_not_affect_siblings`
  - [x] `sync_success_returns_complete_variant`
  - [x] `async_path_still_returns_pending`
- [x] 3.3 Create `tests/file_lifetime.rs`:
  - [x] `op_outlives_registered_file_clone`
  - [~] `submit_after_remove_file_errors` — mapped to
    `RegisteredFile::deactivate()` (v2 has no `remove_file`).
  - [~] `in_flight_op_completes_after_remove_file` — mapped to
    `RegisteredFile::deactivate()` (v2 has no `remove_file`).
  - [x] `poller_dropped_before_op_completion`
  - [~] 3.3 `drop_pending_op_does_not_uaf` — Miri-only stub; the v2
    submit path is unconditional Win32 syscalls (`ReadFile` /
    `CancelIoEx`) which Miri cannot evaluate, so a meaningful
    Miri-friendly variant is blocked without a `#[cfg(test)]`
    constructor for `OpInner`. Non-Miri equivalent is
    `poller_dropped_before_op_completion`.
  - [x] `buf_addr_stable_across_submit`
  - [~] `vec_grown_after_submit_is_safe` — runtime variant impossible
    because the v2 API takes the buffer by value (caller has no
    handle to the `Vec` between `submit_*` and `take`); recorded as
    a `compile_fail`-style note in the test file.
- [x] 3.4 `#[ignore]` stress test `many_ops_stress` (10 000 ops).
- [x] 3.5 `cargo test --features iocp-file-v2 --target x86_64-pc-windows-msvc`
  green; `RUSTDOCFLAGS=-D warnings cargo doc --no-deps
  --target x86_64-pc-windows-msvc` green (with and without the
  feature). Miri opt-in deferred to user.

---

## Step 4 — Port the existing test suite

> **Refined by Step 7** — `submit_*` + `FileCompletion::take` rewritten
> as `submit_*` + `OpHandle::take`.

Translate `tests/windows_overlapped.rs` per §8.1 disposition table.

- [x] 4.1 `win32_file_io` → `submit_write` + `FileCompletion::take`
- [x] 4.2 `writable_after_register`
- [x] 4.3 `write_then_read`
- [x] 4.4 `close_before_read_complete`
- [x] 4.5 `close_before_write_twice_complete` → folded into
  `two_concurrent_writes_distinguish_completions`
- [x] 4.6 `connect_before_client`
- [x] 4.7 `write_disconnected`
- [x] 4.8 `write_then_drop` → replaced by `drop_writer_drain`
  (assertions on `test_ref_count` removed)
- [x] 4.9 `connect_twice`
- [x] 4.10 `remove_file_before_add_file`
- [x] 4.11 `add_file_different_poll`
- [x] 4.12 Inline helper copies removed; `mod common;` used instead.

---

## Step 5 — Remove the old API

- [x] 5.1 Delete `IocpFilePacket` (struct + impls).
- [x] 5.2 Delete `FileOverlappedConverter`, `FileOverlappedWrapper`.
- [x] 5.3 Delete `Overlapped<T>` newtype (logic absorbed by `OpInner`).
- [x] 5.4 Delete `read_file_overlapped`, `write_file_overlapped`,
  `connect_named_pipe_overlapped`.
- [x] 5.5 Delete `file_op_overlapped` helper.
- [x] 5.6 Delete `PacketInner::File` variant + `FileFields`.
- [x] 5.7 Delete `IocpFilePacket::test_ref_count` references.
- [x] 5.8 Drop the feature gate / `#[doc(hidden)]` from step 2 — new
  types become the stable surface.
- [x] 5.9 Update `examples/named_pipe.rs` to the new shape.
- [x] 5.10 Add `examples/named_pipe_concurrent.rs` (two reads + cancel).
- [x] 5.11 Add "Superseded by `named-pipe.design.md`" banner to
  obsolete §2.x items in `docs/named-pipe.design.md`.
- [x] 5.12 Update `CHANGELOG.md`.

---

## Step 6 — PR description & changelog

- [ ] 6.1 Rebase commits onto current `kail/windows_file`.
- [ ] 6.2 Update PR #248 description: link to
  `docs/named-pipe.design.md`, call out the breaking change vs the
  prior unreleased shape.
- [ ] 6.3 Final CI green: `cargo test`, `cargo doc -D warnings`, Miri
  opt-in tests.

---

## Step 7 — Refactor: drop `FileCompletion`, `OpHandle` owns completion

Goal: collapse the two-step `OpHandle` → `FileCompletion` handoff into
`OpHandle` itself, and fix the latent kernel-Arc-bump bug that forced
`OpHandle::Drop` to leak via `ManuallyDrop`.

- [x] 7.1 Add an `atomic_waker::AtomicWaker` field to `OpInner` and
  initialize it in both constructors. (Used `atomic-waker = "1.1"` —
  `futures-core` does not contain `AtomicWaker`.)
- [x] 7.2 Bump the `Packet` strong count via `mem::forget(packet.clone())`
  on the `ERROR_IO_PENDING` branches of `classify_submission` and
  `submit_connect_named_pipe`. Document as the kernel's owned strong ref.
- [x] 7.3 Switch `Pin<Arc<T>>::file_op_done` from
  `Arc::increment_strong_count` (clone) to plain `Arc::from_raw`
  (reclaim). Update `OverlappedEntry::Drop` to reclaim file completions
  symmetrically.
- [x] 7.4 In the dispatcher (`Poller::wait_deadline` file-completion
  branch): stash `(bytes, nt_status)` on the op, unconditionally
  publish `OpState::Completed` (cancellation outcome lives in
  `nt_status`). *(Step 7b: now also pushes an `Event` instead of
  waking a per-op `Waker` — see Step 7b.5.)*
- [x] 7.5 Add `OpHandle` methods: `is_complete`, `try_take`, `take`
  (panic on incomplete), `register_waker`. *(Step 7b removed
  `register_waker` — see Step 7b.2.)*
- [x] 7.6 Remove the custom `impl<B> Drop for OpHandle<B>` —
  default `Pin<Arc<...>>` drop is now correct because the kernel owns
  one strong ref until the dispatcher reclaims it.
- [x] 7.7 Delete `FileCompletion<'a>`, `Events::file_completions`,
  `Events::iter_file_completions`, `Events::drain_file_completions`.
- [x] 7.8 Rewrite `tests/windows_overlapped.rs`,
  `tests/file_concurrent.rs`, `tests/file_lifetime.rs`,
  `examples/named_pipe.rs`, and `examples/named_pipe_concurrent.rs`
  against the new surface.
- [x] 7.9 Update `docs/named-pipe.design.md` (Step 7 amendment
  banner) and this checklist (Step 7 section + Step 2/3/4 banners).
- [x] 7.10 Gates green: `cargo check --target x86_64-pc-windows-msvc
  --tests --examples`, `cargo test --target x86_64-pc-windows-msvc`,
  `RUSTDOCFLAGS=-D warnings cargo doc --no-deps
  --target x86_64-pc-windows-msvc`.

## Step 7b — Replace waker with event emission (corrects Step 7)

The first Step 7 implementation added `AtomicWaker` to `OpInner` and
`OpHandle::register_waker(&Waker)`. That broke layering: `polling` is
the *event* layer; the reactor (e.g. `async-io`'s `ReactorLock::react`
in `D:\rust\async-io\src\reactor.rs`) owns the per-source waker
registry keyed by `Event::key`. Step 7b deletes the waker layer and
emits a normal `Event` per file-op completion instead.

- [x] 7b.1 Remove `waker: atomic_waker::AtomicWaker` field from
  `OpInner` and its initialisation in both `OpInner::new` and
  `make_op_packet`. Drop the `atomic-waker` dependency from
  `Cargo.toml`. Remove the `use std::task::Waker` from `mod v2`.
- [x] 7b.2 Remove `OpHandle::register_waker(&Waker)` and its docs.
  Update `OpHandle::take` panic message to point users at draining
  `Poller::wait` rather than at `register_waker`.
- [x] 7b.3 Add `user_key: usize` to `RegisteredFileInner`; thread it
  through `Poller::register_file(handle, key)` and the public
  `PollerIocpFileExt::register_file(file, key)` extension method.
- [x] 7b.4 Add `OpInterest { readable, writable }` to `OpInner`; wire
  `make_op_packet` to accept it. `submit_read` →
  `(readable: true, writable: false)`; `submit_write` →
  `(readable: false, writable: true)`; `submit_connect_named_pipe` →
  `(readable: true, writable: false)` (server connect typically
  precedes a read).
- [x] 7b.5 Update the `Poller::wait_deadline` file-op completion arm
  to perform the 5 stores in this order: bytes_transferred → nt_status
  → state → push `Event { key, readable, writable, .. }` → drop the
  kernel-bumped `Arc`. The `state` Release MUST precede the event push.
- [x] 7b.6 Update `tests/windows_overlapped.rs`,
  `tests/file_concurrent.rs`, `tests/file_lifetime.rs`,
  `examples/named_pipe.rs`, `examples/named_pipe_concurrent.rs`: every
  `register_file` call now passes a small distinct `usize` key.
- [x] 7b.7 Add a tighter test that asserts `events.iter()` contains an
  `Event { key, readable, writable }` matching the op's direction
  (`tests/windows_overlapped.rs::read_completion_emits_event_with_key_and_direction`).
- [x] 7b.8 Update `docs/named-pipe.design.md` Step 7 banner and add a
  Step 7b banner documenting: the layering rationale, the dispatcher
  store order, the `OpInterest` field, that connect = readable-only,
  and that spurious wakes are bounded by in-flight ops on the same
  file in the same direction.
- [x] 7b.9 Gates green: `cargo check --target x86_64-pc-windows-msvc
  --tests --examples`, `cargo test --target x86_64-pc-windows-msvc`,
  `RUSTDOCFLAGS=-D warnings cargo doc --no-deps
  --target x86_64-pc-windows-msvc`.

---

## Step 7c — Reactor-friendly key rebinding (`set_user_key`)

Required by the async-io integration described in
[`named-pipe.design.md`](./named-pipe.design.md) §5.2: a reactor
that allocates the key from a `Slab` only knows the key *after*
constructing the `RegisteredFile`. Today `register_file(handle, key)`
forces the caller to commit to the key up-front, which means the
reactor would need to either (a) construct `RegisteredFile` lazily on
first use or (b) use a placeholder key and rebind. Option (b) is
strictly cheaper and safer.

- [x] 7c.1 Change `RegisteredFileInner.user_key: usize` to
  `AtomicUsize`. Initialize from the value passed to
  `register_file`.
- [x] 7c.2 Replace the dispatcher's `op.file.user_key` read with an
  `Acquire` load on the `AtomicUsize`. Verify the existing release
  fence on `state.store(Completed, Release)` still happens-before the
  user observing the event (it does — the event push reads `user_key`
  *after* the state store).
- [x] 7c.3 Add `pub fn RegisteredFile::set_user_key(&self, key: usize)`
  that does a `Release` store. Document: "Intended for reactors that
  allocate the event key after constructing the `RegisteredFile`. Has
  no effect on completions already enqueued by the kernel."
- [x] 7c.4 Add a unit / integration test
  (`tests/file_concurrent.rs::set_user_key_takes_effect`):
  register with key=0, submit a read, before peer writes call
  `set_user_key(KEY)`, peer writes, assert the emitted `Event::key ==
  KEY`.
- [x] 7c.5 Update `docs/named-pipe.design.md` §5.2 to drop the
  "TODO" framing on `set_user_key` and link to the implementation.
- [x] 7c.6 Gates green: `cargo check --target x86_64-pc-windows-msvc
  --tests --examples`, `cargo test --target x86_64-pc-windows-msvc`,
  `$env:RUSTDOCFLAGS="-D warnings"; cargo doc --no-deps --target x86_64-pc-windows-msvc`.

---

## Cross-cutting verification (run after every step)

- [ ] `cargo check`
- [ ] `cargo test`
- [ ] `$env:RUSTDOCFLAGS="-D warnings"; cargo doc --no-deps`
- [ ] (After Steps 3 & 4) `cargo +nightly miri test --target x86_64-pc-windows-msvc`
