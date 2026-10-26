# EE segment barrier and gameplay-loop observation

`barriers.py` generates and links an offline helper and guarded patch plan for
NTSC-U `SCUS-97472`. It does not install patches, access an emulator, or modify
an ISO. `g` and `m` mean **loaded disassembly-listing origins**: the actual
`.text` addresses minus `0x38` for this revision. The
caller owns the separate code/state allocations and must exclude overlaps with
all game allocations and other helpers. The generator checks its own extents
and guarded instruction locations, not whole-module or live heap ownership.

## Scope and original contracts

* MANAGER `+0xE35CC`: the sheet worker's call to `+0xE2CC8`, the segment
  dependency-release walk. The original delay slot loads the segment index
  into `a1`; `a0` is the sheet header and `a2` is zero. The wrapper waits before
  invoking that walk exactly once. It tail-jumps to the original function with
  the original call-site return address, arguments and stack pointer.
* MANAGER `+0xE35D4`: the immediately following call to `+0xE26D8`, resource
  cleanup. Its wrapper calls the original once and publishes completion only
  after it returns. This function has no stack arguments. Its result registers
  and machine-state changes are preserved, rather than restoring pre-call
  values over its results.
* GAMECORE `+0x17500`: entry to the normal `st_gameflow` gameplay loop. Sets
  `gameplay_ready=1` as an observation. Its displaced `lw` and `beqz` are
  replayed with the original branch target `+0x1756C` and original LUI delay
  slot on **both** paths. The PC-relative branch is not copied verbatim.
* GAMECORE `+0x178D8`: gameplay-loop exit call to `PlayerSprStatusEnd`
  (`+0xC0CD0`). Clears `gameplay_ready`, then tail-jumps to the original.

The segment reference count and resolved bit have already changed at `E35CC`.
Dependency release and cleanup have not run. The sheet-worker queue semaphore
is not held here; it is acquired later at `E37A0`. Waiting uses `sheetWait`
(`+0xE3978`), which sleeps the sheet thread and participates in its existing
scheduler wakeup mechanism. The wrapper never calls `scrRun` or spins on RAM.

This does **not** replace the asynchronous `sheetMgrUnloadSegmentIndex` API,
invent retry return codes, or defer a pointer into the sender's stack. The
worker retains the original request and eventually writes its original
completion word through the original code.

**Coverage is limited to actual zero-reference segment-index unloads.** It does
not cover the worker's map-block or stage-texture unload operations (operation
codes 3, 5 and 6), all resource releases, or in-place restart work that does not
unload a segment. Operation 1 is the segment-index unload intercepted here.
Earlier lifecycle invalidation remains necessary for in-place restarts.

## State and single-pending handshake

State is `0x50` bytes of little-endian words; `OFF` is the authoritative field
layout. Initialize it with `initial_state(generation=..., wait_limit=...)` only
when there is no outstanding request and no executing wrapper. Generation is a
nonzero host-established epoch, not a discovered P1/resource generation.

1. The target refuses entry if a request is active, completion is unacknowledged,
   a fault is latched, sequence would wrap, or a stale host command exists.
2. It increments sequence, fills `request_sheet/request_segment`, clears the
   readiness observation, then publishes `phase=WAIT` after `sync`.
3. The host observes a coherent **paused** snapshot, drains all owned P2 objects
   through final-free acknowledgements, and revalidates the same epoch/request.
   Only then it writes `permit_generation` and `permit_sequence` for that exact
   request before resuming. These words are a pair, not independent live writes.
4. The target rejects mismatched identities and changes to the active identity.
   An exact permit changes phase to `RELEASING`; this consumes the permit. The
   accepted permit fields remain as an identity check until cleanup finishes.
5. After original cleanup returns, the target writes `complete_sequence` and
   `complete_generation`, clears permit fields, executes `sync`, then clears
   phase to `IDLE`. This is the COMPLETE publication; there is no transient
   COMPLETE phase that a polling host could miss.
6. The host explicitly acknowledges the matching completed identity with
   `ack_sequence/ack_generation`, in a coherent paused transaction. Without
   that acknowledgement a later unload fails closed; it cannot overwrite the
   previous completion. Acknowledgement does not authorize spawning.

No ring is involved. `Handshake` is an executable in-memory model for tests and
integration design, not a transport or thread-safe live RAM writer. Actual
host integration must pause and recheck the target for command/ack/recovery
transactions; `sync` is not a replacement for an atomic multiword host write.

An abort is an exact request identity written into `abort_*`. Abort has priority
over permit. It latches a fault and keeps the worker asleep: **abort never skips
the original dependency walk and resumes normal execution.**

`wait_limit` counts sleeps without a permit, not wall-clock milliseconds. Zero
disables the configured limit, but counter overflow still faults. Timeout,
unknown permit and abort latch faults; no timeout auto-permits an unload. The
host can pause, independently revalidate the pending request and drain, clear
those recoverable faults and command words, reset the wait count, then submit
a fresh matching permit. `recover_wait` models that explicit operation. Nested,
overflow, malformed identity and unexpected-cleanup faults require restoring
a known-safe epoch; they cannot borrow another request's permit.

The host's drain must not wait for a sheet request queued behind the blocked
worker. In particular, independently verify any callbacks installed on the
owned P2 objects do not synchronously wait on this worker. Do not claim the
barrier eliminates arbitrary callback-induced deadlocks.

## Preservation and readiness limits

Each observation/wait wrapper saves all 31 nonzero GPRs as 128-bit quantities,
including the original SP and RA, all 32 scalar FPR bit patterns, FCR31,
both HI/LO lanes using `pmfhi/pmflo`, and SA. Frames are `0x400` bytes and
require a valid 16-byte-aligned EE stack with enough space. Cleanup needs two
such frames in addition to the original cleanup function's stack use. The
helper introduces no FPU arithmetic or VU instructions. The scalar FPU
accumulator and VU state are not explicitly serialized by this helper;
cross-thread preservation of those relies on the original scheduler/context
contract and must not be advertised as a separately proven guarantee.

Readiness is only proof that the normal gameplay loop was reached. The host
still requires canonical P1 identity, live constructor/resource epochs, no
`__gameMode & 1`, no pending teardown, and its cutscene/transition checks.
Control mode zero alone is not proof of gameplay readiness. Clear stale
readiness during host-owned restart/invalidation; the target also clears it
when publishing a segment barrier and at gameplay-loop exit.

Loader-relocated data HI/LO immediates are opcode/register guarded and replayed
from the supplied original loaded words. The generator never guesses a data
base from the text base. Call targets, branch displacement and unrelocated
instructions are exactly guarded. Integration must establish original-image
provenance and perform compare-before-write using the returned expected words.
