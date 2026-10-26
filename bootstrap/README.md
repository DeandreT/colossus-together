# Offline fresh-boot allocation bootstrap

This is an unapplied plan generator, not a launcher or an approved installer.
It has no emulator, ISO writer, process discovery or Python-side game allocator.
Only explicitly invoked local assembler builds create temporary files.

`AllocationSpec` takes actual loaded **.text** bases for GAMECORE, KERNEL and
MANAGER; never pass XFF header addresses. It accepts only the original NTSC-U
`DebugSnapShot` function at GAMECORE `.text+0x4A40`, size `0x3D4`. The original
GAMECORE SHA-256 and symbol extent are checked against caller-supplied bytes.
`original_cave` must contain all independently verified **relocated original**
function bytes. Source verification checks every non-relocated bit, but does not
authenticate relocation operands: the caller's provenance evidence must cover
those against the original module and resolved imports. RAM matching itself is
not provenance. Synthetic/unrelocated fixtures do not qualify as loaded code.

The caller must separately attest:

- Exclusive control and a quiescent installation boundary, including saved
  continuations outside the cave, not merely a paused CPU.
- DebugSnapShot is unused: disable its triggers and exclude every caller during
  the entire temporary installation. A debug name is not proof of unused code.
- Correct revision, loaded module identity/bases, allocator GP and live root heap.
- Sufficient incoming stack headroom for the bootstrap plus allocator, scheduler
  and interrupt usage. No game constructors run here.

## Native contract

The retained `allocate_survival_work.py` calls header-based `K+0x3790`, which is
KERNEL `.text+0x3758`, **iosMallocAlignNoCheck**. Original KERNEL metadata gives
size `0x80`. Its body preserves a0=root heap, a1=size, a2=alignment across
WaitSema, passes those to its allocator, signals the semaphore and returns the
allocation/null. Unlike iosMallocAlign, it does not invoke the out-of-memory
recovery callback. It still can wait/yield or fail nonlocally; no timeout or
automatic retry is safe. Do not substitute a similarly named allocator.

The bootstrap temporarily replaces only GAMECORE `.text+0xC640`'s JAL; the NOP
delay slot is guarded and unchanged. After saving state it calls the allocator
once with the supplied root heap, 64 KiB–2 MiB size and alignment 16. It restores
incoming full-width GPRs (including original SP/GP/RA), both packed HI/LO lanes,
SA, 32 scalar FPRs and FCSR, then tail-calls original MANAGER
`.text+0xD05B8` USB exactly once, preserving USB's actual results naturally.
FPU accumulator, VU/CP0 and device state are not explicitly saved; no floating
arithmetic is emitted. Their preservation requires the original native/scheduler
contract. The bootstrap reserves `0x300` stack bytes, including 64-byte outgoing
EABI home space. Headroom on the stock 4 KiB stack remains unqualified.

The final aligned 16-byte area inside the cave is initialized separately by the
plan. Code must end before it. Words are status, accepted base, raw returned
base, error. Status is 0=fresh, 1=attempt started, 2=success, 3=failed. Error is
1=null, 2=bad alignment/range/bootstrap overlap. Nonzero status never reallocates.
A nonreturning allocator leaves status 1. Invalid returns are retained but not
freed; numerical checks are not proof of heap ownership or overlap freedom with
all game allocations. No allocation is published before successful validation.

## Integration and recovery contract

Call `build(spec, original_gamecore_bytes, offline_read, assembler=...)` against
a stable snapshot. Its `guards` must all be rechecked immediately before a real
installation. Reserve exclusive ownership, write/read back code and zero state,
perform qualified cache maintenance, then publish `patches` last using the
existing reviewed-patch machinery. Capture actual write receipts and uncertain
writes; the plan and `restore_call` are not proof anything was installed.

After observing status 2 (or a returned failure), the host can pause and restore
the USB seam only if it still equals this plan's jump. **Do not yet restore the
cave.** Resume through a separately verified scheduling cycle, then prove no PC,
stack continuation or pending invocation still points into the cave. An allocator
may yield, so one cycle or an outside PC alone is insufficient. Only afterward
restore cave bytes from the original installation record, conditional on each
byte still being ours (state words legitimately changed). Preserve foreign or
uncertain writes and stop. Never restore/free an in-flight cave or automatically
free the new allocation. No restoration function is supplied here.

This breaks the historical dependency on P2, camera hooks, old heap allocations
and savestates. It does **not** prove the cave is safe on a fresh boot, qualify
stack/cache behavior, create P2, or establish automatic co-op readiness.

Focused checks: `python -m pytest tests/test_bootstrap_allocator.py`.
Source-instruction tests cover register preservation, arguments, repeated calls,
sticky failure and invalid returns. Private-original and real EE build checks
skip when their local prerequisites are absent. No test runs a game.
