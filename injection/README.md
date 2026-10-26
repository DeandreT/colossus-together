# Offline EE constructor telemetry

This is a foundation, **not a live installer or a completed co-op runtime**.
It contains no game asset/binary payloads. `render()` returns our assembly;
`build()` assembles it with EE binutils, removes ABI-only metadata with the
matching `objcopy`, then links the relocatable object using `runtime.elf`.
It returns payload bytes and compare-before-write `WordPatch` plans without
performing memory I/O. No emulator, SSH or ISO access occurs here.

## Placement and guards

`capture_delete_requests=False` leaves the delete-request entry untouched when
another explicitly composed subsystem owns it. Constructor and final-free
captures remain enabled. In that mode the controller must receive deletion
intent from a separate verified source; final-free events alone do not replace
pre-deletion invalidation. The option does not silently chain unknown hooks.

An optional `free_watch` table limits final-free records to explicitly tracked
allocation addresses. Its first word is a count, followed by up to
`free_watch_capacity` addresses. Publish it only while producers are quiescent;
it is not an allocation-liveness discovery mechanism. Unwatched frees still call
the original routine without generating a record. An excessive count marks
capture loss rather than reading outside the table. This prevents unrelated
short-lived game objects from exhausting the lifecycle ring.

`Config(g, m, k, code, ring, state)` uses **loaded listing origins** (actual
`.text` minus `0x38` for this revision), not section-relative XFF offsets or file
header positions. `g` is accepted for the shared module configuration but no
GAMECORE hook is implemented. All addresses are caller-owned, 16-byte-aligned
physical EE RAM addresses. Reserve `0x4000` bytes for code, `0x4000` for the
64-entry ring, and 32 bytes for state. Start state with `initial_state()` and
zero the ring. The caller must separately prove these allocations are unused;
range/overlap validation is not ownership discovery.

Supply a mapping of address to freshly read uint32 for **all** addresses from
`guard_expectations(config)`. It returns expected values and masks, including
the loaded-address-dependent `iosFree` JAL and a relocated LUI opcode mask.
Every mismatch/missing word rejects generation. Guard all words again before
any eventual installation, not only the two overwritten words. Guards cover:

| Function | Module offset | First two words |
|---|---:|---|
| `initScriptCharObj` | MANAGER `0x832d8` | `27bdfcf0 0000702d` |
| `initAliasLayoutObj` | MANAGER `0x82fa0` | `27bdfe90 3c020003` |
| `isysRequestDeleteObj` | KERNEL `0x1abe8` | `27bdffd0 ffb00000` |

The final-free callsite is KERNEL `0x1975c`, guarded together with `0x19758`
(`lw a0,0(s1)`) and `0x19760` (`daddu s1,s0,zero`). Its JAL must target
`iosFree` at KERNEL `0x39c8`; the helper changes **only the JAL**, retaining the
original delay instruction. Additional guards at `iosFree` establish its
stack setup and save-before-overwrite use of s0. The relocated LUI immediate
is not hardcoded.

These and the extra save/overwrite guards were verified against the NTSC-U
`sotc-decomp/asm/xff/{MANAGER,KERNEL}/text.s` definitions. The two displaced
instructions are position-independent and execute exactly once in each
trampoline before jumping to entry+8. Other game revisions are unsupported.

Constructor wrappers leave `a0-a3`, `t0-t3`, original SP/stack arguments, GP,
HI/LO and floating-point state untouched before entering the original. No FPU
instruction is used, so floating arguments/status remain untouched and the
original's return-side floating state is preserved. Only caller-scratch
`t4-t9` are used for capture. `s0` carries the reserved slot through the
original, whose verified code saves it before overwriting it and restores it
on return. The wrapper restores the caller's full 128-bit `s0` and RA; all
other callee-saved registers are left to the original function. Original full
`v0`/`v1` returns are untouched; telemetry stores the 32-bit object address.
There is no wrapper stack frame to move the game's stack arguments.

The delete-request hook records `a0` **before** tail-entering the original,
without replacing its RA. It is a notification, not an interception/barrier:
an asynchronous host cannot act before the game continues merely because a
record was published first. Resource retention and child-before-parent
deletion still require an actual target-side barrier in a future integration.

The allocation-free hook saves `a0` before entering `iosFree` and publishes
`FINAL_FREE_ALLOCATION` only after `iosFree` returns (including its tail call
to `SignalSema`). At wrapper entry the original callsite delay has already
changed s1 to the next list node; s1 is **not** used to identify the object.
The wrapper carries its reserved slot in s0, which `iosFree` saves before
overwriting and restores before returning. It restores original s0/RA and
leaves `v0/v1`, s1, original SP and the other argument/callee-save contracts
unchanged apart from the original callee's effects. Post-return code reads
only the capture slot, never the freed object or allocation. A nonlocal exit
never publishes completion; the pending record deliberately blocks draining.
This observes only this deferred-object-free callsite, not arbitrary frees,
other destruction paths, or allocator-wide quiescence.

## Ring protocol (version 2)

State: eight little-endian uint32 words: magic `COOP`, version `2`, capacity
`64`, stride `256`, producer count, acknowledged consumer count, sticky loss,
reserved zero. Counters never wrap: producer `0xffffffff` latches loss.

Each 256-byte slot has:

| Offset | Contents |
|---:|---|
| `0x00` | ready sequence (zero while pending) |
| `0x04` | reserved sequence = producer count + 1 |
| `0x08` | kind: 1 script character, 2 alias layout, 3 delete request, 4 final-free allocation |
| `0x0c` | flags: 1 missing parameters, 2 invalid GP source, 4 invalid created-object address |
| `0x10` | constructor return `v0`, delete-request `a0`, or zero for final-free |
| `0x14` | raw pointer read from parameter bytes at `+0x20` |
| `0x18/1c` | parameter/GP captured byte counts |
| `0x20` | eight raw uint32 arguments: a0-a3, t0-t3 |
| `0x40` | `0x3c` parameter bytes (a2) |
| `0x7c` | constructor's `createdObject[0]`, or pre-free saved allocation `a0` |
| `0x80` | optional `0x40` GP source bytes |
| `0xc0/d0` | private full-width s0/RA save areas, not host metadata |
| other | zero/reserved |

The alias source is raw `t0`, never inferred from a fixed shrine asset.
Parameter and GP copies use bounded byte loads, support unaligned addresses,
and reject source extents outside physical EE RAM `[0x80000, 0x2000000)`.
Null/invalid parameter pointers emit an explicit missing flag; a null GP is
allowed, while an invalid non-null GP is flagged. Address-range validation
does **not** establish object lifetime, type, or resource ownership.
After a nonzero constructor result, a single `lw` captures `createdObject[0]`
only when the result is four-byte aligned and its entire word lies in the
same RAM range. Invalid results set flag 4 without dereferencing them. Zero
constructor results leave allocation zero without a read. A captured zero or
invalid allocation value cannot establish an allocation identity binding.

A slot is cleared and its sequence initialized before publishing the new
producer count. The constructor commits ready only after the original returns;
`sync` precedes publication. Nested calls reserve distinct slots. The host
stops at an unfinished outer record, even if inner records have completed.
At capacity or sequence exhaustion, loss is latched and the hook tail-calls
the original without another reservation, allocation, loop or overwrite.

This producer protocol supports nested constructors on **one serialized EE
execution thread**. It is not interrupt-safe or a multi-producer queue; no
installation is authorized until single-producer execution is established
or a separately verified target synchronization mechanism exists. Do not
infer safety merely because the reservation path has no calls or explicit
yields: an IRQ can interrupt its load/check/store sequence. Producer exclusion
across known handlers and scheduler paths has not been proved. `iosFree`
itself calls `WaitSema`, so callees are not assumed to be non-yielding. No
`DI`/`EI` or guessed interrupt-state restoration is emitted. Do not
consume concurrent/unpaused memory reads as coherent snapshots. Pause the EE,
read state and ring, drain, dispatch once, write only the acknowledged consumer
word, confirm it, and acknowledge that cursor locally before resuming. Never
clear target loss to resume an old epoch. Reset requires a fully quiescent new
session/epoch with independently invalidated lifecycle state.

## Lifecycle contract and missing pieces

`map_record()` returns an explicit missing-metadata result rather than guessing
which constructor belongs to P1 or represents body/mantle/head. A caller must
provide authoritative canonical identity, monotonic object/resource epochs,
part, parent, all transitive resource dependencies, and an independently owned
GP copy matching the captured bytes. Raw source GP addresses are not reused as
owned copies. The raw record retains the complete eight-argument snapshot;
the existing lifecycle event only accepts its narrower parameter/GP contract.
It does not yet describe constructor replay of every argument.

`AllocationIdentityMap.register(record, VerifiedAllocationIdentity(...))`
requires an exact constructor allocation/object/sequence match plus explicit
host-verified canonical or owned identity and generation. It rejects replacing
a live allocation binding. Resolve final-free records through that map, then
`map_record()` produces `CanonicalFinalFree` or `OwnedFinalFree` only for a
matching allocation and a later sequence. Retire the binding only after
successful delivery. Unknown/mismatched allocations return the raw record and
missing-metadata explanation, never a guessed object event. The map is local
to a capture epoch and is not restored across resets or telemetry loss;
monotonic ownership IDs and generations remain the host's responsibility.

`ControllerAdapter` dispatches mapped events, preserves missing-metadata
results, and rejects `GameplayReady(True)` after any ring loss. Loss requests
drain through `GameplayReady(False)`; resulting cleanup actions are available
as `loss_actions`. Route readiness through this adapter, not directly to its
lifecycle instance. Delete-request never produces a final-free event.
Canonical discovery, coverage of other free paths, unload barriers, target synchronization, cache coherency,
main-object creation, replay/group substitution, gameplay readiness and live
installation remain separate, unimplemented integration responsibilities.

## Offline validation

```
python -m unittest discover -s tests -p 'test_injection*.py' -v
SOTC_EE_AS=/path/to/mips64r5900el-ps2-elf-as \
  python -m unittest discover -s tests -p 'test_injection_build.py' -v
```

The synthetic instruction harness exercises entry arguments, full return and
s0 restoration, nested completion, overflow bypass, reuse, invalid pointers,
pre-return allocation capture, post-free completion, allocation identity
mapping, nonlocal failure, and no reads of freed memory. The optional
real-binutils test validates ELF relocation, patch destinations, retained
free-call delay slot and emitted trampoline words. Neither test is live-game
qualification.
