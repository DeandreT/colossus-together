# EE game-thread command mailbox

Offline protocol and generated **project-owned** R5900 assembly. No module
connects to an emulator, installs a hook, writes a game object, edits an ISO, or
implements lifecycle policy. `Host` accepts the existing `runtime.pine.PineClient`
interface (`read32` / `write32`) or an equivalent bounded memory adapter.

## Hook and installer contract

The NTSC-U listing places the main-loop call at `GAMECORE+0xC678` relative to
its listing origin (actual `.text+0xC640`), with a NOP delay slot.
`usbdevFrameInit` is at listing-origin `MANAGER+0xD05F0`
(actual `.text+0xD05B8`); its first
two instructions are `addiu sp,sp,-16` and `sd s0,0(sp)`. `guards(config)`
checks the relocated original JAL, original USB entry, delay slot, and nearby
loop instructions. `render` refuses missing or changed observations. These
small guard words are not a copy of the game function. The original USB is an
external symbol in generated code.

The installer must independently establish the correct game revision, loaded
module listing origins, executable extents, target signatures and GP values. Build
fixtures use synthetic placements, not a ready-to-install address map. Supply
`original_usb=manager_listing_origin+USB_OFFSET` and `usb_entry=USB_ENTRY`. A signature
match alone does not establish the correct module identity.

`Config` freezes the approved target table and executable ranges. A `Target`
contains an entry and its module GP. Known physical/KSEG0/KSEG1 aliases are
normalized only after segment, RAM-bound and alignment checks; unsupported
segments and unaligned entries fail. Each target must lie in an approved
half-open executable extent. The dispatcher additionally checks index,
alignment and executable ranges before JALR. It never accepts a host-supplied
address. The table lives with the generated code and has no mutation API.
Immutability is an installer/ownership contract, **not hardware protection**;
arbitrary writes to EE RAM can still corrupt code, GP or table entries.

An upgrade may specify `previous_dispatch` after independently verifying its
ownership and an idle mailbox. The call-site guard then matches that dispatcher,
while the replacement still invokes the original USB callback exactly once.
Use fresh code/mailbox storage and retain the old code until in-flight calls
finish. The previous dispatcher may not overlap replacement storage; this option
does not validate its provenance or authorize resetting pending commands.

Before enabling the single-word hook, an installer must:

1. Pause and establish exclusive control/ownership, identity and loaded bases.
2. Reserve disjoint writable code (`CODE_SIZE`) and 96-byte, 16-aligned mailbox
   regions, plus any explicitly configured target stack. None may overlap any
   whitelisted stock executable range.
3. Observe and validate all `guards`; build offline with verified EE tools.
4. Write and read back the linked payloads/table and all-zero initial mailbox.
   Make injected code visible to the EE instruction cache using the platform's
   verified cache-coherency procedure. Keep table/code immutable thereafter.
5. Recheck **all** guards immediately before patching only the original JAL.
   `Build.patches` contains this one word; do not replace its delay slot. The
   existing patch API checks its patch word, not all the auxiliary guards.
6. Resume only after readback. Removing/replacing the hook or mailbox requires
   a verified quiescent state: never free code while a command or USB frame can
   still use it, including a target stack owned by a pending continuation. An
   interrupted installation is not automatically rolled back.

No installer or cache-flush mechanism is provided here. Treat ownership races,
invalid placement, stale instruction cache and unsupported revisions as blockers.

## ABI and execution

`render(config, observed_words)` returns assembly. `build(..., assembler=...)`
uses PS2 binutils with `-EL -march=r5900 -mabi=eabi`, checks R5900/EABI64 ELF
flags, links through `runtime.elf`, and returns source, relocatable object bytes,
linked payloads, zeroed mailbox and guarded patch. A matching `-objcopy` is
derived from `-as`, or supplied explicitly. Everything is generated offline.

CALL passes eight uint32 words in `a0..a3,t0..t3` via `lw` (normal EE signed
extension into 64-bit GPRs), and raw float words in `f12,f13,f14`. Return words
are the low 32 bits of `v0,v1` and raw `f0`. Pass double-width values only when
the actual callee signature agrees with this register layout. There are **no
extra stack arguments**. The 896-byte aligned wrapper frame reserves 64 bytes
of outgoing ABI space, separate from saved context.

The wrapper saves/restores all writable GPRs at full 128-bit width, including
SP before arithmetic, all 32 FPRs, FCSR, HI/LO on both multiply units and SA.
After processing/skipping the command it restores the incoming context and
tail-jumps to the original USB function exactly once per dispatcher entry.
USB sees the original arguments, GP, SP and RA; its return values and ordinary
effects reach the original caller. Explicit NOP delay slots avoid scheduling
surprises. VU state, CP0, DMA, memory, device state and the callee's intended
game changes are not rolled back or preserved by this wrapper.

Only ordinary returning, EE EABI-compatible callees are supported. They must
preserve SP and obey the platform's stack/GP rules. The selected game thread
must have at least 896 bytes plus the target's stack needs available. Incorrect
arguments, stale object pointers, a wrong signature/GP, exceptions, target code
bugs and unsafe game phase can crash or corrupt the game; a function whitelist
does **not** make those inputs safe. Approve stock create/delete/getter entries
only after resolving their actual signatures. This layer chooses no lifecycle,
ownership, spawn, deletion, retry or object-validity policy.

### Optional dedicated target stack

`Config(..., target_stack=(base, size))` moves only the approved target CALL onto
caller-reserved RAM. The default `None` preserves the original generated bytes
and uses the incoming thread stack throughout. This matters for the native
game-command hook's 4096-byte main-thread stack: the 896-byte dispatcher frame
plus constructors or deep callbacks can exhaust it. A dedicated stack does not
remove the dispatcher's own incoming-stack requirement.

The base must be an explicit physical EE RAM address, 16-byte aligned; size must
be a multiple of 16 in `0x2000..0x10000`. The entire extent must be in RAM and
disjoint from code, mailbox and whitelisted executable extents. A configured
`previous_dispatch` address inside it is rejected, but its unknown full extent
is not validated. The installer must prove ownership and disjointness from the
full old dispatcher, thread stacks, live game allocations and all other users.
There is no allocator, ownership claim, stack initialization or overflow guard.

After all eight integer and three float argument registers are loaded, the
wrapper saves its old dispatch SP in `t8`, switches SP to `base+size-80`, and
stores the return bridge at `64(sp)`, above the 64-byte outgoing EABI home area.
The callee may use that home area and descend within the reserved extent; no
additional stack arguments are supported. On ordinary return the wrapper loads
the saved dispatch SP from memory (not from a callee-preserved temporary),
restores it without disturbing `v0/v1/f0`, then publishes the normal reply. The
outer frame ultimately restores the original full 128-bit SP. Target locals
must not overwrite the return bridge; callees must restore their entry SP.

BUSY prevents nested target dispatch, not normal callbacks or interrupts: those
may use this private SP and must fit within its budget too. Nonlocal exits such
as `longjmp` have no hidden stack restoration or cleanup; BUSY remains set and
no reply commits. Stack choice and size require separate ABI, depth, interrupt
and lifecycle qualification before live integration.

### Optional per-frame callback

`Config(..., frame_callback=Target(address, gp), target_stack=(base, size))`
adds one trusted `void callback(void)` call per normal main-loop dispatch,
including frames with no outstanding host command. It requires the explicit
private stack described above. The callback entry must be in the executable
whitelist and its entry/GP obey the same `Target` address validation as command
targets. It is embedded in generated code, not selected by a host value or added
to the host command table. With `frame_callback=None`, generated bytes remain
unchanged, including configurations that already use `target_stack`.

The callback takes no arguments and returns no protocol result. It uses its own
GP and static, caller-owned global context; argument register contents are
unspecified. This provides an entry point for an autonomous lifecycle controller,
not a controller implementation or allocation policy. The callback shares the
persistent private stack serially with host targets. Its return bridge remains
at `64(sp)` above the outgoing home area, while dispatcher locals remain on the
incoming stack. All original registers and the original USB tail call retain
the same preservation contract.

An entry that finds BUSY or FAULT set skips both command and frame work and
tails to original USB. Otherwise the command, if any, runs first; the callback
runs second with BUSY held at 1. Nested dispatch while either runs only tails
USB, never invokes another callback or target. Command results are retained;
the reply sequence and clearing BUSY are deferred until the callback returns
normally. On idle frames the callback does not change the previous reply.
Invalid command operations/indices still get their error reply after the frame
callback; sequence faults skip the callback.

The callback must return normally and must not yield or restart the game. Its
controller actions may call approved native constructors only within the
qualified, serialized stack and game-phase contract. A nonlocal exit leaves
BUSY latched, does not restore the incoming stack, and commits no pending reply.
There is no implicit cleanup, recovery, continuation management or safe retry.
Integrators must qualify stack depth, lifetime and native callbacks separately;
generating this code does not update an already compiled or running dispatcher.

## Protocol and failure semantics

`mailbox.h` gives exact offsets and status codes. All words are little-endian;
the host uses the physical mailbox and the EE uses its uncached KSEG1 alias.
The adapter must provide ordered, coherent writes, atomic aligned 32-bit words
and bounded I/O operations. Only one host owner/instance may publish commands.
The Python lock is process-local, not an interprocess ownership lease.

```python
from commands import Call, Host

# memory is a caller-owned, already connected PineClient or equivalent.
host = Host(memory, mailbox_address, table_size=len(approved_targets))
sequence = host.submit(Call(index=0, args=(0,) * 8, floats=(0,) * 3))
reply = host.wait(timeout=2.0)
```

`submit` validates the command and idle state, writes index/op/arguments first,
and request sequence **last**. It never writes game objects. The EE accepts only
`last+1`, sets BUSY and LAST before calling, then writes result/status, clears
BUSY, executes SYNC and commits reply sequence last. Unsupported operations or
indices consume the sequence with an error reply; invalid sequencing produces
a sticky fault without invoking a target. Sequence zero is initial state, not
a command. `0xFFFFFFFF` may complete, but the host then fails closed: no wrap,
in-place reset, replay or reuse within that installation.

Duplicate/reentrant entries while BUSY do not invoke the command again; they
still invoke original USB once. If a callee yields, its continuation owns the
pending command. If it never returns/nonlocally exits, BUSY remains set and no
reply commits; another frame must not clear or retry it. Exactly-once invocation
depends on exclusive publication and intact mailbox/code, not on the callee
eventually returning. The wrapper cannot force a callback after a callee that
never returns; it only calls USB after normal return or on skipped entries.

`wait` uses a monotonic deadline and bounded polling. Total wall time may exceed
the polling deadline by an individual adapter I/O bound; the adapter must not
block indefinitely. Timeout, transport failure or uncertain partial publication
leaves `pending_sequence` intact. Call `wait` again to observe **that same**
command, never `submit` again. There is no automatic retry, cancellation,
takeover, reset, success inference or automatic reconnection. Even a payload
write failure before publication is treated conservatively as unknown. A fresh
Host rejects a non-idle/faulted mailbox; it does not recover another owner's
pending command. `reply.status != 0` is a dispatched protocol error, not success.

## Offline checks

Run `python -m pytest -q tests/test_commands*.py`. Source-level mock R5900 tests
execute the actual generated control flow with delay slots, 128-bit register
sentinels, reentry, nonlocal exit, sequence exhaustion, corrupt targets and
publication ordering, with both incoming and dedicated target stacks. Dedicated
stack checks include register arguments, deep stack writes, the return bridge,
placement rejection and full incoming-SP restoration. Frame-callback checks cover
idle frames, command ordering, deferred replies, BUSY/FAULT skips, reentry and
nonlocal exits. They are not an EE emulator and cannot prove timing,
cache coherence, real callee ABI, device effects or game-phase safety.

Set `SOTC_EE_AS` to the actual PS2 assembler, or put
`mips64r5900el-ps2-elf-as` and matching objcopy on PATH. The optional real-object
test checks ELF machine/ABI flags, assembled delay slots, register-save opcodes,
linking and the exact single JAL patch. It skips rather than installing tools
when unavailable. Actual EE execution and installer cache/ownership validation
remain separate qualifications; passing source mocks is not authorization to
run stock create/delete functions against a live game.
