# Runtime foundation — not a complete co-op mod

This package contains standard-library-only infrastructure, not co-op gameplay,
hooks, an injector, or a runtime lifecycle. It never opens an emulator on import,
discovers processes, changes emulator configuration, starts/stops a game, loads a
save state, uses SSH, or reads/copies game ROM assets. No gameplay or emulator
integration has been validated by these offline tests.

## PINE

`PineClient('/explicit/absolute/socket/path')` connects lazily and keeps one Unix
connection until closed. Use it as a context manager. `read8`, `read32`, `read64`,
and `read_bulk(address, size)` accept only physical EE RAM `[0, 0x02000000)`;
word reads/writes require natural alignment. Bulk reads use bounded Read8 batches
(default maximum total 1 MiB). Frame lengths and complete replies are validated.
The timeout is a whole-frame deadline, including fragmented reads; each bulk
batch gets its own deadline. There is no automatic reconnect/retry within an
operation, especially for uncertain writes. A later explicit call can reconnect.

The PCSX2 server may service one connected client at a time. A continuously
connected monitor can therefore block a separate controller even while the
monitor is idle between requests. Share one serialized client within a runner;
if diagnostic processes must share the endpoint, release their connections
between transactions. That does not remove the single-writer requirement for
patches, commands or telemetry acknowledgements.

`uuid()`, `title()`, and `status()` query PINE metadata. UUID is the game's CRC,
not a secret. `write32` only checks address/value/protocol bounds; use the patch
runner for identity, pause, whitelist and expected-word guards. Protocol source:
https://github.com/PCSX2/pcsx2/blob/master/pcsx2/PINE.cpp

## Offline object linking

`link_object(object_bytes, {'.text': address, '.data': address, '.bss': address},
externals={'helper': address})` returns immutable payload bytes (including zeroed
BSS) and named global/weak exports. Supply every allocated PROGBITS/NOBITS
section, including `.rodata` or section suffixes if present. There is no automatic
layout, cross-object symbol resolution, executable loading, GOT, or ABI adaptation.
Allocated MIPS `.reginfo`/`.MIPS.abiflags` metadata is not emitted.

Only ELF32 little-endian MIPS ET_REL and REL relocations NONE, 32, 26, HI16,
LO16 are supported; unknown runtime relocations, COMMON/unresolved symbols,
unpaired HI16, overlap, bad bounds/alignment and cross-region jumps fail closed.
HI16 pairs with the next LO16 for that symbol in the same relocation section,
including multiple pending highs and signed-low carry. Non-allocated debug
relocations are ignored. Sony EE EABI and hand-written LLVM O32 containers can
be parsed, but **the caller must ensure calling convention, instruction-set,
register, stack and ABI compatibility**. This is not a general MIPS linker.
Input is limited to 16 MiB, sections to 4096, and output to 32 MiB.

## Reviewed patch plans

`runtime.runner.apply_reviewed_plan(client, patches, code_ranges=[(start,end)])`
requires paused status and exact UUID `C19A374E`. Ranges are explicit half-open
physical EE **code** ranges chosen by the caller; this package does not determine
whether a range is safe or reserved. Use `WordPatch(address, expected, replacement)`.
All guards are read before any writes. Every write rechecks identity, pause and
its old word, then reads back its new word. Successful and partial-error receipts
record confirmed and uncertain attempts (`PatchError.receipt`). There is no
automatic rollback. Call `rollback_reviewed_plan` explicitly with the receipt;
it only restores words still equal to this plan's replacement, skipping foreign
values. No-op or duplicate patches are rejected.

**PINE offers no transaction, memory ownership lease, or atomic compare/exchange.**
Another writer can race between checks and writes, even while emulation is paused.
Use exclusive external control. Receipts are in-memory records, not proof of
exclusive ownership or durable recovery; callers must retain them if needed.
A transport error can leave a write or rollback uncertain; rollback error receipts
include uncertain addresses separately from confirmed restorations. Do not blindly retry.
Instruction-cache visibility, safe hook selection, allocated code storage, ABI
correctness, reversible gameplay state, synchronization, and any future injection
lifecycle remain the integrating runner's responsibilities.

A paused CPU is not necessarily at a safe function boundary. Never overwrite an
active function body with a different instruction layout while its program
counter or a saved return address can still refer to that body. Place replacement
code in a new owned region and redirect a same-layout entry/call seam; retain the
old body until all in-flight calls have returned. Activate new shared layouts at
the replacement's entry, not halfway through the old call.

Handwritten helpers also need R5900 instruction validation independently of ELF
metadata. For example, the game's floating-point comparisons use quiet EQ/OLT/OLE
encodings (`0x32`, `0x34`, `0x36` in the COP1 function field). Generic MIPS
assemblers can encode `c.lt.s` as signaling LT (`0x3c`), which is not interchangeable
with the EE instruction used here. Explicitly assemble the intended quiet form
and inspect its bytes. Tests that emulate generic MIPS comparisons can otherwise
hide an incompatibility even when the arithmetic formula is correct.

An emulator IPC acknowledgement does not necessarily mean an asynchronous
operation has completed. In particular, do not copy a savestate immediately
after requesting its creation: wait for the output file to be closed or
atomically replaced, validate the archive, and check expected captured state
before using it as a recovery point.

When passing an address to GNU `ld -Ttext`, format it with an explicit `0x`
prefix. A decimal-looking string can be interpreted as hexadecimal. Validate the
linked section address and decode every published J/JAL target back into an
approved executable extent; fitting the payload in reserved storage does not
prove that its branch relocations point there.

`runtime.ee_calls` emits fixed-target C-to-native call veneers that align the
stack to 16 bytes and preserve full-width SP, GP and RA. Do not assume an EE C
caller is already 16-byte aligned: its frame can leave SP at an 8-byte boundary.
The veneer supports the eight register arguments, not additional stack-passed
arguments. Native target identity and executable ownership remain caller checks.

EE hooks must not use the kernel-reserved `k0`/`k1` registers as working values:
an interrupt can overwrite them between instructions. Capture an ordinary
register before using it as scratch, then restore it on every return path.
Using `at` requires `.set noat` and full-width preservation. Merely saving `k0`
once does not protect a later temporary value held in it from an interrupt.

## Linux test isolation

PCSX2 appends `PCSX2` to `-datapath`; pass the private profile's parent directory.
Use a separate PINE slot and socket location rather than sharing a running
emulator's socket or memory cards. `profile.prepare_profile` copies inputs and
rewrites paths; it never refreshes an existing modified profile over its saves.

For hardware-rendering tests without taking over the desktop, use an explicitly
headless compositor and its own Xwayland display. An Xvfb display alone may not
provide a Vulkan presentation queue, and software-rendered OpenGL results are
not GPU performance evidence. Force the emulator's Qt XCB backend and do not
inherit the user's live Wayland display. Flatpak still needs its authorized
audio socket; an audio-error dialog invalidates presentation testing even if
game counters continue to advance.

The pause binding is `Hotkeys/TogglePause`, not `Hotkeys/Pause`. Check that the
chosen keysym exists on the assigned X server; F13 is not universally mapped.
For a sandboxed X11 client, translate the verified host process through its
`NSpid` metadata before comparing `_NET_WM_PID`. A namespace PID by itself is not
an ownership check.

Run offline checks from the project root: `python -m pytest tests/test_runtime*.py`.
