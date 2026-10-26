# Quiescent game metadata

`Snapshot(read, quiescent=True, undefined_symbol=...)` accepts a read-only
`read(address, size)` callback over one explicitly quiescent 32 MiB physical EE
snapshot. Passing a live PINE connection without stopping execution does not
meet that contract. No virtual-address masking, pointer repair, scanning,
emulator connection, or writes are performed. The undefined symbol is a value
supplied by the caller, not a guessed symbol address.

`live` requires an independently verified definition pointer and constructor
family. ISYS byte `object+8` is 9 for characters and 11 (decimal) for aliases;
both observed layout paths yield `object+0x90`. Character-definition kind 11
does not mean ISYS alias type 11. `definition_model` uses the compact alias
model field at `+4` or character field at `+0x14`.

The live chain is layout `+0x144` → display word zero → resource `+0x20`
→ NMO header. The header must have magic `0x004f4d4e`, version 3 at `+4`,
and a name pointer at `+0x70`. Names must terminate within 128 bytes and match
exact basenames. Body, mantle and head support no level suffix or levels
1, 4, 8, 12, 16. Paths, unknown levels and dummy/death/guard/shaman/swordcase
variants are rejected rather than normalized.

Packed references subtract only `word & 0x3ffff` from the field address to
locate the symbol-pointer word. The index is `(word >> 18) & 0xfff`;
descriptor `symbol+8` supplies stride at `+0xc`, and `symbol+0x10` supplies
the entry base. Entry `+8` gives the resource. Every dereference and arithmetic
result must fit aligned physical RAM without wrapping.

Canonical P1 is the type 9 character using `player_A_dummy.nmo`, not the visual
body. Body and mantle records use separate type 11 alias objects; only heads
use the character family. All three visual parts require a parent GP pointing
to canonical P1, with verified type 1 at `object+0x150` (object at `+0`, type at
`+0x30`). Other GP types remain unsupported. Both body and mantle alias skeleton
sources at layout `+0x194` must equal canonical P1. `captured` additionally
checks the captured alias source for both body and mantle, captured parent,
and compact definition model against the live object. Its immutable
`VisualRecord` copies parameter and GP bytes; the original stack pointers are
never dereferenced or retained as reusable storage.

The optional `group` walker requires explicit group address, node pool, pool
count, traversal cap, and caller-verified deletion flag offset/mask. The group
starts with a 16-bit node index; node zero is the null sentinel. Nodes have a
24-byte stride, object word at zero, and next 16-bit index at `+0xe`.
Deleted objects are skipped without changing references. Stale indices, bad
pointers and cycles reject the whole walk without returning partial results.

These checks do not establish allocation lifetime, generation, resource
residency or permission to construct another object. Those remain independent
requirements of lifecycle/injection integration. An in-bounds stale allocation
cannot be identified from address arithmetic alone.

## View-local presentation

`render_packets.split_display_copy` builds a Path3 DMA chain with two explicit
CT32 local-to-local copies into the display surface. The views have independent
source base addresses and share one destination at different vertical offsets.
This matters when a hardware renderer caches the lower, offset render target
separately from the full-frame target: reading the latter alone need not include
the lower target's updated pixels. The helper requires page-aligned halves,
matching source/display dimensions and non-overlapping source/display surfaces.
It does not allocate VRAM, scale images, synchronize graphics, or submit packets.
