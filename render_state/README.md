# Authored render-state bank

This is a freestanding, integer-only byte bank, not a game-field enumerator or
live integration. It does not establish full-game lighting correctness. No game
addresses, executable hooks, assets, rendering calls or DMA implementation are
included.

## Storage and authority

The caller provides a bank object, a workspace (1,024 original identity records
and 1,024 union entries), two byte buffers, and a bounded source range array.
There is no allocation or mutable global storage in `bank.c`. Allocate the
workspace off the EE stack. The limit is a configurable caller admission limit
up to `RB_MAX_RANGES`, not an assertion about a game's maximum population.
`bytes` reports the union size, not the sum of overlapping input sizes. Each
snapshot needs that many bytes; both full allocated buffers must have `capacity`
bytes. `max_bytes` is a separate caller-selected admission budget.

Only aligned, nonempty physical ranges inside `[0, 0x02000000)` are accepted.
Virtual/cached address aliases and MMIO are not normalized or accepted. Supply
the full physical allocation extents of both buffers, and one enclosing metadata
extent covering the bank, workspace, and any bank-owned EE bookkeeping. Reserve
the whole enclosing extent exclusively. Targets may overlap each other, but
cannot overlap these three storage extents, which must also be mutually disjoint.
Metadata must have at least `sizeof(rb_bank) + sizeof(rb_workspace)` bytes; its
actual placement and any alignment padding are the caller's responsibility.

The ordinary C pointers identify real allocated host/EE objects; physical extents
describe their corresponding EE ownership. No pointer is inferred from a physical
address. Host tests may use separate synthetic RAM and ordinary host buffers, but
the supplied physical model must accurately describe any actual alias. Read/write
callbacks must access exactly their requested physical RAM extent and buffer,
not hidden aliases or MMIO. Pointers, allocation sizes and this mapping are trusted
caller obligations; a C library cannot discover the allocation behind a pointer.
Native-pointer overlaps among input/config, buffers, bank and workspace are also
rejected. Initialization with overlapping objects returns `RB_ALIAS` without
touching them: such an object is **not initialized** and must not be used. This
exception avoids modifying target/buffer memory merely to store a diagnostic.

The `alive(context, range)` callback is authoritative: check the owner ID,
generation, and the entire extent against the owner's current live allocation.
Every original range is checked, including duplicate bytes with different owners.
Union sorting never erases identity records. Callers must serialize the bank and
keep objects, config and workspace immutable and alive through a frame. The owner
callback/fence must not mutate, free or reallocate target storage. Prevent concurrent
writers/retirement from the start of validation through each copy; a liveness
check is not a lock. An allocation that changes after validation invalidates this
contract. The source range array and input config may be released after successful
initialization, since they are copied.

## Protocol

After once-only global light deletion/list maintenance, enumerate the qualified
surviving state and initialize. Use this exact sequence:

1. `rb_begin_frame`: drain prior consumers through the fence; validate all owners;
   read the base. Phase becomes `RB_BASE_CAPTURED`.
2. Render P1 externally, then `rb_capture_p1`: fence, validate, read P1 final.
3. `rb_restore_base`: fence, validate, restore the base before rendering P2.
4. Render P2 externally, then `rb_restore_p1`: fence, validate, restore P1 final.
5. `rb_end_frame`: fence, validate, return to `RB_IDLE`.

Each copy makes exactly one callback per ordered, disjoint union range. Adjacent
ranges also coalesce. A render or capture callback is never invoked implicitly.
The fence must prove **all relevant consumers are finished**, not merely that a
CPU render function returned. It must be non-destructive, and nonzero means success.
`rb_cancel_before_render(..., 1)` is permitted only immediately after the base
capture, with explicit caller acknowledgment that no render/other mutable target
write happened. It fences and validates, but does not restore anything.

An operation failure latches the first frame fault. No further normal operation
reads or writes targets. Identity, order, extent and capacity errors are detected
before a transfer writes anything. Read/write callback failure means the transfer
may already be partial (even the failing callback may have changed bytes), and
latches `RB_INDETERMINATE`. There is **no atomic rollback**, no automatic retry,
and no automatic buffer clearing; preserve partially captured buffers for analysis.
After external quiescence and repair, `rb_abort_quiescent(..., 1)` may clear a
successfully initialized bank's fault only after a successful fence and identity
revalidation. Failed initialization requires fresh initialization; abort cannot
make an incomplete range plan usable. Do not call `rb_init` on an active/faulted
frame to bypass this requirement: fresh initialization after a prior frame also
requires externally confirmed quiescence and repair. Re-enumerate when identities
change. An abort performs no target reads/writes and cannot resurrect dead owners.

## Qualification still outside this component

The actual field set and original global maintenance order, real DMA fences,
camera-facing geometry and variable joint/matrix arrays, attachment ancestors,
P2-only/exchanged visibility, light particles, callback classification, clipping,
reverb ownership and independent P2 light-volume evaluation remain external work.
The bank preserves exactly the bytes provided; it cannot prove they are sufficient.
In particular, never restore light pointers already freed by maintenance.

Run `python -m unittest discover -s tests -p test_render_state_bank.py` from the
project root. Tests exercise synthetic overlapping/shared ranges and owners,
allocation/generation retirement, malformed ranges, storage aliasing and budgets,
fences at each copy boundary, ordering, canaries, uncertain callbacks, and exact
base/P1 restoration. Host tests use ASan/UBSan. With the existing EE compiler
(or `SOTC_EE_CC`), the test also checks a freestanding R5900 object for unresolved
symbols, mutable static storage, floating-point instructions and bounded stack use.
