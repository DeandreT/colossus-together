# Pure streaming-union planner

`planner.c` plans interests only. It does not read EE memory, allocate, enqueue,
change native slot states, move players, or provide a live hook. Storage belongs
to the caller. This is not a claim of full-world streaming or resource capacity.

## Inputs and transaction

Supply verified row-major map metadata, with positive dimensions and at most
4096 cells (the researched map is 60 by 60). Supply both actors' rounded chip
coordinates and containing-cell coordinates separately: native `G+1EA58` and
`G+221B4–2223C` calculate different inputs. The containing coordinates must be
in bounds, and their descriptor identity, mode and extra-field presence must
match the supplied map metadata. `extra` is a Boolean presence, not a pointer.

Radii are nonnegative integer chip counts; their sum must fit `int32_t`.
Snapshot them **after P1's force-path updates**. There are no floating-point
inputs or instructions: an adapter accepting world/normalized floats must reject
NaN/infinity before reproducing the native coordinate conversion. Do not cast
unchecked floats into this API. Extreme rounded integer inputs use 64-bit
arithmetic rather than overflowing.

Views contain decoded signed coordinates, not raw native bytes. Ordinary
descriptor rectangles come from `descriptor+14/+18`, 12-byte native records
with signed halfwords X/Z/width/height at 0/2/4/6. Special type-5 records have
8-byte stride and X/Z/width at 0/2/4; decode each with height 1. All supplied
rectangles must be positive and wholly inside the map. Zero records mean an
empty list. Descriptor modes outside 0–5 are rejected rather than guessed.

The callback must implement the pure native semantic policy at `G+1F028`, with
the `G+1EF58` load-state admission prefix removed. It receives the candidate's
metadata and the actor context. Return exactly 0 or 1. The callback must not
mutate inputs, outputs, workspace or game state, retain pointers, or allocate.
It remains external: the C test oracle is not a native-policy implementation.

`max_candidates` bounds unique enumerated cells across both actors.
`max_requests` conservatively bounds all desired cells, **including loaded
cells**, since the planner deliberately has no native load-state input. Both
are explicit, may be zero, and must not exceed 4096. These counts do not prove
an NMO/texture byte budget. Views must remain stable throughout the call.

Use distinct input/views, workspace and output storage. The planner rejects
overlap involving its writable storage. All bounds and view metadata are
validated before workspace construction; a candidate/request/callback failure
may change workspace but leaves output byte-for-byte unchanged. Pointer
readability, descriptor provenance and callback purity are caller obligations.
Workspace is approximately 12 KiB: allocate it outside the native stream
thread's 0x2000-byte stack.

## Enumeration and merge

For each active actor:

- Mode 5: enumerate its row spans.
- Modes 1–3 with no center extra field: enumerate its descriptor rectangles.
- Otherwise: enumerate the ordinary square using near + outer-band radius.
- P1 may instead supply an explicit native batcher coordinate list. Duplicates
  are deduplicated; this replaces only P1 enumeration, not the callback policy.

The original square clamps upper bounds to `dimension-1` and then uses exclusive
`<` comparisons (`G+20CD4–20D8C`, also `20A68–20B34`). This omits the last map
row/column in that path. The planner deliberately preserves that behavior;
descriptor lists and explicit lists can include those boundary cells.

Evaluate both layers for both actors. Layer 0 wins if **either** actor desires
it; otherwise layer 1 wins if either desires it; otherwise `SU_NONE`. This
selection is independent of loaded/queued states, so actor order cannot replace
a near representation with the other actor's far representation.

## Retention and native states

`keep_p2[cell]` has bits 0 and 1 set together for ordinary native retention:

- P2 modes 1–3: same descriptor or **P2 center** extra present, and inside the
  outer square.
- P2 modes 0/4: inside the outer square, except candidate mode 3 without
  **candidate** extra.
- P2 mode 5: membership in P2's row spans, independent of radius.

This is separate from enumeration and ignores native states. The integer outer
test `-R <= cell-rounded < R` exactly represents the researched native
`abs(cell-rounded+0.5) <= R`. It supports a mask before the type-3 unload-first
path, without executing load/fog code.

`su_choose_layer` admits only the planned layer and native state **0 or 5**.
This preserves `G+1EF58–1F028`: state 3 remains interested but produces no new
request. State 5 remains eligible for selection. The native batcher trims leading
and trailing state-5 entries at `G+20554–20664` and emits a strip only if it found
at least one state-0 slot (`G+2049C–204AC`, `20668`). Interior state-5 entries
can remain inside that emitted range. An all-state-5 selection therefore creates
no standalone load. State 5 does **not** cause this planner to choose the other
layer or manufacture a fallback load. The tile coordinates are selection input,
not individual load commands: the adapter must retain this native batching
behavior. Native state-6 failure cleanup is outside the keep-mask decision and
must remain intact.

## Bounded submission and missing integration

`su_tiles_next` visits disjoint, row-major tiles no larger than 16 by 16. It emits
only desired coordinates, each exactly once, and skips empty tiles. A native
batcher grid is at most 256 words / 1024 bytes. This avoids a world-spanning
sparse union bounding box on the stream thread stack. Coordinates here have
8-byte C stride; the adapter must encode the native batcher's **16-byte stride**.

Still required for live integration:

1. Verified map/descriptor adapters, actor generation and position snapshots,
   and the native pure-policy thunk, with register/FCSR preservation.
2. Interception of P1 batching calls at `G+20CB8`, `20DB8`, `20FE4`; merge before
   submission while retaining P1's original force/fog handling.
3. A scoped request-predicate adapter at `G+200F0`, not a replacement for every
   `G+1EF58` call; supply tile ABI and encode coordinate stride.
4. Keep-mask checks before both unlink and request at ordinary eviction blocks
   `G+2136C`, `214CC`, `216EC`; do not suppress the separate state-6 paths.
5. Refresh interests at `G+21020` entry for type-3's first unload and a once-per-
   iteration fallback at `G+22764` when stationary P1 skipped native selection.
6. Generation-safe asynchronous owner revalidation, graphics fencing, native
   request/texture accounting, byte-budget admission and a defined capacity-
   failure policy. This module neither retires nor teleports P2 on failure.

Run `python -m unittest discover -s tests -p test_streaming_planner.py`. Tests
compile/run the C harness, run host sanitizers, and, when the local cross compiler
exists, check the EE object for undefined symbols and floating-point operations.
They do not execute the native callback or qualify live hooks.
