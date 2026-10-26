# Offline sheet-worker resource gate

`resource_gate.py` produces an offline guarded patch plan, not an installer or a
live controller. It has not been qualified against the live scheduler. Do not
ship it on the strength of synthetic tests.

## Scope and seams

The MANAGER worker cancellation `beql` at `M+E3338` skips the gate on cancellation.
The gate replaces the first two words at `M+E3350`, after that check. Operations
1 (segment), 3 (mapblock), 5 (stage texture), and 6 (existing stage textures) wait
for permission before reaching their original operation bodies. Other operations
do not read or change the gate state. Only request offsets 0 (operation), 8
(sheet/handle), and C (region/segment) are inspected, after checking the request
address fits aligned physical EE RAM.

The original `sltiu`, relocated conditional branch and observed delay-slot LUI
are replayed. The LUI executes on both branch paths. Execution resumes at
`M+E335C` or `M+E3788`; no operation body is copied.

At `M+E37A0`, after the operation body and complete-word store, a replacement
JAL observes completion. Its original semaphore-loading delay slot remains
untouched. Only the active request in RELEASING completes. Other requests cannot
clear pending work. The helper restores the full context and tail-calls the
explicitly configured, guarded WaitSema target with the original stack, arguments,
and return address. WaitSema therefore runs once and returns directly to
`M+E37A8`, with its own actual post-call register results. A nonreturning operation
error path cannot publish completion.

## Controller contract

Allocate disjoint code/state extents, guard the observed loaded MANAGER words,
and explicitly write `initial_state(generation=...)` while the worker is safely
quiescent. No constructor initializes target memory. `Config` reserves the
manager text extent too; the caller must also check these allocations against
all other loaded code/data allocations. The caller owns publication/installation
and must not mix these hooks with another hook at the same seams.

The state layout is the little-endian uint32 `FIELDS`/`OFF` table. One worker and
one pending request are supported. `sequence` is monotonically incremented and
refuses to wrap. Before publishing WAIT, the worker writes request, sheet,
segment, operation, and `ready=0`. WAIT does not mean gameplay is safe.

The external main-thread controller must stop all P2 resource use and free all
P2-owned resources before granting permission. It must write both
`permit_sequence` and `permit_generation` coherently, matching the observed WAIT
request. Use a paused/coherent target transaction; uncoordinated live writes can
be seen as a wrong or partial permit and deliberately fail closed. There is no
permission timeout. Waiting invokes `sheetWait` at `M+E3978`, not a CPU spin.
The worker must actually be woken by the integrating scheduler/controller;
writing state alone is not evidence that the sleeping worker can run.

Once permitted, RELEASING lasts through the original operation body. Only IDLE
with matching `complete_sequence`/`complete_generation` establishes completion.
The controller must observe completion before rebuilding P2 state or considering
it safe. A completed permit is cleared automatically; no completion ACK is
required. Epoch replacement is an explicit quiescent recovery operation, never
an implicit way to reset a live pending request.

`fault` is a native sticky bitmask: bad state, nested request, exhausted sequence,
wrong permit, or bad request. Invalid state/magic, identity loss, and nested
requests remain in `sheetWait` and do not release resources. A later correct
permit cannot heal a fault. Recovery requires separately established safety and
explicit reinitialization. There is no automatic recovery or silent timeout.

Helpers preserve 128-bit GPRs, packed HI/LO, all FPU registers/FCSR and SA. Saved
state uses a private frame below the original SP; original parameter-stack space
is neither borrowed nor assumed free. Calls made while waiting use a separate
32-byte argument area beneath the saved frame. Runtime stack headroom and live
scheduler wake/resume behavior still require on-target qualification.
