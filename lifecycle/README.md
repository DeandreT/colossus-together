# Co-op lifecycle core

`Lifecycle` is a persistent **in-process**, typed, standard-library-only event/action
state machine. Keep the same instance across telemetry ticks, P1 destruction,
level changes and cold boots. It performs no memory I/O and is not a live game
integration. Never restore pointer-bearing state from disk into another emulator
session; reconnect by invalidating the old epoch and registering a fresh epoch.

## Protocol

1. Register the canonical P1 with a strictly increasing `generation` and the
   current `resource_generation`. Both are adapter-issued epochs, not addresses.
   An address reused after deletion must have a new generation.
2. Capture body, mantle and head constructor records **while their sources are
   live**: definition address, original object, canonical parent, copied parameter
   bytes, copied GP register value, and all transitive resource dependency IDs.
   Records are immutable copies, bounded to one per part and a configurable byte
   limit. Captures with stale epochs, a different parent, or unloaded dependencies
   are rejected. An in-flight build uses a frozen snapshot, not later captures.
3. Deliver `GameModeChanged` and explicit `GameplayReady(True)`. By default the
   no-spawn flag is mask `0x1` (the flag named “bit 1”); if telemetry uses zero-based
   bit numbering, configure `no_spawn_mask=1 << 1`. The adapter must verify the
   game's actual mask. A clear flag alone is **not** gameplay readiness.
4. Execute `CreateMain`, report its `CreationResult`, then execute the three
   `CreateVisual` commands. Request IDs also become lifetime/ownership IDs.
   Only all four successes publish `ACTIVE`/`active_p2`. The adapter must keep
   provisional objects unpublished and non-playable until `ACTIVE` is observed.
   `parent_ownership_id` lets the adapter validate the P2 parent's exact lifetime.
   Both creation commands demand a separate ownership group; P2 must never join
   P1's group. `parent_p2`, not the captured `parent_p1`, is the visual's actual
   construction parent. Captured `original_obj` is provenance, not a live clone
   source to dereference later. World/save authority always remains P1.
5. Feed canonical delete-request telemetry **before** game deletion callbacks.
   The reducer clears P1 validity and snapshots before returning cleanup actions.
   Neither late captures nor ready events can revive this epoch. Final-free is
   also an invalidation fallback, not a substitute for the pre-delete hook.
6. Use the native held-parent teardown below (`native_parent_hold=True`, the
   default). Execute each action once and retain lifetime hooks through actual
   `OwnedFinalFree`. Delete-request is not a free acknowledgement. Late successful
   creations remain owned even after invalidation.
7. Intercept `ResourceUnloadRequested` **before** releasing resources. Do not
   unload until its matching `AllowResourceUnload`. Pending constructors and
   every dependent owned object block that permit through final-free. Resource
   IDs cannot become available again inside the same resource epoch; a reload
   requires a new resource epoch and a new canonical registration.

`RespawnRequested` drains only P2. It requires fresh explicit readiness before
rebuilding; it does not alter P1's generation or any save/progress state. Failed
creation drains partial objects, then latches `FAILED`: ordinary ticks, captures,
readiness and respawn requests never retry. A newer P1 generation or explicit
`RetryRequested`, followed by fresh readiness, unlocks it. No per-frame allocator
loop is present. An asynchronous creation that never reports completion or an
object that never reports final-free deliberately holds the barrier indefinitely.

## Native held-parent teardown

SotC P2 still uses collision aliases and weapon pointers while normally executing.
At a safe game-thread boundary, the selected protocol is:

1. On `AcquireDeleteHold`, acquire **one** `isysObjDeleteLock(P2)` (`K1ad20`),
   while P2 and its members are still valid. Acknowledge only that owned hold with
   `ParentDeletionPrepared(ownership_id)`. Until acknowledged, the reducer emits
   neither parent nor child deletion commands.
2. Execute the returned parent `DeleteOwned` once. Native immediate cleanup stops
   normal P2 execution, sets the pending-delete flag and can automatically request
   deletion of children. The hold keeps the parent allocation alive.
3. Buffer the immediate-cleanup observations. Deliver `OwnedDeleteRequested`
   for every automatically requested child **before** delivering the parent's
   `OwnedDeleteRequested`. The parent's event is the completion fence for native
   immediate cleanup, not merely notification that a command was queued. This
   lets the reducer request only the remaining children once, without racing
   delayed automatic-request telemetry. For children, this event is observation
   only; it never causes a second request for that child.
4. Wait for every outstanding creation result and every child's actual final-free.
   Late-created children are requested once and extend the wait. Then execute
   `ReleaseDeleteHold` using `K1ad48` to release **only our one hold**, not all native
   references. Acknowledge successful unlock with `ParentDeleteHoldReleased`,
   then deliver the parent's actual `OwnedFinalFree` (buffer synchronous free
   callbacks until after the unlock acknowledgement).
5. Resource permits remain blocked until all dependent objects, including the
   held parent, have actually freed. Reverse-LIFO ready-list processing is not a
   final-free ordering guarantee when other native references are held.

Both hold acknowledgements accept `error` for a failed or timed-out operation.
For an error/timeout during another native teardown step, deliver
`TeardownFailed(ownership_id, error)`.
Missing acknowledgements cause no retry, unlock, or assumed success. An explicit
error or early parent final-free quarantines teardown in `DRAINING` with
`teardown_error`; it cannot be bypassed by retry or a newer P1 generation. No
further native cleanup actions are emitted. An early-freed parent's pointer is
never used again, and its resource barrier remains conservatively blocked for
external recovery. A release failure does not mark our hold released. There is
no automatic recovery from an ambiguous native operation.

`native_parent_hold=False` preserves the generic child-final-free-before-parent-
request model for non-SotC callers and legacy pure-model tests. It is **not safe
for SotC P2**. The native protocol acquires no hold if no main object was created;
partial main allocations reported in `CreationResult` do require the hold.

## Required memory adapter (not implemented)

The future MIPS/emulator adapter must serialize events and actions on one queue;
do not invoke it reentrantly. It must maintain canonical-P1 selection, monotonic
epochs, object lifetime IDs, an authoritative resource dependency graph and
readiness telemetry. Validate epochs and liveness immediately before any pointer
access/constructor execution. If validation fails, report a failed creation
result without reading the stale pointer. Return exactly one result per creation
command, even for cancelled commands; report partial allocated objects as a
non-null `object_ptr` plus `error` so cleanup is retained. Deliver creation results
before that object's delete/final-free events. Duplicate results/free events are
ignored. Do not recycle ownership IDs or unload IDs within an adapter session.

The adapter must capture all inputs required by the real main constructor, map
the copied visual arguments and GP correctly, substitute P2's parent/group, and
prevent P2 from acquiring world/save authority. `canonical_p1` in `CreateMain` is
an epoch-checked identity, **not** permission to read uncaptured P1 memory. The
core does not establish constructor ABI, safe main-object cloning, allocation,
input/render/camera hooks, native deletion execution, readiness signals, dependency
completeness, or split-screen behavior. Those are missing integration work and
must be verified in the game before full split co-op can be claimed.

Run focused checks from the project root:

```sh
python -m unittest discover -s tests -p 'test_lifecycle*.py' -v
```
