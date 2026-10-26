# Native lifecycle actions

`lifecycle.c` and `lifecycle.h` are project-authored, freestanding C. They contain
no stock game implementation, assets, fixed game addresses, host memory writer,
emulator connection, installer, or network input. Provision a trusted `NLContext`
and immutable callback table on the game thread. Expose only the action entry
points through the existing approved `commands` target table; do not accept
arbitrary callback addresses or context contents from a remote client.

## Adapter contract

- Execute serially at a safe game-thread boundary. `busy` rejects reentry; it is
  not a cross-thread lock. Context, callbacks, captures and allocation records must
  outlive every action. Callbacks must not mutate configuration/ownership arrays.
- Set matching nonzero `generation` and `current_generation` from the verified
  epoch. Keep an authoritative allocation registry: `lifetime` must distinguish
  the exact allocation's final-free from an unknown/reused address. Never infer
  final-free from a pending-delete flag. IDs must not wrap or be reused.
- Verify definitions, private parameter buffers, resource dependencies and the
  canonical P1 allocation before provisioning. `canonical_p1_verified` is a host
  attestation, additionally checked against the live registry. Address checks
  admit aligned physical/KSEG0/KSEG1 addresses wholly within 32 MiB RAM, but do
  **not** prove those addresses are mapped, live, correctly typed or privately
  owned. No game offsets other than the explicitly selected parameter GP slot
  (`+0x20`) are assumed. Supply the independently verified header-flags offset.
- Stock callback signatures are typed here, not discovered by this library.
  `create_alias(partition, definition, parameters, script, parent, 0, 1)` uses
  seven EE EABI arguments. Provide approved module-GP thunks where necessary;
  writing the parent object's GP word is not switching the CPU GP register.
- `publish_actor` synchronously establishes P2 HP/grip/charge and other required
  mod banks before returning to the scheduler. It is **not** view publication or
  permission to run gameplay before commit. It must neither register P2 in P1's
  group nor touch P1/world/save authority. `publish_view` publishes the completed
  view last; `unpublish_actor` clears only mod-owned P2 registries. Return false
  on publication failure. No callbacks may yield to the scheduler.

## Actions and one-shot behavior

`spawn_actor` accepts READY/QUIESCENT only, a verified live canonical allocation,
fresh readiness and no resource barrier. It retains the new pointer/allocation
and publishes banks before returning. Then invoke each of the three
`spawn_visual` indices separately. Each reads GP from that visual's private
parameter buffer at `+0x20`, writes the P2 pointer into that private geometry
buffer's first word, and calls
the selected character or alias constructor. Alias parent is explicitly P2;
the character constructor's private parameters must already encode P2 ownership.
There is no P1 group-registration call. `commit_active` requires all three live
visuals, no pending creations, and external confirmation of all intrinsic
children; it publishes the view and enters ACTIVE only on success.

Before `begin_retire`, withdraw P2 input/view and snapshot **every** owned child
(including intrinsic children) with its allocation ID into the bounded 32-entry
list. ACTIVE, withdrawn and a preverified live P2 are mandatory. The action copies
the list locally, takes one parent hold and requests parent deletion exactly
once. Native immediate cleanup stops parent updates while the hold retains its
allocation. Only afterward does the action recheck each captured child lifetime:
final-freed children are skipped without reading memory, already queued children
(`0x10000`) are skipped, and remaining children receive one request. Nested native
requests are therefore observed before the next child. No LIFO free-order
assumption is used. Successful unpublication enters DRAINING.

Deliver actual final-free acknowledgements through the host allocation registry.
Only set `allchild_final` after all captured children have final-freed and all
pending creations have settled. `release_parent` rechecks those lifetimes, then
unlocks once and enters WAIT_PARENT_FREE. It never requests parent deletion again.
Buffer any synchronous parent final-free until the action has acknowledged the
unlock. Only an actual final-free permits the host to advance to QUIESCENT and
explicitly provision fresh object/list/visual/attempt state. Generation remains
an epoch, not a pointer. No automatic reset or retry exists.

Invalid preconditions return REJECTED without side effects. Once an action has
begun native work, detected failure latches `error`/`teardown_needed`; later calls
return LATCHED. A retirement failure retains its hold and ownership records.
Never clear this latch to retry an ambiguous stock call. Void native lock,
request and unlock functions cannot report success: an exception, hang or
nonlocal exit requires external quarantine, not replay.

## Remaining integration work

These are action primitives, not a finished memory/lifetime adapter. The Python
`lifecycle` reducer emits separate hold/delete/release actions and treats ACTIVE
publication differently; an adapter must reconcile those events with this
combined retirement action and the separate early bank/view publications.
It must maintain hooks, capture resources and private parameters, track late
creations, populate all child ownership, and implement final-free acknowledgements.
It must **not** simply execute both protocols and double-request the parent.

Partial construction failures deliberately retain provisional pointers and latch
teardown-needed. `begin_retire` requires ACTIVE, so failed BUILDING transactions
use `retire_failed_build` after the adapter has completed the intrinsic ownership
inventory. The original construction error remains available, while cleanup
errors are recorded separately. Never promote a failed build to ACTIVE or forget
its provisional allocations. Resource barriers remain held until those
allocations actually free and retirement is acknowledged.

An address can represent multiple successive allocation identities. Retirement
may retain a positively final-freed identity alongside a replacement at the same
address; it never issues another deletion for the old identity. Two live or
unknown identities at one address remain an error.

Stock P2 constructors also need the independently qualified initialization guard:
skip P2 global `initWeapon`/`SCRPlayerGetWeapon` initialization and shared death-
alert writes. Those game patches are **not** implemented here. Native constructors
can otherwise affect P1 despite these helpers never writing P1. Safe constructor
ABI, CPU GP, callback availability, scheduling, cache coherence, and actual game
execution remain separate qualification requirements.

Construct the actor and all required visuals in one game-thread operation before
allowing its coroutine to run. These constructors recurse through model bones and
must not borrow the stock small command-coroutine stack. Use a separately owned,
bounded stack, retain it across the entire operation, and qualify its maximum
depth with guard space. A successful constructor return alone does not prove that
the caller's stack or saved coroutine state survived.

The controller's completed-render source must advance for both split rendering
and its single-view fallback. A split-only success counter stops advancing after
view withdrawal and cannot establish the next safe retirement boundary.

Rendering and deep collision queries also need a separately owned persistent
stack when the stock display coroutine's stack cannot accommodate the added
call depth. Do not share the command stack: render waits can suspend with live
frames. The render wrapper's busy guard prevents reuse while suspended, and its
normal return restores the full original stack and return-address registers.
An emulator reporting running is not evidence of scene progression; verify an
advancing render counter and preserve any stalled scheduler state for diagnosis.

## Offline checks

Run `python -m unittest discover -s tests -p 'test_native_lifecycle*.py' -v`.
The standard-library runner compiles the real C against synthetic callbacks and
tests nested cleanup, final-free ordering, retained holds, stale allocations,
generation/readiness guards, failure latches, canaries and repeated recreation.
It also compiles the same implementation to an actual R5900 EABI64 object and
checks ELF metadata and absence of floating arithmetic. The compiler defaults to
`mips64r5900el-ps2-elf-gcc` on PATH, or `SOTC_EE_CC`.
Flags include `-mabi=eabi -mlong32 -mgp64 -march=r5900 -G0
-mno-abicalls -fno-pic`; this toolchain's default abicalls conflicts with EABI.
No floats are needed, so no FPU comparison/NaN behavior is introduced.
Offline mocks and object inspection do not prove live EE behavior.
