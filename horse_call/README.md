# Horse-call ownership policy

This is authored, address-free C policy for future scoped begin-call,
select-target and end-call hooks. It is not a hook generator or a qualified game
patch. It reuses only `NLObject` (address plus allocation ID) and `NLLifetime`
from the lifecycle header; it does not require a GameProvider implementation.

`HCbegin(ctx, actor)` accepts only a current, live P1/P2 in the snapshot epoch,
with live Agro and all three mounted indicators and the separate reservation
indicator clear. The accepted actor, epoch and horse allocation are recorded
only after a successful transaction. Serialized calls use last accepted wins;
refreshing the same player's call reuses that player's token. Neither player
ends the other's camera interest. Rejected calls leave a still-valid previous
target intact. The policy owns no mount reservation and never writes raw mount
fields or canonical P1/P2 globals.

`HCselect(ctx, updating_actor, fallback_p1, &output)` always initializes output
to the supplied fallback, unchanged. Only the exact current Agro allocation
can receive the still-live accepted caller while unmounted and unreserved.
Every other AI retains the original fallback. Selection does not read or
consume call flags: the existing native condition remains responsible for
consumption. `HCend(ctx, actor)` ends only that actor's recorded token and,
when enabled, clears only that actor's call flag. It retains the approach
target. Ending a stale epoch/allocation never calls a flag or camera accessor.

## Adapter requirements

Zero-initialize `HCCtx`, then supply immutable callbacks and user data. Calls
are serialized on the game thread. Callbacks must not reenter, mutate the
context, change snapshot identity, retire allocations, or yield between
prepare and commit. `busy` detects reentry, not multi-threaded access. The
adapter must validate its own reads and writes; all game addresses, layouts,
native thunks/GP handling, lifetime evidence and camera validation live there.
No non-null address alone establishes lifetime.

* `snapshot` provides a coherent epoch and exact P1/P2/Agro allocation IDs.
  P2 may be absent. Epochs/allocation IDs must not be reused while records exist.
* `lifetime` proves the exact allocation is live without dereferencing freed
  memory. `riding` safely reads validated state for Agro/P1/P2 and the external
  mount reservation; absent actors must be handled safely. Non-OK snapshot or
  riding results invalidate the approach and keep the original AI fallback.
* `camera_begin(PREPARE)` validates the explicit actor, camera, optional flag
  write and interest token **without visible side effects or resource
  acquisition**, including on failure. A refresh must preserve its token.
* `camera_begin(COMMIT)` uses that same token, and atomically applies camera
  interest plus `HC_SET_FLAG` if requested. COMMIT must not change the token.
  The adapter must provide a no-fail commit after preparation, an atomic
  transaction, or rollback proven complete before reporting a clean rejection.
  A separate fallible camera call followed by an unprotected flag write does
  **not** satisfy this contract. If the native operations cannot satisfy it,
  reject during preparation and do not install that integration.
* `camera_end` validates the explicit actor and exact token, and atomically
  ends only that interest plus `HC_CLEAR_FLAG` if requested. The recorded horse
  is identity/context only: it may already have been replaced and must not be
  dereferenced without independent validation. Camera state may also have
  retired independently; the adapter must not operate on a replacement camera.
* Flag read is optional through `flag_read`; `manage_flags=0` requests
  `HC_KEEP_FLAG`, so native code can manage flags instead. When enabled, the
  safe adapter supplies the flag setter as part of the atomic camera
  transaction, not an independently fallible policy write. Reads must be
  side-effect-free, and writes must preserve unrelated flag bits.

Tokens are opaque four-word adapter identities, not unchecked camera pointers.
For P2 manual orbit, the adapter may deliberately issue a validated **no-focus
token**: begin/end perform no camera focus change, while honoring flag actions
and ownership. This is an explicit integration choice, not a claim that a
native P2 camera exists. Never silently use the global P1 camera as fallback.

## Status, invalidation and cleanup

`HC_OK` means completed, `HC_INACTIVE` means no applicable record/selection,
`HC_REJECTED` means a clean refusal, and `HC_STALE` means identity is unusable.
`HC_PENDING` and `HC_FAULT` from a commit/end mean external outcome may be
uncertain. Any other non-OK commit/end result guarantees no external effects.
Preparation failure always guarantees no effects, regardless of its status.
The caller must observe every status; selection output remains usable fallback
even on errors. A failure is scoped to this call, not a game-wide admission gate.

Uncertain commit/end retains the exact token and blocks further callbacks for
that record. There is no automatic retry. Uncertain begin publishes no target
and invalidates any previous approach; the other player's slot remains usable.
Only an external reconciliation that proves safe cleanup may call
`HCresolved` with the exact actor/epoch/allocation and token. It refuses to drop
a healthy active record. Do not reset/reinitialize a context with retained
interests. Stale records similarly require externally proven token cleanup,
without dereferencing their retired actors, before acknowledgement.

`HCsync` and all world-reading entry points invalidate the approach on horse
replacement, actor retirement/epoch change, mounted state or reservation.
Invoke `HCmount_accepted` at mount acceptance and `HCretire` before actor
retirement, and publish the corresponding snapshot/riding changes before new
calls. These explicit invalidations return pending if attempted reentrantly;
the integration must deliver them at a safe serialized boundary. Interest
ownership is retained separately for explicit cleanup: never discard it merely
because an approach was invalidated. Live actors can still end old-horse
interests using their validated tokens. Generation changes do not authorize
reading or clearing flags on a reused actor address.

## Validation

`python -m pytest -q tests/test_horse_call.py` compiles/runs synthetic host C
tests both normally and with address/undefined-behavior sanitizers. The optional
EE object compile uses `tests.local_config.ee_tool` (`SOTC_EE_CC` or PATH) and
skips when unavailable. Tests cover last-accepted ordering, per-player cleanup,
refresh, unchanged unrelated-AI fallback, mounted/reserved refusal, replacements,
same-address new generations, stale end, optional flags and transactional
failure/uncertain-token retention. None establishes emulator or gameplay
qualification. No original bodies, captures, private paths or binaries are
required.
