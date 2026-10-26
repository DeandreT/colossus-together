# Occupied mount gate

`gate.py` emits a configurable, offline-only gate and unapplied entry patches.
There are no game addresses, game bodies, installer, emulator connection or
automatic input discovery. See issue [14](https://github.com/DeandreT/colossus-together/issues/14).

The caller supplies a reviewed native code extent (including entry+8),
entry/prologue words, caller return, three callback identities, reserved
code/arm placements and exact read-only guard
records (`address`, `expected`, `width`, byte or word). Registration guards attest
P1/P2/horse; generation guards must collectively establish their current,
matching allocation/lifecycle authority. Additional lifetime guards must prove
actor/control pointers and the pending state remain safe to read, including the
control object's mounted field. The emitter cannot infer this from addresses.
Source guards must cover the caller, callback route meanings, entry's zero-result
reject semantics and the proof that **v0 and v1 are dead** on all original paths.
`SourceContract` records that source-specific review, not a generic ABI promise.
Changing only addresses does not qualify another game revision.

Only v0/v1 are scratch. No calls, frame allocation, interrupted kernel-register
dependency, FP/special-register changes, claims, reservations or actor writes are
introduced. A rejection returns zero; fallthrough replays the two supplied
prologue words exactly once, then continues at entry+8. Both 8- and 16-byte stack
alignment are supported by the reviewed 8-byte-aligned store prologue. Actor
type is checked using `LBU` at the named type offset: high header flag bytes are
not part of `GetCharacterClass` identity.

An identified mount request is denied only for the other registered occupant or
the other registered pending owner. Self, idle, unknown and stale authority
fall through to native behavior. The existing stale-committed exception is
retained: when the committed flag is nonzero, the horse controls itself, and the
pending owner has a valid control object with mounted flag zero, fall through.
The arm payload starts at zero; enabling it requires externally established authority.
All untouched guards are rechecked at entry; the original two entry words are
pre-install guards only, since installation replaces them. Reads are not atomic. The external owner
must keep reviewed allocations stable during a call and revoke the arm before
changing authority. **This does not fix simultaneous starts**: no reservation is
published by this read-only gate. Synthetic tests are not gameplay qualification.
