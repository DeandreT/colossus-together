"""Explicit contract bridge; no pointer discovery, liveness guesses or writes."""

from dataclasses import dataclass

from lifecycle import (
    CanonicalDeleteRequested,
    CanonicalFinalFree,
    ConstructorCaptured,
    ConstructorRecord,
    GameplayReady,
    OwnedDeleteRequested,
    OwnedFinalFree,
    Part,
)

from .records import ALLOCATION_INVALID, Kind, RingReader, TelemetryLoss


@dataclass(frozen=True)
class ConstructorMetadata:
    generation: int
    resource_generation: int
    part: Part
    parent_p1: int
    dependency_ids: frozenset[str]
    # Independently owned GP copy in the consumer's allocation, not source GP.
    gp_copy: int = 0
    gp_copy_bytes: bytes = b""


@dataclass(frozen=True)
class DeleteMetadata:
    generation: int | None = None
    canonical_p1: int | None = None
    ownership_id: int | None = None


@dataclass(frozen=True)
class Mapping:
    event: object | None
    missing: tuple[str, ...] = ()
    raw: object | None = None


@dataclass(frozen=True)
class VerifiedAllocationIdentity:
    """Host-verified lifetime, not an address-derived guess.

    constructor_sequence binds allocation reuse to this capture epoch. The
    caller establishes canonical/owned identity and generation independently.
    """

    allocation_ptr: int
    object_ptr: int
    generation: int
    constructor_sequence: int
    canonical: bool = False
    ownership_id: int | None = None


class AllocationIdentityMap:
    """Explicit constructor-to-allocation bindings for one capture epoch.

    Register only after authoritative ownership/epoch verification. Retire
    after delivering the matching final-free event. Never silently overwrite
    a live binding when an address is reused or reconstruct one after loss.
    """

    def __init__(self):
        self._identities = {}

    def register(self, record, identity):
        if (
            record.kind not in (Kind.SCRIPT_CHAR, Kind.ALIAS_LAYOUT)
            or record.flags & ALLOCATION_INVALID
            or not isinstance(identity, VerifiedAllocationIdentity)
            or not _valid_identity(identity)
            or record.allocation_ptr != identity.allocation_ptr
            or record.object_ptr != identity.object_ptr
            or record.sequence != identity.constructor_sequence
        ):
            raise ValueError(
                "allocation binding requires a matching live constructor capture"
            )
        prior = self._identities.get(identity.allocation_ptr)
        if prior is not None and prior != identity:
            raise ValueError("allocation still has a live identity")
        self._identities[identity.allocation_ptr] = identity

    def resolve(self, record):
        if record.kind != Kind.FINAL_FREE_ALLOCATION:
            return None
        identity = self._identities.get(record.allocation_ptr)
        return (
            identity
            if identity and record.sequence > identity.constructor_sequence
            else None
        )

    def retire(self, record):
        identity = self.resolve(record)
        if identity is None:
            raise ValueError("unknown allocation lifetime")
        del self._identities[record.allocation_ptr]


def _valid_identity(identity):
    return (
        0x80000 <= identity.allocation_ptr < 0x2000000
        and identity.allocation_ptr % 4 == 0
        and 0x80000 <= identity.object_ptr <= 0x1FFFFFC
        and identity.object_ptr % 4 == 0
        and identity.generation >= 0
        and identity.constructor_sequence > 0
        and (
            identity.canonical
            and identity.ownership_id is None
            or not identity.canonical
            and identity.ownership_id is not None
            and identity.ownership_id > 0
        )
    )


def map_record(record, metadata=None):
    """Metadata must come from authoritative epoch/ownership/resource tracking.

    Raw a0 is NOT inferred to be P1, a1 does not identify a body part, and the
    GP pointer is NOT reused as an owned GP copy. Unrelated constructors may
    be left unmapped. Allocation-free events require an explicit verified
    identity binding; unknown allocations remain available as raw records.
    """
    if record.kind == Kind.FINAL_FREE_ALLOCATION:
        if (
            not isinstance(metadata, VerifiedAllocationIdentity)
            or not _valid_identity(metadata)
            or metadata.allocation_ptr != record.allocation_ptr
            or record.sequence <= metadata.constructor_sequence
        ):
            return Mapping(None, ("verified allocation-to-lifetime identity",), record)
        event = (
            CanonicalFinalFree(metadata.generation, metadata.object_ptr)
            if metadata.canonical
            else OwnedFinalFree(metadata.ownership_id)
        )
        return Mapping(event, raw=record)
    if record.kind == Kind.DELETE_REQUEST:
        if not isinstance(metadata, DeleteMetadata):
            return Mapping(None, ("delete identity and epoch/ownership",))
        if metadata.ownership_id is not None:
            if (
                metadata.ownership_id <= 0
                or metadata.canonical_p1 is not None
                or metadata.generation is not None
            ):
                return Mapping(None, ("unambiguous deletion identity",))
            return Mapping(OwnedDeleteRequested(metadata.ownership_id))
        if (
            metadata.generation is None
            or metadata.generation < 0
            or not metadata.canonical_p1
            or record.object_ptr != metadata.canonical_p1
        ):
            return Mapping(None, ("matching canonical identity and generation",))
        return Mapping(
            CanonicalDeleteRequested(metadata.generation, metadata.canonical_p1)
        )
    if not isinstance(metadata, ConstructorMetadata):
        return Mapping(
            None,
            (
                "generation",
                "resource generation",
                "part",
                "canonical parent",
                "transitive dependencies",
                "owned GP copy if present",
            ),
        )
    missing = []
    if record.flags or len(record.parameters) != 0x3C:
        missing.append("complete parameter/GP snapshot")
    if not record.object_ptr:
        missing.append("successful created object")
    if metadata.generation < 0 or metadata.resource_generation < 0:
        missing.append("valid epochs")
    if not isinstance(metadata.part, Part) or metadata.parent_p1 <= 0:
        missing.append("verified part and canonical parent")
    if not metadata.dependency_ids or any(not key for key in metadata.dependency_ids):
        missing.append("transitive dependencies")
    if record.gp_ptr:
        if (
            metadata.gp_copy <= 0
            or bytes(metadata.gp_copy_bytes) != record.gp_bytes
            or len(record.gp_bytes) != 0x40
        ):
            missing.append("independent GP copy matching captured bytes")
    elif metadata.gp_copy or metadata.gp_copy_bytes:
        missing.append("null GP mapping")
    if not record.definition_ptr:
        missing.append("definition")
    if missing:
        return Mapping(None, tuple(missing))
    return Mapping(
        ConstructorCaptured(
            ConstructorRecord(
                metadata.generation,
                metadata.resource_generation,
                metadata.part,
                record.definition_ptr,
                record.object_ptr,
                metadata.parent_p1,
                record.parameters,
                metadata.gp_copy,
                metadata.dependency_ids,
            )
        )
    )


class ControllerAdapter:
    """Snapshot -> resolved events. Caller explicitly commits consumer progress.

    All readiness events must pass dispatch(); loss latches and asks the core
    to drain, and can never be cleared by retry/readiness or target reset.
    A fresh instance requires a separately re-established capture epoch.
    """

    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.reader = RingReader()

    def dispatch(self, event):
        if self.reader.failed and isinstance(event, GameplayReady) and event.ready:
            raise TelemetryLoss("activation forbidden after capture loss")
        return self.lifecycle.dispatch(event)

    def snapshot(self, state, ring, resolve_metadata):
        try:
            records, cursor = self.reader.drain(state, ring)
        except TelemetryLoss:
            generation = self.lifecycle.generation
            self.loss_actions = (
                self.lifecycle.dispatch(GameplayReady(generation, False))
                if generation is not None
                else ()
            )
            raise
        mappings = tuple(
            map_record(record, resolve_metadata(record)) for record in records
        )
        actions = []
        for mapping in mappings:
            if mapping.event is not None:
                actions.extend(self.dispatch(mapping.event))
        return mappings, tuple(actions), cursor
