"""Deterministic, memory-I/O-free ownership and resource-lifetime reducer.

Addresses are opaque handles. Only an adapter may dereference them, after its
own generation/liveness check; this module never reads game memory.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TypeAlias


class State(str, Enum):
    WAITING = "WAITING"
    BUILDING = "BUILDING"
    ACTIVE = "ACTIVE"
    DRAINING = "DRAINING"
    FAILED = "FAILED"


class Part(str, Enum):
    BODY = "body"
    MANTLE = "mantle"
    HEAD = "head"


@dataclass(frozen=True)
class ConstructorRecord:
    generation: int
    resource_generation: int
    part: Part
    definition_ptr: int
    original_obj: int
    parent_p1: int
    parameter_copy: bytes
    gp_copy: int
    dependency_ids: frozenset[str]

    def __post_init__(self) -> None:
        # Take actual immutable copies even if a caller passed bytearray/set.
        object.__setattr__(self, "parameter_copy", bytes(self.parameter_copy))
        object.__setattr__(self, "dependency_ids", frozenset(self.dependency_ids))
        if min(self.definition_ptr, self.original_obj, self.parent_p1) <= 0:
            raise ValueError("constructor addresses must be nonzero")
        if not self.dependency_ids or any(not key for key in self.dependency_ids):
            raise ValueError("constructor dependencies must be explicit")


@dataclass(frozen=True)
class CanonicalRegistered:
    generation: int
    resource_generation: int
    p1: int


@dataclass(frozen=True)
class CanonicalDeleteRequested:
    generation: int
    p1: int


@dataclass(frozen=True)
class CanonicalFinalFree:
    generation: int
    p1: int


@dataclass(frozen=True)
class ConstructorCaptured:
    record: ConstructorRecord


@dataclass(frozen=True)
class GameplayReady:
    generation: int
    ready: bool


@dataclass(frozen=True)
class GameModeChanged:
    generation: int
    bits: int


@dataclass(frozen=True)
class CreationResult:
    request_id: int
    object_ptr: int | None
    error: str | None = None


@dataclass(frozen=True)
class OwnedDeleteRequested:
    ownership_id: int


@dataclass(frozen=True)
class OwnedFinalFree:
    ownership_id: int


@dataclass(frozen=True)
class ParentDeletionPrepared:
    """Acknowledge our one native parent hold, or report failure/timeout."""

    ownership_id: int
    error: str | None = None


@dataclass(frozen=True)
class ParentDeleteHoldReleased:
    """Acknowledge release of only our hold, before reporting final-free."""

    ownership_id: int
    error: str | None = None


@dataclass(frozen=True)
class TeardownFailed:
    """An adapter error/timeout with uncertain native teardown completion."""

    ownership_id: int
    error: str


@dataclass(frozen=True)
class ResourceUnloadRequested:
    unload_id: int
    resource_generation: int
    dependency_id: str


@dataclass(frozen=True)
class RespawnRequested:
    generation: int


@dataclass(frozen=True)
class RetryRequested:
    generation: int


@dataclass(frozen=True)
class CreateMain:
    request_id: int
    generation: int
    resource_generation: int
    canonical_p1: int
    dependency_ids: frozenset[str]
    # An adapter must allocate a separate ownership group, never P1's group.
    independent_group: bool = True
    world_save_authority: str = "P1"


@dataclass(frozen=True)
class CreateVisual:
    request_id: int
    generation: int
    resource_generation: int
    parent_p2: int
    parent_ownership_id: int
    constructor: ConstructorRecord
    independent_group: bool = True
    world_save_authority: str = "P1"


@dataclass(frozen=True)
class DeleteOwned:
    ownership_id: int
    object_ptr: int
    generation: int
    resource_generation: int


@dataclass(frozen=True)
class AcquireDeleteHold:
    ownership_id: int
    object_ptr: int
    generation: int
    resource_generation: int


@dataclass(frozen=True)
class ReleaseDeleteHold:
    ownership_id: int
    object_ptr: int
    generation: int
    resource_generation: int


@dataclass(frozen=True)
class AllowResourceUnload:
    unload_id: int
    resource_generation: int
    dependency_id: str


Event: TypeAlias = (
    CanonicalRegistered | CanonicalDeleteRequested | CanonicalFinalFree
    | ConstructorCaptured | GameplayReady | GameModeChanged | CreationResult
    | OwnedDeleteRequested | OwnedFinalFree | ResourceUnloadRequested
    | RespawnRequested | RetryRequested | ParentDeletionPrepared
    | ParentDeleteHoldReleased
    | TeardownFailed
)
Action: TypeAlias = (
    CreateMain | CreateVisual | DeleteOwned | AllowResourceUnload
    | AcquireDeleteHold | ReleaseDeleteHold
)


@dataclass(frozen=True)
class _Request:
    request_id: int
    generation: int
    resource_generation: int
    dependency_ids: frozenset[str]
    part: Part | None


@dataclass
class _Owned:
    request: _Request
    object_ptr: int
    delete_requested: bool = False
    delete_observed: bool = False
    hold_requested: bool = False
    hold_acquired: bool = False
    release_requested: bool = False
    hold_released: bool = False
    final_freed: bool = False


class Lifecycle:
    """Keep one instance across telemetry ticks, cold boots and P1 generations.

    dispatch() mutates only local state and returns ordered, one-shot commands.
    Deliver every creation result and final-free acknowledgement, including
    after a build has been invalidated. Never run adapter callbacks reentrantly
    inside dispatch(). See README.md for the required memory-adapter contract.
    """

    def __init__(
        self, *, max_constructor_records: int = 3,
        max_parameter_bytes: int = 65536, no_spawn_mask: int = 0x1,
        native_parent_hold: bool = True,
    ) -> None:
        if max_constructor_records < len(Part):
            raise ValueError("capacity must cover body, mantle and head")
        if max_parameter_bytes < 0 or no_spawn_mask <= 0:
            raise ValueError("invalid parameter bound or no-spawn mask")
        self.max_constructor_records = max_constructor_records
        self.max_parameter_bytes = max_parameter_bytes
        self.no_spawn_mask = no_spawn_mask
        self.native_parent_hold = native_parent_hold
        self.state = State.WAITING
        self.failure: str | None = None
        # A native teardown protocol violation must not be cleared by retry or
        # a new P1 generation. Quarantine preserves the resource barrier.
        self.teardown_error: str | None = None
        self._highest_generation = -1
        self._generation: int | None = None
        self._resource_generation: int | None = None
        self._p1: int | None = None
        self._ready = False
        self._game_mode: int | None = None
        self._records: dict[Part, ConstructorRecord] = {}
        self._build_records: dict[Part, ConstructorRecord] = {}
        self._pending: dict[int, _Request] = {}
        self._owned: dict[int, _Owned] = {}
        self._next_request = 1
        self._draining = False
        self._unloads: dict[int, ResourceUnloadRequested] = {}
        self._completed_unloads: dict[int, ResourceUnloadRequested] = {}
        self._blocked_resources: set[tuple[int, str]] = set()

    @property
    def generation(self) -> int | None:
        return self._generation

    @property
    def canonical_p1(self) -> int | None:
        return self._p1

    @property
    def constructor_count(self) -> int:
        return len(self._records)

    @property
    def owned_ids(self) -> tuple[int, ...]:
        return tuple(self._owned)

    @property
    def pending_ids(self) -> tuple[int, ...]:
        return tuple(self._pending)

    @property
    def active_p2(self) -> int | None:
        if self.state != State.ACTIVE:
            return None
        return next(o.object_ptr for o in self._owned.values() if o.request.part is None)

    def dispatch(self, event: Event) -> tuple[Action, ...]:
        actions: list[Action] = []
        if isinstance(event, CanonicalRegistered):
            if event.generation > self._highest_generation:
                if event.p1 <= 0 or event.resource_generation < 0:
                    raise ValueError("invalid canonical registration")
                self._invalidate()
                self._highest_generation = event.generation
                self._generation = event.generation
                self._resource_generation = event.resource_generation
                self._p1 = event.p1
                self.failure = None
                self._game_mode = None
                # Old resource tombstones can be dropped only when no old
                # object/request/unload can still refer to that generation.
                self._prune_resource_tombstones()
        elif isinstance(event, (CanonicalDeleteRequested, CanonicalFinalFree)):
            if self._matches(event.generation) and event.p1 == self._p1:
                # Invalidate before the returned deletion commands can invoke
                # any external callback; never consult P1 again in this epoch.
                self._invalidate()
                self._p1 = None
        elif isinstance(event, ConstructorCaptured):
            record = event.record
            if (
                self._matches(record.generation)
                and record.resource_generation == self._resource_generation
                and record.parent_p1 == self._p1
                and isinstance(record.part, Part)
                and len(record.parameter_copy) <= self.max_parameter_bytes
                and not self._blocked(record.resource_generation, record.dependency_ids)
                and (record.part in self._records or len(self._records) < self.max_constructor_records)
            ):
                self._records[record.part] = record
        elif isinstance(event, GameplayReady):
            if self._matches(event.generation):
                self._ready = event.ready
                if not event.ready:
                    self._begin_drain()
        elif isinstance(event, GameModeChanged):
            if self._matches(event.generation):
                self._game_mode = event.bits
                if event.bits & self.no_spawn_mask:
                    self._ready = False
                    self._begin_drain()
        elif isinstance(event, CreationResult):
            request = self._pending.pop(event.request_id, None)
            if request is not None:
                aliases_live_object = event.object_ptr is not None and (
                    event.object_ptr == self._p1
                    or any(o.object_ptr == event.object_ptr for o in self._owned.values())
                )
                if event.object_ptr is not None and event.object_ptr > 0 and not aliases_live_object:
                    # Even a success after invalidation is owned and must be
                    # deleted, not forgotten. An error can accompany a partial
                    # object and still requires this cleanup.
                    self._owned[request.request_id] = _Owned(request, event.object_ptr)
                if event.error or event.object_ptr is None or event.object_ptr <= 0 or aliases_live_object:
                    if request.generation == self._generation and not self._draining:
                        self.failure = event.error or ("creation aliased a live object" if aliases_live_object else "creation failed")
                        self._ready = False
                        self._begin_drain()
        elif isinstance(event, OwnedDeleteRequested):
            owned = self._owned.get(event.ownership_id)
            if owned is not None:
                if self.native_parent_hold and owned.request.part is None and not owned.hold_acquired:
                    self.teardown_error = "parent deletion observed without our acquired hold"
                owned.delete_requested = True
                owned.delete_observed = True
                self._ready = False
                self._begin_drain()
        elif isinstance(event, OwnedFinalFree):
            owned = self._owned.get(event.ownership_id)
            if owned is not None and self.native_parent_hold and owned.request.part is None and (
                self.teardown_error is not None or not owned.hold_released
                or any(r.part is not None for r in self._live_requests())
            ):
                # The pointer is now stale. Keep only a quarantined ownership
                # tombstone, never issue further native operations against it.
                owned.final_freed = True
                self.teardown_error = "parent final-free before safe hold release and child settlement"
                self._ready = False
                self._begin_drain()
            elif owned is not None:
                del self._owned[event.ownership_id]
            if owned is not None and not self._draining:
                self._ready = False
                self._begin_drain()
        elif isinstance(event, ParentDeletionPrepared):
            owned = self._owned.get(event.ownership_id)
            if self.teardown_error is None and self.native_parent_hold and owned is not None and owned.request.part is None and owned.hold_requested:
                if not owned.hold_acquired:
                    if event.error:
                        self.teardown_error = "parent hold acquisition failed: " + event.error
                    else:
                        owned.hold_acquired = True
        elif isinstance(event, ParentDeleteHoldReleased):
            owned = self._owned.get(event.ownership_id)
            if self.teardown_error is None and self.native_parent_hold and owned is not None and owned.request.part is None and owned.release_requested:
                if not owned.hold_released:
                    if event.error:
                        self.teardown_error = "parent hold release failed: " + event.error
                    else:
                        owned.hold_released = True
        elif isinstance(event, TeardownFailed):
            if event.ownership_id in self._owned:
                self.teardown_error = "native teardown failed: " + event.error
                self._ready = False
                self._begin_drain()
        elif isinstance(event, ResourceUnloadRequested):
            previous = self._unloads.get(event.unload_id) or self._completed_unloads.get(event.unload_id)
            if previous is not None and previous != event:
                raise ValueError("an unload ID cannot identify two requests")
            key = (event.resource_generation, event.dependency_id)
            # A repeated completed unload notification is not another permit.
            if previous is None:
                self._unloads[event.unload_id] = event
                self._blocked_resources.add(key)
                affected = [part for part, r in self._records.items()
                            if self._depends(r.resource_generation, r.dependency_ids, event)]
                for part in affected:
                    del self._records[part]
                if affected or any(self._depends(r.resource_generation, r.dependency_ids, event)
                                   for r in self._live_requests()):
                    self._ready = False
                    self._begin_drain()
        elif isinstance(event, (RespawnRequested, RetryRequested)):
            if self._matches(event.generation):
                # Neither request supplies gameplay readiness or modifies any
                # P1/world-save state. Fresh explicit readiness is mandatory.
                self._ready = False
                if isinstance(event, RetryRequested):
                    self.failure = None
                self._begin_drain()
        else:
            raise TypeError(f"unsupported event: {type(event).__name__}")

        self._reconcile(actions)
        return tuple(actions)

    def _matches(self, generation: int) -> bool:
        return self._p1 is not None and generation == self._generation

    def _blocked(self, resource_generation: int, dependencies: frozenset[str]) -> bool:
        return any((resource_generation, key) in self._blocked_resources for key in dependencies)

    @staticmethod
    def _depends(resource_generation: int, dependencies: frozenset[str], unload: ResourceUnloadRequested) -> bool:
        return resource_generation == unload.resource_generation and unload.dependency_id in dependencies

    def _live_requests(self) -> tuple[_Request, ...]:
        return tuple(self._pending.values()) + tuple(o.request for o in self._owned.values())

    def _prune_resource_tombstones(self) -> None:
        generations = {r.resource_generation for r in self._live_requests()}
        generations.update(u.resource_generation for u in self._unloads.values())
        generations.add(self._resource_generation)
        self._blocked_resources.intersection_update(
            key for key in self._blocked_resources if key[0] in generations
        )

    def _begin_drain(self) -> None:
        self._draining = bool(self._pending or self._owned)
        self._build_records.clear()

    def _invalidate(self) -> None:
        self._ready = False
        self._records.clear()
        self._begin_drain()

    def _new_request(self, dependencies: frozenset[str], part: Part | None) -> _Request:
        assert self._generation is not None and self._resource_generation is not None
        request = _Request(self._next_request, self._generation, self._resource_generation, dependencies, part)
        self._next_request += 1
        self._pending[request.request_id] = request
        return request

    def _reconcile(self, actions: list[Action]) -> None:
        if self._draining:
            if self.native_parent_hold:
                self._reconcile_native_teardown(actions)
            else:
                # Compatibility mode for generic objects, NOT SotC P2.
                children_live = any(r.part is not None for r in self._live_requests())
                for owned in sorted(self._owned.values(), key=lambda o: o.request.part is None):
                    if not owned.delete_requested and not (children_live and owned.request.part is None):
                        self._request_delete(owned, actions)
            self._draining = bool(self._pending or self._owned)

        for unload_id, unload in tuple(self._unloads.items()):
            if not any(self._depends(r.resource_generation, r.dependency_ids, unload)
                       for r in self._live_requests()):
                actions.append(AllowResourceUnload(unload_id, unload.resource_generation, unload.dependency_id))
                del self._unloads[unload_id]
                self._completed_unloads[unload_id] = unload

        if self._draining:
            self.state = State.DRAINING
            return
        if self.failure is not None or self.teardown_error is not None:
            self.state = State.FAILED
            return
        eligible = (
            self._p1 is not None and self._ready and self._game_mode is not None
            and not self._game_mode & self.no_spawn_mask
            and len(self._records) == len(Part)
        )
        if not eligible:
            self.state = State.WAITING
            return

        if not self._owned and not self._pending:
            self._build_records = dict(self._records)
            dependencies = frozenset(key for r in self._build_records.values() for key in r.dependency_ids)
            request = self._new_request(dependencies, None)
            assert self._p1 is not None
            actions.append(CreateMain(request.request_id, request.generation, request.resource_generation, self._p1, dependencies))
            self.state = State.BUILDING
            return

        main = next((o for o in self._owned.values() if o.request.part is None), None)
        if main is not None and len(self._owned) == 1 and not self._pending:
            for part in Part:
                record = self._build_records[part]
                request = self._new_request(record.dependency_ids, part)
                actions.append(CreateVisual(request.request_id, request.generation, request.resource_generation, main.object_ptr, main.request.request_id, record))
        self.state = State.ACTIVE if len(self._owned) == len(Part) + 1 and not self._pending else State.BUILDING

    @staticmethod
    def _request_delete(owned: _Owned, actions: list[Action]) -> None:
        owned.delete_requested = True
        r = owned.request
        actions.append(DeleteOwned(r.request_id, owned.object_ptr, r.generation, r.resource_generation))

    def _reconcile_native_teardown(self, actions: list[Action]) -> None:
        if self.teardown_error is not None:
            return
        parent = next((o for o in self._owned.values() if o.request.part is None), None)
        if parent is not None:
            r = parent.request
            if not parent.hold_requested:
                parent.hold_requested = True
                actions.append(AcquireDeleteHold(r.request_id, parent.object_ptr, r.generation, r.resource_generation))
                return
            if not parent.hold_acquired:
                return
            if not parent.delete_requested:
                self._request_delete(parent, actions)
                return
            # Main's observed deletion is the terminal immediate-cleanup
            # notification, after all automatic child-request observations.
            if not parent.delete_observed:
                return
        elif any(r.part is None for r in self._pending.values()):
            return

        for owned in self._owned.values():
            if owned.request.part is not None and not owned.delete_requested:
                self._request_delete(owned, actions)

        if parent is not None and not self._pending and not any(
            o.request.part is not None for o in self._owned.values()
        ) and not parent.release_requested:
            parent.release_requested = True
            r = parent.request
            actions.append(ReleaseDeleteHold(r.request_id, parent.object_ptr, r.generation, r.resource_generation))
