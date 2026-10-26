"""Compare-before-write patches. PINE has no atomic compare/exchange or lease."""

from dataclasses import dataclass

from .pine import Status, check_range


@dataclass(frozen=True)
class WordPatch:
    address: int
    expected: int
    replacement: int


@dataclass(frozen=True)
class Change:
    patch: WordPatch
    confirmed: bool


@dataclass(frozen=True)
class Receipt:
    uuid: str
    changes: tuple[Change, ...]


@dataclass(frozen=True)
class RollbackReceipt:
    restored: tuple[int, ...]
    skipped: tuple[int, ...]
    uncertain: tuple[int, ...] = ()


class PatchError(RuntimeError):
    def __init__(self, message, receipt):
        super().__init__(message)
        self.receipt = receipt


def _context(client, uuid):
    if client.status() != Status.PAUSED:
        raise ValueError("emulator must already be paused")
    if client.uuid().upper() != uuid:
        raise ValueError("game UUID mismatch")


def _validate(patches, ranges):
    ranges = tuple(ranges)
    for start, end in ranges:
        check_range(start, end - start, 4)
        if end <= start or end % 4:
            raise ValueError("invalid whitelist range")
    seen = set()
    for patch in patches:
        check_range(patch.address, 4, 4)
        if patch.address in seen:
            raise ValueError("duplicate patch address")
        seen.add(patch.address)
        if not any(
            start <= patch.address and patch.address + 4 <= end for start, end in ranges
        ):
            raise ValueError("patch outside whitelisted EE code ranges")
        if any(
            not isinstance(word, int) or not 0 <= word <= 0xFFFFFFFF
            for word in (patch.expected, patch.replacement)
        ):
            raise ValueError("patch words must be uint32")
        if patch.expected == patch.replacement:
            raise ValueError("no-op patches do not establish ownership")


def apply_patches(client, patches, *, expected_uuid, code_ranges):
    """Preflight every word, then write individually. Never auto-roll back.

    Failure carries a Receipt, including any uncertain write whose reply/readback
    failed. Exclusive external control is required: these guards are not atomic.
    """
    uuid = expected_uuid.upper()
    if len(uuid) != 8 or any(c not in "0123456789ABCDEF" for c in uuid):
        raise ValueError("expected_uuid must be an eight-digit CRC UUID")
    patches = tuple(patches)
    _validate(patches, code_ranges)
    changes = []
    try:
        _context(client, uuid)
        for patch in patches:
            if client.read32(patch.address) != patch.expected:
                raise ValueError(f"preflight guard failed at {patch.address:#x}")
        for patch in patches:
            _context(client, uuid)
            if client.read32(patch.address) != patch.expected:
                raise ValueError(f"word changed since preflight at {patch.address:#x}")
            changes.append(Change(patch, False))
            client.write32(patch.address, patch.replacement)
            if client.read32(patch.address) != patch.replacement:
                raise ValueError(f"write readback failed at {patch.address:#x}")
            changes[-1] = Change(patch, True)
    except Exception as exc:
        raise PatchError(str(exc), Receipt(uuid, tuple(changes))) from exc
    return Receipt(uuid, tuple(changes))


def rollback(client, receipt, *, expected_uuid, code_ranges):
    """Explicit best-effort rollback; foreign current values are never replaced.

    Unconfirmed writes may be restored only when their current value equals new.
    On error the exception receipt is a partial RollbackReceipt. No auto-retry.
    """
    uuid = expected_uuid.upper()
    if receipt.uuid != uuid:
        raise ValueError("receipt UUID mismatch")
    _validate(tuple(change.patch for change in receipt.changes), code_ranges)
    restored, skipped, uncertain = [], [], []
    try:
        _context(client, uuid)
        for change in reversed(receipt.changes):
            patch = change.patch
            _context(client, uuid)
            if client.read32(patch.address) != patch.replacement:
                skipped.append(patch.address)
                continue
            uncertain.append(patch.address)
            client.write32(patch.address, patch.expected)
            if client.read32(patch.address) != patch.expected:
                raise ValueError(f"rollback readback failed at {patch.address:#x}")
            restored.append(patch.address)
            uncertain.pop()
    except Exception as exc:
        raise PatchError(
            str(exc), RollbackReceipt(tuple(restored), tuple(skipped), tuple(uncertain))
        ) from exc
    return RollbackReceipt(tuple(restored), tuple(skipped))
