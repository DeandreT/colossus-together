"""Checked metadata only; no live polling, writes, or lifetime inference."""

import re
from dataclasses import dataclass
from enum import Enum

from injection.records import GP_SIZE, PARAM_SIZE, Kind
from runtime.pine import EE_RAM_SIZE


class MetadataError(ValueError):
    """Unverified, unsupported, or malformed snapshot data."""


class Part(Enum):
    BODY = "body"
    MANTLE = "mantle"
    HEAD = "head"


class ConstructorFamily(Enum):
    CHARACTER = "character"
    ALIAS = "alias"


@dataclass(frozen=True)
class Model:
    name: str
    part: Part
    level: int | None


@dataclass(frozen=True)
class VisualRecord:
    object_ptr: int
    definition_ptr: int
    family: ConstructorFamily
    model: Model
    canonical_p1: int
    parent_p1: int
    skeleton_source: int | None
    parameters: bytes = b""
    gp_bytes: bytes = b""
    sequence: int | None = None


def classify_name(name):
    """Only exact basenames; paths, case folding and unknown variants fail."""
    match = re.fullmatch(r"player_A(_mantle|_head)?(?:_LV(1|4|8|12|16))?\.nmo", name)
    if match is None:
        raise MetadataError("unsupported model basename")
    part = {None: Part.BODY, "_mantle": Part.MANTLE, "_head": Part.HEAD}[match[1]]
    return Model(name, part, int(match[2]) if match[2] else None)


class Snapshot:
    """read(address, size) must return bytes from ONE quiescent physical EE view.

    The caller owns pause/snapshot and lifetime verification. A valid pointer is
    not proof of a live allocation. No virtual-address masking is performed.
    """

    def __init__(self, read, *, quiescent, undefined_symbol):
        if quiescent is not True or not callable(read):
            raise MetadataError("explicit quiescent read callback required")
        if type(undefined_symbol) is not int or not 0 <= undefined_symbol <= 0xFFFFFFFF:
            raise MetadataError("explicit uint32 undefined symbol required")
        self._read = read
        self.undefined_symbol = undefined_symbol

    @staticmethod
    def checked(address, size=4, alignment=4):
        if (
            type(address) is not int
            or type(size) is not int
            or type(alignment) is not int
            or alignment <= 0
            or address <= 0
            or size <= 0
            or address % alignment
            or address + size > EE_RAM_SIZE
        ):
            raise MetadataError("invalid aligned physical EE range")
        return address

    def read(self, address, size, alignment=1):
        self.checked(address, size, alignment)
        try:
            data = self._read(address, size)
        except Exception as exc:
            raise MetadataError("snapshot read failed") from exc
        if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != size:
            raise MetadataError("short or non-byte snapshot read")
        return bytes(data)

    def u32(self, address):
        return int.from_bytes(self.read(address, 4, 4), "little")

    def pointer(self, address, *, size=4, alignment=4):
        return self.checked(self.u32(address), size, alignment)

    def model_from_resource(self, resource):
        self.checked(resource)
        header = self.pointer(resource + 0x20, size=0x74)
        if self.u32(header) != 0x004F4D4E or self.u32(header + 4) != 3:
            raise MetadataError("unsupported NMO header")
        name = self.pointer(header + 0x70, size=1, alignment=1)
        raw = bytearray()
        for offset in range(128):
            byte = self.read(name + offset, 1)[0]
            if not byte:
                try:
                    return classify_name(raw.decode("ascii"))
                except UnicodeError as exc:
                    raise MetadataError("non-ASCII model name") from exc
            raw.append(byte)
        raise MetadataError("unterminated model name")

    def packed_model(self, field):
        word = self.u32(field)
        distance, index = word & 0x3FFFF, (word >> 18) & 0xFFF
        # Subtract the masked distance, not the entire packed word. Arithmetic
        # must never wrap or carry index bits into a pointer calculation.
        symbol = self.u32(field - distance)
        if symbol in (0, self.undefined_symbol):
            raise MetadataError("undefined packed symbol")
        self.checked(symbol, 0x14)
        descriptor = self.pointer(symbol + 8, size=0x10)
        stride = self.u32(descriptor + 0xC)
        if stride < 0xC or stride % 4:
            raise MetadataError("invalid resource stride")
        base = self.pointer(symbol + 0x10)
        entry = self.checked(base + index * stride, size=0xC)
        return self.model_from_resource(self.pointer(entry + 8))

    def _ownership(self, obj, family, model, canonical_p1, parent):
        self.checked(canonical_p1, size=9)
        if self.read(canonical_p1 + 8, 1)[0] != 9:
            raise MetadataError("canonical P1 is not a character")
        expected = (
            ConstructorFamily.CHARACTER
            if model.part == Part.HEAD
            else ConstructorFamily.ALIAS
        )
        if family != expected:
            raise MetadataError("wrong constructor family")
        if obj == canonical_p1:
            raise MetadataError("visual object is canonical P1")
        if parent != canonical_p1:
            raise MetadataError("wrong canonical parent")
        skeleton = None
        if family == ConstructorFamily.ALIAS:
            skeleton = self.pointer(obj + 0x90 + 0x194)
            if skeleton != canonical_p1:
                raise MetadataError("wrong alias skeleton source")
        return parent, skeleton

    def definition_model(self, definition_ptr, *, family):
        self.checked(definition_ptr)
        if not isinstance(family, ConstructorFamily):
            raise MetadataError("unsupported constructor family")
        return self.packed_model(
            definition_ptr + (4 if family == ConstructorFamily.ALIAS else 0x14)
        )

    def live(self, obj, *, definition_ptr, family, canonical_p1):
        """definition_ptr/family come from independently verified construction."""
        self.checked(obj, size=0x228)
        self.checked(definition_ptr)
        object_type = self.read(obj + 8, 1)[0]
        if (object_type, family) not in (
            (9, ConstructorFamily.CHARACTER),
            (11, ConstructorFamily.ALIAS),
        ):
            raise MetadataError("unsupported ISYS type/family")
        display = self.pointer(obj + 0x90 + 0x144)
        model = self.model_from_resource(self.pointer(display))
        if self.u32(obj + 0x150 + 0x30) != 1:
            raise MetadataError("unsupported parent GP type")
        parent = self.pointer(obj + 0x150)
        parent, skeleton = self._ownership(obj, family, model, canonical_p1, parent)
        return VisualRecord(
            obj, definition_ptr, family, model, canonical_p1, parent, skeleton
        )

    def captured(self, record, *, canonical_p1):
        """Use captured bytes, never dereference the original parameter/GP stack."""
        families = {
            Kind.SCRIPT_CHAR: ConstructorFamily.CHARACTER,
            Kind.ALIAS_LAYOUT: ConstructorFamily.ALIAS,
        }
        family = families.get(record.kind)
        if family is None or record.flags or len(record.parameters) != PARAM_SIZE:
            raise MetadataError("incomplete constructor capture")
        self.checked(record.object_ptr, size=0x228)
        definition = self.checked(record.definition_ptr)
        model = self.definition_model(definition, family=family)
        parameters, gp = bytes(record.parameters), bytes(record.gp_bytes)
        parent = 0
        if record.gp_ptr:
            if len(gp) != GP_SIZE or int.from_bytes(gp[0x30:0x34], "little") != 1:
                raise MetadataError("unsupported captured parent GP")
            parent = int.from_bytes(gp[:4], "little")
        elif gp:
            raise MetadataError("GP bytes without captured GP")
        live = self.live(
            record.object_ptr,
            definition_ptr=definition,
            family=family,
            canonical_p1=canonical_p1,
        )
        if live.model != model:
            raise MetadataError("captured/live model mismatch")
        parent, skeleton = self._ownership(
            record.object_ptr, family, model, canonical_p1, parent
        )
        if family == ConstructorFamily.ALIAS and record.alias_source != canonical_p1:
            raise MetadataError("wrong captured alias source")
        return VisualRecord(
            record.object_ptr,
            definition,
            family,
            model,
            canonical_p1,
            parent,
            skeleton,
            parameters,
            gp,
            record.sequence,
        )

    def group(
        self,
        group_address,
        *,
        node_pool,
        node_count,
        max_nodes=4096,
        deleted_flags_offset,
        deleted_mask,
    ):
        """Walk explicit group/pool; caller supplies verified deletion flag layout.

        Returns a tuple only after the entire chain passes validation. Node zero
        is the null sentinel. Quiescence is required, including deletion flags.
        """
        if (
            type(node_count) is not int
            or not 1 <= node_count <= 65536
            or type(max_nodes) is not int
            or not 1 <= max_nodes <= 65536
            or type(deleted_flags_offset) is not int
            or deleted_flags_offset < 0
            or deleted_flags_offset % 4
            or type(deleted_mask) is not int
            or not 0 < deleted_mask <= 0xFFFFFFFF
        ):
            raise MetadataError("invalid group bounds/deletion contract")
        self.checked(node_pool, node_count * 24)
        index = int.from_bytes(self.read(group_address, 2, 2), "little")
        seen, objects = set(), []
        while index:
            if index >= node_count or index in seen or len(seen) >= max_nodes:
                raise MetadataError("stale, cyclic, or oversized group")
            seen.add(index)
            node = node_pool + index * 24
            obj = self.pointer(node, size=max(9, deleted_flags_offset + 4))
            if not self.u32(obj + deleted_flags_offset) & deleted_mask:
                objects.append(obj)
            index = int.from_bytes(self.read(node + 0xE, 2, 2), "little")
        return tuple(objects)
