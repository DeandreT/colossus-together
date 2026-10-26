"""Bounded ELF32 little-endian MIPS ET_REL linker for project-owned helpers.

No instruction execution, ELF loading, GOT, ABI conversion, or game assets.
Addresses are caller supplied, keyed by allocated section name.
"""

import struct
from dataclasses import dataclass


class LinkError(ValueError):
    pass


@dataclass(frozen=True)
class Payload:
    section: str
    address: int
    data: bytes


@dataclass(frozen=True)
class LinkedObject:
    payloads: tuple[Payload, ...]
    exports: dict[str, int]


def link_object(blob, addresses, externals=None, *, max_output=32 * 1024 * 1024):
    """Link one ET_REL object. EABI/O32 flags are retained as caller concerns.

    Supports SHT_REL R_MIPS_NONE/32/26/HI16/LO16 only. Allocated PROGBITS
    and NOBITS require explicit placements; MIPS ABI metadata is not loaded.
    COMMON symbols and all other relocation/allocated section kinds fail shut.
    """
    externals = dict(externals or {})
    if len(blob) > 16 * 1024 * 1024 or len(blob) < 52:
        raise LinkError("ELF input size out of bounds")
    if not isinstance(max_output, int) or not 0 < max_output <= 32 * 1024 * 1024:
        raise LinkError("invalid output limit")

    def region(offset, size):
        if offset < 0 or size < 0 or offset + size > len(blob):
            raise LinkError("truncated ELF region")
        return blob[offset : offset + size]

    header = struct.unpack("<16sHHIIIIIHHHHHH", region(0, 52))
    ident, kind, machine, version = header[:4]
    if ident[:7] != b"\x7fELF\x01\x01\x01" or kind != 1 or machine != 8 or version != 1:
        raise LinkError("requires ELF32 little-endian MIPS ET_REL version 1")
    if header[8] != 52 or header[10] != 0 or header[11] != 40:
        raise LinkError("unsupported ELF header/program headers")
    shoff, shnum, shstr = header[6], header[12], header[13]
    if not 0 < shnum <= 4096 or not 0 < shstr < shnum:
        raise LinkError("unsupported section table")
    region(shoff, shnum * 40)
    sections = [struct.unpack("<10I", region(shoff + i * 40, 40)) for i in range(shnum)]
    if sections[0] != (0,) * 10 or sections[shstr][1] != 3:
        raise LinkError("invalid null section/string table")

    def string(table, offset):
        if offset >= len(table):
            raise LinkError("string offset out of range")
        end = table.find(b"\0", offset)
        if end < 0:
            raise LinkError("unterminated ELF string")
        try:
            return table[offset:end].decode("utf-8")
        except UnicodeError as exc:
            raise LinkError("invalid ELF name") from exc

    names_blob = region(sections[shstr][4], sections[shstr][5])
    names = [string(names_blob, sec[0]) for sec in sections]
    images, bases, occupied = {}, {}, []
    total = 0
    for index, sec in enumerate(sections):
        _, stype, flags, _, offset, size, _, _, align, _ = sec
        if stype != 8:
            region(offset, size)
        if align and align & (align - 1):
            raise LinkError("section alignment is not a power of two")
        if not flags & 2:
            continue
        if stype in (0x70000006, 0x7000002A):  # .reginfo, .MIPS.abiflags
            continue
        if stype not in (1, 8) or names[index] not in addresses:
            raise LinkError(f"unsupported or unplaced allocated section {names[index]}")
        base = addresses[names[index]]
        if (
            not isinstance(base, int)
            or base < 0
            or base + size > 0x100000000
            or base % max(1, align)
        ):
            raise LinkError("section address alignment/range error")
        total += size
        if total > max_output:
            raise LinkError("output exceeds limit")
        if size:
            if any(base < end and start < base + size for start, end in occupied):
                raise LinkError("overlapping output sections")
            occupied.append((base, base + size))
        bases[index] = base
        images[index] = (
            bytearray(size) if stype == 8 else bytearray(region(offset, size))
        )
    if set(addresses) != {names[i] for i in images}:
        raise LinkError("unknown or duplicate placement names")
    if len({names[i] for i in images}) != len(images):
        raise LinkError("duplicate allocated section names")

    symtabs, exports = {}, {}
    for index, sec in enumerate(sections):
        if sec[1] != 2:
            continue
        if sec[9] != 16 or sec[5] % 16 or not 0 <= sec[6] < shnum:
            raise LinkError("invalid symbol table")
        strsec = sections[sec[6]]
        if strsec[1] != 3:
            raise LinkError("symbol names require string table")
        strings = region(strsec[4], strsec[5])
        symbols = []
        for at in range(sec[4], sec[4] + sec[5], 16):
            nameoff, value, size, info, _other, defined = struct.unpack(
                "<IIIBBH", region(at, 16)
            )
            name = string(strings, nameoff)
            if defined == 0:
                if len(symbols) == 0 and not name and value == 0:
                    resolved = 0
                elif name in externals:
                    resolved = externals[name]
                else:
                    raise LinkError(f"unresolved symbol {name!r}")
            elif defined == 0xFFF1:  # SHN_ABS
                resolved = value
            elif defined in bases:
                if value > len(images[defined]) or size > len(images[defined]) - value:
                    raise LinkError("defined symbol outside its section")
                resolved = bases[defined] + value
            elif defined < shnum and not sections[defined][2] & 2:
                resolved = None  # debug/non-allocated symbols cannot be used by code
            else:
                raise LinkError(f"unsupported symbol section for {name!r}")
            if resolved is not None and (
                not isinstance(resolved, int) or not 0 <= resolved <= 0xFFFFFFFF
            ):
                raise LinkError("symbol address outside uint32")
            symbols.append(resolved)
            if defined and info >> 4 in (1, 2) and name and resolved is not None:
                if name in exports:
                    raise LinkError(f"duplicate export {name}")
                exports[name] = resolved
        symtabs[index] = symbols

    def checked(value):
        if not 0 <= value <= 0xFFFFFFFF:
            raise LinkError("relocation result outside uint32")
        return value

    used = set()
    for sec in sections:
        if sec[1] not in (4, 9):
            continue
        if sec[7] not in images:
            if sec[7] >= shnum:
                raise LinkError("invalid relocation target")
            if sections[sec[7]][2] & 2:
                raise LinkError("relocation into ignored allocated section")
            continue  # debug relocations have no runtime output
        if sec[1] != 9 or sec[9] != 8 or sec[5] % 8 or sec[6] not in symtabs:
            raise LinkError("requires REL relocations and a valid symbol table")
        target = sec[7]
        image, symbols = images[target], symtabs[sec[6]]
        pending = {}
        for at in range(sec[4], sec[4] + sec[5], 8):
            offset, info = struct.unpack("<II", region(at, 8))
            sym, rtype = info >> 8, info & 255
            if rtype not in (0, 2, 4, 5, 6):
                raise LinkError(f"unsupported MIPS relocation {rtype}")
            if rtype == 0:
                continue
            if sym >= len(symbols) or symbols[sym] is None:
                raise LinkError("invalid relocation symbol")
            if offset % 4 or offset + 4 > len(image) or (bases[target] + offset) % 4:
                raise LinkError("unaligned/out-of-range relocation")
            if (target, offset) in used:
                raise LinkError("overlapping relocation words")
            used.add((target, offset))
            (word,) = struct.unpack_from("<I", image, offset)
            symbol = symbols[sym]

            def put(where, value, image=image):
                struct.pack_into("<I", image, where, value)

            if rtype == 2:
                put(offset, (symbol + word) & 0xFFFFFFFF)
            elif rtype == 4:
                addend = (word & 0x3FFFFFF) << 2
                if addend & 0x8000000:
                    addend -= 0x10000000
                address = checked(symbol + addend)
                if address % 4 or (address ^ (bases[target] + offset + 4)) & 0xF0000000:
                    raise LinkError("MIPS26 alignment/region error")
                put(offset, (word & 0xFC000000) | ((address >> 2) & 0x3FFFFFF))
            elif rtype == 5:
                pending.setdefault(sym, []).append((offset, word))
            else:
                low = word & 0xFFFF
                signed_low = low - 0x10000 if low & 0x8000 else low
                # Each pending HI has its own addend; one LO can consume many.
                for high_offset, high_word in pending.pop(sym, []):
                    value = (
                        symbol + ((high_word & 0xFFFF) << 16) + signed_low
                    ) & 0xFFFFFFFF
                    put(
                        high_offset,
                        (high_word & 0xFFFF0000) | (((value + 0x8000) >> 16) & 0xFFFF),
                    )
                put(offset, (word & 0xFFFF0000) | ((symbol + signed_low) & 0xFFFF))
        if pending:
            raise LinkError("unpaired R_MIPS_HI16")
    return LinkedObject(
        tuple(Payload(names[i], bases[i], bytes(data)) for i, data in images.items()),
        exports,
    )
