"""Bounded, read-only parser for little-endian Team Ico ``xff2`` modules.

No loader, filesystem access, third-party packages, or code execution is involved.
Unstored sections (including BSS) have ``data=None``: their declared size never
causes a zero-filled allocation. The API also fits Metadata.from_xff2's adapter.
Only the documented xff2 layout is supported, not ELF or other XFF versions.
"""

import struct
from dataclasses import dataclass
from itertools import pairwise

HEADER_SIZE = 0x70
POINTER_BASE = 0x40010000
MAX_FILE_SIZE = 128 * 1024 * 1024
MAX_SECTION_SIZE = 32 * 1024 * 1024
MAX_TOTAL_SECTION_SIZE = 128 * 1024 * 1024
MAX_SECTIONS = 4096
MAX_SYMBOLS = 262144
MAX_RELOCATIONS = 1048576
MAX_NAME_SIZE = 4096
MAX_TOTAL_NAME_SIZE = 32 * 1024 * 1024
SHT_NOBITS = 8
SHN_ABS = 0xFFF1
_TYPES = {0, 1, 2, 3, 4, 8, 9, 0x70000006, 0x7FFFF420, 0x7FFFF421}


class XffError(ValueError):
    """Malformed, oversized, or unsupported XFF input."""


@dataclass(frozen=True)
class Section:
    name: str
    name_offset: int
    type: int
    offset: int
    size: int
    align: int
    data: bytes | None


@dataclass(frozen=True)
class RelTable:
    target: int
    is_import: bool
    entries: tuple[tuple[int, int, int, int], ...]


@dataclass(frozen=True)
class Module:
    sections: tuple[Section, ...]
    shstrtab: bytes
    strtab: bytes
    symbols: bytes
    reltables: tuple[RelTable, ...]
    imports: tuple[int, ...]
    entry: int
    num_locals: int
    _symbol_names: tuple[str, ...]

    @property
    def num_symbols(self):
        return len(self.symbols) // 16

    def symbol(self, index):
        if not isinstance(index, int) or not 0 <= index < self.num_symbols:
            raise IndexError(index)
        return struct.unpack_from('<IIIBBH', self.symbols, index * 16)

    def symbol_name(self, index):
        self.symbol(index)  # Reject Python's negative-index convention.
        return self._symbol_names[index]

    def section_name(self, index):
        if not isinstance(index, int) or not 0 <= index < len(self.sections):
            raise IndexError(index)
        return self.sections[index].name

    def index_of(self, name):
        for index, section in enumerate(self.sections):
            if section.name == name:
                return index
        raise KeyError(name)


def parse(data: bytes) -> Module:
    """Validate and copy a module; raise XffError on invalid format or limits.

    Symbol names need not be unique (ELF local names often aren't). Section
    names must be unambiguous. Undefined symbols may carry nonzero values;
    absolute symbols are preserved, while COMMON/extended indices are rejected.
    KERNEL's unused, unnamed one-past-end section marker is preserved verbatim;
    it is not a real section and cannot be referenced by relocations.
    Opaque import ``extra`` words and relocation types are preserved, not run.
    """
    if not isinstance(data, bytes):
        raise TypeError('XFF input must be bytes')
    if not HEADER_SIZE <= len(data) <= MAX_FILE_SIZE:
        raise XffError('file size outside supported limits or truncated header')
    if data[:4] != b'xff2':
        raise XffError('unsupported magic/version; expected little-endian xff2')
    h = struct.unpack_from('<28I', data)
    if any(h[i] for i in (1, 2, 4, 6)):
        raise XffError('unsupported header encoding/reserved fields')
    if h[5] != len(data):
        raise XffError('file size does not match header')
    ni, ns, nr, nc = h[7], h[9], h[14], h[16]
    if not 1 <= nc <= MAX_SECTIONS or not 1 <= ns <= MAX_SYMBOLS:
        raise XffError('section/symbol count outside supported limits')
    if ni >= ns or h[3] >= ns or nr > 2 * nc or nr % 2:
        raise XffError('invalid import/local/relocation table count')
    io, so, sto, sho, sao, ro, no, sno = h[20:28]
    for slot, off in zip((8, 10, 11, 12, 13, 15, 17, 18), h[20:28]):
        if h[slot] != POINTER_BASE + off:
            raise XffError('header pointer/offset mismatch')

    ranges = [(0, HEADER_SIZE, 'header')]

    def region(off, size, label, *, claim=True):
        if off < HEADER_SIZE or off > len(data) or size > len(data) - off:
            raise XffError(f'{label}: outside file bounds')
        if claim and size:
            ranges.append((off, off + size, label))
        return memoryview(data)[off:off + size]

    def table(off, count, width, label):
        if off % 4:
            raise XffError(f'{label}: unaligned table')
        region(off, count * width, label)

    table(no, nc, 4, 'section names')
    table(sho, nc, 32, 'section headers')
    table(sao, ns, 4, 'symbol addresses')
    table(ro, nr, 28, 'relocation descriptors')
    table(io, ni, 4, 'imports')
    raw_sections = []
    total = 0
    for i in range(nc):
        reserved, ptr, size, align, kind, bss, reserved2, off = struct.unpack_from(
            '<8I', data, sho + 32 * i)
        if kind not in _TYPES or reserved or reserved2 or bss != (kind == SHT_NOBITS):
            raise XffError(f'section {i}: unsupported type/encoding')
        if kind == 4 and size:
            raise XffError(f'section {i}: nonempty RELA sections are unsupported')
        if align and (align & (align - 1) or align > MAX_SECTION_SIZE):
            raise XffError(f'section {i}: invalid alignment')
        total += size
        if size > MAX_SECTION_SIZE or total > MAX_TOTAL_SECTION_SIZE:
            raise XffError('section size limit exceeded')
        if ptr != (POINTER_BASE + off if off else 0):
            raise XffError(f'section {i}: pointer/offset mismatch')
        if off:
            if kind not in (1, 2, 3, 0x7FFFF420) or off % max(align, 4):
                raise XffError(f'section {i}: unsupported stored section/alignment')
            region(off, size, f'section {i}')
        elif size and kind in (1, 2, 0x7FFFF420):
            raise XffError(f'section {i}: missing stored contents')
        raw_sections.append((kind, off, size, align))

    # The name table's own descriptor must be found before names can be decoded.
    # It may use offset zero, as in original files; other tables may not alias it.
    candidates = []
    for i, (kind, off, size, _) in enumerate(raw_sections):
        name_off = struct.unpack_from('<I', data, no + 4 * i)[0]
        if kind == 3 and (not off or off == sno) and name_off < size:
            blob = region(sno, size, 'section string table', claim=False)
            if blob[name_off:name_off + 10] == b'.shstrtab\0':
                candidates.append(i)
    if len(candidates) != 1:
        raise XffError('missing or ambiguous section string table')
    name_index = candidates[0]
    shstrtab = bytes(region(sno, raw_sections[name_index][2], 'section string table',
                           claim=not raw_sections[name_index][1]))

    def strings(blob, label):
        if not blob or blob[0] != 0:
            raise XffError(f'{label}: missing empty initial string')
        cache = {}
        decoded_size = 0

        def get(off):
            nonlocal decoded_size
            if off not in cache:
                if off >= len(blob):
                    raise XffError(f'{label}: string offset outside table')
                end = blob.find(b'\0', off, min(len(blob), off + MAX_NAME_SIZE + 1))
                if end < 0:
                    raise XffError(f'{label}: unterminated or oversized name')
                decoded_size += end - off + 1
                if decoded_size > MAX_TOTAL_NAME_SIZE:
                    raise XffError(f'{label}: decoded name budget exceeded')
                cache[off] = blob[off:end].decode('latin-1')
            return cache[off]
        return get

    get_section_name = strings(shstrtab, 'section names')
    names = [get_section_name(struct.unpack_from('<I', data, no + 4 * i)[0])
             for i in range(nc)]
    if len(set(names)) != len(names):
        raise XffError('duplicate ambiguous section names')
    if h[19] and ('.text' not in names or h[19] % 4 or
                  h[19] + 4 > raw_sections[names.index('.text')][2]):
        raise XffError('entry point outside text or unaligned')
    try:
        sym_index, str_index = names.index('.symtab'), names.index('.strtab')
    except ValueError as exc:
        raise XffError('missing symbol/string table section') from exc
    if raw_sections[sym_index][:3] != (2, so, ns * 16):
        raise XffError('symbol table descriptor mismatch')
    skind, soff, ssize, _ = raw_sections[str_index]
    if skind != 3 or soff not in (0, sto):
        raise XffError('symbol string table descriptor mismatch')
    strtab = bytes(region(sto, ssize, 'symbol string table', claim=not soff))
    get_symbol_name = strings(strtab, 'symbol names')
    symbols = bytes(region(so, ns * 16, 'symbols', claim=False))
    symbol_names, undefined, orphan_markers = [], set(), set()
    for i in range(ns):
        name, value, size, info, other, shndx = struct.unpack_from('<IIIBBH', symbols, 16 * i)
        symbol_names.append(get_symbol_name(name))
        if shndx == 0:
            if i:
                undefined.add(i)
        elif (shndx == nc and name == value == size == other == 0 and info == 3):
            # Original KERNEL retains one empty STB_LOCAL/STT_SECTION marker
            # from its ELF layout. Keep metadata, never treat it as an address.
            orphan_markers.add(i)
        elif shndx != SHN_ABS and (shndx >= nc or value + size > raw_sections[shndx][2]):
            raise XffError(f'symbol {i}: unsupported index or outside section')
        if struct.unpack_from('<I', data, sao + 4 * i)[0] != value:
            raise XffError('symbol address array mismatch')
    if symbols[:16] != bytes(16):
        raise XffError('invalid null symbol')
    imports = tuple(struct.unpack_from('<I', data, io + 4 * i)[0] for i in range(ni))
    if len(set(imports)) != ni or set(imports) != undefined:
        raise XffError('invalid import symbol indices')

    reltables, targets, total_rels = [], [], 0
    for t in range(nr):
        kind, count, target, pa, pb, a, b = struct.unpack_from('<7I', data, ro + 28 * t)
        total_rels += count
        if kind != 9 or total_rels > MAX_RELOCATIONS or not 0 < target < nc:
            raise XffError('invalid relocation descriptor/count/target')
        if pa != POINTER_BASE + a or pb != POINTER_BASE + b:
            raise XffError('relocation pointer/offset mismatch')
        table(a, count, 8, 'relocation A')
        table(b, count, 8, 'relocation B')
        is_import = t < nr // 2
        entries = []
        for i in range(count):
            offset, info = struct.unpack_from('<II', data, a + 8 * i)
            saved, extra = struct.unpack_from('<II', data, b + 8 * i)
            sym = info >> 8
            if sym >= ns or sym in orphan_markers or (sym in undefined) != is_import:
                raise XffError('invalid relocation symbol or import/local mismatch')
            if offset % 4 or offset + 4 > raw_sections[target][2]:
                raise XffError('relocation word outside target section or unaligned')
            entries.append((offset, info, saved, extra))
        targets.append(target)
        reltables.append(RelTable(target, is_import, tuple(entries)))
    if targets[:nr // 2] != targets[nr // 2:] or len(set(targets)) != nr // 2:
        raise XffError('relocation tables must have unique paired targets')
    # Empty ranges can share positions. Nonempty payloads may only alias their
    # own header references, which were deliberately claimed exactly once.
    ranges.sort()
    for left, right in pairwise(ranges):
        if left[1] > right[0]:
            raise XffError(f'overlapping file regions: {left[2]} and {right[2]}')
    sections = tuple(Section(name, struct.unpack_from('<I', data, no + 4 * i)[0],
                             kind, off, size, align,
                             data[off:off + size] if off else None)
                     for i, (name, (kind, off, size, align)) in
                     enumerate(zip(names, raw_sections)))
    return Module(sections, shstrtab, strtab, symbols, tuple(reltables), imports,
                  h[19], h[3], tuple(symbol_names))
