"""Recover original XFF addresses from relocated, unmodified EE instructions.

No game assets, decompiler import, emulator connection, or writes are involved.
``text_base`` is the actual .text address (G + 0x38), not the module header.
The caller must supply original metadata and keep memory stable during resolve.
"""

from dataclasses import dataclass
import struct
from typing import Callable, Iterable, Mapping


EE_SIZE = 32 * 1024 * 1024
R_MIPS_32, R_MIPS_26, R_MIPS_HI16, R_MIPS_LO16 = 2, 4, 5, 6


class ResolutionError(ValueError):
    """No unique, bounded, original-address evidence was available."""


@dataclass(frozen=True)
class Section:
    name: str
    size: int


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    shndx: int


@dataclass(frozen=True)
class Relocation:
    offset: int
    r_info: int
    saved_word: int
    extra: int = 0


@dataclass(frozen=True)
class RelocationTable:
    target: int
    is_import: bool
    entries: tuple[Relocation, ...]


@dataclass(frozen=True)
class Metadata:
    sections: tuple[Section, ...]
    symbols: tuple[Symbol, ...]
    reltables: tuple[RelocationTable, ...]

    @classmethod
    def from_xff2(cls, module):
        """Copy a duck-typed tools.xff2.Module; never import that tool."""
        return cls(
            tuple(Section(module.section_name(i), s.size)
                  for i, s in enumerate(module.sections)),
            tuple(Symbol(module.symbol_name(i), module.symbol(i)[1],
                         module.symbol(i)[5]) for i in range(module.num_symbols)),
            tuple(RelocationTable(t.target, t.is_import,
                                  tuple(Relocation(*e) for e in t.entries))
                  for t in module.reltables),
        )


def _signed16(word):
    low = word & 0xFFFF
    return low - 0x10000 if low & 0x8000 else low


class OriginalXffResolver:
    """Resolve names or symbol indices against a byte-reading callback.

    ``read(address, size)`` must return exactly size bytes, little endian.
    Patch sites are absolute EE addresses: points exclude any overlapping word;
    ranges are half-open. Include every modified site, even same-opcode patches.
    Only text J/JAL and HI/LO evidence is trusted by default. R_MIPS_32 is
    allowed only for sections explicitly certified readable and immutable via
    ``immutable_bases`` (section index -> actual address).

    Candidate limits fail closed rather than accepting a partial consensus.
    Reads are word-sized, cached only for one resolve, at most twice the limit.
    """

    def __init__(
        self, metadata: Metadata, read: Callable[[int, int], bytes], text_base: int,
        *, patched_sites: Iterable[int] = (),
        patched_ranges: Iterable[tuple[int, int]] = (),
        immutable_bases: Mapping[int, int] | None = None,
        max_candidates: int = 256,
    ):
        self.metadata, self.read, self.text_base = metadata, read, text_base
        self.patched_sites = frozenset(patched_sites)
        self.patched_ranges = tuple(patched_ranges)
        self.immutable_bases = dict(immutable_bases or {})
        if not isinstance(max_candidates, int) or not 1 <= max_candidates <= 65536:
            raise ResolutionError("invalid candidate limit")
        self.max_candidates = max_candidates
        text = [i for i, s in enumerate(metadata.sections) if s.name == ".text"]
        if len(text) != 1:
            raise ResolutionError("requires exactly one .text section")
        self.text = text[0]
        for s in metadata.sections:
            if not 0 <= s.size <= EE_SIZE:
                raise ResolutionError("invalid section size")
        self._region(text_base, metadata.sections[self.text].size)
        if text_base % 4:
            raise ResolutionError("unaligned text base")
        for index, base in self.immutable_bases.items():
            if not 0 <= index < len(metadata.sections) or base % 4:
                raise ResolutionError("invalid immutable section placement")
            self._region(base, metadata.sections[index].size)
            if index == self.text and base != text_base:
                raise ResolutionError("conflicting text placement")
        for start, end in self.patched_ranges:
            if not 0 <= start <= end <= EE_SIZE:
                raise ResolutionError("invalid patch range")
        if any(not 0 <= p < EE_SIZE for p in self.patched_sites):
            raise ResolutionError("invalid patch site")
        self._names = {}
        self._candidates = {}
        self._sections = {}
        for i, sym in enumerate(metadata.symbols):
            self._names.setdefault(sym.name, []).append(i)
            if not 0 <= sym.value <= 0xFFFFFFFF or not 0 <= sym.shndx < len(metadata.sections):
                raise ResolutionError("unsupported symbol value/section")
            if sym.shndx and sym.value > metadata.sections[sym.shndx].size:
                raise ResolutionError("symbol outside section")
        for table in metadata.reltables:
            if not 0 <= table.target < len(metadata.sections):
                raise ResolutionError("invalid relocation target")
            pending = {}
            for entry in table.entries:
                sym, kind = entry.r_info >> 8, entry.r_info & 255
                if not 0 <= sym < len(metadata.symbols):
                    raise ResolutionError("invalid relocation symbol")
                if table.is_import != (metadata.symbols[sym].shndx == 0):
                    raise ResolutionError("relocation import/local mismatch")
                if (entry.offset < 0 or entry.offset % 4 or
                        entry.offset + 4 > metadata.sections[table.target].size or
                        not 0 <= entry.saved_word <= 0xFFFFFFFF):
                    raise ResolutionError("invalid relocation word")
                candidate = None
                if table.target == self.text:
                    if kind == R_MIPS_HI16:
                        pending.setdefault(sym, []).append(entry)
                    elif kind == R_MIPS_LO16:
                        for hi in pending.pop(sym, []):
                            self._add(sym, (table.target, hi, entry))
                    elif kind == R_MIPS_26:
                        candidate = (table.target, entry, None)
                if kind == R_MIPS_32 and table.target in self.immutable_bases:
                    candidate = (table.target, entry, None)
                if candidate:
                    self._add(sym, candidate)

    def _add(self, sym, candidate):
        self._candidates.setdefault(sym, []).append((sym, candidate))
        section = self.metadata.symbols[sym].shndx
        if section:
            self._sections.setdefault(section, []).append((sym, candidate))

    @staticmethod
    def _region(address, size=1):
        if not isinstance(address, int) or address < 0 or address + size > EE_SIZE:
            raise ResolutionError("address outside EE 32 MB")
        return address

    def _patched(self, address):
        return (any(address <= p < address + 4 for p in self.patched_sites) or
                any(address < end and start < address + 4
                    for start, end in self.patched_ranges))

    def resolve(self, name_or_index: str | int) -> int:
        if isinstance(name_or_index, str):
            matches = self._names.get(name_or_index, [])
            if len(matches) != 1:
                raise ResolutionError(f"unknown or ambiguous symbol {name_or_index!r}")
            index = matches[0]
        else:
            index = name_or_index
        if not isinstance(index, int) or not 0 <= index < len(self.metadata.symbols):
            raise ResolutionError("invalid symbol index")
        symbol = self.metadata.symbols[index]
        if symbol.shndx == self.text:
            return self._region(self.text_base + symbol.value)
        candidates = (self._sections.get(symbol.shndx, []) if symbol.shndx
                      else self._candidates.get(index, []))
        cache, values = {}, set()

        def word(address):
            if address not in cache:
                self._region(address, 4)
                try:
                    data = self.read(address, 4)
                except Exception as exc:
                    raise ResolutionError(f"memory read failed at {address:#x}") from exc
                if not isinstance(data, (bytes, bytearray, memoryview)) or len(data) != 4:
                    raise ResolutionError("short or invalid memory read")
                cache[address] = struct.unpack("<I", data)[0]
            return cache[address]

        examined = 0
        for source, (target, first, low) in candidates:
            base = self.text_base if target == self.text else self.immutable_bases[target]
            address = base + first.offset
            if self._patched(address) or (low and self._patched(base + low.offset)):
                continue
            examined += 1
            if examined > self.max_candidates:
                raise ResolutionError("candidate limit exceeded; consensus incomplete")
            live = word(address)
            kind = first.r_info & 255
            if low:
                live_low = word(base + low.offset)
                if (live >> 16 != first.saved_word >> 16 or
                        live_low >> 16 != low.saved_word >> 16 or
                        first.saved_word >> 26 != 15):
                    continue
                actual = ((live & 0xFFFF) << 16) + _signed16(live_low)
                original = ((first.saved_word & 0xFFFF) << 16) + _signed16(low.saved_word)
                recovered = (actual - original) & 0xFFFFFFFF
            elif kind == R_MIPS_26:
                if (live >> 26 != first.saved_word >> 26 or live >> 26 not in (2, 3)):
                    continue
                actual = ((address + 4) & 0xF0000000) | ((live & 0x3FFFFFF) << 2)
                addend = (first.saved_word & 0x3FFFFFF) << 2
                if addend & 0x8000000:
                    addend -= 0x10000000
                recovered = (actual - addend) & 0xFFFFFFFF
            else:
                recovered = (live - first.saved_word) & 0xFFFFFFFF
            # Evidence recovers the referenced symbol, not its section base.
            self._region(recovered)
            if symbol.shndx:
                recovered -= self.metadata.symbols[source].value
                self._region(recovered, self.metadata.sections[symbol.shndx].size)
                recovered += symbol.value
            values.add(self._region(recovered))
            if len(values) > 1:
                raise ResolutionError(f"conflicting evidence for {symbol.name!r}")
        if not values:
            raise ResolutionError(f"unresolved original symbol {symbol.name!r}")
        return values.pop()

    def resolve_bindings(self, names: Iterable[str], *, prefix="original_symbol_") -> dict[str, int]:
        """Return helper-linker externals, stripping only the requested prefix."""
        bindings = {}
        for name in names:
            if not prefix or not name.startswith(prefix):
                raise ResolutionError(f"not an original-symbol binding: {name!r}")
            bindings[name] = self.resolve(name[len(prefix):])
        return bindings
