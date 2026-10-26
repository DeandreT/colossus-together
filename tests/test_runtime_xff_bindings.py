"""Synthetic original-XFF metadata and fake EE reads; no game assets needed."""

import struct
from types import SimpleNamespace

import pytest

from runtime.xff_bindings import (
    EE_SIZE, Metadata, OriginalXffResolver, Relocation, RelocationTable,
    ResolutionError, Section, Symbol,
)


TEXT = 0x100038  # actual text, not G
SECTIONS = (Section("", 0), Section(".text", 0x400),
            Section(".data", 0x200), Section(".bss", 0x200),
            Section(".rodata", 0x200))


class Memory:
    def __init__(self, words):
        self.words = words
        self.reads = []

    def __call__(self, address, size):
        self.reads.append((address, size))
        assert size == 4
        return struct.pack("<I", self.words[address])


def rel(offset, kind, saved, sym=1):
    return Relocation(offset, (sym << 8) | kind, saved)


def resolver(symbols, entries=(), words=None, *, tables=None, **kwargs):
    metadata = Metadata(SECTIONS, (Symbol("", 0, 0), *symbols),
                        tuple(tables) if tables is not None else
                        (RelocationTable(1, symbols[0].shndx == 0, tuple(entries)),))
    memory = Memory(words or {})
    return OriginalXffResolver(metadata, memory, TEXT, **kwargs), memory


def hilo(value, hi_opcode=0x3C080000, lo_opcode=0x25080000):
    return hi_opcode | (((value + 0x8000) >> 16) & 0xFFFF), lo_opcode | (value & 0xFFFF)


def test_text_symbols_and_helper_bindings_need_no_reads():
    r, m = resolver([Symbol("local_function", 0x28, 1)])
    assert r.resolve("local_function") == TEXT + 0x28
    assert r.resolve_bindings(["original_symbol_local_function"]) == {
        "original_symbol_local_function": TEXT + 0x28}
    assert not m.reads


@pytest.mark.parametrize("addend", [0x18004, -0x1234, 0x7FFF, 0x8000])
def test_hilo_carry_and_signed_low(addend):
    address = 0x128ABC
    hi, lo = hilo(addend)
    livehi, livelo = hilo(address + addend)
    r, m = resolver([Symbol("import", 0xDEADBEEF, 0)],
                    [rel(0, 5, hi), rel(4, 6, lo)],
                    {TEXT: livehi, TEXT + 4: livelo})
    assert r.resolve("import") == address
    assert len(m.reads) == 2


def test_multiple_hi_per_lo_each_has_own_original_addend():
    address = 0x120000
    h1, low = hilo(0x18004)
    h2, _ = hilo(0x28004)
    live1, live_low = hilo(address + 0x18004)
    live2, _ = hilo(address + 0x28004)
    r, m = resolver([Symbol("import", 0, 0)],
                    [rel(0, 5, h1), rel(4, 5, h2), rel(8, 6, low)],
                    {TEXT: live1, TEXT + 4: live2, TEXT + 8: live_low})
    assert r.resolve(1) == address
    assert len(m.reads) == 3


@pytest.mark.parametrize("section", [2, 3])
def test_section_base_and_named_local_no_double_addition(section):
    hi, lo = hilo(0x24)
    livehi, livelo = hilo(0x500000 + 0x40 + 0x24)
    syms = [Symbol("named_local", 0x40, section),
            Symbol("section_symbol", 0, section), Symbol("other", 0x80, section)]
    r, _ = resolver(syms, [rel(0, 5, hi), rel(4, 6, lo)],
                    {TEXT: livehi, TEXT + 4: livelo})
    assert r.resolve("named_local") == 0x500040
    assert r.resolve("section_symbol") == 0x500000
    assert r.resolve("other") == 0x500080


def test_section_symbol_evidence_resolves_named_local():
    high, low = hilo(0)
    lh, ll = hilo(0x500000)
    r, _ = resolver([Symbol(".bss", 0, 3), Symbol("local", 0x84, 3)],
                    [rel(0, 5, high), rel(4, 6, low)], {TEXT: lh, TEXT + 4: ll})
    assert r.resolve("local") == 0x500084


@pytest.mark.parametrize("addend", [0x44, -4])
def test_jump_original_addend(addend):
    saved = 0x0C000000 | ((addend >> 2) & 0x3FFFFFF)
    live = 0x0C000000 | ((0x230000 + addend) >> 2)
    r, _ = resolver([Symbol("callee", 99, 0)], [rel(0, 4, saved)], {TEXT: live})
    assert r.resolve("callee") == 0x230000


def test_mixed_modified_sites_and_opcode_changes_are_skipped():
    high, low = hilo(0)
    lh, ll = hilo(0x345678)
    entries = [rel(0, 4, 0x0C000000), rel(4, 4, 0x0C000000),
               rel(8, 5, high), rel(12, 6, low), rel(16, 5, high), rel(20, 6, low),
               rel(24, 5, high), rel(28, 6, low)]
    r, m = resolver([Symbol("import", 0, 0)], entries,
                    {TEXT + 8: lh ^ 0x10000, TEXT + 12: ll,
                     TEXT + 16: lh, TEXT + 20: ll ^ 0x10000,
                     TEXT + 24: lh, TEXT + 28: ll},
                    patched_sites={TEXT + 1}, patched_ranges=[(TEXT + 4, TEXT + 8)])
    assert r.resolve(1) == 0x345678
    assert all(a >= TEXT + 8 for a, _ in m.reads)


def test_patched_lo_skips_whole_pair():
    r, m = resolver([Symbol("import", 10, 0)],
                    [rel(0, 5, 0x3C080000), rel(4, 6, 0x25080000)],
                    patched_sites={TEXT + 4})
    with pytest.raises(ResolutionError, match="unresolved"):
        r.resolve(1)
    assert not m.reads


def test_conflict_and_unresolved_never_use_undefined_value():
    r, _ = resolver([Symbol("import", 0x1234, 0)],
                    [rel(0, 4, 0x0C000000), rel(4, 4, 0x0C000000)],
                    {TEXT: 0x0C040000, TEXT + 4: 0x0C080000})
    with pytest.raises(ResolutionError, match="conflicting"):
        r.resolve("import")
    r, _ = resolver([Symbol("import", 0x1234, 0)], [rel(0, 9, 0)])
    with pytest.raises(ResolutionError, match="unresolved"):
        r.resolve("import")
    with pytest.raises(ResolutionError, match="unknown"):
        r.resolve("missing")


def test_r32_requires_explicit_readable_immutable_placement():
    table = RelocationTable(4, True, (rel(0, 2, 0x80),))
    syms = [Symbol("import", 0, 0)]
    r, m = resolver(syms, tables=[table], words={0x600000: 0x500080})
    with pytest.raises(ResolutionError, match="unresolved"):
        r.resolve(1)
    assert not m.reads
    r, _ = resolver(syms, tables=[table], words={0x600000: 0x500080},
                    immutable_bases={4: 0x600000})
    assert r.resolve(1) == 0x500000


@pytest.mark.parametrize("address", [EE_SIZE, 0x80001000, 0xFFFFFFFF])
def test_outside_ee_evidence_rejected(address):
    hi, lo = hilo(address)
    r, _ = resolver([Symbol("import", 0, 0)],
                    [rel(0, 5, 0x3C080000), rel(4, 6, 0x25080000)],
                    {TEXT: hi, TEXT + 4: lo})
    with pytest.raises(ResolutionError, match="outside EE"):
        r.resolve(1)


def test_budget_does_not_accept_partial_consensus():
    r, m = resolver([Symbol("import", 0, 0)],
                    [rel(i * 4, 4, 0x0C000000) for i in range(3)],
                    {TEXT + i * 4: 0x0C040000 for i in range(3)}, max_candidates=2)
    with pytest.raises(ResolutionError, match="limit"):
        r.resolve(1)
    assert len(m.reads) == 2


def test_read_failures_and_short_reads_fail_closed():
    r, _ = resolver([Symbol("import", 0, 0)], [rel(0, 4, 0x0C000000)])
    with pytest.raises(ResolutionError, match="read failed"):
        r.resolve(1)
    r.read = lambda a, n: b"\0"
    with pytest.raises(ResolutionError, match="short"):
        r.resolve(1)


def test_pairing_is_per_symbol_and_unpaired_high_is_not_evidence():
    syms = [Symbol("first", 0, 0), Symbol("second", 0, 0)]
    entries = [rel(0, 5, 0x3C080000), rel(4, 6, 0x25080000, sym=2)]
    r, m = resolver(syms, entries)
    for name in ("first", "second"):
        with pytest.raises(ResolutionError, match="unresolved"):
            r.resolve(name)
    assert not m.reads


def test_duplicate_names_require_index_and_reads_are_not_cached_across_resolves():
    r, m = resolver([Symbol("duplicate", 0, 0), Symbol("duplicate", 0, 0)],
                    [rel(0, 4, 0x0C000000)], {TEXT: 0x0C040000})
    with pytest.raises(ResolutionError, match="ambiguous"):
        r.resolve("duplicate")
    assert r.resolve(1) == 0x100000
    m.words[TEXT] = 0x0C080000
    assert r.resolve(1) == 0x200000


def test_inferred_section_must_fit_entirely_in_ee():
    hi, lo = hilo(EE_SIZE - 0x100)
    r, _ = resolver([Symbol(".bss", 0, 3)],
                    [rel(0, 5, 0x3C080000), rel(4, 6, 0x25080000)],
                    {TEXT: hi, TEXT + 4: lo})
    with pytest.raises(ResolutionError, match="outside EE"):
        r.resolve(1)


def test_adapter_copies_duck_typed_module():
    module = SimpleNamespace(
        sections=[SimpleNamespace(size=s.size) for s in SECTIONS],
        section_name=lambda i: SECTIONS[i].name,
        num_symbols=2, symbol_name=lambda i: ("", "local")[i],
        symbol=lambda i: (0, 0x24 if i else 0, 0, 0, 0, 1 if i else 0),
        reltables=[SimpleNamespace(target=1, is_import=False,
                                   entries=[(0, 0x104, 0x0C000000, 17)])],
    )
    metadata = Metadata.from_xff2(module)
    assert metadata.symbols[1] == Symbol("local", 0x24, 1)
    assert metadata.reltables[0].entries[0].extra == 17


@pytest.mark.parametrize("kwargs", [{"text_base": EE_SIZE - 4},
                                    {"text_base": TEXT + 1},
                                    {"max_candidates": 0}])
def test_invalid_configuration(kwargs):
    metadata = Metadata(SECTIONS, (Symbol("", 0, 0),), ())
    options = {"text_base": TEXT, **kwargs}
    with pytest.raises(ResolutionError):
        OriginalXffResolver(metadata, Memory({}), **options)
