import pytest

from runtime.patches import PatchError, WordPatch
from runtime.runner import apply_reviewed_plan, rollback_reviewed_plan


class Memory:
    def __init__(self):
        self.words = {0x100: 1, 0x104: 2, 0x108: 3}
        self.writes = []
        self.state = 1
        self.identity = "c19a374e"
        self.fail_at = None

    def status(self):
        return self.state

    def uuid(self):
        return self.identity

    def read32(self, address):
        return self.words[address]

    def write32(self, address, value):
        self.writes.append((address, value))
        self.words[address] = value
        if address == self.fail_at:
            raise TimeoutError("reply lost after write")


RANGES = [(0x100, 0x10C)]
PLAN = [WordPatch(0x100, 1, 10), WordPatch(0x104, 2, 20), WordPatch(0x108, 3, 30)]


def apply(memory, plan=PLAN):
    return apply_reviewed_plan(memory, plan, code_ranges=RANGES)


@pytest.mark.parametrize("bad_address", [0x100, 0x104, 0x108])
def test_all_guards_preflight_no_writes(bad_address):
    m = Memory()
    m.words[bad_address] = 99
    with pytest.raises(PatchError) as error:
        apply(m)
    assert not m.writes and error.value.receipt.changes == ()


@pytest.mark.parametrize(
    "field,value", [("state", 0), ("state", 2), ("identity", "DEADBEEF")]
)
def test_context_gates(field, value):
    m = Memory()
    setattr(m, field, value)
    with pytest.raises(PatchError):
        apply(m)
    assert not m.writes


@pytest.mark.parametrize(
    "plan",
    [
        [WordPatch(0x10C, 0, 1)],
        [WordPatch(0x101, 1, 2)],
        [PLAN[0], PLAN[0]],
        [WordPatch(0x100, 1, 1)],
        [WordPatch(0x100, -1, 2)],
        [WordPatch(0x100, 1, 1 << 32)],
    ],
)
def test_plan_rejected_before_writes(plan):
    m = Memory()
    with pytest.raises(ValueError):
        apply(m, plan)
    assert not m.writes


def test_rollback_preserves_foreign_changes():
    m = Memory()
    receipt = apply(m)
    assert all(c.confirmed for c in receipt.changes)
    m.words[0x104] = 999
    result = rollback_reviewed_plan(m, receipt, code_ranges=RANGES)
    assert result.restored == (0x108, 0x100)
    assert result.skipped == (0x104,)
    assert m.words == {0x100: 1, 0x104: 999, 0x108: 3}


def test_partial_error_receipt_no_automatic_rollback():
    m = Memory()
    m.fail_at = 0x104
    with pytest.raises(PatchError) as error:
        apply(m)
    receipt = error.value.receipt
    assert [c.confirmed for c in receipt.changes] == [True, False]
    assert m.writes == [(0x100, 10), (0x104, 20)]
    m.fail_at = None
    result = rollback_reviewed_plan(m, receipt, code_ranges=RANGES)
    assert result.restored == (0x104, 0x100)


def test_context_rechecked_before_each_write():
    m = Memory()
    original = m.write32

    def write(address, value):
        original(address, value)
        m.state = 0

    m.write32 = write
    with pytest.raises(PatchError) as error:
        apply(m)
    assert len(m.writes) == 1 and len(error.value.receipt.changes) == 1


def test_changed_word_after_preflight():
    m = Memory()
    original = m.read32
    reads = 0

    def read(address):
        nonlocal reads
        reads += 1
        if reads == 4:
            m.words[address] = 500
        return original(address)

    m.read32 = read
    with pytest.raises(PatchError):
        apply(m)
    assert not m.writes


def test_rollback_error_retains_uncertain_attempt():
    m = Memory()
    receipt = apply(m)
    m.fail_at = 0x104
    with pytest.raises(PatchError) as error:
        rollback_reviewed_plan(m, receipt, code_ranges=RANGES)
    assert error.value.receipt.restored == (0x108,)
    assert error.value.receipt.uncertain == (0x104,)
    assert m.words[0x100] == 10  # no further writes after failure


def test_rollback_requires_original_context_and_whitelist():
    m = Memory()
    receipt = apply(m)
    original_count = len(m.writes)
    m.identity = "DEADBEEF"
    with pytest.raises(PatchError):
        rollback_reviewed_plan(m, receipt, code_ranges=RANGES)
    with pytest.raises(ValueError):
        rollback_reviewed_plan(m, receipt, code_ranges=[(0x100, 0x104)])
    assert len(m.writes) == original_count
