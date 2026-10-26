"""Synthetic interrupt boundaries for existing EE instruction interpreters.

Only kernel-reserved GPRs are poisoned. This tests interrupted application
instructions, not execution of a BIOS or the timing of a hardware interrupt.
"""


class InterruptModel:
    interrupt_at = None  # None: disabled; "all": every boundary; int: one boundary

    def boundary(self, instruction):
        if not hasattr(self, "boundaries"):
            self.boundaries = []
        index = len(self.boundaries)
        self.boundaries.append(instruction)
        if self.interrupt_at == "all" or self.interrupt_at == index:
            registers = self.r if hasattr(self, "r") else self.reg
            for reg in (26, 27):
                registers[reg] = ((0xDEAD0000 + index) << 96) | (0x70000000 + reg)

    def compared_registers(self):
        return (i for i in range(1, 32)
                if i not in (29, 31)
                and (self.interrupt_at is None or i not in (26, 27)))

    def assert_context(self, actual, expected):
        if self.interrupt_at is not None:
            actual = ([v for i, v in enumerate(actual[0]) if i not in (26, 27)],
                      *actual[1:])
            expected = ([v for i, v in enumerate(expected[0]) if i not in (26, 27)],
                        *expected[1:])
        assert actual == expected
