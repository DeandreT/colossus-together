import struct

import pytest

from game.render_packets import split_display_copy


def test_two_distinct_render_target_reads_compose_one_display():
    packet = split_display_copy(width=512, height=448, source_fbp=224)
    assert len(packet) == 160
    assert struct.unpack_from("<4I", packet) == (0x70000009, 0, 0, 0)
    assert struct.unpack_from("<QQ", packet, 16) == (0x1000000000008008, 0xE)
    writes = [struct.unpack_from("<QQ", packet, p) for p in range(32, 160, 16)]
    assert [register for _, register in writes] == [0x50, 0x51, 0x52, 0x53] * 2
    for view in range(2):
        bitblt, position, size, direction = [
            v for v, _ in writes[view * 4 : view * 4 + 4]
        ]
        assert bitblt & 0x3FFF == (224 + view * 56) * 32
        assert (bitblt >> 16) & 0x3F == 8
        assert (bitblt >> 32) & 0x3FFF == 0
        assert (bitblt >> 48) & 0x3F == 8
        assert position == (view * 224) << 48
        assert size == (224 << 32) | 512
        assert direction == 2


@pytest.mark.parametrize(
    "changes",
    [
        {"width": 511},
        {"height": 450},
        {"source_fbp": 500},
        {"source_fbp": -1},
        {"destination_fbp": 224},
        {"width": True},
        {"height": 448.0},
    ],
)
def test_invalid_or_overlapping_surfaces_are_rejected(changes):
    args = {"width": 512, "height": 448, "source_fbp": 224}
    args.update(changes)
    with pytest.raises(ValueError):
        split_display_copy(**args)
