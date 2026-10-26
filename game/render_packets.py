"""Owned GS packets for composing two page-aligned local-origin views.

This builds data only. Callers own synchronization, allocation, cache coherence,
and submission. No emulator access or game-derived instructions are included.
"""

import struct

VRAM_BYTES = 4 * 1024 * 1024
PAGE_BYTES = 8192


def split_display_copy(*, width, height, source_fbp, destination_fbp=0):
    """Return a Path3 DMA END chain containing two CT32 local-to-local copies.

    FBP arguments use GS 8192-byte pages. The source views are contiguous in
    physical VRAM, but are deliberately referenced by separate base addresses:
    hardware renderer caches may represent them as separate render targets.
    Draw and display dimensions must match; this does not scale or blend.
    """
    values = (width, height, source_fbp, destination_fbp)
    if any(isinstance(value, bool) or not isinstance(value, int) for value in values):
        raise ValueError("dimensions and page addresses must be integers")
    if not 64 <= width <= 2048 or width % 64:
        raise ValueError("width must be a multiple of 64, at most 2048")
    if not 64 <= height <= 2048 or height % 64:
        raise ValueError("each half must contain complete CT32 page rows")
    size = width * height * 4
    for base in (source_fbp, destination_fbp):
        if base < 0 or base * PAGE_BYTES + size > VRAM_BYTES:
            raise ValueError("surface exceeds GS VRAM")
    source_range = (source_fbp * PAGE_BYTES, source_fbp * PAGE_BYTES + size)
    destination_range = (
        destination_fbp * PAGE_BYTES,
        destination_fbp * PAGE_BYTES + size,
    )
    if max(source_range[0], destination_range[0]) < min(
        source_range[1], destination_range[1]
    ):
        raise ValueError("source and display surfaces must not overlap")

    half = height // 2
    displacement = width * half * 4 // PAGE_BYTES
    # Nine GIF quadwords: tag plus eight A+D writes. DMA itself adds one tag.
    packet = bytearray(struct.pack("<4I", 0x70000009, 0, 0, 0))
    packet += struct.pack("<QQ", 0x1000000000008008, 0xE)
    for view in range(2):
        source_tbp = (source_fbp + view * displacement) * 32
        destination_tbp = destination_fbp * 32
        bitblt = (
            source_tbp
            | (width // 64) << 16
            | destination_tbp << 32
            | (width // 64) << 48
        )
        packet += struct.pack("<QQ", bitblt, 0x50)
        packet += struct.pack("<QQ", (view * half) << 48, 0x51)
        packet += struct.pack("<QQ", (half << 32) | width, 0x52)
        packet += struct.pack("<QQ", 2, 0x53)
    return bytes(packet)
