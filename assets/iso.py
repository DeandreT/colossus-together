"""Bounded, standard-library ISO9660 reader; no mounting or extraction."""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Self

SECTOR_SIZE = 2048
MAX_DIRECTORY_BYTES = 1024 * 1024
MAX_DIRECTORY_ENTRIES = 4096
MAX_PATH_DEPTH = 16
MAX_READ_BYTES = 16 * 1024 * 1024
DEFAULT_CHUNK_BYTES = 1024 * 1024


class IsoError(ValueError):
    """The image or requested path is outside the supported ISO9660 subset."""


@dataclass(frozen=True)
class IsoEntry:
    """An extent in 2048-byte sectors and its exact byte size."""

    extent: int
    size: int
    is_directory: bool

    @property
    def offset(self) -> int:
        """Absolute byte offset in the source image."""
        return self.extent * SECTOR_SIZE


def _both(data: bytes, offset: int, width: int, field: str) -> int:
    little = int.from_bytes(data[offset : offset + width], "little")
    big = int.from_bytes(data[offset + width : offset + 2 * width], "big")
    if little != big:
        raise IsoError(f"Conflicting both-endian {field}")
    return little


def _name(value: str) -> str:
    if not value or not value.isascii() or any(c in value for c in "/\\\x00"):
        raise IsoError("Names must be nonempty ASCII without path separators or NUL")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise IsoError("Control characters are not supported in ISO names")
    result = value.upper().removesuffix(";1")
    if not result or result in (".", "..") or ":" in result:
        raise IsoError("Path traversal and drive-qualified names are not allowed")
    return result


class IsoImage:
    """Open an explicit regular-file path read-only using a context manager.

    ``locate`` returns an IsoEntry, with a sector extent and byte size.
    Paths are relative, slash-separated ASCII ISO names (case insensitive).
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self._file: BinaryIO | None = None
        self._lock = threading.Lock()
        self._image_size = 0
        self._volume_size = 0
        self._root: IsoEntry | None = None

    def __enter__(self) -> Self:
        if self._file is not None:
            raise IsoError("ISO image is already open")
        # Nonblocking prevents opening a FIFO from hanging before fstat rejects it.
        fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise IsoError("ISO source must be a regular file")
            # Avoid cached bytes masking a source that was truncated after open.
            self._file = os.fdopen(fd, "rb", buffering=0)
            fd = -1
            self._image_size = info.st_size
            self._volume_size = self._image_size
            self._load_primary()
        except BaseException:
            self.close()
            raise
        finally:
            if fd != -1:
                os.close(fd)
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
        self._file = None
        self._root = None

    def _read(self, offset: int, size: int) -> bytes:
        if self._file is None:
            raise IsoError("Use IsoImage inside a with statement")
        if offset < 0 or size < 0 or offset + size > self._volume_size:
            raise IsoError("Read lies outside the image or declared volume bounds")
        with self._lock:
            self._file.seek(offset)
            result = self._file.read(size)
        if len(result) != size:
            raise IsoError("Truncated ISO image during read")
        return result

    def _load_primary(self) -> None:
        descriptor = self._read(16 * SECTOR_SIZE, SECTOR_SIZE)
        if descriptor[1:6] != b"CD001" or descriptor[6] != 1:
            raise IsoError(
                "Expected an ISO9660 CD001 version 1 descriptor at sector 16"
            )
        if descriptor[0] != 1:
            raise IsoError(
                "A primary volume descriptor is required at sector 16; Joliet-only images are unsupported"
            )
        blocks = _both(descriptor, 80, 4, "volume block count")
        block_size = _both(descriptor, 128, 2, "logical block size")
        if block_size != SECTOR_SIZE:
            raise IsoError("Only 2048-byte ISO9660 logical blocks are supported")
        if _both(descriptor, 120, 2, "volume set size") != 1:
            raise IsoError("Multi-volume images are unsupported")
        if _both(descriptor, 124, 2, "volume sequence") != 1:
            raise IsoError("Only volume sequence 1 is supported")
        if blocks < 17 or blocks * SECTOR_SIZE > self._image_size:
            raise IsoError(
                "Declared volume bounds exceed the image or exclude the primary descriptor"
            )
        self._volume_size = blocks * SECTOR_SIZE
        length = descriptor[156]
        if length < 34 or 156 + length > SECTOR_SIZE:
            raise IsoError("Invalid primary root record length")
        root, name = self._record(descriptor[156 : 156 + length])
        if name != b"\x00" or not root.is_directory:
            raise IsoError("Primary root record must describe the root directory")
        self._root = root

    def _record(self, data: bytes) -> tuple[IsoEntry, bytes]:
        if len(data) < 34 or data[0] != len(data):
            raise IsoError("Invalid directory record length")
        name_length = data[32]
        minimum = 33 + name_length + (1 if name_length % 2 == 0 else 0)
        if not name_length or len(data) < minimum:
            raise IsoError("Directory record is too short for its filename")
        if name_length % 2 == 0 and data[33 + name_length] != 0:
            raise IsoError("Invalid directory filename padding")
        extent = _both(data, 2, 4, "directory extent")
        size = _both(data, 10, 4, "directory data length")
        if _both(data, 28, 2, "directory volume sequence") != 1:
            raise IsoError("Multi-volume directory records are unsupported")
        if data[1]:
            raise IsoError("Extended-attribute (xattr) extents are unsupported")
        if data[25] & 0x80:
            raise IsoError("Multi-extent files are unsupported")
        if data[26] or data[27]:
            raise IsoError("Interleaved files are unsupported")
        if data[25] & ~0x03:
            raise IsoError(
                "Unsupported directory record flags (including xattr/record-format flags)"
            )
        entry = IsoEntry(extent, size, bool(data[25] & 2))
        if entry.offset >= self._volume_size or entry.offset + size > self._volume_size:
            raise IsoError("Directory extent lies outside the declared volume bounds")
        if entry.is_directory and (not size or size > MAX_DIRECTORY_BYTES):
            raise IsoError("Directory size must be between 1 byte and the 1 MiB limit")
        return entry, data[33 : 33 + name_length]

    def _directory(
        self, directory: IsoEntry, ancestors: set[int]
    ) -> dict[str, IsoEntry]:
        entries: dict[str, IsoEntry] = {}
        count = 0
        for offset in range(0, directory.size, SECTOR_SIZE):
            sector = self._read(
                directory.offset + offset, min(SECTOR_SIZE, directory.size - offset)
            )
            position = 0
            while position < len(sector):
                length = sector[position]
                if not length:
                    if any(sector[position:]):
                        raise IsoError("Nonzero data after directory sector padding")
                    break
                if position + length > len(sector):
                    raise IsoError(
                        "Directory record crosses a sector or directory boundary"
                    )
                count += 1
                if count > MAX_DIRECTORY_ENTRIES:
                    raise IsoError("Directory exceeds the 4096-entry limit")
                entry, raw_name = self._record(sector[position : position + length])
                position += length
                if raw_name in (b"\x00", b"\x01"):
                    if not entry.is_directory:
                        raise IsoError(
                            "Dot directory records must describe directories"
                        )
                    continue
                try:
                    name = _name(raw_name.decode("ascii"))
                except UnicodeDecodeError as exc:
                    raise IsoError(
                        "Non-ASCII ISO names are unsupported; Joliet is not used"
                    ) from exc
                if name in entries:
                    raise IsoError(f"Ambiguous duplicate ISO name: {name}")
                if entry.is_directory and entry.extent in ancestors:
                    raise IsoError("Directory cycle detected")
                entries[name] = entry
        return entries

    def locate(self, path: str) -> IsoEntry:
        """Find a file or directory without reading file payloads."""
        if self._root is None:
            raise IsoError("Use IsoImage inside a with statement")
        if not isinstance(path, str):
            raise IsoError("ISO paths must be strings")
        parts = path.split("/")
        if len(parts) > MAX_PATH_DEPTH:
            raise IsoError("ISO paths exceed the 16-component depth limit")
        names = [_name(part) for part in parts]
        current = self._root
        ancestors = {current.extent}
        for name in names:
            if not current.is_directory:
                raise IsoError("Cannot traverse through a file")
            entries = self._directory(current, ancestors)
            if name not in entries:
                raise FileNotFoundError(f"ISO path not found: {path}")
            current = entries[name]
            if current.is_directory:
                ancestors.add(current.extent)
        return current

    def _file_entry(self, path: str) -> IsoEntry:
        entry = self.locate(path)
        if entry.is_directory:
            raise IsoError("Requested ISO path is a directory, not a file")
        return entry

    def read_file(self, path: str, max_bytes: int = MAX_READ_BYTES) -> bytes:
        """Read a file only if its entire size fits the caller's byte limit."""
        if type(max_bytes) is not int or max_bytes < 0:
            raise IsoError("max_bytes must be a nonnegative integer")
        entry = self._file_entry(path)
        if entry.size > max_bytes:
            raise IsoError(
                "File exceeds max_bytes; use iter_file for bounded streaming"
            )
        return self._read(entry.offset, entry.size)

    def iter_file(
        self, path: str, chunk_size: int = DEFAULT_CHUNK_BYTES
    ) -> Iterator[bytes]:
        """Stream a file in chunks of 1 byte to 16 MiB, defaulting to 1 MiB."""
        if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_READ_BYTES:
            raise IsoError("chunk_size must be an integer between 1 byte and 16 MiB")
        entry = self._file_entry(path)
        for offset in range(0, entry.size, chunk_size):
            yield self._read(
                entry.offset + offset, min(chunk_size, entry.size - offset)
            )
