# Read-only ISO assets

`IsoImage` reads only an explicit, user-supplied regular file. It never mounts,
executes, modifies or extracts the image, invokes external tools, or searches for
game files. No game assets are included here.

```python
from assets import IsoImage

with IsoImage(user_iso_path) as image:
    core = image.locate("GAMECORE.XFF")  # extent in sectors, size in bytes
    data = image.read_file("GAMECORE.XFF")  # default maximum: 16 MiB
    for chunk in image.iter_file("NICO.DAT"):
        consume(chunk)  # caller-owned processing, default chunks: 1 MiB
```

Supported format: ISO9660 version 1 primary descriptor at sector 16, 2048-byte
blocks, single volume, contiguous extents and ASCII relative paths. Matching is
case-insensitive and removes a final `;1`. Joliet-only images, multi-extent files,
interleaving, extended attributes and record flags beyond hidden/directory are
rejected. Supplementary descriptors and system-use extensions are not used.

All both-endian fields consumed by the reader must agree; extents must fit the
declared volume and source file. Directories are limited to 1 MiB and 4096 records
(including dot records); paths to 16 components. Malformed records, sector
crossings, nonzero padding, duplicate normalized names and ancestor directory
cycles fail closed. Directories are checked lazily along the requested path, not
by scanning the entire image. Streaming chunks cannot exceed 16 MiB; whole-file
reads require an explicit larger `max_bytes` to exceed the default. Keep the
source image unchanged for the lifetime of the context.
