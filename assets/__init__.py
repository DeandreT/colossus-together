"""Read-only access to assets in a user-supplied disc image."""

from .iso import IsoEntry, IsoError, IsoImage

__all__ = ["IsoEntry", "IsoError", "IsoImage"]
