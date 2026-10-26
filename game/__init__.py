"""Read-only game metadata from an explicitly quiescent EE snapshot."""

from .metadata import (
    ConstructorFamily,
    MetadataError,
    Model,
    Part,
    Snapshot,
    VisualRecord,
    classify_name,
)

__all__ = [
    "ConstructorFamily",
    "MetadataError",
    "Model",
    "Part",
    "Snapshot",
    "VisualRecord",
    "classify_name",
]
