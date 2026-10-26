"""Explicit entry points for reviewed SotC word patches; no automatic injection."""

from .patches import apply_patches, rollback

# Public game-build identity, not a credential. No title-only or wildcard match.
SOTC_UUID = "C19A374E"


def apply_reviewed_plan(client, patches, *, code_ranges):
    """Caller supplies reviewed expected words and explicit safe code ranges."""
    return apply_patches(
        client, patches, expected_uuid=SOTC_UUID, code_ranges=code_ranges
    )


def rollback_reviewed_plan(client, receipt, *, code_ranges):
    return rollback(client, receipt, expected_uuid=SOTC_UUID, code_ranges=code_ranges)
