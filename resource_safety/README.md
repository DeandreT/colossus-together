# Read-only resource release classification

Build a generation-bound closure with `rs_build_protected`, extend it with
constructor-proven dependencies such as the equipped weapon through
`rs_extend_protected`, then classify the actual queued request with
`rs_classify`. Workspaces and memory readers belong to the caller; the module
does not allocate, alter reference counts, submit requests or access an emulator.

- `RS_SAFE` permits only the examined request under the validated snapshot.
- `RS_RETIRE` means the release could destroy a protected dependency.
- `RS_UNKNOWN` means the proof is incomplete or stale, not permission to proceed.

The caller must validate code and descriptor provenance, freeze relevant
resource mutations, cover every borrowed dependency, and establish the graphics
boundary before allowing a release. Rebuild and reclassify if identities,
reference counts, language or request contents change. Extending a closure after
failure requires rebuilding it; partial output is not usable.

Segment and texture releases follow the native dependency flags and decrement
multiplicity. Protection traverses resident owners; native release traversal
does not. Each native release transaction has a 1,024-nonresident-owner limit,
even when a larger workspace holds several texture transactions.

Asynchronous map-block deletion (operation 3) is deliberately `RS_UNKNOWN`.
Its module/layout destruction and streaming-interest requirements need separate
proof. A disjoint sheet dependency graph alone does not certify that path.
