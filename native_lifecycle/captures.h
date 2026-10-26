/* Trusted constructor-event capture, not a scanner or a complete provider.
 *
 * A verified stock CHAR/ALIAS wrapper calls nl_captures_observe(cap, returned
 * object, definition_argument, family) AFTER the actual constructor returns.
 * The definition is the wrapper's original call argument, never guessed from
 * object fields. All callbacks run serialized on the game thread without yield.
 * read callbacks are mandatory, read-only, and cover the entire requested range.
 * No host-pointer bypass, allocation, P1 writes, or direct EE loads exist here.
 *
 * Category-2 CHAR events retain the definition and raw identity without bridge
 * registration. Only an exact live canonical lookup binds the canonical ID.
 * Other events are filtered by type/GP ownership and live NMO name BEFORE bridge
 * registration. Accepted visuals use bridge.generation for their lifetime ID;
 * resource_generation is separate and attested by the caller. Later metadata
 * discovery still validates definition resource provenance, part/family pairing
 * and alias skeletons; capture never silently hides a recognized wrong-family
 * visual from that validator.
 *
 * The primary final-free hook calls BOTH nl_captures_on_final_free and
 * nl_bridge_mark_final_free before address reuse. This module never calls the
 * latter itself. Tombstones are removed only by explicit purge at quiescence.
 * Strict resource advance is allowed only after the real destructive gate completes,
 * at quiescence with ALL retained records final-freed. Never clear/age out a live
 * record or dereference an old unloaded definition. Output excludes other
 * resource generations but preserves their records. No generation wraps.
 * Canonical replacement instead uses admit_epoch after verified bridge admission
 * and before new child constructors. It retains old live records and retags only
 * the exact newly admitted main. This is a canonical-player resource epoch, not
 * a per-texture unload counter. Metadata must still be freshly read before spawn.
 *
 * Bootstrap seed requires externally verified constructor-argument provenance
 * (verified_proof == 1), current generation and exactly the same validation.
 * It does not establish completeness, discover parameters, or qualify live use.
 * Optional canonical_group_first must be a verified read-only GetFirst adapter.
 * It is an additional check, not a replacement for bridge canonical admission.
 *
 * EE compile: same freestanding flags as metadata.c; link bridge + lifecycle.
 */
#ifndef COOP_NATIVE_LIFECYCLE_CAPTURES_H
#define COOP_NATIVE_LIFECYCLE_CAPTURES_H
#include "bridge.h"
#include "metadata.h"
#define NL_CAPTURES_CAPACITY 64u
typedef enum {
    NL_CAPTURE_OK, NL_CAPTURE_INVALID, NL_CAPTURE_READ_FAILED,
    NL_CAPTURE_MALFORMED, NL_CAPTURE_STALE, NL_CAPTURE_OVERFLOW
} NLCaptureFault;
typedef struct {
    NLVerifiedCandidate candidate;
    NLAddress raw_allocation;
    NLObject canonical_owner;
    NLLifetime state;
    uint32_t main_candidate;
} NLCaptureEntry;
typedef struct {
    NLBridge *bridge;
    void *user;
    int (*read32)(void *, NLAddress, uint32_t *);
    int (*read_bytes)(void *, NLAddress, uint8_t *, uint32_t);
    NLAddress (*canonical_group_first)(void *);
    uint32_t resource_generation, count;
    NLObject last_epoch_canonical;
    NLCaptureEntry entries[NL_CAPTURES_CAPACITY];
    NLCaptureFault fault;
} NLCaptures;
/* Zero-init once; callbacks/configuration remain immutable after use. */
int nl_captures_init(NLCaptures *, NLBridge *, void *,
                     int (*)(void *, NLAddress, uint32_t *),
                     int (*)(void *, NLAddress, uint8_t *, uint32_t),
                     NLAddress (*)(void *), uint32_t resource_generation);
void nl_captures_observe(void *, NLAddress object, NLAddress definition,
                         NLVisualKind family);
int nl_captures_seed(NLCaptures *, NLAddress, NLAddress, NLVisualKind,
                     uint32_t resource_generation, uint32_t verified_proof);
/* raw must be the exact saved object+0 identity, not an inferred address. */
NLAddress nl_captures_canonical_definition(NLCaptures *, NLAddress object,
                                          NLAddress raw);
/* On success writes count candidates (possibly zero). Failure leaves output
 * and count untouched. canonical must be the current exact bridge identity. */
int nl_captures_output_candidates(NLCaptures *, NLObject canonical,
                                  uint32_t resource_generation,
                                  NLVerifiedCandidate *, uint32_t capacity,
                                  uint32_t *count);
uint32_t nl_captures_on_final_free(NLCaptures *, NLAddress raw);
uint32_t nl_captures_purge_freed(NLCaptures *, uint32_t quiescent);
int nl_captures_advance_generation(NLCaptures *, uint32_t generation,
                                   uint32_t quiescent);
/* Returns 1 only after an exact live, changed canonical ID and its unique trusted
 * main record are verified. Requires quiescent == 1 and a strictly newer nonzero
 * epoch. The main must have been captured in the current epoch before admission.
 * Binds that main's ID/owner and new epoch; all other entries remain unchanged.
 * Reads only the new canonical header (through bridge lifetime), never any
 * definition. Returns 0 without changing capture state on any failed check.
 * Same-ID advances are rejected, including arbitrary texture unload events. */
int nl_captures_admit_epoch(NLCaptures *, uint32_t new_resource_generation,
                            NLObject newly_admitted, uint32_t quiescent);
#endif
