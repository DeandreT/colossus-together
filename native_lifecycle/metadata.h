/* Read-only, bounded subset of game/metadata.py, not an automatic scanner.
 *
 * Event-source contract: at a serialized quiescent boundary, supply a complete
 * candidate list from independently verified layout-group enumeration (including
 * deletion filtering). Capture each definition/family from verified construction;
 * pointer plausibility or object+0x11d0 is NOT definition provenance. Register
 * canonical and candidate allocation IDs before discovery and deliver final-free
 * events before address reuse. lifetime must recognize the exact ID, not just
 * pointer presence. No callbacks may yield or mutate this input or its snapshot.
 * read32 returns a decoded little-endian word; read_bytes fills the entire
 * requested range. Both return nonzero only on success. There is no direct
 * memory fallback. Inputs/output and callback storage must not alias.
 *
 * Re-enumerate and re-capture after canonical replacement/resource unload. Supply
 * the current nonzero resource generation for every candidate; discard results
 * when it changes. This attestation is not an unload hook or a resource registry.
 * Neither an address check nor matching resource names proves provenance.
 *
 * Only physical EE addresses are accepted (no virtual alias masking). The fixed
 * layout is the source-guarded Python layout: display at object+0x90+0x144,
 * GP at +0x150, alias skeleton at +0x90+0x194. Unknown valid model basenames are
 * ignored; malformed records, missing provenance, stale identities and duplicate
 * supported parts reject the entire snapshot. No first-match selection occurs.
 *
 * Output has three records in BODY/MANTLE/HEAD order and private copies of the
 * 64-byte GP only. It is unchanged on failure. No parameter-stack capture, flags,
 * partition/script discovery, allocation, writes, I/O or constructors occur.
 * The later constructor adapter must build owned parameters/flags and private GP
 * storage, revalidate resource/lifetime readiness, and never write through P1 GP.
 * This does not qualify live execution or implement whole automatic recreation.
 *
 * EE compile: -std=c11 -O2 -ffreestanding -fno-builtin -mabi=eabi -mlong32
 * -mgp64 -march=r5900 -G0 -mno-abicalls -fno-pic -c metadata.c
 */
#ifndef COOP_NATIVE_LIFECYCLE_METADATA_H
#define COOP_NATIVE_LIFECYCLE_METADATA_H
#include "lifecycle.h"

#define NL_METADATA_MAX_CANDIDATES 256u
#define NL_METADATA_NAME_BYTES 128u
#define NL_METADATA_GP_BYTES 64u
typedef enum { NL_META_BODY, NL_META_MANTLE, NL_META_HEAD } NLMetadataPart;
typedef enum {
    NL_META_OK, NL_META_INVALID, NL_META_READ_FAILED, NL_META_STALE,
    NL_META_MALFORMED, NL_META_MISSING, NL_META_AMBIGUOUS
} NLMetadataResult;
typedef struct {
    NLObject owned;
    NLAddress definition;
    NLVisualKind family;
    uint32_t definition_verified, resource_generation;
} NLVerifiedCandidate;
typedef struct {
    void *user;
    int (*read32)(void *, NLAddress, uint32_t *);
    int (*read_bytes)(void *, NLAddress, uint8_t *, uint32_t);
    NLLifetime (*lifetime)(void *, NLAddress, uint32_t);
    NLObject canonical_p1;
    uint32_t quiescent, resource_generation, undefined_symbol;
    const NLVerifiedCandidate *candidates;
    uint32_t candidate_count;
} NLMetadataInput;
typedef struct {
    NLObject owned;
    NLAddress definition, model_resource;
    NLVisualKind family;
    NLMetadataPart part;
    uint32_t level; /* zero means no _LV suffix; otherwise 1,4,8,12,16 */
    uint8_t private_gp_bytes[NL_METADATA_GP_BYTES];
    char model_name[NL_METADATA_NAME_BYTES];
} NLMetadataVisual;
typedef struct {
    NLObject canonical_p1;
    uint32_t resource_generation;
    NLMetadataVisual visuals[NL_VISUALS];
} NLMetadata;
NLMetadataResult nl_metadata_discover(const NLMetadataInput *, NLMetadata *);
#endif
