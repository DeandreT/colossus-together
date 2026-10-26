/* Offline, read-only NTSC-U sheet-release classifier. No game calls or writes.
 * Source contract: MANAGER E2CC8/E2A40/E2568/E26D8 and E2FD8.
 * This proves declared sheet dependencies only, NOT all borrowed pointers or
 * asynchronous map-block (op 3) deletion. The caller must keep the sheet worker
 * paused and the main thread at a verified boundary for the entire transaction.
 */
#ifndef SOTC_RESOURCE_SAFETY_H
#define SOTC_RESOURCE_SAFETY_H
#include <stdint.h>

typedef enum { RS_UNKNOWN = 0, RS_SAFE = 1, RS_RETIRE = 2 } RSResult;
typedef enum { RS_CHARACTER = 0, RS_ALIAS = 1, RS_SCRIPT_LAYOUT = 2 } RSFamily;
#define RS_MAX_EXTRA_DEFINITIONS 32u
typedef int (*RSRead32)(void *, uint32_t, uint32_t *);
typedef int (*RSRead8)(void *, uint32_t, uint8_t *);

/* Both fields are source/loader-proven, not inferred from neighboring memory.
 * object is the type-4 header object; descriptor == *(object+0x38).
 */
typedef struct { uint32_t object, descriptor; } RSHeader;
typedef struct {
    void *user;
    RSRead32 read32;
    RSRead8 read8;
    const RSHeader *headers;
    uint32_t header_count, list_limit;
    uint32_t generation, generation_address;
    uint32_t quiescent, source_guards_verified;
    uint32_t language, language_address, undefined_symbol;
    /* Exact verified SH_StageDataDEFAULT descriptor and counter allocation. */
    uint32_t stage_descriptor, segment_counters, segment_capacity;
    /* Verified sheetFs texture table: {uint32 count, uint32 object}, stride 8. */
    uint32_t texture_table, texture_capacity;
} RSConfig;

typedef struct {
    uint32_t address, family, generation, constructor_verified;
} RSDefinition;
typedef struct {
    RSDefinition proof;
    uint32_t definition_owner, model_owner, model, model_raw, model_header;
} RSExtraBinding;

typedef struct {
    uint32_t object, raw, header, descriptor, flags, object_flags;
    uint32_t header_raw, header_flags;
    uint32_t type, count, base, stride, reference_count, references;
    uint32_t next, reference_fingerprint, decrements, color;
} RSNode;
typedef struct { uint32_t node, next_reference; } RSFrame;
/* All storage belongs to caller. No allocation, recursion, or static scratch.
 * Protected capacity >=512; release capacity selectable up to 4096.
 * Frame capacity must be >= node capacity. Do not alias workspaces/storage.
 * Native release transactions are limited to 1024 unique nonresident owners:
 * op1 combines all roots, op5 has one texture, op6 restarts per texture.
 * Thus only op6's aggregate (or protection) may exceed 1024 nodes.
 * Protection follows eligible dependencies THROUGH resident owners too;
 * release excludes resident owners. No resident-dependency invariant is assumed.
 */
typedef struct {
    RSNode *nodes;
    RSFrame *frames;
    uint32_t capacity, frame_capacity, count;
    uint32_t generation, language, complete;
    uint32_t definition_owners[4], model_owners[4], definitions[4], models[4];
    uint32_t families[4], model_raw[4], model_headers[4];
    /* Appended: offsets of the original four-root workspace fields are stable.
     * sizeof(RSWorkspace) has grown; all callers must allocate the new size. */
    uint32_t extra_count;
    RSExtraBinding extras[RS_MAX_EXTRA_DEFINITIONS];
} RSWorkspace;

/* Exactly four constructor-proven definitions: main character plus body,
 * mantle and head, in any order. Identity/provenance is supplied by caller;
 * model names or address coincidence cannot manufacture constructor proof.
 * RS_SAFE here means the protected closure was built, not an unload verdict.
 */
RSResult rs_build_protected(const RSConfig *, const RSDefinition definitions[4],
                            RSWorkspace *protected_closure);
/* Append up to 32 TOTAL additional constructor-proven definitions, including
 * RS_SCRIPT_LAYOUT (model reference at definition+8; CHARACTER +0x14, ALIAS +4).
 * Requires a complete current closure. Duplicate addresses are rejected.
 * No owner pointers are accepted as proof: owners are resolved by verified
 * record membership. Success returns RS_SAFE; any failure sets complete=0
 * (partial output may remain) and requires rebuilding the four-root closure.
 * count=0 is a validated no-op; proofs may then be NULL. Rebuild clears extras.
 */
RSResult rs_extend_protected(const RSConfig *, const RSDefinition *proofs,
                             uint32_t count, RSWorkspace *protected_closure);
/* request is the original 0x30-byte queued request, still held by its worker.
 * SAFE permits only this request under this snapshot, not later requests.
 * A changed identity/counter since build requires rebuilding the closure.
 * source_guards_verified is the trusted adapter's assertion of actual loaded
 * code/loader/header-census verification, not verification performed here.
 */
RSResult rs_classify(const RSConfig *, uint32_t request,
                     const RSWorkspace *protected_closure, RSWorkspace *release);
#endif
