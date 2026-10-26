/* Project-authored game-thread actions; no game code or address map. */
#ifndef COOP_NATIVE_LIFECYCLE_H
#define COOP_NATIVE_LIFECYCLE_H
#include <stdint.h>

#define NL_MAX_CHILDREN 32u
#define NL_VISUALS 3u
#define NL_PENDING_DELETE 0x10000u
#define NL_PARAMETER_GP_OFFSET 0x20u

typedef uint32_t NLAddress;
typedef enum { NL_QUIESCENT, NL_READY, NL_BUILDING, NL_ACTIVE,
               NL_DRAINING, NL_WAIT_PARENT_FREE } NLPhase;
typedef enum { NL_OK, NL_REJECTED, NL_LATCHED, NL_BAD_MEMORY,
               NL_STALE, NL_CONSTRUCTOR_FAILED, NL_CALLBACK_FAILED } NLResult;
/* FREED means this exact lifetime ended, not merely that its address is absent.
 * An address occupied by another allocation without such evidence is MISMATCH. */
typedef enum { NL_MISMATCH, NL_LIVE, NL_FREED } NLLifetime;
typedef enum { NL_CHARACTER, NL_ALIAS } NLVisualKind;
typedef struct { NLAddress object; uint32_t allocation; } NLObject;
typedef struct {
    NLVisualKind kind;
    NLAddress definition, parameters, partition, script;
    NLObject owned;
    uint32_t attempted;
} NLVisual;
typedef struct NLContext NLContext;

/* Immutable after provisioning. Stock functions need approved module-GP thunks
 * if their GP differs from this payload. The alias signature has SEVEN words. */
typedef struct {
    void (*delete_lock)(NLAddress);
    void (*request_delete)(NLAddress);
    void (*delete_unlock)(NLAddress);
    NLAddress (*create_character)(NLAddress definition, NLAddress parameters);
    NLAddress (*create_alias)(NLAddress partition, NLAddress definition,
                            NLAddress parameters, NLAddress script,
                            NLAddress parent, uint32_t zero, uint32_t one);
    NLLifetime (*lifetime)(void *, NLAddress, uint32_t allocation);
    uint32_t (*new_allocation)(void *, NLAddress);
    int (*publish_actor)(void *, NLContext *);
    int (*unpublish_actor)(void *, NLContext *);
    int (*publish_view)(void *, NLContext *);
#ifdef NL_HOST_TEST
    /* Offline model only; production dereferences range-checked EE addresses. */
    int (*read32)(void *, NLAddress, uint32_t *);
    int (*write32)(void *, NLAddress, uint32_t);
#endif
} NLFunctions;

struct NLContext {
    NLFunctions fn;
    void *user;
    uint32_t generation, current_generation;
    NLPhase phase;
    NLResult error;
    uint32_t busy, withdrawn, held, parent_requested, teardown_needed;
    uint32_t allchild_final, pending_creations;
    uint32_t readiness, resource_barrier, canonical_p1_verified;
    uint32_t intrinsics_validated;
    NLObject canonical_p1, actor;
    NLAddress actor_definition, actor_parameters;
    /* Captured by the adapter BEFORE retirement, includes intrinsic children.
     * BUILDING retirement (failed or cancelled) merges visual ownership here.
     * No callback may mutate this list during an action. */
    NLObject children[NL_MAX_CHILDREN];
    uint32_t child_count;
    /* Verified byte offset of uint32 pending-delete flags within object header. */
    uint32_t header_flags_offset;
    NLVisual visuals[NL_VISUALS];
    /* Appended to preserve existing field offsets. Recovery keeps the original
     * construction error; an independent cleanup failure forbids releasing it. */
    NLResult cleanup_error;
    /* Historical name: marks BOTH failed and normally cancelled BUILDING
     * retirement. Kept in place for ABI compatibility; does not imply error. */
    uint32_t failed_build_retirement;
};

int nl_address_valid(NLAddress address, uint32_t bytes);
NLResult begin_retire(NLContext *);
/* Explicit recovery only: preserves error, keeps all ownership until native
 * final-free, and never retries uncertain cleanup calls. Host must consume the
 * retirement acknowledgement before reprovisioning/resetting either error. */
NLResult retire_failed_build(NLContext *);
/* Normal provisional-build cancellation, never error recovery. Requires
 * BUILDING, no error/cleanup_error, teardown_needed=1, withdrawn=1, matching
 * epoch and no pending creations. Merges owned visuals/intrinsics and uses the
 * same native parent hold/final-free protocol without injecting an error.
 * Ownership inventory must be complete before calling. */
NLResult cancel_build(NLContext *);
NLResult release_parent(NLContext *);
NLResult spawn_actor(NLContext *);
NLResult spawn_visual(NLContext *, uint32_t index);
NLResult commit_active(NLContext *);
#endif
