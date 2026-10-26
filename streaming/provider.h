#ifndef SP_PROVIDER_H
#define SP_PROVIDER_H

#include "planner.h"
#include <stddef.h>
#include <stdint.h>

#define SP_RECT_CAP 512u
#define SP_EE_END 0x02000000u
#if defined(__GNUC__)
#define SP_ALIGN __attribute__((aligned(16)))
#else
#error "Provider requires a compiler supporting explicit 16-byte alignment"
#endif

typedef struct {
    uint32_t actor, generation, active;
} sp_actor_ref;
typedef struct {
    uint32_t coords, count, min_x, min_z, width, height;
    uint32_t rounded_x, rounded_z, containing_x, containing_z;
} sp_batch_args;
typedef struct { uint32_t word[4]; } sp_native_coord;
typedef enum {
    SP_OK = 0, SP_CONFIG, SP_THREAD, SP_EXECUTION, SP_REENTRY, SP_READ, SP_MAP,
    SP_ACTOR, SP_GEOMETRY, SP_GENERATION, SP_CAPACITY, SP_POLICY,
    SP_BATCH, SP_NO_ITERATION, SP_RECORD
} sp_fault;

/* Resolver returns 1 for a verified snapshot (active is exactly 0/1), 0 for
 * failure. Active means the authoritative registry's ACTIVE phase, with a
 * nonzero verified generation. Actor/phase/generation changes require an
 * installer-owned quiescent reinitialization, not silent acceptance next frame.
 * No fixed actor address.
 * All native function pointers below are startup-attested, GP-correct entries
 * or thunks. Native getters are G+1EA58 and G+245E0; policy is native.py's
 * stream_policy; original_enable includes the G+1EF58 state prefix. */
typedef struct {
    uint32_t stream_state, gc_global, width, height, owner_thread;
    /* Exact stream ISYS object returned by K+1D850 isysGetThisSubThread.
     * Keep owner_thread too: the token is a scheduler global, not OS TLS. */
    uint32_t owner_execution;
    /* max_requests bounds desired cells including loaded ones, not resource
     * bytes or the native batcher's eventual request count. */
    uint32_t max_candidates, max_requests;
    void *user;
    int (*read)(void *, uint32_t, void *, uint32_t); /* NULL: checked EE reader */
    int (*resolve)(void *, uint32_t slot, sp_actor_ref *);
    uint32_t (*thread_id)(void *);
    /* Synchronous/read-only isysGetThisSubThread binding; never GetThreadId.
     * Must not yield while reading the scheduler token. */
    uint32_t (*execution_id)(void *);
    uint32_t (*get_layout)(uint32_t actor);
    void (*get_chip)(const float *, int32_t *, int32_t *);
    void (*get_chip_float)(const float *, float *, float *);
    int (*policy)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    uint32_t (*original_enable)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
    /* May suspend, then return on the same logical owner. Only the intended
     * native batching call is allowed; no unrelated recursive batching. */
    uint32_t (*batch)(const sp_batch_args *);
    /* NULL on EE: checked physical address of the provider-owned buffer.
     * Host fixtures may translate that exact buffer to a synthetic EE address. */
    uint32_t (*buffer_address)(void *, const void *, uint32_t);
    void (*on_fault)(void *, sp_fault); /* required: once, no reentry/yield */
} sp_config;

typedef struct {
    uint32_t table, width, height, size_x, size_z, origin_x, origin_z;
    int32_t near_radius, outer_band;
} sp_map_header;

typedef struct SP_ALIGN {
    sp_config config;
    sp_fault fault;
    uint32_t busy, scope_active, iteration, snapshot_valid, plan_valid, submitted;
    /* Nonzero, nonreused invocation nonce and iteration, valid only between
     * entry to config.batch and its normal return (including suspension). */
    uint32_t batch_sequence, active_batch, active_iteration;
    sp_actor_ref refs[2];
    float position[2][4] SP_ALIGN;
    sp_map_header geometry;
    su_actor actors[2];
    su_cell cells[SU_MAX_CELLS];
    su_rect rects[2][SP_RECT_CAP];
    su_coord p1_coords[SU_MAX_CELLS];
    su_workspace workspace;
    su_output plan;
    su_tile tile;
    sp_native_coord native_coords[256] SP_ALIGN;
} sp_provider;

/* Initialization/reset only at an installer-owned quiescent boundary. Faults
 * are sticky: keep_record holds ALL records until the parent quiesces/rebinds.
 * No silent native fallback on failed submit, no teleport or eviction on fault.
 * on_fault must notify the parent installer to quiesce/reconcile co-op before
 * reset. The sticky retention barrier is not a normal unlimited hold policy.
 * Already submitted native work is not rolled back by this module. This is not
 * a resource-byte budget, a full-world capacity claim or async op-3 proof.
 * Config/state must be disjoint and the state must have 16-byte alignment. */
int sp_init(sp_provider *, const sp_config *);
int sp_ee_read(void *, uint32_t, void *, uint32_t);
size_t sp_storage_size(void);
void sp_begin(void *);
void sp_submit(void *, const sp_batch_args *);
uint32_t sp_predicate(void *, uint32_t x, uint32_t z, uint32_t layer,
                      uint32_t rounded_x, uint32_t rounded_z,
                      uint32_t containing_x, uint32_t containing_z);
void sp_refresh_keep(void *);
uint32_t sp_keep_record(void *, uint32_t record);
void sp_fallback(void *);

#endif
