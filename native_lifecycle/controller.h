/* Authored, address-free game-thread orchestration. No hooks are installed here. */
#ifndef COOP_NATIVE_CONTROLLER_H
#define COOP_NATIVE_CONTROLLER_H
#include "bridge.h"

typedef struct NLController NLController;
typedef struct {
    uint32_t desired_active, gameplay_ready, resource_barrier;
    NLObject canonical_p1;
    /* Monotonic completed-render counter, not a frame-start counter. No wrap.
     * The caller is already at a game-thread safe point. */
    uint64_t completed_render;
    uint32_t team_death, death_epoch, p1_transition;
} NLControllerInput;
typedef struct {
    void *user;
    /* Explicit fresh provisioning, including new epoch, verified canonical
     * definitions and PRIVATE parameter/GP buffers. Set ctx to NL_READY, bind
     * bridge functions and advance bridge generation. Never reuse old inputs
     * without validation. May clear old errors ONLY after retirement ack.
     * Failure must leave no allocated objects; it latches controller fault. */
    int (*prepare_spawn)(void *, NLController *, NLContext *);
    /* Remove P2 from rendering and restore the external activation bypass.
     * Must be synchronous; success means no future render can select P2.
     * Failure is uncertain and is never retried automatically. */
    int (*withdraw_view)(void *, NLContext *);
    /* 0 = pending, 1 = validated, -1 = failed with COMPLETE ownership,
     * -2 = unsafe/incomplete inventory (retain allocations for recovery).
     * Populate ALL discovered owned
     * intrinsic identities, registering newly discovered allocations in bridge.
     * On -1, the ownership inventory must still be complete; use 0 while
     * discovery is incomplete, even during failed-build cleanup. Called during
     * a failed constructor batch too, but only for a known-live parent.
     * Visuals are merged here.
     * No scheduler yield or mutation of actor/epoch/canonical is permitted. */
    int (*validate_intrinsics)(void *, NLContext *);
    /* Called only after exact final-free of every owned identity. Return true
     * only when ALL external users acknowledge these IDs. False means pending,
     * not failure. Controller then removes ONLY these owned tombstones. */
    int (*on_retired)(void *, const NLContext *);
    /* Called at most once per monotonic death epoch, after retirement ack.
     * Must request the approved team restart, NOT independently call GameOver.
     * Never called if the input says P1 is already transitioning. Uncertain
     * failure is latched, not retried. Keep each death epoch asserted until
     * serviced; a new epoch must not replace an outstanding one. */
    int (*request_team_restart)(void *, uint32_t death_epoch);
} NLControllerFunctions;
struct NLController {
    NLContext *ctx;
    NLBridge *bridge;
    NLControllerFunctions fn;
    NLControllerInput input;
    NLResult fault;
    uint32_t initialized, busy, retirement_ack, retiring, view_exposed;
    uint32_t withdrawal_attempted, withdrawn;
    /* 0 pending inventory, 1 complete, 2 unsafe/quarantined (never auto-retry). */
    uint32_t cleanup_discovered;
    uint64_t withdrawn_render;
    uint32_t last_generation, pending_death, handled_death;
};
/* Initialize once around an empty QUIESCENT context and initialized bridge. */
int nl_controller_init(NLController *, NLContext *, NLBridge *,
                       const NLControllerFunctions *);
/* Bootstrap an already qualified ACTIVE transaction without reinitializing it.
 * published_actor is the trusted bootstrap hook's attestation that both views
 * are configured and the P2 view currently publishes this EXACT actor address.
 * No game callbacks, memory/registry I/O, phase changes or ownership changes.
 * LIVE evidence comes from the serialized bridge allocation table. Caller must
 * have verified actual lifetimes before calling. On failure ALL inputs and the
 * output are unchanged. Output must be uninitialized (initialized == 0). */
int nl_controller_adopt_active(NLController *controller, NLContext *ctx,
                              NLBridge *bridge,
                              const NLControllerFunctions *functions,
                              NLAddress published_actor);
/* Normal stop signals cancel provisional BUILDING work without latching an
 * error. Once cancellation starts it drains even if the signal clears; after
 * final-free and owner ack, prepare_spawn provisions the next fresh generation.
 * Constructor/metadata failures still require explicit recovery/reprepare. */
NLResult nl_controller_pump(NLController *, const NLControllerInput *);
/* Explicit authorization to reprepare after fault AND successful retirement
 * acknowledgement. Does not clear ctx errors or provision anything itself. */
int nl_controller_reprepare(NLController *);
int nl_controller_resource_permit(const NLController *);
/* Missing integration: verified signal hooks, native final-free notifications,
 * intrinsic discovery, render withdrawal/bypass restoration and restart adapter.
 * All calls/callbacks are serial on the game thread; callbacks cannot yield.
 * No network commands, guessed readiness, stock offsets, or game flow code. */
#endif
