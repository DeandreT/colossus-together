/* Authored policy only. No game addresses, native function bodies or hooks. */
#ifndef COOP_HORSE_CALL_H
#define COOP_HORSE_CALL_H
#include "../native_lifecycle/lifecycle.h"

typedef enum { HC_OK, HC_INACTIVE, HC_REJECTED, HC_STALE,
               HC_PENDING, HC_FAULT } HCStatus;
typedef struct { NLObject object; uint32_t generation; } HCActor;
typedef struct { uint32_t words[4]; } HCToken;
typedef struct {
    uint32_t generation;
    NLObject p1, p2, agro;
} HCSnapshot;
typedef struct {
    uint32_t agro_mounted, p1_mounted, p2_mounted, reserved;
} HCRiding;
typedef enum { HC_PREPARE, HC_COMMIT } HCStage;
typedef enum { HC_KEEP_FLAG, HC_SET_FLAG, HC_CLEAR_FLAG } HCFlag;
typedef struct {
    HCStatus (*snapshot)(void *, HCSnapshot *);
    NLLifetime (*lifetime)(void *, NLObject);
    HCStatus (*riding)(void *, const HCSnapshot *, HCRiding *);
    /* Optional diagnostic read; select never reads/consumes native flags. */
    HCStatus (*flag_read)(void *, HCActor, uint32_t *);
    /* PREPARE validates everything, with NO visible effect; returns a token.
     * COMMIT atomically applies camera interest + requested flag write.
     * refresh means the supplied token already owns this actor's interest.
     * See README for failure/uncertainty and no-focus-token contracts. */
    HCStatus (*camera_begin)(void *, HCStage, HCActor, NLObject,
                             HCToken *, uint32_t refresh, HCFlag);
    /* Atomically ends only this token and optionally clears only this flag. */
    HCStatus (*camera_end)(void *, HCActor, NLObject, HCToken, HCFlag);
    uint32_t manage_flags;
} HCCallbacks;
typedef struct {
    HCActor actor;
    NLObject horse;
    HCToken token;
    uint32_t occupied;
    HCStatus status;
} HCInterest;
typedef struct {
    HCCallbacks fn;
    void *user;
    HCInterest interest[2];
    HCActor accepted;
    NLObject horse;
    uint32_t has_accepted;
    uint32_t busy;
} HCCtx;

/* Zero-initialize once, then install immutable callbacks/user. Game-thread only. */
HCStatus HCbegin(HCCtx *, HCActor);
HCStatus HCend(HCCtx *, HCActor);
/* Always initializes output to fallback, including errors/unrelated actors. */
HCStatus HCselect(HCCtx *, NLObject updating_actor, NLObject fallback_p1,
                  NLObject *output);
HCStatus HCread_flag(HCCtx *, HCActor, uint32_t *);
/* Revalidate/invalidate approach; does not silently discard camera ownership. */
HCStatus HCsync(HCCtx *);
HCStatus HCmount_accepted(HCCtx *);
HCStatus HCretire(HCCtx *, HCActor);
/* Explicit acknowledgement AFTER external safe cleanup proves token resolved.
 * Never retries an uncertain callback; exact actor+token match required. */
HCStatus HCresolved(HCCtx *, HCActor, HCToken);
#endif
