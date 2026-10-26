#include "call.h"

static int object_equal(NLObject a, NLObject b) {
    return a.object == b.object && a.allocation == b.allocation;
}
static int actor_equal(HCActor a, HCActor b) {
    return a.generation == b.generation && object_equal(a.object, b.object);
}
static int token_equal(HCToken a, HCToken b) {
    unsigned i;
    for (i = 0; i < 4; ++i) if (a.words[i] != b.words[i]) return 0;
    return 1;
}
static int valid(NLObject a) { return a.object && a.allocation; }
static int slot(const HCSnapshot *s, HCActor a) {
    if (!s->generation || a.generation != s->generation || !valid(a.object)) return -1;
    if (object_equal(a.object, s->p1)) return 0;
    if (object_equal(a.object, s->p2)) return 1;
    return -1;
}
static int live(HCCtx *c, NLObject a) {
    return valid(a) && c->fn.lifetime(c->user, a) == NL_LIVE;
}
static HCStatus enter(HCCtx *c) {
    if (!c) return HC_FAULT;
    if (c->busy) return HC_PENDING;
    if (!c->fn.snapshot || !c->fn.lifetime || !c->fn.riding) return HC_FAULT;
    c->busy = 1;
    return HC_OK;
}
static HCStatus leave(HCCtx *c, HCStatus s) { c->busy = 0; return s; }
static HCStatus world(HCCtx *c, HCSnapshot *s, HCRiding *r) {
    HCStatus status = c->fn.snapshot(c->user, s);
    if (status != HC_OK) {
        c->has_accepted = 0;
        return status;
    }
    if (!s->generation || !valid(s->p1) ||
        s->p1.object == s->p2.object || s->agro.object == s->p1.object ||
        (valid(s->p2) && s->agro.object == s->p2.object)) {
        c->has_accepted = 0;
        return HC_FAULT;
    }
    status = c->fn.riding(c->user, s, r);
    if (status != HC_OK) {
        c->has_accepted = 0;
        return status;
    }
    if (c->has_accepted &&
        (slot(s, c->accepted) < 0 || !live(c, c->accepted.object) ||
         !object_equal(c->horse, s->agro) || !live(c, c->horse) ||
         r->agro_mounted || r->p1_mounted || r->p2_mounted || r->reserved))
        c->has_accepted = 0;
    return HC_OK;
}
HCStatus HCsync(HCCtx *c) {
    HCSnapshot s = {0}; HCRiding r = {0};
    HCStatus status = enter(c);
    if (status != HC_OK) return status;
    status = world(c, &s, &r);
    return leave(c, status);
}
HCStatus HCbegin(HCCtx *c, HCActor a) {
    HCSnapshot s = {0}; HCRiding r = {0};
    HCToken token = {{0, 0, 0, 0}};
    HCToken prepared;
    HCInterest *i;
    HCFlag flag;
    int index;
    HCStatus status = enter(c);
    if (status != HC_OK) return status;
    status = world(c, &s, &r);
    if (status != HC_OK) return leave(c, status);
    index = slot(&s, a);
    if (index < 0 || !live(c, a.object) || !live(c, s.agro))
        return leave(c, HC_STALE);
    if (r.agro_mounted || r.p1_mounted || r.p2_mounted || r.reserved)
        return leave(c, HC_REJECTED);
    if (!c->fn.camera_begin || !c->fn.camera_end) return leave(c, HC_FAULT);
    i = &c->interest[index];
    if (i->occupied) {
        if (!actor_equal(i->actor, a) || !object_equal(i->horse, s.agro))
            return leave(c, HC_STALE);
        if (i->status != HC_OK) return leave(c, i->status);
        token = i->token;
    }
    flag = c->fn.manage_flags ? HC_SET_FLAG : HC_KEEP_FLAG;
    status = c->fn.camera_begin(c->user, HC_PREPARE, a, s.agro,
                                &token, i->occupied, flag);
    /* PREPARE is pure: any failure must leave existing ownership untouched. */
    if (status != HC_OK) return leave(c, status);
    if (i->occupied && !token_equal(token, i->token)) return leave(c, HC_FAULT);
    prepared = token;
    status = c->fn.camera_begin(c->user, HC_COMMIT, a, s.agro,
                                &token, i->occupied, flag);
    /* COMMIT cannot transfer ownership to a different token. Preserve the
     * prepared identity for external reconciliation on a contract violation. */
    if (!token_equal(token, prepared)) { token = prepared; status = HC_FAULT; }
    if (status == HC_OK || status == HC_PENDING || status == HC_FAULT) {
        i->actor = a; i->horse = s.agro; i->token = token;
        i->occupied = 1; i->status = status;
    }
    if (status == HC_OK) {
        c->accepted = a; c->horse = s.agro; c->has_accepted = 1;
    } else if (status == HC_PENDING || status == HC_FAULT) {
        /* Uncertain side effects cannot safely retain even an older target. */
        c->has_accepted = 0;
    }
    return leave(c, status);
}
HCStatus HCend(HCCtx *c, HCActor a) {
    HCSnapshot s = {0}; HCRiding r = {0};
    HCInterest *i = 0;
    HCStatus status = enter(c);
    unsigned n;
    if (status != HC_OK) return status;
    for (n = 0; n < 2; ++n)
        if (c->interest[n].occupied && actor_equal(c->interest[n].actor, a))
            i = &c->interest[n];
    if (!i) return leave(c, HC_INACTIVE);
    if (i->status != HC_OK) return leave(c, i->status);
    status = world(c, &s, &r);
    if (status != HC_OK) return leave(c, status);
    if (slot(&s, a) < 0 || !live(c, a.object)) {
        i->status = HC_STALE;
        return leave(c, HC_STALE);
    }
    if (!c->fn.camera_end) return leave(c, HC_FAULT);
    status = c->fn.camera_end(c->user, a, i->horse, i->token,
                              c->fn.manage_flags ? HC_CLEAR_FLAG : HC_KEEP_FLAG);
    if (status == HC_OK) i->occupied = 0;
    else if (status == HC_PENDING || status == HC_FAULT) i->status = status;
    return leave(c, status);
}
HCStatus HCselect(HCCtx *c, NLObject updating, NLObject fallback, NLObject *out) {
    HCSnapshot s = {0}; HCRiding r = {0};
    HCStatus status;
    if (!out) return HC_FAULT;
    *out = fallback;
    status = enter(c);
    if (status != HC_OK) return status;
    status = world(c, &s, &r);
    if (status == HC_OK) {
        if (c->has_accepted && object_equal(updating, s.agro))
            *out = c->accepted.object;
        else status = HC_INACTIVE;
    }
    return leave(c, status);
}
HCStatus HCread_flag(HCCtx *c, HCActor a, uint32_t *out) {
    HCSnapshot s = {0}; HCRiding r = {0};
    HCStatus status;
    if (!out) return HC_FAULT;
    status = enter(c);
    if (status != HC_OK) return status;
    status = world(c, &s, &r);
    if (status == HC_OK) {
        if (slot(&s, a) < 0 || !live(c, a.object)) status = HC_STALE;
        else if (!c->fn.flag_read) status = HC_INACTIVE;
        else status = c->fn.flag_read(c->user, a, out);
    }
    return leave(c, status);
}
HCStatus HCmount_accepted(HCCtx *c) {
    if (!c) return HC_FAULT;
    if (c->busy) return HC_PENDING;
    c->has_accepted = 0;
    return HC_OK;
}
HCStatus HCretire(HCCtx *c, HCActor a) {
    unsigned n;
    if (!c) return HC_FAULT;
    if (c->busy) return HC_PENDING;
    if (c->has_accepted && actor_equal(c->accepted, a)) c->has_accepted = 0;
    for (n = 0; n < 2; ++n)
        if (c->interest[n].occupied && actor_equal(c->interest[n].actor, a))
            c->interest[n].status = HC_STALE;
    return HC_OK;
}
HCStatus HCresolved(HCCtx *c, HCActor a, HCToken token) {
    unsigned n;
    if (!c) return HC_FAULT;
    if (c->busy) return HC_PENDING;
    for (n = 0; n < 2; ++n) {
        HCInterest *i = &c->interest[n];
        if (i->occupied && actor_equal(i->actor, a) && token_equal(i->token, token)) {
            if (i->status == HC_OK) return HC_REJECTED;
            i->occupied = 0;
            return HC_OK;
        }
    }
    return HC_INACTIVE;
}
