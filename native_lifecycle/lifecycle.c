#include "lifecycle.h"

/* Only physical RAM and its KSEG0/KSEG1 aliases; a range check is NOT proof of
 * mapped/allocated memory. Lifetime/resource provenance comes from the adapter. */
int nl_address_valid(NLAddress a, uint32_t bytes) {
    uint32_t physical;
    if (!a || (a & 3u) || !bytes) return 0;
    if (a < 0x02000000u) physical = a;
    else if (a >= 0x80000000u && a < 0x82000000u) physical = a - 0x80000000u;
    else if (a >= 0xa0000000u && a < 0xa2000000u) physical = a - 0xa0000000u;
    else return 0;
    return bytes <= 0x02000000u - physical;
}

static uint32_t physical(NLAddress a) { return a & 0x1fffffffu; }
static int same(NLAddress a, NLAddress b) { return physical(a) == physical(b); }
static int read_word(NLContext *c, NLAddress a, uint32_t *value) {
    if (!nl_address_valid(a, 4)) return 0;
#ifdef NL_HOST_TEST
    return c->fn.read32 && c->fn.read32(c->user, a, value);
#else
    (void)c;
    *value = *(volatile uint32_t *)(uintptr_t)a;
    return 1;
#endif
}
static int write_word(NLContext *c, NLAddress a, uint32_t value) {
    if (!nl_address_valid(a, 4)) return 0;
#ifdef NL_HOST_TEST
    return c->fn.write32 && c->fn.write32(c->user, a, value);
#else
    (void)c;
    *(volatile uint32_t *)(uintptr_t)a = value;
    return 1;
#endif
}
static int live(NLContext *c, NLObject o) {
    return nl_address_valid(o.object, 4) && o.allocation && c->fn.lifetime &&
           c->fn.lifetime(c->user, o.object, o.allocation) == NL_LIVE;
}
static int epoch(NLContext *c) {
    return c->generation && c->generation == c->current_generation;
}
static NLResult enter(NLContext *c) {
    if (!c || c->busy) return NL_REJECTED;
    if (c->error) return NL_LATCHED;
    if (!epoch(c)) return NL_REJECTED;
    return NL_OK;
}
static NLResult fail(NLContext *c, NLResult r) {
    c->error = r;
    c->teardown_needed = 1;
    c->busy = 0;
    return r;
}
static NLResult done(NLContext *c) { c->busy = 0; return NL_OK; }
static int p2_live(NLContext *c) {
    return !same(c->actor.object, c->canonical_p1.object) && live(c, c->actor);
}
static int inputs(NLAddress def, NLAddress params) {
    return nl_address_valid(def, 4) &&
           nl_address_valid(params, NL_PARAMETER_GP_OFFSET + 4);
}

static NLResult cleanup_fail(NLContext *c, NLResult r) {
    c->cleanup_error = r;
    if (!c->error) c->error = r;
    c->teardown_needed = 1;
    c->busy = 0;
    return r;
}

/* mode: 0 ACTIVE retirement, 1 failed BUILDING, 2 normal BUILDING cancellation. */
static NLResult retire(NLContext *c, int recovery) {
    uint32_t i, j, flags, count;
    NLObject snapshot[NL_MAX_CHILDREN];
    NLResult r;
    if (recovery) {
        if (!c || c->busy) return NL_REJECTED;
        if (c->cleanup_error) return NL_LATCHED;
        if (recovery == 2 && c->error) return NL_LATCHED;
        if (!epoch(c) || c->phase != NL_BUILDING || (recovery == 1 && !c->error) ||
            c->teardown_needed != 1 || c->pending_creations ||
            c->failed_build_retirement) return NL_REJECTED;
        r = NL_OK;
    } else r = enter(c);
    if (r) return r;
    if ((!recovery && c->phase != NL_ACTIVE) ||
        (recovery ? c->withdrawn != 1 : !c->withdrawn) || c->held ||
        c->parent_requested || c->child_count > NL_MAX_CHILDREN)
        return NL_REJECTED;
    if (recovery && !c->actor.object && !c->actor.allocation) {
        if (c->child_count) return NL_REJECTED;
        for (i = 0; i < NL_VISUALS; ++i)
            if (c->visuals[i].owned.object || c->visuals[i].owned.allocation)
                return NL_REJECTED;
        c->failed_build_retirement = 1;
        c->allchild_final = 1;
        c->phase = NL_QUIESCENT;
        return NL_OK;
    }
    if (!c->fn.delete_lock || !c->fn.request_delete ||
        !c->fn.unpublish_actor || !p2_live(c) ||
        (c->header_flags_offset & 3u) || c->header_flags_offset > 0x01fffffcu)
        return NL_REJECTED;
    /* Reject bad/aliased ownership before any irreversible call. The copied
     * pairs remain safe even when native callbacks clear registry entries. */
    count = 0;
    /* BUILDING retirement merges the intrinsic list with every partial visual.
     * Identical ownership pairs are harmless; conflicting identities are not. */
    for (i = 0; i < c->child_count + (recovery ? NL_VISUALS : 0); ++i) {
        NLObject o = i < c->child_count ? c->children[i] :
                     c->visuals[i - c->child_count].owned;
        if (recovery && i >= c->child_count && !o.object && !o.allocation) continue;
        for (j = 0; j < count; ++j) {
            if (!same(o.object, snapshot[j].object)) continue;
            if (o.allocation == snapshot[j].allocation) {
                if (!recovery) return NL_REJECTED;
                break;
            }
            {
                NLLifetime a = c->fn.lifetime(c->user, o.object, o.allocation);
                NLLifetime b = c->fn.lifetime(c->user, snapshot[j].object,
                                             snapshot[j].allocation);
                if ((a != NL_LIVE && a != NL_FREED) ||
                    (b != NL_LIVE && b != NL_FREED) ||
                    (a != NL_FREED && b != NL_FREED))
                    return NL_REJECTED;
            }
        }
        if (j < count) continue;
        if (count == NL_MAX_CHILDREN) return NL_REJECTED;
        snapshot[count++] = o;
    }
    for (i = 0; i < count; ++i) {
        if (!nl_address_valid(snapshot[i].object, c->header_flags_offset + 4) ||
            !snapshot[i].allocation || same(snapshot[i].object, c->actor.object) ||
            same(snapshot[i].object, c->canonical_p1.object)) return NL_REJECTED;
        if (recovery) {
            NLLifetime life = c->fn.lifetime(c->user, snapshot[i].object, snapshot[i].allocation);
            if (life != NL_LIVE && life != NL_FREED) return NL_REJECTED;
        }
    }
    c->busy = 1;
    if (recovery) {
        for (i = 0; i < count; ++i) c->children[i] = snapshot[i];
        c->child_count = count;
        c->failed_build_retirement = 1;
    }
    c->allchild_final = 0; /* acknowledgements must follow this retirement */
    c->held = 1; /* latch BEFORE call; uncertain completion must never retry */
    c->fn.delete_lock(c->actor.object);
    if (!epoch(c) || !p2_live(c)) return cleanup_fail(c, NL_STALE);
    c->parent_requested = 1;
    c->fn.request_delete(c->actor.object);
    if (!epoch(c) || !p2_live(c)) return cleanup_fail(c, NL_STALE);
    for (i = 0; i < count; ++i) {
        NLLifetime life = c->fn.lifetime(c->user, snapshot[i].object, snapshot[i].allocation);
        if (life == NL_FREED) continue;
        if (life != NL_LIVE) return cleanup_fail(c, NL_STALE);
        if (!read_word(c, snapshot[i].object + c->header_flags_offset, &flags))
            return cleanup_fail(c, NL_BAD_MEMORY);
        if (!(flags & NL_PENDING_DELETE)) c->fn.request_delete(snapshot[i].object);
        if (!epoch(c) || !p2_live(c)) return cleanup_fail(c, NL_STALE);
    }
    if (!c->fn.unpublish_actor(c->user, c)) return cleanup_fail(c, NL_CALLBACK_FAILED);
    c->phase = NL_DRAINING;
    return done(c);
}

NLResult begin_retire(NLContext *c) { return retire(c, 0); }
NLResult retire_failed_build(NLContext *c) { return retire(c, 1); }
NLResult cancel_build(NLContext *c) { return retire(c, 2); }

NLResult release_parent(NLContext *c) {
    uint32_t i;
    NLResult r;
    if (c && c->failed_build_retirement) {
        if (c->busy) return NL_REJECTED;
        if (c->cleanup_error) return NL_LATCHED;
        r = epoch(c) ? NL_OK : NL_REJECTED;
    } else r = enter(c);
    if (r) return r;
    if (c->phase != NL_DRAINING || c->child_count > NL_MAX_CHILDREN ||
        !c->allchild_final || c->pending_creations ||
        c->held != 1 || !c->parent_requested || !c->fn.delete_unlock || !p2_live(c))
        return NL_REJECTED;
    for (i = 0; i < c->child_count; ++i)
        if (c->fn.lifetime(c->user, c->children[i].object, c->children[i].allocation) != NL_FREED)
            return NL_REJECTED;
    c->busy = 1;
    c->fn.delete_unlock(c->actor.object);
    /* Unlock may synchronously final-free. Never dereference the parent again.
     * Host buffers that event until it has observed this acknowledgement. */
    c->held = 0;
    c->phase = NL_WAIT_PARENT_FREE;
    return done(c);
}

NLResult spawn_actor(NLContext *c) {
    uint32_t i;
    NLResult r = enter(c);
    if (r) return r;
    if ((c->phase != NL_QUIESCENT && c->phase != NL_READY) ||
        !c->readiness || c->resource_barrier || !c->canonical_p1_verified ||
        !live(c, c->canonical_p1) || c->actor.object || c->held ||
        c->pending_creations || !inputs(c->actor_definition, c->actor_parameters) ||
        !c->fn.create_character || !c->fn.new_allocation || !c->fn.publish_actor)
        return NL_REJECTED;
    for (i = 0; i < NL_VISUALS; ++i)
        if (c->visuals[i].attempted || c->visuals[i].owned.object) return NL_REJECTED;
    c->busy = 1;
    c->phase = NL_BUILDING;
    c->intrinsics_validated = 0;
    c->actor.object = c->fn.create_character(c->actor_definition, c->actor_parameters);
    if (!c->actor.object) return fail(c, NL_CONSTRUCTOR_FAILED);
    /* Preserve partial output even on validation/publication failure. */
    if (!nl_address_valid(c->actor.object, 4) || same(c->actor.object, c->canonical_p1.object))
        return fail(c, NL_STALE);
    c->actor.allocation = c->fn.new_allocation(c->user, c->actor.object);
    if (!epoch(c) || !p2_live(c)) return fail(c, NL_STALE);
    /* Banks must be established synchronously, before scheduler return. This is
     * not view publication and must not register P2 in P1's stock group. */
    if (!c->fn.publish_actor(c->user, c)) return fail(c, NL_CALLBACK_FAILED);
    return done(c);
}

NLResult spawn_visual(NLContext *c, uint32_t index) {
    uint32_t gp, i;
    NLVisual *v;
    NLResult r = enter(c);
    if (r) return r;
    if (index >= NL_VISUALS || c->phase != NL_BUILDING ||
        !c->readiness || c->resource_barrier || !p2_live(c) ||
        !c->fn.new_allocation) return NL_REJECTED;
    v = &c->visuals[index];
    if (v->attempted || !inputs(v->definition, v->parameters) ||
        (v->kind != NL_ALIAS && v->kind != NL_CHARACTER) ||
        (v->kind == NL_ALIAS && (!c->fn.create_alias ||
            !nl_address_valid(v->partition, 4) || !nl_address_valid(v->script, 4))) ||
        (v->kind == NL_CHARACTER && !c->fn.create_character)) return NL_REJECTED;
    c->busy = 1;
    v->attempted = 1;
    if (!read_word(c, v->parameters + NL_PARAMETER_GP_OFFSET, &gp) ||
        !nl_address_valid(gp, 4)) return fail(c, NL_BAD_MEMORY);
    /* This is the sole game-memory write performed by these helpers. */
    if (!write_word(c, gp, c->actor.object)) return fail(c, NL_BAD_MEMORY);
    if (v->kind == NL_ALIAS)
        v->owned.object = c->fn.create_alias(v->partition, v->definition,
            v->parameters, v->script, c->actor.object, 0, 1);
    else v->owned.object = c->fn.create_character(v->definition, v->parameters);
    if (!v->owned.object) return fail(c, NL_CONSTRUCTOR_FAILED);
    if (!nl_address_valid(v->owned.object, 4) || same(v->owned.object, c->canonical_p1.object) ||
        same(v->owned.object, c->actor.object)) return fail(c, NL_STALE);
    for (i = 0; i < NL_VISUALS; ++i)
        if (i != index && c->visuals[i].owned.object &&
            same(v->owned.object, c->visuals[i].owned.object)) return fail(c, NL_STALE);
    v->owned.allocation = c->fn.new_allocation(c->user, v->owned.object);
    if (!epoch(c) || !p2_live(c) || !live(c, v->owned)) return fail(c, NL_STALE);
    return done(c);
}

NLResult commit_active(NLContext *c) {
    uint32_t i;
    NLResult r = enter(c);
    if (r) return r;
    if (c->phase != NL_BUILDING || !c->readiness || c->resource_barrier ||
        !c->intrinsics_validated || c->pending_creations || !p2_live(c) ||
        !c->fn.publish_view) return NL_REJECTED;
    for (i = 0; i < NL_VISUALS; ++i)
        if (!c->visuals[i].attempted || !live(c, c->visuals[i].owned)) return NL_REJECTED;
    c->busy = 1;
    if (!c->fn.publish_view(c->user, c)) return fail(c, NL_CALLBACK_FAILED);
    c->phase = NL_ACTIVE;
    return done(c);
}
