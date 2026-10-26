#include "controller.h"

static int equal(NLObject a, NLObject b) {
    return (a.object & 0x1fffffffu) == (b.object & 0x1fffffffu) &&
           a.allocation == b.allocation;
}
/* Deliberately do NOT call lifetime(): even its LIVE path reads object memory.
 * Native final-free events, not an absent address or speculative read, decide. */
static NLLifetime observed(const NLController *d, NLObject o) {
    uint32_t i;
    if (!o.object || !o.allocation || d->bridge->count > NL_BRIDGE_CAPACITY)
        return NL_MISMATCH;
    for (i = 0; i < d->bridge->count; ++i) {
        const NLBridgeAllocation *r = &d->bridge->allocations[i];
        NLObject p = {r->object, r->id};
        if (equal(o, p)) return r->state;
    }
    return NL_MISMATCH;
}
static NLResult fault(NLController *d, NLResult r) {
    if (!d->fault) d->fault = r;
    return r;
}
static int empty(const NLContext *c) {
    uint32_t i;
    if (c->actor.object || c->actor.allocation || c->child_count ||
        c->pending_creations || c->held || c->parent_requested) return 0;
    for (i = 0; i < NL_VISUALS; ++i)
        if (c->visuals[i].owned.object || c->visuals[i].owned.allocation) return 0;
    return 1;
}
static int merge_visuals(NLContext *c) {
    uint32_t i, j;
    if (c->child_count > NL_MAX_CHILDREN) return 0;
    for (i = 0; i < NL_VISUALS; ++i) {
        NLObject o = c->visuals[i].owned;
        if (!o.object && !o.allocation) continue;
        for (j = 0; j < c->child_count; ++j)
            if (equal(o, c->children[j])) break;
        if (j == c->child_count) {
            if (j == NL_MAX_CHILDREN) return 0;
            c->children[c->child_count++] = o;
        }
    }
    return 1;
}
/* Returns -1 on unknown, 0 if any live, 1 only on positive final-free evidence. */
static int children_final(NLController *d) {
    uint32_t i;
    int all = 1;
    if (d->ctx->child_count > NL_MAX_CHILDREN) return -1;
    for (i = 0; i < d->ctx->child_count; ++i) {
        NLLifetime s = observed(d, d->ctx->children[i]);
        if (s == NL_MISMATCH) return -1;
        if (s != NL_FREED) all = 0;
    }
    return all;
}
static int owns(NLContext *c, NLBridgeAllocation *r) {
    uint32_t i;
    NLObject o = {r->object, r->id};
    if (equal(c->actor, o)) return 1;
    for (i = 0; i < c->child_count; ++i)
        if (equal(c->children[i], o)) return 1;
    return 0;
}
static NLResult acknowledge(NLController *d) {
    NLContext *c = d->ctx;
    uint32_t i, kept = 0;
    if (c->pending_creations || children_final(d) != 1 ||
        ((c->actor.object || c->actor.allocation) && observed(d, c->actor) != NL_FREED))
        return fault(d, NL_STALE);
    if (!d->fn.on_retired(d->fn.user, c)) return NL_OK;
    /* No generation-wide eviction: unrelated P1/other-owner tombstones stay. */
    for (i = 0; i < d->bridge->count; ++i) {
        NLBridgeAllocation r = d->bridge->allocations[i];
        if (r.state == NL_FREED && owns(c, &r)) continue;
        d->bridge->allocations[kept++] = r;
    }
    d->bridge->count = kept;
    d->retirement_ack = 1;
    d->retiring = 0;
    return NL_OK;
}
static NLResult withdraw(NLController *d) {
    if (d->withdrawal_attempted) return fault(d, NL_CALLBACK_FAILED);
    d->withdrawal_attempted = 1;
    if (!d->fn.withdraw_view(d->fn.user, d->ctx)) return fault(d, NL_CALLBACK_FAILED);
    d->withdrawn = d->ctx->withdrawn = 1;
    d->withdrawn_render = d->input.completed_render;
    return NL_OK;
}
static NLResult cleanup(NLController *d) {
    NLResult r, discovery_error = NL_OK;
    int discovered;
    if (d->cleanup_discovered == 2) return NL_LATCHED;
    if (!d->withdrawn) {
        r = withdraw(d);
        if (r) return r;
    }
    if (d->view_exposed && d->input.completed_render <= d->withdrawn_render) return NL_OK;
    /* Provisional construction may still have stock intrinsic children. Inventory
     * them before holding/deleting the parent, never infer an empty inventory. */
    if (!d->cleanup_discovered && observed(d, d->ctx->actor) == NL_LIVE) {
        discovered = d->fn.validate_intrinsics(d->fn.user, d->ctx);
        if (!discovered) return NL_OK;
        if (discovered != 1 && discovered != -1) {
            d->cleanup_discovered = 2;
            if (!d->ctx->error) d->ctx->error = NL_CALLBACK_FAILED;
            return fault(d, NL_CALLBACK_FAILED);
        }
        d->cleanup_discovered = 1;
        if (discovered == -1) {
            if (!d->ctx->error) {
                d->ctx->error = NL_CALLBACK_FAILED;
                discovery_error = NL_CALLBACK_FAILED;
            }
            fault(d, NL_CALLBACK_FAILED);
        }
    }
    if (d->ctx->pending_creations) return discovery_error;
    if (!merge_visuals(d->ctx) || children_final(d) < 0) {
        d->cleanup_discovered = 2;
        if (!d->ctx->error) d->ctx->error = NL_STALE;
        return fault(d, NL_STALE);
    }
    r = d->ctx->error ? retire_failed_build(d->ctx) : cancel_build(d->ctx);
    if (r) return fault(d, r);
    return discovery_error;
}
static NLResult build_failure(NLController *d, NLResult r) {
    fault(d, r);
    if (!d->ctx->error) d->ctx->error = r;
    d->ctx->teardown_needed = 1;
    d->retiring = 1;
    /* A failed atomic constructor batch never returns without attempting safe
     * cleanup. An uncertain/unknown ownership failure remains quarantined. */
    return cleanup(d) == NL_OK ? r : d->fault;
}
int nl_controller_init(NLController *d, NLContext *c, NLBridge *b,
                       const NLControllerFunctions *f) {
    uint32_t i;
    volatile unsigned char *bytes;
    if (!d || d->initialized || !c || !b || !b->initialized || !f ||
        c->phase != NL_QUIESCENT || !empty(c) || !f->prepare_spawn ||
        !f->withdraw_view || !f->validate_intrinsics || !f->on_retired ||
        !f->request_team_restart) return 0;
    /* Volatile byte stores keep EE GCC from introducing a libc memset call. */
    bytes = (volatile unsigned char *)d;
    for (i = 0; i < sizeof(*d); ++i) bytes[i] = 0;
    d->ctx = c; d->bridge = b; d->fn = *f;
    d->initialized = d->retirement_ack = 1;
    d->last_generation = c->generation;
    return 1;
}
static int adopt_live(const NLBridge *b, NLObject o, uint32_t generation) {
    uint32_t i;
    if (!nl_address_valid(o.object, 4) || !o.allocation) return 0;
    for (i = 0; i < b->count; ++i) {
        const NLBridgeAllocation *r = &b->allocations[i];
        NLObject p = {r->object, r->id};
        if (equal(o, p))
            return r->state == NL_LIVE && r->generation == generation;
    }
    return 0;
}
int nl_controller_adopt_active(NLController *d, NLContext *c, NLBridge *b,
                              const NLControllerFunctions *f,
                              NLAddress published_actor) {
    uint32_t i, j;
    volatile unsigned char *bytes;
    if (!d || d->initialized || !c || !b || !f || !b->initialized || b->fault ||
        b->count > NL_BRIDGE_CAPACITY || c->phase != NL_ACTIVE ||
        !c->generation || c->generation != c->current_generation ||
        c->generation != b->generation || c->user != b ||
        c->error || c->cleanup_error || c->busy || c->held || c->parent_requested ||
        c->pending_creations || c->withdrawn || c->teardown_needed ||
        c->failed_build_retirement || c->readiness != 1 || c->resource_barrier ||
        c->intrinsics_validated != 1 || c->canonical_p1_verified != 1 ||
        c->child_count > NL_MAX_CHILDREN || published_actor != c->actor.object ||
        (c->actor.object & 0x1fffffffu) == (c->canonical_p1.object & 0x1fffffffu) ||
        c->canonical_p1.allocation != b->canonical_id ||
        (c->canonical_p1.object & 0x1fffffffu) != (b->canonical_object & 0x1fffffffu) ||
        !f->prepare_spawn || !f->withdraw_view || !f->validate_intrinsics ||
        !f->on_retired || !f->request_team_restart ||
        !c->fn.delete_lock || !c->fn.delete_unlock || !c->fn.request_delete ||
        !c->fn.create_character || !c->fn.create_alias || !c->fn.lifetime ||
        !c->fn.new_allocation || !c->fn.publish_actor || !c->fn.unpublish_actor ||
        !c->fn.publish_view ||
        !adopt_live(b, c->actor, c->generation) ||
        !adopt_live(b, c->canonical_p1, b->canonical_generation)) return 0;
#ifdef NL_HOST_TEST
    if (!c->fn.read32 || !c->fn.write32) return 0;
#endif
    for (i = 0; i < c->child_count; ++i) {
        NLObject o = c->children[i];
        if (!adopt_live(b, o, c->generation) ||
            (o.object & 0x1fffffffu) == (c->actor.object & 0x1fffffffu) ||
            (o.object & 0x1fffffffu) == (c->canonical_p1.object & 0x1fffffffu)) return 0;
        for (j = 0; j < i; ++j)
            if ((o.object & 0x1fffffffu) == (c->children[j].object & 0x1fffffffu)) return 0;
    }
    for (i = 0; i < NL_VISUALS; ++i) {
        NLObject o = c->visuals[i].owned;
        if (c->visuals[i].attempted != 1 || !adopt_live(b, o, c->generation)) return 0;
        for (j = 0; j < c->child_count; ++j)
            if (equal(o, c->children[j])) break;
        if (j == c->child_count) return 0;
        for (j = 0; j < i; ++j)
            if (equal(o, c->visuals[j].owned)) return 0;
    }
    /* Commit output only after every validation; no calls or context writes. */
    bytes = (volatile unsigned char *)d;
    for (i = 0; i < sizeof(*d); ++i) bytes[i] = 0;
    d->ctx = c; d->bridge = b; d->fn = *f;
    d->initialized = d->view_exposed = 1;
    d->last_generation = c->current_generation;
    return 1;
}
int nl_controller_resource_permit(const NLController *d) {
    return d && d->initialized && !d->busy && d->retirement_ack &&
           d->ctx->phase == NL_QUIESCENT && !d->ctx->pending_creations &&
           !d->ctx->held && !d->ctx->cleanup_error;
}
int nl_controller_reprepare(NLController *d) {
    if (!d || d->busy || !nl_controller_resource_permit(d)) return 0;
    d->fault = NL_OK;
    return 1;
}
static NLResult pump(NLController *d) {
    NLContext *c = d->ctx;
    const NLControllerInput *s = &d->input;
    NLResult r;
    uint32_t i;
    int stop, valid;
    if (s->team_death) {
        if (!s->death_epoch || s->death_epoch < d->handled_death ||
            (d->pending_death && s->death_epoch != d->pending_death))
            return fault(d, NL_STALE);
        if (s->death_epoch > d->handled_death) d->pending_death = s->death_epoch;
    }
    stop = !s->desired_active || !s->gameplay_ready || s->resource_barrier ||
           s->team_death || d->pending_death || d->bridge->fault ||
           !equal(s->canonical_p1, c->canonical_p1) ||
           s->canonical_p1.allocation != d->bridge->canonical_id ||
           (s->canonical_p1.object & 0x1fffffffu) !=
               (d->bridge->canonical_object & 0x1fffffffu);
    /* Do not replace ctx canonical/epoch/readiness while the old P2 drains. */
    if (c->phase == NL_ACTIVE) {
        if (!stop && !d->fault && !d->retiring) return NL_OK;
        d->retiring = 1;
        if (!d->withdrawn) return withdraw(d);
        if (s->completed_render <= d->withdrawn_render) return NL_OK;
        /* Withdrawal is one-shot; complete ownership discovery is not. Do not
         * hold/delete an ACTIVE parent until post-render inventory is complete.
         * A failed inventory is quarantined, not retried or treated as empty. */
        if (d->fault) return NL_LATCHED;
        valid = d->fn.validate_intrinsics(d->fn.user, c);
        if (!valid) return NL_OK;
        if (valid != 1) return fault(d, NL_CALLBACK_FAILED);
        if (!merge_visuals(c)) return fault(d, NL_STALE);
        if (children_final(d) < 0 || observed(d, c->actor) != NL_LIVE)
            return fault(d, NL_STALE);
        r = begin_retire(c);
        return r ? fault(d, r) : NL_OK;
    }
    if (c->phase == NL_DRAINING) {
        valid = children_final(d);
        if (valid < 0 || observed(d, c->actor) != NL_LIVE) return fault(d, NL_STALE);
        if (!valid || c->pending_creations) return NL_OK;
        c->allchild_final = 1;
        r = release_parent(c);
        return r ? fault(d, r) : NL_OK;
    }
    if (c->phase == NL_WAIT_PARENT_FREE) {
        NLLifetime life = observed(d, c->actor);
        if (life == NL_MISMATCH) return fault(d, NL_STALE);
        if (life != NL_FREED || c->pending_creations) return NL_OK;
        if (children_final(d) != 1) return fault(d, NL_STALE);
        c->phase = NL_QUIESCENT;
        return acknowledge(d);
    }
    if (c->phase == NL_BUILDING) {
        if (c->error) {
            fault(d, c->error);
            return cleanup(d);
        }
        if (d->fault || d->bridge->fault)
            return build_failure(d, d->fault ? d->fault : d->bridge->fault);
        if (stop || d->retiring) {
            d->retiring = c->teardown_needed = 1;
            return cleanup(d);
        }
        valid = d->fn.validate_intrinsics(d->fn.user, c);
        if (valid == 1 || valid == -1) d->cleanup_discovered = 1;
        else if (valid < 0 || valid > 1) d->cleanup_discovered = 2;
        if (!merge_visuals(c)) return build_failure(d, NL_STALE);
        if (valid < 0) return build_failure(d, NL_CALLBACK_FAILED);
        if (!valid || c->pending_creations) return NL_OK;
        if (valid != 1 || children_final(d) < 0) return build_failure(d, NL_STALE);
        c->intrinsics_validated = 1;
        d->cleanup_discovered = 1;
        if (!nl_bridge_refresh_actor_work(d->bridge, c))
            return build_failure(d, NL_CALLBACK_FAILED);
        d->view_exposed = 1; /* even a failed publication can be partial */
        r = commit_active(c);
        return r ? build_failure(d, r) : NL_OK;
    }
    if (c->phase != NL_QUIESCENT) return fault(d, NL_REJECTED);
    if (!d->retirement_ack) return acknowledge(d);
    if (d->pending_death) {
        uint32_t epoch = d->pending_death;
        d->pending_death = 0;
        d->handled_death = epoch; /* latch BEFORE uncertain external call */
        if (!s->p1_transition && !d->fn.request_team_restart(d->fn.user, epoch))
            return fault(d, NL_CALLBACK_FAILED);
        return NL_OK;
    }
    if (d->fault) return NL_LATCHED;
    if (!s->desired_active || !s->gameplay_ready || s->resource_barrier || s->team_death ||
        d->bridge->fault || observed(d, s->canonical_p1) != NL_LIVE ||
        s->canonical_p1.allocation != d->bridge->canonical_id ||
        (s->canonical_p1.object & 0x1fffffffu) !=
            (d->bridge->canonical_object & 0x1fffffffu)) return NL_OK;
    if (!d->fn.prepare_spawn(d->fn.user, d, c)) {
        if (empty(c)) c->phase = NL_QUIESCENT;
        return fault(d, NL_CALLBACK_FAILED);
    }
    if (c->phase != NL_READY || !empty(c) || c->error || c->cleanup_error ||
        !c->generation || c->generation <= d->last_generation ||
        c->generation != c->current_generation || c->generation != d->bridge->generation ||
        !equal(c->canonical_p1, s->canonical_p1) || !c->canonical_p1_verified ||
        !c->readiness || c->resource_barrier || c->user != d->bridge) {
        if (empty(c)) c->phase = NL_QUIESCENT;
        return fault(d, NL_REJECTED);
    }
    d->last_generation = c->generation;
    d->retirement_ack = d->retiring = d->withdrawal_attempted = d->withdrawn = 0;
    d->view_exposed = d->cleanup_discovered = 0;
    r = spawn_actor(c);
    if (r) {
        if (c->phase == NL_BUILDING) return build_failure(d, r);
        return fault(d, r);
    }
    for (i = 0; i < NL_VISUALS; ++i) {
        r = spawn_visual(c, i);
        if (r) return build_failure(d, r);
    }
    return NL_OK; /* intrinsics MUST wait for a later pump */
}
NLResult nl_controller_pump(NLController *d, const NLControllerInput *s) {
    NLResult r;
    if (!d || !d->initialized || !s || d->busy || d->ctx->busy) return NL_REJECTED;
    if (s->completed_render < d->input.completed_render) return fault(d, NL_STALE);
    d->busy = 1;
    d->input = *s;
    r = pump(d);
    d->busy = 0;
    return r;
}
