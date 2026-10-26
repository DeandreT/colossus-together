#include "bridge.h"

enum { S_SIZE = 24, BANK_SIZE = 32, C_SIZE = 32, H_SIZE = 32, V_SIZE = 0x1d0 };
static uint32_t physical(NLAddress a) { return a & 0x1fffffffu; }
static int same(NLAddress a, NLAddress b) { return physical(a) == physical(b); }
static int read32(NLBridge *b, NLAddress a, uint32_t *v) {
    if (!nl_address_valid(a, 4)) return 0;
    if (b->config.read32) return b->config.read32(b->config.memory_user, a, v);
#ifdef NL_HOST_TEST
    return 0;
#else
    *v = *(volatile uint32_t *)(uintptr_t)physical(a);
    return 1;
#endif
}
static int write32(NLBridge *b, NLAddress a, uint32_t v) {
    if (!nl_address_valid(a, 4)) return 0;
    if (b->config.write32) return b->config.write32(b->config.memory_user, a, v);
#ifdef NL_HOST_TEST
    return 0;
#else
    *(volatile uint32_t *)(uintptr_t)physical(a) = v;
    return 1;
#endif
}
static int eq(NLBridge *b, NLAddress a, uint32_t expected) {
    uint32_t v;
    return read32(b, a, &v) && v == expected;
}
static int ready(NLBridge *b, NLAddress a) {
    uint32_t flags;
    return read32(b, a, &flags) && (flags & 1u);
}
static int pointer_eq(NLBridge *b, NLAddress a, NLAddress expected) {
    uint32_t v;
    return read32(b, a, &v) && nl_address_valid(v, 4) && same(v, expected);
}
static int no_overlap(NLAddress a, uint32_t as, NLAddress d, uint32_t ds) {
    a = physical(a); d = physical(d);
    return a + as <= d || d + ds <= a;
}

int nl_bridge_init(NLBridge *b, const NLBridgeConfig *cfg, uint32_t generation) {
    NLAddress addresses[7];
    const uint32_t sizes[7] = {S_SIZE, BANK_SIZE, C_SIZE, BANK_SIZE, H_SIZE, 4, V_SIZE};
    uint32_t i, j;
    if (!b || b->initialized || !cfg || !generation || !cfg->get_max_hp || !cfg->get_max_grip ||
        (!!cfg->read32 != !!cfg->write32) ||
        (!cfg->get_ai_work && ((cfg->ai_work_offset & 3u) || cfg->ai_work_offset > 0x01fffffcu)))
        return 0;
#ifdef NL_HOST_TEST
    if (!cfg->read32 || !cfg->write32) return 0;
#endif
    addresses[0] = cfg->survival; addresses[1] = cfg->survival_bank;
    addresses[2] = cfg->charge; addresses[3] = cfg->charge_bank;
    addresses[4] = cfg->horse; addresses[5] = cfg->routing; addresses[6] = cfg->view;
    for (i = 0; i < 7; ++i) {
        if (!nl_address_valid(addresses[i], sizes[i])) return 0;
        for (j = 0; j < i; ++j)
            if (!no_overlap(addresses[i], sizes[i], addresses[j], sizes[j])) return 0;
    }
    /* Caller must never reinitialize an in-use bridge. No implicit reset path. */
    b->config = *cfg;
    b->count = b->last_id = 0;
    b->generation = generation;
    b->canonical_object = b->canonical_id = b->canonical_generation = 0;
    b->fault = NL_OK;
    b->initialized = 1;
    for (i = 0; i < NL_BRIDGE_CAPACITY; ++i) {
        b->allocations[i].object = b->allocations[i].raw_allocation = 0;
        b->allocations[i].id = b->allocations[i].generation = 0;
        b->allocations[i].state = NL_MISMATCH;
    }
    return 1;
}

int nl_bridge_set_generation(NLBridge *b, uint32_t generation) {
    if (!b || !b->initialized || generation <= b->generation) return 0;
    b->generation = generation;
    return 1;
}
static uint32_t register_allocation(NLBridge *b, NLAddress object, uint32_t object_generation) {
    uint32_t raw, i;
    NLBridgeAllocation *r;
    if (!b || !b->initialized || !object_generation || !nl_address_valid(object, 4) ||
        !read32(b, object, &raw) || !nl_address_valid(raw, 4)) return 0;
    for (i = 0; i < b->count; ++i) {
        r = &b->allocations[i];
        if (r->state != NL_LIVE) continue;
        if (same(r->object, object)) {
            if (same(r->raw_allocation, raw) && r->generation == object_generation) return r->id;
            return 0; /* missing final-free, changed identity or stale epoch */
        }
        if (same(r->raw_allocation, raw)) return 0;
    }
    if (b->count == NL_BRIDGE_CAPACITY || b->last_id == UINT32_MAX) return 0;
    r = &b->allocations[b->count++];
    r->object = object; r->raw_allocation = raw;
    r->id = ++b->last_id; r->generation = object_generation; r->state = NL_LIVE;
    return r->id;
}
uint32_t nl_bridge_new_allocation(void *user, NLAddress object) {
    NLBridge *b = user;
    if (!b) return 0;
    return register_allocation(b, object, b->generation);
}
NLLifetime nl_bridge_lifetime(void *user, NLAddress object, uint32_t id) {
    NLBridge *b = user;
    uint32_t i, raw;
    if (!b || !b->initialized || !id || !nl_address_valid(object, 4)) return NL_MISMATCH;
    for (i = 0; i < b->count; ++i) {
        NLBridgeAllocation *r = &b->allocations[i];
        if (r->id != id) continue;
        if (!same(r->object, object)) return NL_MISMATCH;
        if (r->state == NL_FREED) return NL_FREED;
        if (r->state != NL_LIVE) return NL_MISMATCH;
        if (!read32(b, object, &raw) || !nl_address_valid(raw, 4) ||
            !same(raw, r->raw_allocation)) return NL_MISMATCH;
        return NL_LIVE;
    }
    return NL_MISMATCH;
}
uint32_t nl_bridge_mark_final_free(NLBridge *b, NLAddress raw) {
    uint32_t i, n = 0;
    if (!b || !b->initialized || !nl_address_valid(raw, 4)) return 0;
    for (i = 0; i < b->count; ++i) {
        NLBridgeAllocation *r = &b->allocations[i];
        if (r->state == NL_LIVE && same(r->raw_allocation, raw)) {
            r->state = NL_FREED; ++n;
        }
    }
    return n;
}
int nl_bridge_acknowledge_retired_ids(NLBridge *b, const NLObject *ids, uint32_t count) {
    uint32_t i, j, k, kept = 0;
    if (!b || !b->initialized || count > NL_BRIDGE_CAPACITY || (count && !ids)) return 0;
    /* Validate the entire batch before moving any records. */
    for (i = 0; i < count; ++i) {
        if (!nl_address_valid(ids[i].object, 4) || !ids[i].allocation ||
            ids[i].allocation == b->canonical_id) return 0;
        for (j = 0; j < i; ++j)
            if (ids[i].allocation == ids[j].allocation) return 0;
        for (j = 0; j < b->count; ++j)
            if (b->allocations[j].id == ids[i].allocation) break;
        if (j == b->count || b->allocations[j].state != NL_FREED ||
            !same(b->allocations[j].object, ids[i].object)) return 0;
    }
    for (i = 0; i < b->count; ++i) {
        for (k = 0; k < count; ++k)
            if (b->allocations[i].id == ids[k].allocation) break;
        if (k != count) continue;
        if (kept != i) b->allocations[kept] = b->allocations[i];
        ++kept;
    }
    b->count = kept;
    return 1;
}
uint32_t nl_bridge_acknowledge_retired_before(NLBridge *b, uint32_t generation) {
    uint32_t i, kept = 0, removed = 0;
    if (!b || !b->initialized || !generation || generation > b->generation) return 0;
    for (i = 0; i < b->count; ++i) {
        NLBridgeAllocation *r = &b->allocations[i];
        if (r->state == NL_FREED && r->generation < generation) {
            ++removed;
        } else {
            if (kept != i) b->allocations[kept] = *r;
            ++kept;
        }
    }
    b->count = kept;
    return removed;
}
static int actor_context(NLBridge *b, NLContext *c) {
    uint32_t i;
    if (!(b && b->initialized && c && c->user == b && c->generation &&
        c->generation == c->current_generation && c->generation == b->generation &&
        !same(c->actor.object, c->canonical_p1.object) &&
        nl_bridge_lifetime(b, c->actor.object, c->actor.allocation) == NL_LIVE)) return 0;
    for (i = 0; i < b->count; ++i)
        if (b->allocations[i].id == c->actor.allocation)
            return b->allocations[i].generation == c->generation;
    return 0;
}
static int context(NLBridge *b, NLContext *c) {
    return actor_context(b, c) && !b->fault && c->canonical_p1_verified &&
        nl_bridge_lifetime(b, c->canonical_p1.object, c->canonical_p1.allocation) == NL_LIVE;
}
static int canonical(NLBridge *b, NLContext *c) {
    uint32_t i, generation = 0;
    for (i = 0; i < b->count; ++i)
        if (b->allocations[i].id == c->canonical_p1.allocation)
            generation = b->allocations[i].generation;
    return pointer_eq(b, b->config.survival, c->canonical_p1.object) &&
        pointer_eq(b, b->config.charge, c->canonical_p1.object) &&
        pointer_eq(b, b->config.horse, c->canonical_p1.object) &&
        generation && eq(b, b->config.charge + 16, generation);
}
static int owned(NLBridge *b, NLContext *c) {
    return pointer_eq(b, b->config.survival + 4, c->actor.object) &&
        eq(b, b->config.survival + 8, c->generation) &&
        pointer_eq(b, b->config.charge + 4, c->actor.object) &&
        eq(b, b->config.charge + 8, c->generation) &&
        pointer_eq(b, b->config.survival + 12, b->config.survival_bank) &&
        pointer_eq(b, b->config.charge + 12, b->config.charge_bank) &&
        pointer_eq(b, b->config.survival_bank, c->actor.object) &&
        eq(b, b->config.survival_bank + 4, c->generation) &&
        pointer_eq(b, b->config.charge_bank, c->actor.object) &&
        eq(b, b->config.charge_bank + 4, c->generation);
}
static int object_work(NLBridge *b, NLAddress actor, uint32_t *w) {
    if (b->config.get_ai_work) *w = b->config.get_ai_work(actor);
    else {
        if (!nl_address_valid(actor, b->config.ai_work_offset + 4) ||
            !read32(b, actor + b->config.ai_work_offset, w)) return 0;
    }
    return !*w || nl_address_valid(*w, 4);
}
static int work(NLBridge *b, NLContext *c, uint32_t *w) {
    return object_work(b, c->actor.object, w);
}

int nl_bridge_adopt_canonical(NLBridge *b, NLAddress actor, uint32_t generation) {
    uint32_t id;
    if (!b || !b->initialized || b->fault || b->canonical_id || !generation ||
        !nl_address_valid(actor, 4) ||
        !pointer_eq(b, b->config.survival, actor) ||
        !pointer_eq(b, b->config.charge, actor) ||
        !pointer_eq(b, b->config.horse, actor) ||
        !eq(b, b->config.charge + 16, generation)) return 0;
    id = register_allocation(b, actor, generation);
    if (!id) return 0;
    b->canonical_object = actor;
    b->canonical_id = id;
    b->canonical_generation = generation;
    return 1;
}

void nl_bridge_canonical_admitted(void *user, NLAddress actor) {
    NLBridge *b = user;
    uint32_t id, generation, w;
    if (!b || !b->initialized || b->fault) return;
    if (!nl_address_valid(actor, 4)) { b->fault = NL_BAD_MEMORY; return; }
    if (b->canonical_id && same(actor, b->canonical_object) &&
        nl_bridge_lifetime(b, actor, b->canonical_id) == NL_LIVE) return;
    if (b->canonical_generation == UINT32_MAX) { b->fault = NL_REJECTED; return; }
    generation = b->canonical_generation + 1;
    id = register_allocation(b, actor, generation);
    if (!id) { b->fault = NL_STALE; return; }
    /* Retain the admitted allocation even if work lookup or publication fails.
     * The fault distinguishes a failed admission from completed readiness. */
    b->canonical_object = actor;
    b->canonical_id = id;
    b->canonical_generation = generation;
    if (!object_work(b, actor, &w)) { b->fault = NL_BAD_MEMORY; return; }
    /* No gameplay callbacks run until this synchronous hook returns. Clear
     * epoch flags first; canonical charge identity is committed last. */
    if (!write32(b, b->config.view + 0x140, actor) ||
        !write32(b, b->config.view + 0x1c8, 0) ||
        !write32(b, b->config.view + 0x1cc, 0) ||
        !write32(b, b->config.charge + 24, 0) ||
        !write32(b, b->config.charge + 20, 1) ||
        !write32(b, b->config.charge + 16, generation) ||
        !write32(b, b->config.survival + 16, w) ||
        !write32(b, b->config.survival, actor) ||
        !write32(b, b->config.horse, actor) ||
        !write32(b, b->config.charge, actor)) b->fault = NL_BAD_MEMORY;
}

int nl_bridge_refresh_canonical_work(NLBridge *b) {
    uint32_t w;
    if (!b || !b->initialized || b->fault || !b->canonical_id) return 0;
    if (nl_bridge_lifetime(b, b->canonical_object, b->canonical_id) != NL_LIVE) {
        b->fault = NL_STALE;
        return 0;
    }
    if (!pointer_eq(b, b->config.survival, b->canonical_object) ||
        !pointer_eq(b, b->config.charge, b->canonical_object) ||
        !pointer_eq(b, b->config.horse, b->canonical_object) ||
        !eq(b, b->config.charge + 16, b->canonical_generation)) {
        b->fault = NL_STALE;
        return 0;
    }
    if (!object_work(b, b->canonical_object, &w) ||
        !write32(b, b->config.survival + 16, w)) {
        b->fault = NL_BAD_MEMORY;
        return 0;
    }
    return 1;
}
static int max_bits(float value, uint32_t *bits) {
    union { float f; uint32_t u; } v;
    v.f = value; *bits = v.u;
    /* Positive finite nonzero, using integer bits: no FP comparisons/NaN traps. */
    return !(v.u & 0x80000000u) && (v.u & 0x7fffffffu) &&
        (v.u & 0x7f800000u) != 0x7f800000u;
}

int nl_bridge_publish_actor(void *user, NLContext *c) {
    NLBridge *b = user;
    uint32_t hp, grip, w, i;
    uint32_t s[8], q[8];
    if (!context(b, c) || c->phase != NL_BUILDING || !canonical(b, c) ||
        !eq(b, b->config.survival + 4, 0) || !eq(b, b->config.charge + 4, 0) ||
        !eq(b, b->config.horse + 4, 0) || !eq(b, b->config.routing, 0) ||
        !max_bits(b->config.get_max_hp(c->actor.object), &hp) ||
        !max_bits(b->config.get_max_grip(c->actor.object), &grip) || !work(b, c, &w)) return 0;
    s[0] = q[0] = c->actor.object; s[1] = q[1] = c->generation;
    s[2] = hp; s[3] = grip; s[4] = s[5] = s[6] = s[7] = 0;
    q[2] = q[3] = 0; q[4] = 1; q[5] = q[6] = q[7] = 0;
    /* Disable flags BEFORE overwriting any bank payload. */
    if (!write32(b, b->config.survival_bank + 16, 0) ||
        !write32(b, b->config.charge_bank + 8, 0)) return 0;
    for (i = 0; i < 8; ++i)
        if (!write32(b, b->config.survival_bank + i * 4, s[i]) ||
            !write32(b, b->config.charge_bank + i * 4, q[i])) return 0;
    if (!write32(b, b->config.survival + 8, c->generation) ||
        !write32(b, b->config.survival + 12, b->config.survival_bank) ||
        !write32(b, b->config.survival + 20, w) ||
        !write32(b, b->config.charge + 8, c->generation) ||
        !write32(b, b->config.charge + 12, b->config.charge_bank) ||
        !write32(b, b->config.horse + 12, 0) ||
        !write32(b, b->config.horse + 16, 0)) return 0;
    /* Both complete bank payloads precede either READY flag. Routing is last. */
    return write32(b, b->config.survival_bank + 16, 1) &&
        write32(b, b->config.charge_bank + 8, 1) &&
        write32(b, b->config.survival + 4, c->actor.object) &&
        write32(b, b->config.charge + 4, c->actor.object) &&
        write32(b, b->config.horse + 4, c->actor.object) &&
        write32(b, b->config.routing, c->actor.object);
}
int nl_bridge_refresh_actor_work(NLBridge *b, NLContext *c) {
    uint32_t w;
    return context(b, c) && canonical(b, c) && owned(b, c) && work(b, c, &w) &&
        write32(b, b->config.survival + 20, w);
}
static int empty_or_actor(NLBridge *b, NLAddress a, NLAddress actor) {
    uint32_t v;
    return read32(b, a, &v) && (!v || (nl_address_valid(v, 4) && same(v, actor)));
}
int nl_bridge_unpublish_actor(void *user, NLContext *c) {
    NLBridge *b = user;
    /* P1 may already have final-freed while P2 drains. Do not dereference it or
     * require canonical readiness for clearing this exact P2 publication. */
    if (!actor_context(b, c) || !owned(b, c) ||
        !empty_or_actor(b, b->config.routing, c->actor.object) ||
        !empty_or_actor(b, b->config.horse + 4, c->actor.object) ||
        !empty_or_actor(b, b->config.view + 0x144, c->actor.object)) return 0;
    return write32(b, b->config.routing, 0) &&
        write32(b, b->config.survival_bank + 16, 0) &&
        write32(b, b->config.charge_bank + 8, 0) &&
        write32(b, b->config.view + 0x144, 0) && write32(b, b->config.view + 0xe0, 0) &&
        write32(b, b->config.survival + 4, 0) && write32(b, b->config.survival + 8, 0) &&
        write32(b, b->config.survival + 20, 0) &&
        write32(b, b->config.charge + 4, 0) && write32(b, b->config.charge + 8, 0) &&
        write32(b, b->config.horse + 4, 0) &&
        write32(b, b->config.horse + 12, 0) && write32(b, b->config.horse + 16, 0);
}
int nl_bridge_publish_view(void *user, NLContext *c) {
    NLBridge *b = user;
    uint32_t i;
    if (!context(b, c) || c->phase != NL_BUILDING || !canonical(b, c) || !owned(b, c) ||
        !ready(b, b->config.survival_bank + 16) || !ready(b, b->config.charge_bank + 8) ||
        !eq(b, b->config.view + 0x144, 0)) return 0;
    if (!write32(b, b->config.view + 0x180, 0)) return 0;
    for (i = 0x1c0; i <= 0x1c4; i += 4)
        if (!write32(b, b->config.view + i, 0)) return 0;
    return write32(b, b->config.view + 0xe0, 1) &&
        write32(b, b->config.view + 0x144, c->actor.object);
}
#ifdef NL_HOST_TEST
static int bound_read(void *u, NLAddress a, uint32_t *v) { return read32(u, a, v); }
static int bound_write(void *u, NLAddress a, uint32_t v) { return write32(u, a, v); }
#endif
int nl_bridge_bind(NLBridge *b, NLContext *c) {
    if (!b || !b->initialized || !c) return 0;
    c->user = b;
    c->fn.lifetime = nl_bridge_lifetime;
    c->fn.new_allocation = nl_bridge_new_allocation;
    c->fn.publish_actor = nl_bridge_publish_actor;
    c->fn.unpublish_actor = nl_bridge_unpublish_actor;
    c->fn.publish_view = nl_bridge_publish_view;
#ifdef NL_HOST_TEST
    c->fn.read32 = bound_read; c->fn.write32 = bound_write;
#endif
    return 1;
}
