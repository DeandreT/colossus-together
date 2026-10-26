/* Offline synthetic memory and trusted callbacks; no emulator or game hooks. */
#include "controller.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static struct {
    NLController d;
    NLContext c;
    NLBridge b;
    NLControllerInput in;
    uint32_t memory[32768];
    unsigned creates, prepare, withdraw, validate, published, retired, restart;
    unsigned locks, unlocks, requests, reads, fail_create;
    int intrinsic_result, allow_ack, fail_prepare, reenter, add_intrinsic;
    NLAddress next;
} m;
static uint32_t physical(NLAddress a) { return a & 0x1fffffffu; }
static int read32(void *u, NLAddress a, uint32_t *v) {
    uint32_t i; (void)u; a = physical(a);
    assert(a / 4 < sizeof(m.memory) / sizeof(m.memory[0]));
    for (i = 0; i < m.b.count; ++i) {
        NLBridgeAllocation *r = &m.b.allocations[i];
        if (a >= physical(r->object) && a < physical(r->object) + 0x40)
            assert(r->state != NL_FREED); /* never inspect freed object memory */
    }
    ++m.reads; *v = m.memory[a / 4]; return 1;
}
static int write32(void *u, NLAddress a, uint32_t v) {
    (void)u; a = physical(a);
    assert(a / 4 < sizeof(m.memory) / sizeof(m.memory[0]));
    m.memory[a / 4] = v; return 1;
}
static float maximum(NLAddress a) { (void)a; return 100.0f; }
static NLAddress work(NLAddress a) { (void)a; return 0x7000; }
static NLAddress create(NLAddress def, NLAddress params) {
    NLAddress a; (void)def; (void)params;
    ++m.creates;
    if (m.reenter) assert(nl_controller_pump(&m.d, &m.in) == NL_REJECTED);
    if (m.fail_create == m.creates) return 0;
    a = m.next; m.next += 0x100;
    m.memory[a / 4] = a;
    return a;
}
static NLAddress alias(NLAddress part, NLAddress def, NLAddress params,
                       NLAddress script, NLAddress parent, uint32_t zero, uint32_t one) {
    assert(part && script && parent == m.c.actor.object && !zero && one == 1);
    return create(def, params);
}
static void lock(NLAddress a) { assert(a == m.c.actor.object); ++m.locks; }
static void unlock(NLAddress a) {
    uint32_t i; assert(a == m.c.actor.object);
    for (i = 0; i < m.c.child_count; ++i)
        assert(nl_bridge_lifetime(&m.b, m.c.children[i].object,
                                  m.c.children[i].allocation) == NL_FREED);
    ++m.unlocks; /* deliberately NOT synchronous free */
}
static void request(NLAddress a) {
    assert(a != m.c.canonical_p1.object);
    ++m.requests; m.memory[(a + 4) / 4] |= NL_PENDING_DELETE;
}
static int publish(void *u, NLContext *c) {
    uint32_t i;
    assert(c->intrinsics_validated && m.validate);
    for (i = 0; i < NL_VISUALS; ++i)
        assert(c->visuals[i].attempted && c->visuals[i].owned.allocation);
    ++m.published;
    return nl_bridge_publish_view(u, c);
}
static int prepare(void *u, NLController *d, NLContext *c) {
    uint32_t i, generation = m.b.generation + 1; (void)u;
    assert(d->retirement_ack); ++m.prepare;
    if (m.fail_prepare) return 0;
    memset(c, 0, sizeof(*c));
    assert(nl_bridge_set_generation(&m.b, generation));
    c->generation = c->current_generation = generation;
    c->phase = NL_READY; c->readiness = c->canonical_p1_verified = 1;
    c->canonical_p1 = m.in.canonical_p1;
    c->actor_definition = 0x3000; c->actor_parameters = 0x4000;
    c->header_flags_offset = 4;
    c->fn.create_character = create; c->fn.create_alias = alias;
    c->fn.delete_lock = lock; c->fn.delete_unlock = unlock; c->fn.request_delete = request;
    assert(nl_bridge_bind(&m.b, c)); c->fn.publish_view = publish;
    for (i = 0; i < NL_VISUALS; ++i) {
        c->visuals[i].kind = i == 1 ? NL_ALIAS : NL_CHARACTER;
        c->visuals[i].definition = 0x3000;
        c->visuals[i].parameters = 0x4100 + i * 0x100;
        c->visuals[i].partition = 0x3000; c->visuals[i].script = 0x3000;
        m.memory[(c->visuals[i].parameters + NL_PARAMETER_GP_OFFSET) / 4] = 0x5000 + i * 4;
    }
    return 1;
}
static int withdraw(void *u, NLContext *c) {
    (void)u; assert(c == &m.c); ++m.withdraw;
    /* External render selection/bypass only; bank withdrawal happens in retire. */
    m.memory[(m.b.config.view + 0x144) / 4] = 0;
    return 1;
}
static int validate(void *u, NLContext *c) {
    (void)u; ++m.validate;
    assert(!m.published || c->error || c->phase == NL_ACTIVE);
    if (m.add_intrinsic) {
        NLAddress a = m.next; m.next += 0x100; m.memory[a / 4] = a;
        c->children[c->child_count].object = a;
        c->children[c->child_count++].allocation = nl_bridge_new_allocation(&m.b, a);
        m.add_intrinsic = 0;
    }
    return m.intrinsic_result;
}
static int retired(void *u, const NLContext *c) {
    uint32_t i; (void)u;
    assert(c->phase == NL_QUIESCENT);
    for (i = 0; i < c->child_count; ++i)
        assert(nl_bridge_lifetime(&m.b, c->children[i].object, c->children[i].allocation) == NL_FREED);
    ++m.retired; return m.allow_ack;
}
static int restart(void *u, uint32_t epoch) {
    (void)u; assert(epoch && m.d.retirement_ack && m.c.phase == NL_QUIESCENT);
    ++m.restart; return 1;
}
static void setup(void) {
    NLBridgeConfig cfg = {0};
    NLControllerFunctions f = {0};
    memset(&m, 0, sizeof(m)); m.next = 0x10000;
    m.intrinsic_result = m.allow_ack = 1;
    cfg.read32 = read32; cfg.write32 = write32;
    cfg.get_max_hp = cfg.get_max_grip = maximum; cfg.get_ai_work = work;
    cfg.survival = 0x1000; cfg.survival_bank = 0x1100;
    cfg.charge = 0x1200; cfg.charge_bank = 0x1300;
    cfg.horse = 0x1400; cfg.routing = 0x1500; cfg.view = 0x1600;
    assert(nl_bridge_init(&m.b, &cfg, 1));
    m.memory[0x6000 / 4] = 0x6000;
    m.memory[cfg.survival / 4] = m.memory[cfg.charge / 4] = m.memory[cfg.horse / 4] = 0x6000;
    m.memory[(cfg.charge + 16) / 4] = 1;
    assert(nl_bridge_adopt_canonical(&m.b, 0x6000, 1));
    m.in.canonical_p1.object = m.b.canonical_object;
    m.in.canonical_p1.allocation = m.b.canonical_id;
    m.in.desired_active = m.in.gameplay_ready = 1;
    f.prepare_spawn = prepare; f.withdraw_view = withdraw; f.validate_intrinsics = validate;
    f.on_retired = retired; f.request_team_restart = restart;
    assert(nl_controller_init(&m.d, &m.c, &m.b, &f));
}
static NLResult pump(void) { return nl_controller_pump(&m.d, &m.in); }
static void activate(void) {
    assert(nl_controller_resource_permit(&m.d));
    assert(pump() == NL_OK);
    assert(m.c.phase == NL_BUILDING && m.creates == 4 && !m.validate && !m.published);
    assert(!nl_controller_resource_permit(&m.d));
    assert(pump() == NL_OK);
    assert(m.c.phase == NL_ACTIVE && m.published == 1 && m.c.child_count == 3);
}
static void free_children(void) {
    uint32_t i;
    for (i = 0; i < m.c.child_count; ++i)
        assert(nl_bridge_mark_final_free(&m.b, m.c.children[i].object) == 1);
}
static void drain(void) {
    assert(pump() == NL_OK && m.withdraw == 1 && !m.locks);
    assert(pump() == NL_OK && !m.locks); /* same render boundary */
    ++m.in.completed_render;
    assert(pump() == NL_OK && m.c.phase == NL_DRAINING && m.locks == 1);
    assert(pump() == NL_OK && !m.unlocks);
    free_children();
    m.c.pending_creations = 1;
    assert(pump() == NL_OK && !m.unlocks && !nl_controller_resource_permit(&m.d));
    m.c.pending_creations = 0;
    assert(pump() == NL_OK && m.c.phase == NL_WAIT_PARENT_FREE && m.unlocks == 1);
    assert(pump() == NL_OK && !m.retired && !nl_controller_resource_permit(&m.d));
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    assert(pump() == NL_OK && m.c.phase == NL_QUIESCENT);
}
static void normal(void) {
    setup(); m.reenter = 1; activate(); m.in.resource_barrier = 1;
    m.allow_ack = 0; drain();
    assert(!nl_controller_resource_permit(&m.d) && m.b.count == 5);
    m.allow_ack = 1; assert(pump() == NL_OK);
    assert(nl_controller_resource_permit(&m.d) && m.b.count == 1);
    assert(pump() == NL_OK && m.prepare == 1);
}
static void death(void) {
    setup(); activate(); m.in.team_death = 1; m.in.death_epoch = 42;
    drain(); assert(!m.restart);
    assert(pump() == NL_OK && m.restart == 1);
    assert(pump() == NL_OK && m.restart == 1);
    m.in.death_epoch = 43; m.in.p1_transition = 1;
    assert(pump() == NL_OK && m.restart == 1);
    assert(pump() == NL_OK && m.restart == 1);
}
static void replacement(void) {
    NLObject old;
    setup(); activate(); old = m.c.canonical_p1;
    m.memory[0x6100 / 4] = 0x6100;
    nl_bridge_canonical_admitted(&m.b, 0x6100);
    assert(!m.b.fault);
    m.in.canonical_p1.object = m.b.canonical_object;
    m.in.canonical_p1.allocation = m.b.canonical_id;
    assert(nl_bridge_mark_final_free(&m.b, old.object) == 1);
    drain(); assert(m.c.canonical_p1.object == old.object);
    assert(m.b.count == 2); /* old P1 tombstone NOT ours to acknowledge */
    assert(pump() == NL_OK && m.c.canonical_p1.object == 0x6100 && m.prepare == 2);
}
static void failed_visual(void) {
    NLResult original;
    setup(); m.fail_create = 3;
    assert(pump() == NL_CONSTRUCTOR_FAILED);
    original = m.c.error;
    assert(m.c.phase == NL_DRAINING && m.c.child_count == 1 && !m.published);
    assert(!nl_controller_resource_permit(&m.d));
    free_children(); assert(pump() == NL_OK && m.unlocks == 1);
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    assert(pump() == NL_OK && m.d.retirement_ack && m.c.error == original);
    assert(pump() == NL_LATCHED && m.prepare == 1);
    assert(nl_controller_reprepare(&m.d));
    m.fail_create = 0; assert(pump() == NL_OK && m.prepare == 2 && m.c.phase == NL_BUILDING);
}
static void unknown(void) {
    unsigned reads;
    setup(); activate(); m.in.resource_barrier = 1;
    assert(pump() == NL_OK); ++m.in.completed_render;
    assert(pump() == NL_OK); free_children();
    m.b.allocations[2].id += 100;
    reads = m.reads;
    assert(pump() == NL_STALE && !m.unlocks && !nl_controller_resource_permit(&m.d));
    assert(m.reads == reads);
}
static void intrinsics(void) {
    setup(); m.intrinsic_result = 0; m.add_intrinsic = 1;
    assert(pump() == NL_OK && m.creates == 4);
    assert(pump() == NL_OK && !m.published && m.c.child_count == 4);
    assert(pump() == NL_OK && !m.published);
    m.intrinsic_result = -1;
    assert(pump() == NL_CALLBACK_FAILED && m.c.phase == NL_DRAINING && !m.published);
    free_children(); assert(pump() == NL_OK);
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    assert(pump() == NL_OK && nl_controller_resource_permit(&m.d));
    setup(); m.intrinsic_result = 0; assert(pump() == NL_OK);
    assert(pump() == NL_OK && !m.published);
    m.intrinsic_result = 1; assert(pump() == NL_OK && m.published == 1);
    setup(); assert(pump() == NL_OK);
    m.intrinsic_result = -2;
    assert(pump() != NL_OK && m.c.phase == NL_BUILDING);
    assert(!m.locks && !m.requests && !m.published);
    assert(!nl_controller_resource_permit(&m.d));
}
static void preparation(void) {
    setup(); m.fail_prepare = 1;
    assert(pump() == NL_CALLBACK_FAILED && !m.creates && !m.published);
    assert(pump() == NL_LATCHED && m.prepare == 1);
    assert(nl_controller_reprepare(&m.d));
    m.fail_prepare = 0; assert(pump() == NL_OK && m.creates == 4);
}
static void delayed_cleanup(void) {
    setup(); m.fail_create = 3; m.intrinsic_result = 0; m.add_intrinsic = 1;
    assert(pump() == NL_CONSTRUCTOR_FAILED && m.c.phase == NL_BUILDING);
    assert(!m.locks && !m.published && !nl_controller_resource_permit(&m.d));
    assert(pump() == NL_OK && !m.locks);
    m.intrinsic_result = -1;
    assert(pump() == NL_OK && m.c.phase == NL_DRAINING && m.c.child_count == 2);
    free_children(); assert(pump() == NL_OK);
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    assert(pump() == NL_OK && nl_controller_resource_permit(&m.d));
}
static void empty_failure(void) {
    setup(); m.in.gameplay_ready = 0;
    assert(pump() == NL_OK && !m.creates);
    m.in.gameplay_ready = 1; m.in.resource_barrier = 1;
    assert(pump() == NL_OK && !m.creates);
    m.in.resource_barrier = 0; m.fail_create = 1;
    assert(pump() == NL_CONSTRUCTOR_FAILED && m.c.phase == NL_QUIESCENT);
    assert(!nl_controller_resource_permit(&m.d) && !m.published);
    assert(pump() == NL_OK && nl_controller_resource_permit(&m.d));
    assert(pump() == NL_LATCHED && m.prepare == 1);
}
static void adopt_fixture(void) {
    setup();
    assert(nl_bridge_set_generation(&m.b, 3));
    activate();
    assert(m.c.generation == 4 && m.c.current_generation == 4 && m.b.generation == 4);
}
static void adoption(void) {
    static unsigned char before[sizeof(m)];
    NLController out, prior;
    NLControllerFunctions f;
    NLAddress published;
    unsigned n;
    adopt_fixture(); f = m.d.fn;
    memset(&out, 0, sizeof(out));
    memcpy(before, &m, sizeof(m));
    assert(nl_controller_adopt_active(&out, &m.c, &m.b, &f, m.c.actor.object));
    /* Includes callback counters, object memory, context and bridge. */
    assert(!memcmp(before, &m, sizeof(m)));
    assert(out.initialized == 1 && out.busy == 0 && out.last_generation == 4);
    assert(out.view_exposed == 1 && !out.withdrawal_attempted && !out.withdrawn);
    assert(!out.retirement_ack && !nl_controller_resource_permit(&out));
    assert(out.ctx == &m.c && out.bridge == &m.b);
    assert(nl_controller_pump(&out, &m.in) == NL_OK);
    assert(!memcmp(before, &m, sizeof(m))); /* ACTIVE pump does not recreate */
    for (n = 0; n < 22; ++n) {
        adopt_fixture(); f = m.d.fn; published = m.c.actor.object;
        switch (n) {
        case 0: published += 4; break;
        case 1: --m.c.child_count; break;
        case 2: ++m.c.actor.allocation; break;
        case 3: ++m.c.current_generation; break;
        case 4: m.c.pending_creations = 1; break;
        case 5: m.c.error = NL_CALLBACK_FAILED; break;
        case 6: m.c.withdrawn = 1; break;
        case 7: m.c.busy = 1; break;
        case 8: m.c.held = 1; break;
        case 9: m.c.parent_requested = 1; break;
        case 10: m.c.readiness = 0; break;
        case 11: m.c.resource_barrier = 1; break;
        case 12: m.c.intrinsics_validated = 0; break;
        case 13: ++m.c.canonical_p1.allocation; break;
        case 14: ++m.c.children[0].allocation; break;
        case 15: m.c.fn.delete_unlock = 0; break;
        case 16: f.withdraw_view = 0; break;
        case 17: m.c.phase = NL_QUIESCENT; break;
        case 18: m.c.visuals[1].owned = m.c.visuals[0].owned; break;
        case 19: m.b.allocations[1].state = NL_FREED; break;
        case 20: m.c.cleanup_error = NL_STALE; break;
        case 21: published ^= 0x80000000u; break; /* exact, not physical alias */
        default: assert(0);
        }
        memset(&out, 0xa5, sizeof(out)); out.initialized = 0;
        memcpy(&prior, &out, sizeof(out));
        memcpy(before, &m, sizeof(m));
        assert(!nl_controller_adopt_active(&out, &m.c, &m.b, &f, published));
        assert(!memcmp(&prior, &out, sizeof(out)));
        assert(!memcmp(before, &m, sizeof(m)));
    }
}
static void active_inventory(void) {
    unsigned validates;
    setup(); activate(); m.in.desired_active = 0; m.intrinsic_result = 0;
    assert(pump() == NL_OK && m.withdraw == 1);
    validates = m.validate;
    assert(pump() == NL_OK && m.validate == validates && !m.locks);
    ++m.in.completed_render;
    assert(pump() == NL_OK && m.validate == validates + 1 && !m.locks);
    assert(pump() == NL_OK && m.validate == validates + 2 && !m.locks);
    m.intrinsic_result = 1; m.add_intrinsic = 1;
    assert(pump() == NL_OK && m.c.phase == NL_DRAINING);
    assert(m.c.child_count == 4 && m.withdraw == 1 && m.locks == 1);
    free_children(); assert(pump() == NL_OK);
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    assert(pump() == NL_OK && m.d.retirement_ack);

    setup(); activate(); m.in.desired_active = 0;
    assert(pump() == NL_OK); ++m.in.completed_render;
    m.intrinsic_result = -1;
    assert(pump() == NL_CALLBACK_FAILED && !m.locks && !m.requests);
    validates = m.validate; m.intrinsic_result = 1;
    assert(pump() == NL_LATCHED && !m.locks && m.validate == validates && m.withdraw == 1);
}
static void finish_cancel(void) {
    uint32_t i;
    assert(m.c.phase == NL_DRAINING && m.c.failed_build_retirement);
    assert(m.c.error == NL_OK && m.d.fault == NL_OK && m.locks == 1);
    assert(pump() == NL_OK && !m.unlocks);
    for (i = 1; i < m.c.child_count; ++i)
        assert(nl_bridge_mark_final_free(&m.b, m.c.children[i].object) == 1);
    assert(pump() == NL_OK && !m.unlocks && !nl_controller_resource_permit(&m.d));
    assert(nl_bridge_mark_final_free(&m.b, m.c.children[0].object) == 1);
    m.c.pending_creations = 1;
    assert(pump() == NL_OK && !m.unlocks);
    m.c.pending_creations = 0;
    assert(pump() == NL_OK && m.unlocks == 1 && m.c.phase == NL_WAIT_PARENT_FREE);
    assert(pump() == NL_OK && !m.retired && !nl_controller_resource_permit(&m.d));
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    m.allow_ack = 0;
    assert(pump() == NL_OK && m.c.phase == NL_QUIESCENT);
    assert(!nl_controller_resource_permit(&m.d));
    m.allow_ack = 1;
    assert(pump() == NL_OK && nl_controller_resource_permit(&m.d));
    assert(!m.c.error && !m.c.cleanup_error && !m.d.fault && !m.published);
}
static void building_cancellation(void) {
    unsigned reason;
    for (reason = 0; reason < 5; ++reason) {
        NLObject canonical;
        uint32_t generation;
        setup();
        assert(pump() == NL_OK && m.creates == 4 && m.c.phase == NL_BUILDING);
        assert(!m.validate && !m.published);
        generation = m.c.generation; canonical = m.c.canonical_p1;
        switch (reason) {
        case 0: m.in.resource_barrier = 1; break;
        case 1: m.in.desired_active = 0; break;
        case 2:
            m.memory[0x6100 / 4] = 0x6100;
            nl_bridge_canonical_admitted(&m.b, 0x6100);
            assert(!m.b.fault);
            m.in.canonical_p1.object = m.b.canonical_object;
            m.in.canonical_p1.allocation = m.b.canonical_id;
            assert(nl_bridge_mark_final_free(&m.b, canonical.object) == 1);
            break;
        case 3: m.in.team_death = 1; m.in.death_epoch = 7; break;
        default: m.in.gameplay_ready = 0; break;
        }
        m.intrinsic_result = 0; m.add_intrinsic = 1;
        assert(pump() == NL_OK && m.c.phase == NL_BUILDING && m.withdraw == 1);
        assert(m.d.retiring && m.c.teardown_needed && !m.d.fault && !m.c.error);
        assert(!m.locks && !m.requests && !m.restart && !m.published);
        assert(pump() == NL_OK && !m.locks && !nl_controller_resource_permit(&m.d));
        /* Clearing a stop does not abandon an already-started cancellation. */
        if (reason == 1) m.in.desired_active = 1;
        m.intrinsic_result = 1; m.c.pending_creations = 1;
        assert(pump() == NL_OK && !m.locks && m.c.phase == NL_BUILDING);
        m.c.pending_creations = 0;
        assert(pump() == NL_OK && m.c.phase == NL_DRAINING && m.c.child_count == 4);
        assert(m.c.generation == generation && m.c.canonical_p1.object == canonical.object);
        finish_cancel();
        if (reason == 3) {
            assert(!m.restart);
            assert(pump() == NL_OK && m.restart == 1);
            assert(pump() == NL_OK && m.restart == 1 && m.prepare == 1);
        } else if (reason != 1 && reason != 2) {
            assert(pump() == NL_OK && m.prepare == 1);
        }
        m.in.resource_barrier = m.in.team_death = 0;
        m.in.desired_active = m.in.gameplay_ready = 1;
        assert(pump() == NL_OK && m.c.phase == NL_BUILDING);
        assert(m.c.generation == generation + 1 && m.prepare == 2 && m.creates == 8);
        assert(!m.c.error && !m.d.fault && !m.published);
        assert(pump() == NL_OK && m.c.phase == NL_ACTIVE && m.published == 1);
    }
}
static void cancellation_faults(void) {
    unsigned validates;
    setup(); assert(pump() == NL_OK);
    m.in.resource_barrier = 1; m.intrinsic_result = -2;
    assert(pump() == NL_CALLBACK_FAILED && m.c.phase == NL_BUILDING);
    assert(m.c.error == NL_CALLBACK_FAILED && m.d.fault == NL_CALLBACK_FAILED);
    assert(!m.locks && !m.requests && !m.published && !nl_controller_resource_permit(&m.d));
    validates = m.validate; m.intrinsic_result = 1;
    assert(pump() == NL_LATCHED && m.validate == validates && !m.locks);
    assert(!nl_controller_reprepare(&m.d));
    setup(); assert(pump() == NL_OK);
    m.in.desired_active = 0; m.intrinsic_result = -1;
    assert(pump() == NL_CALLBACK_FAILED && m.c.phase == NL_DRAINING);
    assert(m.c.error == NL_CALLBACK_FAILED && m.d.fault == NL_CALLBACK_FAILED);
    free_children(); assert(pump() == NL_OK);
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    assert(pump() == NL_OK && m.d.retirement_ack);
    m.in.desired_active = 1;
    assert(pump() == NL_LATCHED && m.prepare == 1);
    setup(); assert(pump() == NL_OK);
    m.c.error = NL_CONSTRUCTOR_FAILED; m.c.teardown_needed = 1;
    m.in.resource_barrier = 1;
    assert(cancel_build(&m.c) == NL_LATCHED && m.c.error == NL_CONSTRUCTOR_FAILED);
    assert(pump() == NL_OK && m.c.phase == NL_DRAINING);
    assert(m.d.fault == NL_CONSTRUCTOR_FAILED && m.c.error == NL_CONSTRUCTOR_FAILED);
    free_children(); assert(pump() == NL_OK);
    assert(nl_bridge_mark_final_free(&m.b, m.c.actor.object) == 1);
    assert(pump() == NL_OK && m.d.retirement_ack);
    m.in.resource_barrier = 0;
    assert(pump() == NL_LATCHED && m.prepare == 1);
    setup(); assert(pump() == NL_OK);
    m.in.resource_barrier = 1;
    ++m.c.visuals[0].owned.allocation;
    assert(pump() == NL_STALE && !m.locks && !m.requests && !m.published);
    assert(m.c.error == NL_STALE && !nl_controller_resource_permit(&m.d));
    assert(pump() == NL_LATCHED && !m.locks);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    if (!strcmp(argv[1], "normal")) normal();
    else if (!strcmp(argv[1], "death")) death();
    else if (!strcmp(argv[1], "replacement")) replacement();
    else if (!strcmp(argv[1], "failed-visual")) failed_visual();
    else if (!strcmp(argv[1], "unknown")) unknown();
    else if (!strcmp(argv[1], "intrinsics")) intrinsics();
    else if (!strcmp(argv[1], "preparation")) preparation();
    else if (!strcmp(argv[1], "delayed-cleanup")) delayed_cleanup();
    else if (!strcmp(argv[1], "empty-failure")) empty_failure();
    else if (!strcmp(argv[1], "adoption")) adoption();
    else if (!strcmp(argv[1], "active-inventory")) active_inventory();
    else if (!strcmp(argv[1], "building-cancellation")) building_cancellation();
    else if (!strcmp(argv[1], "cancellation-faults")) cancellation_faults();
    else assert(0);
    puts("ok"); return 0;
}
