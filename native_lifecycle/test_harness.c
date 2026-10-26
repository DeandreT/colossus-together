/* Synthetic host model. No emulator, game code or external data. */
#include "lifecycle.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct { NLAddress addr; uint32_t alloc, words[16]; NLLifetime life; } Obj;
static struct {
    NLContext c;
    Obj objs[40];
    unsigned count, reads, writes, creates, requests[40], locks, unlocks;
    int nested, null_create, bad_publish, bad_read, bad_write, stale_child;
    int reenter, early_parent_free, auto_children;
    char log[256]; unsigned loglen;
    uint32_t p1_before[16];
    uint32_t gp_parent;
    uint32_t retired_address, retired_id;
} m;
static void log_event(char c) { m.log[m.loglen++] = c; m.log[m.loglen] = 0; }
static Obj *find(NLAddress a) {
    unsigned i; a &= 0x1fffffffu;
    for (i = 0; i < m.count; ++i) if (m.objs[i].addr == a) return &m.objs[i];
    return NULL;
}
static Obj *add(NLAddress a) {
    Obj *o = &m.objs[m.count++]; unsigned i;
    o->addr = a; o->alloc = m.count + 100; o->life = NL_LIVE;
    for (i = 0; i < 16; ++i) o->words[i] = 0xcab00000u + i;
    o->words[1] = 0;
    return o;
}
static NLObject pair(Obj *o) { NLObject r = {o->addr, o->alloc}; return r; }
static NLLifetime lifetime(void *u, NLAddress a, uint32_t id) {
    Obj *o = find(a); (void)u;
    if (id && a == m.retired_address && id == m.retired_id) return NL_FREED;
    if (!o || id != o->alloc) return NL_MISMATCH;
    return o->life;
}
static uint32_t allocation(void *u, NLAddress a) {
    Obj *o = find(a); (void)u; assert(o && o->life == NL_LIVE); return o->alloc;
}
static int read32(void *u, NLAddress a, uint32_t *v) {
    unsigned i; (void)u; ++m.reads;
    if (m.bad_read) return 0;
    if (a >= 0x4020 && a <= 0x4320 && (a & 0xff) == 0x20) { *v = 0x9000; return 1; }
    for (i = 0; i < m.count; ++i) {
        Obj *o = &m.objs[i];
        if (a >= o->addr && a < o->addr + sizeof(o->words)) {
            assert(o->life == NL_LIVE); *v = o->words[(a - o->addr) / 4]; return 1;
        }
    }
    return 0;
}
static int write32(void *u, NLAddress a, uint32_t v) {
    (void)u;
    if (m.bad_write) return 0;
    assert(a == 0x9000 && v == m.c.actor.object);
    assert(find(m.c.actor.object)->life == NL_LIVE);
    ++m.writes; m.gp_parent = v; log_event('G'); return 1;
}
static void lock(NLAddress a) { assert(a == m.c.actor.object); ++m.locks; log_event('L'); }
static void request(NLAddress a) {
    Obj *o = find(a); unsigned idx = (unsigned)(o - m.objs);
    assert(o && o->life == NL_LIVE); assert(!m.requests[idx]++);
    o->words[1] |= NL_PENDING_DELETE;
    if (a == m.c.actor.object) {
        log_event('P');
        assert(m.c.held == 1 && m.c.parent_requested == 1);
        if (m.reenter) assert(begin_retire(&m.c) == NL_REJECTED);
        if (m.reenter) assert(retire_failed_build(&m.c) == NL_REJECTED);
        if (m.auto_children) {
            unsigned i;
            for (i = 0; i < m.c.child_count; ++i)
                request(m.c.children[i].object);
        }
        if (m.nested) {
            request(m.c.children[0].object);
            find(m.c.children[1].object)->life = NL_FREED;
        }
        if (m.stale_child) find(m.c.children[2].object)->alloc++;
        if (m.early_parent_free) o->life = NL_FREED;
    } else {
        log_event('C');
        if (m.nested && a == m.c.children[2].object) request(m.c.children[3].object);
    }
}
static void unlock(NLAddress a) {
    assert(a == m.c.actor.object && m.c.held == 1);
    ++m.unlocks; log_event('R'); find(a)->life = NL_FREED;
    assert(release_parent(&m.c) == NL_REJECTED);
}
static int publish(void *u, NLContext *c) {
    (void)u; assert(c->phase == NL_BUILDING && c->actor.allocation);
    log_event('B'); return !m.bad_publish;
}
static int unpublish(void *u, NLContext *c) {
    (void)u; assert(c->held && c->parent_requested); log_event('U'); return !m.bad_publish;
}
static int view(void *u, NLContext *c) {
    (void)u; assert(c->phase == NL_BUILDING && c->intrinsics_validated);
    log_event('V'); return !m.bad_publish;
}
static NLAddress create(NLAddress def, NLAddress params) {
    assert(def == 0x3000 && params >= 0x4000 && params <= 0x4300);
    ++m.creates; log_event('N');
    if (m.null_create) return 0;
    if (params != 0x4000) {
        assert(m.gp_parent == m.c.actor.object);
        assert(find(m.c.actor.object)->words[0] == 0xcab00000u);
    }
    return add(0x10000 + m.creates * 0x100)->addr;
}
static NLAddress alias(NLAddress partition, NLAddress def, NLAddress params,
                       NLAddress script, NLAddress parent, uint32_t z, uint32_t one) {
    assert(partition == 0x5000 && script == 0x6000);
    assert(parent == m.c.actor.object && z == 0 && one == 1);
    return create(def, params);
}
static void setup(int active) {
    unsigned i; NLContext *c = &m.c;
    memset(&m, 0, sizeof(m));
    c->fn.delete_lock = lock; c->fn.request_delete = request; c->fn.delete_unlock = unlock;
    c->fn.create_character = create; c->fn.create_alias = alias;
    c->fn.lifetime = lifetime; c->fn.new_allocation = allocation;
    c->fn.publish_actor = publish; c->fn.unpublish_actor = unpublish; c->fn.publish_view = view;
    c->fn.read32 = read32; c->fn.write32 = write32;
    c->generation = c->current_generation = 7;
    c->canonical_p1 = pair(add(0x1000));
    memcpy(m.p1_before, m.objs[0].words, sizeof(m.p1_before));
    c->phase = active ? NL_ACTIVE : NL_READY;
    c->withdrawn = c->readiness = c->canonical_p1_verified = 1;
    c->actor_definition = 0x3000; c->actor_parameters = 0x4000;
    c->header_flags_offset = 4;
    for (i = 0; i < NL_VISUALS; ++i) {
        c->visuals[i].kind = i == 1 ? NL_CHARACTER : NL_ALIAS;
        c->visuals[i].definition = 0x3000;
        c->visuals[i].parameters = 0x4100 + i * 0x100;
        c->visuals[i].partition = 0x5000; c->visuals[i].script = 0x6000;
    }
    if (active) {
        c->actor = pair(add(0x2000)); c->child_count = 4;
        for (i = 0; i < c->child_count; ++i) c->children[i] = pair(add(0x7000 + i * 0x100));
    }
}
static void check_canaries(void) {
    unsigned i, j;
    assert(memcmp(m.p1_before, m.objs[0].words, sizeof(m.p1_before)) == 0);
    for (i = 1; i < m.count; ++i)
        for (j = 2; j < 16; ++j) assert(m.objs[i].words[j] == 0xcab00000u + j);
}
static void finish_failed_build(NLResult original) {
    NLContext *c = &m.c; unsigned i;
    assert(c->phase == NL_DRAINING && c->held && c->parent_requested);
    assert(c->error == original && c->cleanup_error == NL_OK);
    assert(begin_retire(c) == (original ? NL_LATCHED : NL_REJECTED));
    assert(retire_failed_build(c) == NL_REJECTED);
    assert(release_parent(c) == NL_REJECTED);
    c->allchild_final = 1;
    if (c->child_count) assert(release_parent(c) == NL_REJECTED);
    for (i = 0; i < c->child_count; ++i)
        find(c->children[i].object)->life = NL_FREED;
    c->pending_creations = 1;
    assert(release_parent(c) == NL_REJECTED);
    c->pending_creations = 0;
    assert(release_parent(c) == NL_OK);
    assert(c->phase == NL_WAIT_PARENT_FREE && !c->held);
    assert(c->error == original && m.locks == 1 && m.unlocks == 1);
    assert(release_parent(c) == NL_REJECTED);
}
int main(int argc, char **argv) {
    NLContext *c = &m.c; unsigned i;
    assert(argc == 2);
    if (!strcmp(argv[1], "retire")) {
        setup(1); m.nested = m.reenter = 1;
        assert(begin_retire(c) == NL_OK); assert(!strcmp(m.log, "LPCCCU"));
        assert(c->phase == NL_DRAINING && c->held == 1 && m.locks == 1);
        assert(begin_retire(c) == NL_REJECTED);
        assert(release_parent(c) == NL_REJECTED);
        c->allchild_final = 1; assert(release_parent(c) == NL_REJECTED);
        for (i = 0; i < c->child_count; ++i) find(c->children[i].object)->life = NL_FREED;
        c->pending_creations = 1; assert(release_parent(c) == NL_REJECTED);
        c->pending_creations = 0; assert(release_parent(c) == NL_OK);
        assert(c->phase == NL_WAIT_PARENT_FREE && !c->held && m.unlocks == 1);
        assert(release_parent(c) == NL_REJECTED && begin_retire(c) == NL_REJECTED);
    } else if (!strcmp(argv[1], "reused_child")) {
        setup(1);
        m.retired_address = c->children[0].object;
        m.retired_id = 999;
        c->children[1] = c->children[0];
        c->children[0].allocation = m.retired_id;
        c->child_count = 2;
        assert(begin_retire(c) == NL_OK);
        assert(m.locks == 1 && m.requests[1] == 1 && m.requests[2] == 1);
        assert(m.loglen == 4 && !strcmp(m.log, "LPCU"));
        c->allchild_final = 1;
        assert(release_parent(c) == NL_REJECTED);
        find(m.retired_address)->life = NL_FREED;
        assert(release_parent(c) == NL_OK && m.unlocks == 1);
    } else if (!strcmp(argv[1], "spawn")) {
        setup(0); assert(spawn_actor(c) == NL_OK);
        assert(!strcmp(m.log, "NB") && c->phase == NL_BUILDING);
        assert(spawn_actor(c) == NL_REJECTED);
        assert(commit_active(c) == NL_REJECTED);
        for (i = 0; i < NL_VISUALS; ++i) {
            assert(spawn_visual(c, i) == NL_OK);
            assert(spawn_visual(c, i) == NL_REJECTED);
        }
        assert(spawn_visual(c, 3) == NL_REJECTED);
        assert(commit_active(c) == NL_REJECTED);
        c->intrinsics_validated = 1; assert(commit_active(c) == NL_OK);
        assert(c->phase == NL_ACTIVE && m.log[m.loglen - 1] == 'V');
        assert(commit_active(c) == NL_REJECTED && m.writes == 3);
    } else if (!strcmp(argv[1], "guards")) {
        setup(1); c->current_generation++; assert(begin_retire(c) == NL_REJECTED);
        setup(1); c->withdrawn = 0; assert(begin_retire(c) == NL_REJECTED);
        setup(1); c->child_count = 33; assert(begin_retire(c) == NL_REJECTED);
        setup(1); c->actor.allocation++; assert(begin_retire(c) == NL_REJECTED);
        setup(1); c->children[0] = c->canonical_p1; assert(begin_retire(c) == NL_REJECTED);
        setup(1); c->children[1] = c->children[0]; assert(begin_retire(c) == NL_REJECTED);
        setup(0); c->resource_barrier = 1; assert(spawn_actor(c) == NL_REJECTED);
        setup(0); c->readiness = 0; assert(spawn_actor(c) == NL_REJECTED);
        setup(0); c->canonical_p1_verified = 0; assert(spawn_actor(c) == NL_REJECTED);
        setup(0); c->canonical_p1.allocation++; assert(spawn_actor(c) == NL_REJECTED);
        setup(0); c->actor_parameters = 0x1ffffff; assert(spawn_actor(c) == NL_REJECTED);
        assert(!m.creates && !m.writes && !m.locks);
    } else if (!strcmp(argv[1], "failures")) {
        setup(1); m.stale_child = 1; assert(begin_retire(c) == NL_STALE);
        assert(c->held && c->teardown_needed && !strchr(m.log, 'U'));
        assert(begin_retire(c) == NL_LATCHED && release_parent(c) == NL_LATCHED);
        setup(1); m.bad_read = 1; assert(begin_retire(c) == NL_BAD_MEMORY && c->held);
        setup(1); m.early_parent_free = 1; assert(begin_retire(c) == NL_STALE && c->held);
        setup(1); m.bad_publish = 1; assert(begin_retire(c) == NL_CALLBACK_FAILED && c->held);
        setup(0); m.null_create = 1; assert(spawn_actor(c) == NL_CONSTRUCTOR_FAILED);
        assert(spawn_actor(c) == NL_LATCHED && m.creates == 1 && c->teardown_needed);
        setup(0); assert(spawn_actor(c) == NL_OK); m.null_create = 1;
        assert(spawn_visual(c, 0) == NL_CONSTRUCTOR_FAILED);
        assert(spawn_visual(c, 0) == NL_LATCHED && c->actor.object && c->teardown_needed);
        setup(0); m.bad_publish = 1; assert(spawn_actor(c) == NL_CALLBACK_FAILED);
        assert(c->actor.object && c->actor.allocation);
        setup(0); assert(spawn_actor(c) == NL_OK); m.bad_write = 1;
        assert(spawn_visual(c, 0) == NL_BAD_MEMORY && m.creates == 1);
    } else if (!strcmp(argv[1], "cancel-build")) {
        setup(0); assert(spawn_actor(c) == NL_OK);
        for (i = 0; i < NL_VISUALS; ++i) assert(spawn_visual(c, i) == NL_OK);
        c->children[0] = pair(add(0x7000)); c->child_count = 1;
        c->teardown_needed = 1; c->readiness = 0; c->resource_barrier = 1;
        assert(cancel_build(c) == NL_OK);
        assert(c->failed_build_retirement && c->child_count == 4 && !c->error);
        assert(!strchr(m.log, 'V'));
        assert(cancel_build(c) == NL_REJECTED);
        finish_failed_build(NL_OK);
        assert(!c->cleanup_error);
        /* Preserve old-FREED/new-LIVE identities at a reused child address. */
        setup(0); assert(spawn_actor(c) == NL_OK);
        assert(spawn_visual(c, 0) == NL_OK);
        c->children[0] = c->visuals[0].owned;
        m.retired_address = c->children[0].object; m.retired_id = 999;
        c->children[0].allocation = m.retired_id;
        c->children[1] = c->visuals[0].owned; c->child_count = 2;
        c->teardown_needed = 1;
        assert(cancel_build(c) == NL_OK && c->child_count == 2);
        finish_failed_build(NL_OK);
    } else if (!strcmp(argv[1], "cancel-build-guards")) {
        NLContext before;
        setup(0); assert(cancel_build(c) == NL_REJECTED);
        assert(spawn_actor(c) == NL_OK);
        assert(cancel_build(c) == NL_REJECTED); /* explicit teardown required */
        c->teardown_needed = 1;
        c->pending_creations = 1; assert(cancel_build(c) == NL_REJECTED); c->pending_creations = 0;
        c->withdrawn = 0; assert(cancel_build(c) == NL_REJECTED); c->withdrawn = 1;
        c->busy = 1; assert(cancel_build(c) == NL_REJECTED); c->busy = 0;
        ++c->current_generation; assert(cancel_build(c) == NL_REJECTED); --c->current_generation;
        c->error = NL_CONSTRUCTOR_FAILED; before = *c;
        assert(cancel_build(c) == NL_LATCHED && !memcmp(c, &before, sizeof(before)));
        assert(!m.locks && !m.unlocks);
        assert(retire_failed_build(c) == NL_OK);
        finish_failed_build(NL_CONSTRUCTOR_FAILED);
        setup(0); assert(spawn_actor(c) == NL_OK); c->teardown_needed = 1;
        c->children[0] = pair(add(0x7000)); c->child_count = 1;
        ++c->children[0].allocation; before = *c;
        assert(cancel_build(c) == NL_REJECTED && !memcmp(c, &before, sizeof(before)));
        assert(!m.locks && !m.unlocks);
        setup(0); assert(spawn_actor(c) == NL_OK); c->teardown_needed = 1;
        m.bad_publish = 1;
        assert(cancel_build(c) == NL_CALLBACK_FAILED && c->cleanup_error == NL_CALLBACK_FAILED);
        assert(c->error == NL_CALLBACK_FAILED && c->held && m.locks == 1);
        assert(cancel_build(c) == NL_LATCHED && release_parent(c) == NL_LATCHED);
    } else if (!strcmp(argv[1], "failed-build")) {
        NLObject visual;
        setup(0); assert(spawn_actor(c) == NL_OK);
        assert(spawn_visual(c, 1) == NL_OK); visual = c->visuals[1].owned;
        c->children[0] = pair(add(0x7000)); /* constructor-owned intrinsic */
        c->children[1] = visual; c->child_count = 2; /* already captured visual */
        m.null_create = 1;
        assert(spawn_visual(c, 2) == NL_CONSTRUCTOR_FAILED);
        assert(begin_retire(c) == NL_LATCHED);
        c->canonical_p1_verified = c->readiness = 0;
        c->resource_barrier = 1;
        c->canonical_p1.allocation++; /* current canonical provenance not required */
        m.auto_children = m.reenter = 1;
        assert(retire_failed_build(c) == NL_OK);
        assert(c->child_count == 2 && c->visuals[1].owned.object == visual.object);
        assert(c->visuals[1].owned.allocation == visual.allocation);
        finish_failed_build(NL_CONSTRUCTOR_FAILED);
        assert(c->resource_barrier == 1); /* only the host owns resource release */
        /* Visual not captured by the host must also enter the owned list. */
        setup(0); assert(spawn_actor(c) == NL_OK);
        assert(spawn_visual(c, 0) == NL_OK); visual = c->visuals[0].owned;
        c->children[0] = pair(add(0x7000)); c->child_count = 1;
        m.null_create = 1; assert(spawn_visual(c, 2) == NL_CONSTRUCTOR_FAILED);
        assert(retire_failed_build(c) == NL_OK);
        assert(c->child_count == 2 && c->children[1].object == visual.object);
        finish_failed_build(NL_CONSTRUCTOR_FAILED);
    } else if (!strcmp(argv[1], "failed-build-callback")) {
        setup(0); m.bad_publish = 1;
        assert(spawn_actor(c) == NL_CALLBACK_FAILED);
        assert(retire_failed_build(c) == NL_CALLBACK_FAILED);
        assert(c->error == NL_CALLBACK_FAILED && c->cleanup_error == NL_CALLBACK_FAILED);
        assert(c->held && m.locks == 1 && c->parent_requested);
        m.bad_publish = 0;
        assert(retire_failed_build(c) == NL_LATCHED);
        c->allchild_final = 1; assert(release_parent(c) == NL_LATCHED);
        assert(m.locks == 1 && !m.unlocks);
        /* A failed publish can be cleaned if unpublish confirms bank removal. */
        setup(0); m.bad_publish = 1;
        assert(spawn_actor(c) == NL_CALLBACK_FAILED); m.bad_publish = 0;
        assert(retire_failed_build(c) == NL_OK);
        finish_failed_build(NL_CALLBACK_FAILED);
        setup(0); assert(spawn_actor(c) == NL_OK); m.null_create = 1;
        assert(spawn_visual(c, 0) == NL_CONSTRUCTOR_FAILED); m.bad_read = 1;
        c->children[0] = pair(add(0x7000)); c->child_count = 1;
        assert(retire_failed_build(c) == NL_BAD_MEMORY);
        assert(c->error == NL_CONSTRUCTOR_FAILED && c->cleanup_error == NL_BAD_MEMORY);
        assert(c->held && release_parent(c) == NL_LATCHED && !m.unlocks);
    } else if (!strcmp(argv[1], "failed-build-empty")) {
        setup(0); m.null_create = 1;
        assert(spawn_actor(c) == NL_CONSTRUCTOR_FAILED);
        c->pending_creations = 1; assert(retire_failed_build(c) == NL_REJECTED);
        c->pending_creations = 0; c->visuals[0].owned.allocation = 12;
        assert(retire_failed_build(c) == NL_REJECTED);
        c->visuals[0].owned.allocation = 0;
        c->children[0] = pair(add(0x7000)); c->child_count = 1;
        assert(retire_failed_build(c) == NL_REJECTED); c->child_count = 0;
        assert(retire_failed_build(c) == NL_OK);
        assert(c->phase == NL_QUIESCENT && c->allchild_final);
        assert(c->error == NL_CONSTRUCTOR_FAILED && !c->cleanup_error);
        assert(!m.locks && !m.unlocks && !c->held && !c->parent_requested);
        assert(!strchr(m.log, 'P') && !strchr(m.log, 'U'));
        assert(retire_failed_build(c) == NL_REJECTED);
        assert(spawn_actor(c) == NL_LATCHED);
    } else if (!strcmp(argv[1], "failed-build-guards")) {
        setup(0); assert(retire_failed_build(c) == NL_REJECTED);
        assert(spawn_actor(c) == NL_OK);
        assert(retire_failed_build(c) == NL_REJECTED);
        m.null_create = 1; assert(spawn_visual(c, 0) == NL_CONSTRUCTOR_FAILED);
        c->busy = 1; assert(retire_failed_build(c) == NL_REJECTED); c->busy = 0;
        c->withdrawn = 0; assert(retire_failed_build(c) == NL_REJECTED); c->withdrawn = 1;
        c->teardown_needed = 0; assert(retire_failed_build(c) == NL_REJECTED); c->teardown_needed = 1;
        c->pending_creations = 1; assert(retire_failed_build(c) == NL_REJECTED); c->pending_creations = 0;
        c->current_generation++; assert(retire_failed_build(c) == NL_REJECTED); c->current_generation--;
        c->actor.allocation++; assert(retire_failed_build(c) == NL_REJECTED); c->actor.allocation--;
        c->visuals[0].owned = pair(add(0x7000));
        c->visuals[0].owned.allocation++; assert(retire_failed_build(c) == NL_REJECTED);
        c->visuals[0].owned.allocation--;
        c->children[0] = c->visuals[0].owned; c->child_count = 1;
        c->children[0].allocation++; assert(retire_failed_build(c) == NL_REJECTED);
        c->children[0].allocation--;
        c->children[1].object = c->children[1].allocation = 0; c->child_count = 2;
        assert(retire_failed_build(c) == NL_REJECTED); c->child_count = 1;
        assert(!m.locks && !m.unlocks);
        assert(retire_failed_build(c) == NL_OK);
        finish_failed_build(NL_CONSTRUCTOR_FAILED);
    } else if (!strcmp(argv[1], "addresses")) {
        setup(0);
        assert(nl_address_valid(0x1000, 4)); assert(nl_address_valid(0x81fffffc, 4));
        assert(nl_address_valid(0xa1fffffc, 4)); assert(!nl_address_valid(0x81fffffc, 8));
        assert(!nl_address_valid(0x02000000, 4)); assert(!nl_address_valid(0x90000000, 4));
        assert(!nl_address_valid(0x1001, 4)); assert(!nl_address_valid(0, 4));
        assert(!nl_address_valid(0xfffffffcu, 8)); assert(!nl_address_valid(0x1000, 0));
        assert(begin_retire(NULL) == NL_REJECTED);
    } else if (!strcmp(argv[1], "bounds")) {
        setup(1);
        for (i = c->child_count; i < NL_MAX_CHILDREN; ++i)
            c->children[i] = pair(add(0x8000 + i * 0x100));
        c->child_count = NL_MAX_CHILDREN;
        /* An earlier external request must not be duplicated. */
        find(c->children[5].object)->words[1] = NL_PENDING_DELETE;
        assert(begin_retire(c) == NL_OK);
        assert(m.requests[7] == 0 && m.locks == 1);
        for (i = 0; i < c->child_count; ++i) find(c->children[i].object)->life = NL_FREED;
        c->allchild_final = 1; c->current_generation++;
        assert(release_parent(c) == NL_REJECTED && !m.unlocks);
        c->current_generation--; assert(release_parent(c) == NL_OK);
    } else if (!strcmp(argv[1], "cycles")) {
        unsigned cycle;
        setup(0);
        for (cycle = 0; cycle < 2; ++cycle) {
            assert(spawn_actor(c) == NL_OK);
            for (i = 0; i < NL_VISUALS; ++i) assert(spawn_visual(c, i) == NL_OK);
            c->intrinsics_validated = 1; assert(commit_active(c) == NL_OK);
            for (i = 0; i < NL_VISUALS; ++i) c->children[i] = c->visuals[i].owned;
            c->child_count = NL_VISUALS;
            assert(begin_retire(c) == NL_OK);
            for (i = 0; i < NL_VISUALS; ++i) find(c->children[i].object)->life = NL_FREED;
            c->allchild_final = 1; assert(release_parent(c) == NL_OK);
            assert(find(c->actor.object)->life == NL_FREED);
            /* Host consumes actual final-free, then explicitly provisions a
             * fresh transaction. The helper never infers or auto-retries it. */
            c->phase = NL_QUIESCENT;
            memset(&c->actor, 0, sizeof(c->actor));
            c->parent_requested = c->child_count = c->allchild_final = 0;
            for (i = 0; i < NL_VISUALS; ++i) {
                c->visuals[i].attempted = 0;
                memset(&c->visuals[i].owned, 0, sizeof(c->visuals[i].owned));
            }
        }
        assert(m.locks == 2 && m.unlocks == 2 && m.writes == 6);
    } else return 2;
    check_canaries(); puts("ok"); return 0;
}
