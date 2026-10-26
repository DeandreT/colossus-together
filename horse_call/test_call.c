/* Synthetic identities and camera transactions; not gameplay qualification. */
#include "call.h"
#include <assert.h>
#include <string.h>

typedef struct {
    HCSnapshot world;
    HCRiding ride;
    HCStatus prepare, commit, end, snapshot, riding;
    unsigned begins, prepares, ends, reads, flags[2], active[2], serial;
    unsigned ended_token;
    NLObject dead;
    HCCtx ctx;
} Fixture;
static int eq(NLObject a, NLObject b) {
    return a.object == b.object && a.allocation == b.allocation;
}
static int index_of(Fixture *f, HCActor a) {
    assert(a.generation == f->world.generation);
    assert(eq(a.object, f->world.p1) || eq(a.object, f->world.p2));
    assert(!eq(a.object, f->dead));
    return eq(a.object, f->world.p2);
}
static HCStatus snapshot(void *u, HCSnapshot *s) {
    Fixture *f = u; *s = f->world; return f->snapshot;
}
static NLLifetime lifetime(void *u, NLObject o) {
    Fixture *f = u;
    if (eq(o, f->dead)) return NL_FREED;
    return eq(o, f->world.p1) || eq(o, f->world.p2) || eq(o, f->world.agro)
        ? NL_LIVE : NL_MISMATCH;
}
static HCStatus riding(void *u, const HCSnapshot *s, HCRiding *r) {
    Fixture *f = u; (void)s; *r = f->ride; return f->riding;
}
static HCStatus read_flag(void *u, HCActor a, uint32_t *v) {
    Fixture *f = u; int i = index_of(f, a);
    ++f->reads; *v = f->flags[i]; return HC_OK;
}
static HCStatus begin(void *u, HCStage stage, HCActor a, NLObject horse,
                      HCToken *token, uint32_t refresh, HCFlag flag) {
    Fixture *f = u; int i = index_of(f, a);
    assert(eq(horse, f->world.agro));
    if (stage == HC_PREPARE) {
        ++f->prepares;
        if (!refresh) token->words[0] = ++f->serial;
        else assert(token->words[0] == f->active[i]);
        return f->prepare;
    }
    ++f->begins;
    /* Failure injection: pending/fault can have applied externally. */
    if (f->commit == HC_OK || f->commit == HC_PENDING || f->commit == HC_FAULT) {
        f->active[i] = token->words[0];
        if (flag == HC_SET_FLAG) f->flags[i] = 1;
    }
    return f->commit;
}
static HCStatus end(void *u, HCActor a, NLObject horse, HCToken token, HCFlag flag) {
    Fixture *f = u; int i = index_of(f, a); (void)horse;
    ++f->ends;
    assert(token.words[0] == f->active[i]);
    f->ended_token = token.words[0];
    if (f->end == HC_OK) {
        f->active[i] = 0;
        if (flag == HC_CLEAR_FLAG) f->flags[i] = 0;
    }
    return f->end;
}
static void init(Fixture *f) {
    memset(f, 0, sizeof(*f));
    f->world.generation = 9;
    f->world.p1 = (NLObject){0x1000, 1};
    f->world.p2 = (NLObject){0x2000, 2};
    f->world.agro = (NLObject){0x3000, 3};
    f->ctx.user = f;
    f->ctx.fn = (HCCallbacks){snapshot, lifetime, riding, read_flag, begin, end, 1};
}
static HCActor actor(Fixture *f, unsigned player) {
    return (HCActor){player ? f->world.p2 : f->world.p1, f->world.generation};
}
static void selected(Fixture *f, NLObject updating, NLObject wanted, HCStatus status) {
    NLObject output = {0, 0}, fallback = {0x9990, 99};
    assert(HCselect(&f->ctx, updating, fallback, &output) == status);
    assert(eq(output, wanted));
}
static void normal(void) {
    Fixture f; unsigned p2_token; uint32_t flag;
    NLObject fallback = {0x9990, 99};
    init(&f);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    p2_token = f.active[1];
    selected(&f, f.world.agro, f.world.p2, HC_OK);
    selected(&f, f.world.p1, fallback, HC_INACTIVE);
    selected(&f, (NLObject){0x3000, 55}, fallback, HC_INACTIVE);
    assert(f.reads == 0 && f.flags[1] == 1);
    assert(HCread_flag(&f.ctx, actor(&f, 1), &flag) == HC_OK && flag == 1);
    assert(HCbegin(&f.ctx, actor(&f, 0)) == HC_OK);
    assert(f.ends == 0 && f.active[1] == p2_token);
    selected(&f, f.world.agro, f.world.p1, HC_OK);
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_OK);
    assert(f.ended_token == p2_token && f.active[0] && !f.flags[1] && f.flags[0]);
    selected(&f, f.world.agro, f.world.p1, HC_OK);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    selected(&f, f.world.agro, f.world.p2, HC_OK);
    p2_token = f.active[1];
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK); /* refresh */
    assert(f.active[1] == p2_token);
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_OK);
    selected(&f, f.world.agro, f.world.p2, HC_OK); /* end keeps approach */
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_INACTIVE);
}
static void rejection(void) {
    Fixture f; unsigned n;
    for (n = 0; n < 4; ++n) {
        init(&f);
        if (n == 0) f.ride.agro_mounted = 1;
        if (n == 1) f.ride.p1_mounted = 1;
        if (n == 2) f.ride.p2_mounted = 1;
        if (n == 3) f.ride.reserved = 1;
        assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_REJECTED);
        assert(!f.prepares && !f.ctx.has_accepted);
    }
    init(&f);
    assert(HCbegin(&f.ctx, (HCActor){{0x4000, 4}, 9}) == HC_STALE);
    assert(HCbegin(&f.ctx, (HCActor){f.world.p2, 8}) == HC_STALE);
    f.dead = f.world.agro;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_STALE);
    assert(!f.prepares);
}
static void invalidation(void) {
    Fixture f; HCActor old; HCToken token; uint32_t value = 87;
    NLObject fallback = {0x9990, 99};
    init(&f); old = actor(&f, 1);
    assert(HCbegin(&f.ctx, old) == HC_OK);
    token = f.ctx.interest[1].token;
    ++f.world.generation; ++f.world.p2.allocation; /* same address, new lifetime */
    selected(&f, f.world.agro, fallback, HC_INACTIVE);
    assert(HCend(&f.ctx, old) == HC_STALE && !f.ends);
    assert(HCread_flag(&f.ctx, old, &value) == HC_STALE && value == 87 && !f.reads);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_STALE);
    assert(HCresolved(&f.ctx, actor(&f, 1), token) == HC_INACTIVE);
    assert(HCresolved(&f.ctx, old, (HCToken){{99, 0, 0, 0}}) == HC_INACTIVE);
    f.active[1] = 0; /* external token retirement proved independently */
    assert(HCresolved(&f.ctx, old, token) == HC_OK);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    ++f.world.agro.allocation;
    selected(&f, f.world.agro, fallback, HC_INACTIVE);
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_OK); /* token cleanup, not horse read */
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    f.ride.reserved = 1;
    assert(HCsync(&f.ctx) == HC_OK && !f.ctx.has_accepted);
    f.ride.reserved = 0;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    assert(HCmount_accepted(&f.ctx) == HC_OK && !f.ctx.has_accepted);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    assert(HCretire(&f.ctx, actor(&f, 1)) == HC_OK);
    assert(!f.ctx.has_accepted && HCend(&f.ctx, actor(&f, 1)) == HC_STALE);
    init(&f);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    f.dead = f.world.p2;
    selected(&f, f.world.agro, fallback, HC_INACTIVE);
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_STALE && !f.ends);
}
static void failures(void) {
    Fixture f; HCToken token; unsigned calls;
    NLObject fallback = {0x9990, 99};
    init(&f);
    assert(HCbegin(&f.ctx, actor(&f, 0)) == HC_OK);
    f.prepare = HC_REJECTED;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_REJECTED);
    assert(!f.flags[1] && !f.active[1] && f.begins == 1);
    selected(&f, f.world.agro, f.world.p1, HC_OK);
    f.prepare = HC_OK; f.commit = HC_REJECTED;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_REJECTED);
    assert(!f.ctx.interest[1].occupied && !f.flags[1]);
    selected(&f, f.world.agro, f.world.p1, HC_OK);
    f.commit = HC_PENDING;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_PENDING);
    token = f.ctx.interest[1].token; calls = f.begins;
    assert(!f.ctx.has_accepted && f.ctx.interest[1].occupied);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_PENDING);
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_PENDING && !f.ends && f.begins == calls);
    selected(&f, f.world.agro, fallback, HC_INACTIVE);
    f.commit = HC_OK;
    assert(HCbegin(&f.ctx, actor(&f, 0)) == HC_OK); /* P2 fault not game-wide */
    selected(&f, f.world.agro, f.world.p1, HC_OK);
    f.active[1] = 0;
    assert(HCresolved(&f.ctx, actor(&f, 1), token) == HC_OK);
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK);
    f.end = HC_FAULT;
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_FAULT);
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_FAULT && f.ends == 1);
    assert(f.ctx.interest[1].occupied);
    f.snapshot = HC_FAULT;
    selected(&f, f.world.agro, fallback, HC_FAULT);
    f.ctx.busy = 1;
    assert(HCmount_accepted(&f.ctx) == HC_PENDING);
    assert(HCretire(&f.ctx, actor(&f, 0)) == HC_PENDING);
    selected(&f, f.world.agro, fallback, HC_PENDING);
    init(&f); f.ctx.fn.manage_flags = 0; f.ctx.fn.flag_read = 0;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_OK && !f.flags[1]);
    assert(HCread_flag(&f.ctx, actor(&f, 1), &calls) == HC_INACTIVE);
    assert(HCend(&f.ctx, actor(&f, 1)) == HC_OK);
}
static void failure_matrix(void) {
    Fixture f;
    HCStatus statuses[] = {HC_INACTIVE, HC_REJECTED, HC_STALE, HC_PENDING, HC_FAULT};
    unsigned n;
    for (n = 0; n < sizeof(statuses) / sizeof(statuses[0]); ++n) {
        init(&f); f.prepare = statuses[n];
        assert(HCbegin(&f.ctx, actor(&f, 1)) == statuses[n]);
        assert(!f.begins && !f.active[1] && !f.flags[1]);
        assert(!f.ctx.has_accepted && !f.ctx.interest[1].occupied);
        init(&f); f.commit = statuses[n];
        assert(HCbegin(&f.ctx, actor(&f, 1)) == statuses[n]);
        assert(!f.ctx.has_accepted);
        if (statuses[n] == HC_PENDING || statuses[n] == HC_FAULT) {
            assert(f.ctx.interest[1].occupied);
            assert(f.ctx.interest[1].token.words[0] == f.active[1]);
            assert(HCbegin(&f.ctx, actor(&f, 1)) == statuses[n]);
            assert(HCend(&f.ctx, actor(&f, 1)) == statuses[n]);
            assert(f.begins == 1 && !f.ends);
        } else assert(!f.ctx.interest[1].occupied && !f.active[1] && !f.flags[1]);
    }
    init(&f); f.world.p2.object = f.world.p1.object;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_FAULT && !f.prepares);
    init(&f); f.ctx.fn.camera_begin = 0;
    assert(HCbegin(&f.ctx, actor(&f, 1)) == HC_FAULT && !f.prepares);
}
int main(void) {
    normal(); rejection(); invalidation(); failures(); failure_matrix();
    return 0;
}
