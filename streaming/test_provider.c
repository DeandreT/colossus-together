#include "provider.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define RAM_SIZE 0x220000u
#define S 0x100000u
#define GC 0x110000u
#define TABLE 0x120000u
#define DESC0 0x160000u
#define DESC1 0x160100u
#define RECTS0 0x161000u
#define RECTS1 0x162000u
#define P1 0x180000u
#define P2 0x190000u
#define COORDS 0x1c0000u
#define RECORD 0x1d0000u
#define BUFFER 0x200000u
#define EXECUTION 0x1f0000u
#define OTHER_EXECUTION 0x1f0100u

static unsigned char ram[RAM_SIZE];
static sp_provider p;
static sp_actor_ref refs[2];
static uint32_t current_thread, batch_calls, notices, policy_calls, submitted_cells;
static uint32_t current_execution, reads, resolutions;
static uint32_t native_args[7], bad_read, action;

static void put(uint32_t a, uint32_t v)
{
    assert(a <= RAM_SIZE - 4);
    ram[a] = (unsigned char)v; ram[a + 1] = (unsigned char)(v >> 8);
    ram[a + 2] = (unsigned char)(v >> 16); ram[a + 3] = (unsigned char)(v >> 24);
}

static uint32_t get(uint32_t a)
{
    assert(a <= RAM_SIZE - 4);
    return (uint32_t)ram[a] | (uint32_t)ram[a + 1] << 8 |
           (uint32_t)ram[a + 2] << 16 | (uint32_t)ram[a + 3] << 24;
}

static void half(uint32_t a, int32_t v)
{
    ram[a] = (unsigned char)v; ram[a + 1] = (unsigned char)((uint32_t)v >> 8);
}

static void real(uint32_t a, float f)
{
    union { float f; uint32_t u; } v;
    v.f = f; put(a, v.u);
}

static float number(uint32_t a)
{
    union { float f; uint32_t u; } v;
    v.u = get(a); return v.f;
}

static int reader(void *user, uint32_t a, void *out, uint32_t n)
{
    (void)user;
    ++reads;
    if (a == bad_read || a > RAM_SIZE || n > RAM_SIZE - a) return 0;
    memcpy(out, ram + a, n); return 1;
}

static int resolve(void *user, uint32_t slot, sp_actor_ref *out)
{
    (void)user; assert(slot < 2); ++resolutions; *out = refs[slot]; return 1;
}

static uint32_t thread(void *user) { (void)user; return current_thread; }
static uint32_t execution(void *user) { (void)user; return current_execution; }
static uint32_t layout(uint32_t actor) { return actor + 0x90; }

static void normalize(const float *pos, float *x, float *z)
{
    /* Test equivalent of G+245E0; real production entry is supplied, not this. */
    *x = (-pos[0] - number(S + 0x50)) / number(S + 0x40);
    *z = (-pos[2] - number(S + 0x54)) / number(S + 0x44);
}

static void rounded(const float *pos, int32_t *x, int32_t *z)
{
    float fx, fz;
    normalize(pos, &fx, &fz);
    *x = (int32_t)fx; *z = (int32_t)fz;
    if (fx - (float)*x >= 0.5f) ++*x;
    if (fz - (float)*z >= 0.5f) ++*z;
}

static int policy(uint32_t x, uint32_t z, uint32_t layer, uint32_t rx,
                  uint32_t rz, uint32_t cx, uint32_t cz)
{
    uint32_t d = get(TABLE + (z * 60 + x) * 24 + 16);
    uint32_t center = get(TABLE + (cz * 60 + cx) * 24 + 16);
    uint32_t mode = d ? get(d) : 0;
    int32_t near = (int32_t)get(S - 0x2c), far = near + (int32_t)get(S - 0x28);
    int32_t dx = (int32_t)x - (int32_t)rx, dz = (int32_t)z - (int32_t)rz;
    int close = dx >= -near && dx < near && dz >= -near && dz < near;
    ++policy_calls;
    if (action == 4) { action = 0; ++refs[1].generation; }
    if (mode == 1) return d == center;
    if ((mode == 2 || mode == 3) && d != center && !get(TABLE + (z * 60 + x) * 24 + 20)) return 0;
    if (!layer) return close;
    return !close && dx >= -far && dx < far && dz >= -far && dz < far;
}

static uint32_t original(uint32_t x, uint32_t z, uint32_t layer, uint32_t rx,
                         uint32_t rz, uint32_t cx, uint32_t cz)
{
    native_args[0] = x; native_args[1] = z; native_args[2] = layer;
    native_args[3] = rx; native_args[4] = rz; native_args[5] = cx; native_args[6] = cz;
    return 0x55u;
}

static void notified(void *user, sp_fault code)
{
    (void)user; assert(code != SP_OK); ++notices;
}

static uint32_t address(void *user, const void *ptr, uint32_t n)
{
    (void)user;
    assert(ptr == p.native_coords && n <= sizeof(p.native_coords));
    return BUFFER;
}

static uint32_t plan_tag(void)
{
    uint32_t i, tag = 0;
    for (i = 0; i < SU_MAX_CELLS; ++i)
        tag = tag * 33u + p.plan.desired[i] * 4u + p.plan.keep_p2[i];
    return tag;
}

static uint32_t batch(const sp_batch_args *args)
{
    uint32_t i, layer;
    assert(args->coords == BUFFER && args->count <= 256);
    assert(args->width && args->height && args->width <= 16 && args->height <= 16);
    assert(args->count <= args->width * args->height);
    assert(args->rounded_x == (uint32_t)p.actors[0].rounded_x);
    assert(args->rounded_z == (uint32_t)p.actors[0].rounded_z);
    assert(args->containing_x == (uint32_t)p.actors[0].containing_x);
    assert(args->containing_z == (uint32_t)p.actors[0].containing_z);
    assert(p.scope_active && p.busy && p.active_batch == p.batch_sequence && p.active_batch);
    assert(p.active_iteration == p.iteration && current_execution == EXECUTION);
    ++batch_calls;
    if (action == 1) { action = 0; ++refs[1].generation; }
    if (action == 2) { action = 0; sp_refresh_keep(&p); }
    if (action == 5) { action = 0; real(S + 0x50, -2900.0f); }
    if (action == 6) {
        uint32_t old_reads = reads, old_resolutions = resolutions;
        uint32_t old_tag = plan_tag(), nonce = p.active_batch;
        const uint32_t expected[7] = {11, 12, 1, 21, 22, 31, 32};
        action = 0;
        /* Simulated suspension: another ISYS coroutine runs on the exact
         * same kernel thread while the owner's batch frame remains live. */
        current_execution = OTHER_EXECUTION;
        assert(current_thread == p.config.owner_thread);
        assert(sp_predicate(&p, 11, 12, 1, 21, 22, 31, 32) == 0x55);
        assert(memcmp(native_args, expected, sizeof(expected)) == 0);
        assert(reads == old_reads && resolutions == old_resolutions);
        assert(p.fault == SP_OK && p.busy && p.scope_active);
        assert(p.active_batch == nonce && p.active_iteration == p.iteration && plan_tag() == old_tag);
        current_execution = EXECUTION;
        /* Owner resumes its original batch; subsequent normal iterations
         * below must still use the union override rather than the fallback. */
    }
    for (i = 0; i < args->count; ++i) {
        uint32_t x = p.native_coords[i].word[0], z = p.native_coords[i].word[1];
        assert(x >= args->min_x && x < args->min_x + args->width);
        assert(z >= args->min_z && z < args->min_z + args->height);
        assert(!p.native_coords[i].word[2] && !p.native_coords[i].word[3]);
        for (layer = 0; layer < 2; ++layer) {
            uint32_t a = TABLE + (z * 60 + x) * 24 + 8 + layer * 4;
            uint32_t enabled = sp_predicate(&p, x, z, layer, args->rounded_x,
                                          args->rounded_z, args->containing_x, args->containing_z);
            if (enabled && (get(a) & 15u) == 0) { put(a, 1); ++submitted_cells; }
        }
    }
    if (action == 3) { action = 0; return 0; }
    return 1;
}

static void position(uint32_t a, float x, float z)
{
    real(a, 3000.0f - 100.0f * x); real(a + 4, 10.0f);
    real(a + 8, 3000.0f - 100.0f * z); real(a + 12, 1.0f);
}

static sp_config setup(void)
{
    sp_config c;
    memset(ram, 0, sizeof(ram)); memset(&c, 0, sizeof(c));
    put(S, 1); put(S + 8, TABLE); put(S + 0x38, 6); put(S + 0x3c, 6);
    real(S + 0x40, 100); real(S + 0x44, 100);
    put(S + 0x48, 60); put(S + 0x4c, 60);
    real(S + 0x50, -3000); real(S + 0x54, -3000);
    put(S - 0x2c, 1); put(S - 0x28, 2);
    refs[0].actor = P1; refs[0].generation = 7; refs[0].active = 1;
    refs[1].actor = P2; refs[1].generation = 11; refs[1].active = 1;
    put(P1 + 8, 9); put(P2 + 8, 9);
    put(P1 + 0x1c4, P1 + 0xa0); put(P2 + 0x1c4, P2 + 0xa0);
    position(GC + 0x340, 30.2f, 30.2f); position(P2 + 0xa0, 30.2f, 30.2f);
    current_thread = 9; current_execution = EXECUTION;
    batch_calls = notices = submitted_cells = policy_calls = bad_read = action = reads = resolutions = 0;
    memset(native_args, 0, sizeof(native_args));
    c.stream_state = S; c.gc_global = GC; c.width = c.height = 60; c.owner_thread = 9;
    c.owner_execution = EXECUTION; c.execution_id = execution;
    c.max_candidates = c.max_requests = 4096;
    c.read = reader; c.resolve = resolve; c.thread_id = thread; c.get_layout = layout;
    c.get_chip = rounded; c.get_chip_float = normalize; c.policy = policy;
    c.original_enable = original; c.batch = batch; c.buffer_address = address; c.on_fault = notified;
    assert(sp_init(&p, &c));
    return c;
}

static uint32_t cell(uint32_t x, uint32_t z) { return z * 60 + x; }

static void record(uint32_t x, uint32_t z, uint32_t layer)
{
    put(RECORD, x); put(RECORD + 4, z); put(RECORD + 8, layer);
    put(TABLE + cell(x, z) * 24 + layer * 4, RECORD);
    put(TABLE + cell(x, z) * 24 + 8 + layer * 4, 3);
}

static void basic(void)
{
    sp_config c;
    su_output solo;
    uint32_t calls;
    c = setup();
    /* Sanitized State-5 fixture values: actual pointed positions, not inline. */
    real(GC + 0x340, -295.3533935546875f); real(GC + 0x344, 12.141127586364746f);
    real(GC + 0x348, -278.3609924316406f);
    real(P2 + 0xa0, -292.8628845214844f); real(P2 + 0xa4, 9.778213500976562f);
    real(P2 + 0xa8, -281.9549255371094f);
    refs[1].active = 0;
    sp_begin(&p); sp_refresh_keep(&p);
    assert(p.fault == SP_OK && p.plan.desired_count == 36);
    solo = p.plan;
    refs[1].active = 1;
    assert(sp_init(&p, &c)); /* installer-owned rebind when registry activates */
    sp_begin(&p); sp_refresh_keep(&p);
    assert(p.fault == SP_OK && p.actors[0].rounded_x == 33 && p.actors[1].rounded_x == 33);
    assert(p.actors[0].containing_x == 32 && p.actors[1].containing_x == 32);
    assert(memcmp(solo.desired, p.plan.desired, sizeof(solo.desired)) == 0);
    assert(batch_calls == 0); /* refresh must not enqueue */
    sp_fallback(&p); calls = batch_calls;
    assert(calls && submitted_cells == 36 && p.submitted && !p.scope_active);
    sp_fallback(&p); assert(batch_calls == calls);
}

static void union_and_explicit(void)
{
    sp_config c = setup();
    uint8_t wanted[4096];
    sp_batch_args a;
    uint32_t x, z, n = 0, count;
    position(P2 + 0xa0, 45.2f, 30.2f);
    sp_begin(&p); sp_refresh_keep(&p);
    assert(p.plan.desired_count == 72 && p.fault == SP_OK);
    record(45, 30, 0); assert(sp_keep_record(&p, RECORD));
    sp_fallback(&p); assert(p.fault == SP_OK && submitted_cells == 71);
    /* Stationary P1, new iteration with moving P2 still submits via fallback. */
    position(P2 + 0xa0, 50.2f, 30.2f); count = batch_calls;
    sp_begin(&p); sp_fallback(&p);
    assert(p.fault == SP_OK && batch_calls > count && p.plan.desired[cell(50, 30)] == 0);
    setup(); position(P2 + 0xa0, 32.2f, 30.2f);
    sp_begin(&p); sp_refresh_keep(&p);
    assert(p.plan.desired[cell(31, 30)] == 0);
    memcpy(wanted, p.plan.desired, sizeof(wanted));
    position(GC + 0x340, 32.2f, 30.2f); position(P2 + 0xa0, 30.2f, 30.2f);
    sp_begin(&p); sp_refresh_keep(&p);
    assert(memcmp(wanted, p.plan.desired, sizeof(wanted)) == 0);
    c = setup(); (void)c;
    sp_begin(&p);
    for (z = 27; z < 33; ++z) for (x = 27; x < 33; ++x) {
        put(COORDS + n * 16, x); put(COORDS + n * 16 + 4, z); ++n;
    }
    a.coords = COORDS; a.count = n; a.min_x = a.min_z = 27; a.width = a.height = 6;
    a.rounded_x = a.rounded_z = a.containing_x = a.containing_z = 30;
    sp_submit(&p, &a);
    assert(p.fault == SP_OK && p.submitted && submitted_cells == 36);
    count = batch_calls; sp_fallback(&p); sp_submit(&p, &a); assert(batch_calls == count);
}

static void descriptor(uint32_t d, uint32_t r, uint32_t mode, uint32_t x, uint32_t z, uint32_t width)
{
    put(d, mode); put(d + 0x14, 1); put(d + 0x18, r);
    half(r, (int32_t)x); half(r + 2, (int32_t)z); half(r + 4, (int32_t)width); half(r + 6, 1);
    put(TABLE + cell(x, z) * 24 + 16, d);
}

static void modes_and_radii(void)
{
    setup(); position(GC + 0x340, 5.2f, 8.2f); position(P2 + 0xa0, 45.2f, 48.2f);
    descriptor(DESC0, RECTS0, 5, 5, 8, 3); descriptor(DESC1, RECTS1, 5, 45, 48, 2);
    sp_begin(&p); sp_refresh_keep(&p);
    assert(p.fault == SP_OK && p.plan.candidate_count == 5 && !batch_calls);
    record(45, 48, 1); assert(sp_keep_record(&p, RECORD));
    record(5, 8, 1); assert(!sp_keep_record(&p, RECORD));
    sp_fallback(&p); assert(p.fault == SP_OK && p.submitted);
    setup(); position(P2 + 0xa0, 40.2f, 40.2f);
    descriptor(DESC1, RECTS1, 3, 40, 40, 2);
    sp_begin(&p); sp_refresh_keep(&p); /* type3 unload-before-load */
    record(40, 40, 0); assert(sp_keep_record(&p, RECORD));
    assert(batch_calls == 0 && p.fault == SP_OK);
    /* P1 force-path radius changes are adopted without writing fog/globals. */
    put(S - 0x2c, 2); put(S - 0x28, 3);
    sp_refresh_keep(&p);
    assert(p.fault == SP_OK && p.actors[0].near_radius == 2 && p.actors[1].outer_band == 3);
    assert(get(S - 0x2c) == 2 && get(S - 0x28) == 3);
}

static void fallback_arguments_and_state5(void)
{
    uint32_t i;
    setup();
    assert(sp_predicate(&p, 11, 12, 1, 21, 22, 31, 32) == 0x55);
    { const uint32_t args[7] = {11, 12, 1, 21, 22, 31, 32};
      for (i = 0; i < 7; ++i) assert(native_args[i] == args[i]); }
    p.scope_active = 1; current_thread = 10;
    assert(sp_predicate(&p, 1, 2, 0, 3, 4, 5, 6) == 0x55);
    current_thread = 9; p.scope_active = 0;
    sp_begin(&p); sp_refresh_keep(&p);
    put(TABLE + cell(30, 30) * 24 + 8, 5);
    p.scope_active = 1;
    p.batch_sequence = p.active_batch = 1; p.active_iteration = p.iteration;
    assert(sp_predicate(&p, 30, 30, 0, 30, 30, 30, 30));
    put(TABLE + cell(30, 30) * 24 + 8, 3);
    assert(!sp_predicate(&p, 30, 30, 0, 30, 30, 30, 30));
    assert(p.plan.desired[cell(30, 30)] == 0);
    p.scope_active = p.active_batch = p.active_iteration = 0;
}

static void logical_execution_scope(void)
{
    uint32_t count;
    sp_config c = setup();
    sp_begin(&p); action = 6; sp_fallback(&p);
    assert(p.fault == SP_OK && p.submitted && submitted_cells == 36);
    assert(!p.busy && !p.scope_active && !p.active_batch && !p.active_iteration);
    assert(p.batch_sequence > 0);
    /* Expired nonce on the owner also cannot activate the override. */
    p.scope_active = 1; p.active_batch = p.batch_sequence + 1; p.active_iteration = p.iteration;
    count = resolutions;
    assert(sp_predicate(&p, 1, 2, 0, 3, 4, 5, 6) == 0x55);
    assert(resolutions == count && p.fault == SP_OK);
    /* A normal callback on a wrong coroutine is a placement fault, not an
     * apparent recursive call from the owner. Predicate is the exception. */
    assert(sp_init(&p, &c)); current_execution = OTHER_EXECUTION; sp_begin(&p);
    assert(p.fault == SP_EXECUTION);
    c = setup(); c.execution_id = 0; assert(!sp_init(&p, &c));
    c = setup(); c.owner_execution = 0; assert(!sp_init(&p, &c));
    c = setup(); c.owner_execution = EXECUTION + 1; assert(!sp_init(&p, &c));
    /* Original owner reentry test remains a hard fault, with nonce cleared
     * only when the suspended native invocation returns. */
    setup(); sp_begin(&p); action = 2; sp_fallback(&p);
    assert(p.fault == SP_REENTRY && !p.scope_active && !p.active_batch && !p.busy);
    setup(); sp_begin(&p); p.batch_sequence = UINT32_MAX; sp_fallback(&p);
    assert(p.fault == SP_BATCH && !batch_calls && !p.active_batch && !p.scope_active);
}

static void failures(void)
{
    sp_config c;
    uint32_t k;
    for (k = 1; k <= 5; ++k) {
        setup(); sp_begin(&p); action = k; sp_fallback(&p);
        assert(p.fault != SP_OK && notices == 1 && !p.scope_active && !p.busy && !p.active_batch);
        assert(sp_keep_record(&p, 0xffffffffu));
        sp_begin(&p); sp_fallback(&p); assert(notices == 1);
    }
    c = setup(); c.max_requests = 35; assert(sp_init(&p, &c));
    sp_begin(&p); sp_refresh_keep(&p);
    assert(p.fault == SP_CAPACITY && !batch_calls && sp_keep_record(&p, RECORD));
    setup(); descriptor(DESC1, RECTS1, 5, 30, 30, 2); put(DESC1 + 0x14, 513);
    sp_begin(&p); sp_refresh_keep(&p); assert(p.fault == SP_CAPACITY && !batch_calls);
    setup(); put(TABLE + cell(30, 30) * 24 + 16, DESC0); put(DESC0, 6);
    sp_begin(&p); sp_refresh_keep(&p); assert(p.fault == SP_MAP && !batch_calls);
    setup(); put(P2 + 0x1c4, 0x7fc00000u); sp_begin(&p);
    assert(p.fault != SP_OK && !p.snapshot_valid); /* pointer, not inline float */
    setup(); put(P2 + 0xa0, 0x7fc00000u); sp_begin(&p); assert(p.fault == SP_GEOMETRY);
    setup(); ram[P2 + 0x90 + 0x151] = 1; sp_begin(&p); assert(p.fault == SP_GEOMETRY);
    setup(); put(S + 0x40, 0); sp_begin(&p); assert(p.fault == SP_MAP);
    setup(); sp_begin(&p); ++refs[1].generation; sp_refresh_keep(&p);
    assert(p.fault == SP_GENERATION && sp_keep_record(&p, RECORD));
    setup(); sp_begin(&p); ++refs[1].generation; sp_begin(&p);
    assert(p.fault == SP_GENERATION && !p.scope_active && sp_keep_record(&p, RECORD));
    setup(); sp_begin(&p); put(S + 8, TABLE + 0x100); sp_begin(&p);
    assert(p.fault == SP_MAP && !batch_calls);
    setup(); bad_read = TABLE + 16; sp_begin(&p); sp_refresh_keep(&p); assert(p.fault == SP_READ);
    setup(); current_thread = 10; sp_begin(&p); assert(p.fault == SP_THREAD);
    setup(); sp_refresh_keep(&p); assert(p.fault == SP_NO_ITERATION);
    c = setup(); c.width = 4097; assert(!sp_init(&p, &c));
    c = setup(); c.on_fault = 0; assert(!sp_init(&p, &c));
    assert(!sp_ee_read(0, 0, &k, 4));
    assert(!sp_ee_read(0, SP_EE_END - 1, &k, 4));
}

int main(void)
{
    basic(); union_and_explicit(); modes_and_radii(); fallback_arguments_and_state5();
    logical_execution_scope(); failures();
    printf("provider checks passed; caller-owned storage=%lu bytes\n", (unsigned long)sp_storage_size());
    return 0;
}
