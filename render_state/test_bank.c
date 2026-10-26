#include "bank.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    unsigned char memory[512];
    unsigned char base[258], p1[258];
    rb_bank bank;
    rb_workspace workspace;
    rb_config config;
    rb_range ranges[8];
    unsigned int reads, writes, owners, fences, fail_read, fail_write;
    int fence_ok, dead;
    uint32_t allocation_end;
} fixture;
/* Static only in host harness: production has no static storage. */
static fixture f;
static int alive(void *ctx, const rb_range *r) {
    fixture *x = ctx;
    ++x->owners;
    return r->generation == r->owner_id + 100 &&
           x->dead != (int)r->owner_id &&
           r->address + r->size <= x->allocation_end;
}
static int fence(void *ctx) {
    fixture *x = ctx;
    ++x->fences;
    return x->fence_ok;
}
static int read_mem(void *ctx, uint32_t address, unsigned char *out, uint32_t size) {
    fixture *x = ctx;
    ++x->reads;
    assert(address >= 64 && address + size <= 512);
    /* Even an error may have copied some bytes. */
    memcpy(out, x->memory + address, size);
    return x->reads != x->fail_read;
}
static int write_mem(void *ctx, uint32_t address, const unsigned char *in, uint32_t size) {
    fixture *x = ctx;
    ++x->writes;
    assert(address >= 64 && address + size <= 512);
    memcpy(x->memory + address, in, size);
    return x->writes != x->fail_write;
}
static void setup(void) {
    unsigned int i;
    memset(&f, 0, sizeof(f));
    f.fence_ok = 1;
    f.dead = -1;
    f.allocation_end = 512;
    memset(f.base, 0xcc, sizeof(f.base));
    memset(f.p1, 0xdd, sizeof(f.p1));
    for (i = 0; i < sizeof(f.memory); ++i) f.memory[i] = (unsigned char)i;
    f.config.context = &f; f.config.alive = alive; f.config.fence = fence;
    f.config.read = read_mem; f.config.write = write_mem;
    f.config.base = f.base + 1; f.config.p1 = f.p1 + 1;
    f.config.capacity = 256; f.config.max_bytes = 256;
    f.config.base_storage = (rb_extent){0x10000, 256};
    f.config.p1_storage = (rb_extent){0x20000, 256};
    f.config.metadata_storage = (rb_extent){0x30000, 0x10000};
    f.ranges[0] = (rb_range){96, 32, 1, 101};
    f.ranges[1] = (rb_range){64, 48, 1, 101};
    f.ranges[2] = (rb_range){64, 48, 2, 102};
    f.ranges[3] = (rb_range){192, 16, 3, 103};
}
static rb_result init(void) {
    return rb_init(&f.bank, &f.workspace, &f.config, f.ranges, 4);
}
static void canaries(void) {
    assert(f.base[0] == 0xcc && f.base[257] == 0xcc);
    assert(f.p1[0] == 0xdd && f.p1[257] == 0xdd);
    assert(f.base[81] == 0xcc && f.p1[81] == 0xdd);
}
static void success(void) {
    unsigned char original[512], p1final[512];
    unsigned int i, before;
    setup(); memcpy(original, f.memory, sizeof(original));
    assert(init() == RB_OK);
    assert(f.bank.union_count == 2 && f.bank.bytes == 80);
    assert(f.workspace.merged[0].extent.address == 64);
    assert(f.workspace.merged[0].extent.size == 64);
    assert(f.workspace.merged[1].offset == 64);
    assert(f.owners == 8); /* Original owners before and after union building. */
    assert(rb_begin_frame(&f.bank) == RB_OK && f.reads == 2);
    /* Synthetic P1 writes only qualified target bytes. */
    for (i = 64; i < 128; ++i) f.memory[i] ^= 0x55;
    for (i = 192; i < 208; ++i) f.memory[i] ^= 0x55;
    memcpy(p1final, f.memory, sizeof(p1final));
    assert(rb_capture_p1(&f.bank) == RB_OK && f.reads == 4);
    before = f.owners;
    assert(rb_restore_base(&f.bank) == RB_OK);
    assert(f.owners == before + 4 && f.writes == 2);
    assert(memcmp(original, f.memory, sizeof(original)) == 0);
    for (i = 64; i < 128; ++i) f.memory[i] ^= 0xaa;
    for (i = 192; i < 208; ++i) f.memory[i] ^= 0xaa;
    assert(rb_restore_p1(&f.bank) == RB_OK && f.writes == 4);
    assert(memcmp(p1final, f.memory, sizeof(p1final)) == 0);
    assert(rb_end_frame(&f.bank) == RB_OK && f.bank.phase == RB_IDLE);
    canaries();
    assert(rb_begin_frame(&f.bank) == RB_OK);
    assert(rb_cancel_before_render(&f.bank, 1) == RB_OK);
}
static void dead_owner(void) {
    unsigned char prior[512];
    setup(); assert(init() == RB_OK);
    assert(rb_begin_frame(&f.bank) == RB_OK);
    assert(rb_capture_p1(&f.bank) == RB_OK);
    memcpy(prior, f.memory, sizeof(prior));
    f.dead = 2; /* Different identity on exactly the same physical bytes. */
    assert(rb_restore_base(&f.bank) == RB_OWNER);
    assert(f.writes == 0 && memcmp(prior, f.memory, sizeof(prior)) == 0);
    assert(rb_restore_p1(&f.bank) == RB_OWNER && f.writes == 0);
    assert(rb_abort_quiescent(&f.bank, 1) == RB_OWNER);
    f.dead = -1;
    assert(rb_abort_quiescent(&f.bank, 1) == RB_OK);
    canaries();
}
static void fences(void) {
    unsigned int stage;
    for (stage = 0; stage < 4; ++stage) {
        unsigned int reads, writes;
        setup(); assert(init() == RB_OK);
        if (stage > 0) assert(rb_begin_frame(&f.bank) == RB_OK);
        if (stage > 1) assert(rb_capture_p1(&f.bank) == RB_OK);
        if (stage > 2) assert(rb_restore_base(&f.bank) == RB_OK);
        reads = f.reads; writes = f.writes; f.fence_ok = 0;
        switch (stage) {
            case 0: assert(rb_begin_frame(&f.bank) == RB_FENCE); break;
            case 1: assert(rb_capture_p1(&f.bank) == RB_FENCE); break;
            case 2: assert(rb_restore_base(&f.bank) == RB_FENCE); break;
            default: assert(rb_restore_p1(&f.bank) == RB_FENCE); break;
        }
        assert(f.reads == reads && f.writes == writes);
        f.fence_ok = 1;
        assert(rb_begin_frame(&f.bank) == RB_FENCE);
        assert(f.reads == reads && f.writes == writes);
        assert(rb_abort_quiescent(&f.bank, 0) == RB_FENCE);
        assert(rb_abort_quiescent(&f.bank, 1) == RB_OK);
    }
}
static void invalid(void) {
    unsigned int i;
    const rb_range bad[] = {
        {0x10000000, 4, 1, 101}, {0x1fffffc, 8, 1, 101},
        {0xfffffffc, 8, 1, 101}, {64, 0, 1, 101},
        {65, 4, 1, 101}, {64, 6, 1, 101},
        {64, 0xfffffffc, 1, 101}
    };
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        setup(); f.ranges[0] = bad[i]; assert(init() == RB_BOUNDS);
        assert(rb_begin_frame(&f.bank) == RB_BOUNDS);
        assert(f.reads == 0 && f.writes == 0); canaries();
    }
    setup(); f.config.max_bytes = 79; assert(init() == RB_CAPACITY);
    assert(rb_abort_quiescent(&f.bank, 1) == RB_CAPACITY);
    setup(); f.config.capacity = 64;
    f.config.base_storage.size = f.config.p1_storage.size = 64;
    assert(init() == RB_CAPACITY);
    setup(); f.config.base_storage.size = 252; assert(init() == RB_CAPACITY);
    setup(); f.config.metadata_storage.size = 4; assert(init() == RB_CAPACITY);
    setup(); f.config.base_storage.address = 64; assert(init() == RB_ALIAS);
    setup(); f.config.p1_storage = f.config.base_storage; assert(init() == RB_ALIAS);
    setup(); f.config.p1_storage.address = f.config.metadata_storage.address;
    assert(init() == RB_ALIAS);
    setup(); f.ranges[0].address = f.config.metadata_storage.address;
    assert(init() == RB_ALIAS);
    setup(); f.config.read = NULL; assert(init() == RB_ARGUMENT);
    setup(); f.allocation_end = 200; assert(init() == RB_OWNER);
    setup(); f.ranges[2].generation = 999; assert(init() == RB_OWNER);
    setup(); assert(rb_init(&f.bank, &f.workspace, &f.config, f.ranges, 1025) == RB_ARGUMENT);
    setup(); f.config.p1 = f.config.base; assert(init() == RB_ALIAS);
    setup(); f.config.base = (unsigned char *)&f.workspace; assert(init() == RB_ALIAS);
    setup(); f.config.base = (unsigned char *)&f.bank; assert(init() == RB_ALIAS);
}
static void wrong_order(void) {
    setup(); assert(init() == RB_OK);
    assert(rb_capture_p1(&f.bank) == RB_ORDER);
    assert(rb_begin_frame(&f.bank) == RB_ORDER && !f.reads && !f.writes);
    assert(rb_abort_quiescent(&f.bank, 1) == RB_OK);
    assert(rb_begin_frame(&f.bank) == RB_OK);
    assert(rb_end_frame(&f.bank) == RB_ORDER);
    assert(rb_cancel_before_render(&f.bank, 1) == RB_ORDER);
    assert(rb_abort_quiescent(&f.bank, 1) == RB_OK);
    assert(rb_begin_frame(&f.bank) == RB_OK);
    assert(rb_cancel_before_render(&f.bank, 0) == RB_ARGUMENT);
    assert(rb_cancel_before_render(&f.bank, 1) == RB_ARGUMENT);
}
static void uncertain(void) {
    unsigned int n;
    for (n = 1; n <= 2; ++n) {
        unsigned char base[258], p1[258];
        setup(); assert(init() == RB_OK);
        assert(rb_begin_frame(&f.bank) == RB_OK);
        assert(rb_capture_p1(&f.bank) == RB_OK);
        memcpy(base, f.base, sizeof(base)); memcpy(p1, f.p1, sizeof(p1));
        f.fail_write = n;
        assert(rb_restore_base(&f.bank) == RB_INDETERMINATE);
        assert(f.writes == n);
        assert(rb_restore_base(&f.bank) == RB_INDETERMINATE);
        assert(rb_restore_p1(&f.bank) == RB_INDETERMINATE);
        assert(rb_begin_frame(&f.bank) == RB_INDETERMINATE && f.writes == n);
        assert(memcmp(base, f.base, sizeof(base)) == 0);
        assert(memcmp(p1, f.p1, sizeof(p1)) == 0); canaries();
        setup(); assert(init() == RB_OK); f.fail_read = n;
        assert(rb_begin_frame(&f.bank) == RB_INDETERMINATE && f.reads == n);
        assert(rb_begin_frame(&f.bank) == RB_INDETERMINATE && f.reads == n);
        assert(f.writes == 0); canaries();
    }
    setup(); assert(init() == RB_OK);
    assert(rb_begin_frame(&f.bank) == RB_OK);
    assert(rb_capture_p1(&f.bank) == RB_OK);
    /* Capacity revalidation before any target write. */
    f.bank.config.max_bytes = 4;
    assert(rb_restore_base(&f.bank) == RB_CAPACITY && f.writes == 0);
    setup(); assert(init() == RB_OK);
    assert(rb_begin_frame(&f.bank) == RB_OK);
    f.fail_read = 4;
    assert(rb_capture_p1(&f.bank) == RB_INDETERMINATE && f.reads == 4);
    assert(rb_restore_base(&f.bank) == RB_INDETERMINATE && f.writes == 0);
    canaries();
    setup(); assert(init() == RB_OK);
    assert(rb_begin_frame(&f.bank) == RB_OK);
    assert(rb_capture_p1(&f.bank) == RB_OK);
    assert(rb_restore_base(&f.bank) == RB_OK);
    f.fail_write = 4;
    assert(rb_restore_p1(&f.bank) == RB_INDETERMINATE && f.writes == 4);
    assert(rb_end_frame(&f.bank) == RB_INDETERMINATE);
    assert(rb_restore_p1(&f.bank) == RB_INDETERMINATE && f.writes == 4);
    canaries();
}
static void max_ranges(void) {
    static rb_range many[RB_MAX_RANGES];
    unsigned int i;
    setup();
    for (i = 0; i < RB_MAX_RANGES; ++i) many[i] = (rb_range){64, 4, 1, 101};
    assert(rb_init(&f.bank, &f.workspace, &f.config, many, RB_MAX_RANGES) == RB_OK);
    assert(f.bank.union_count == 1 && f.bank.bytes == 4);
    assert(rb_begin_frame(&f.bank) == RB_OK && f.reads == 1);
    assert(f.owners == 3 * RB_MAX_RANGES);
    setup();
    f.ranges[0] = (rb_range){80, 16, 1, 101};
    f.ranges[1] = (rb_range){64, 16, 2, 102};
    f.ranges[2] = (rb_range){72, 4, 3, 103};
    f.ranges[3] = (rb_range){92, 12, 4, 104};
    assert(init() == RB_OK);
    assert(f.bank.union_count == 1 && f.bank.bytes == 40);
    assert(rb_begin_frame(&f.bank) == RB_OK && f.reads == 1);
}
int main(void) {
    success(); dead_owner(); fences(); invalid(); wrong_order(); uncertain(); max_ranges();
    printf("ok: workspace=%zu bank=%zu max_ranges=%u union_bytes=80\n",
           sizeof(rb_workspace), sizeof(rb_bank), RB_MAX_RANGES);
    return 0;
}
