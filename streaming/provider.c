#include "provider.h"
#include <limits.h>

typedef char sp_batch_layout_check[sizeof(sp_batch_args) == 40 ? 1 : -1];
typedef char sp_coord_layout_check[sizeof(sp_native_coord) == 16 ? 1 : -1];
typedef char sp_float_layout_check[sizeof(float) == 4 ? 1 : -1];
typedef char sp_buffer_alignment_check[offsetof(sp_provider, native_coords) % 16 == 0 ? 1 : -1];

/* Verified native layouts:
 * S=G's D_17A340: +0 active,+4 suspended,+8 cell table,+40/+44 float chip
 * sizes,+48/+4C u32 dimensions,+50/+54 float origins. Radii S-2C/-28 are
 * integers (G+1F19C CVT.S.W; G+22014..220A8 LW/SW).
 * Each cell is 24 bytes: records[2], state[2], descriptor, extra presence.
 * Descriptor mode +0; rectangles count/pointer +14/+18. Modes1..3 stride12,
 * signed halfwords x,z,w,h; mode5 stride8 signed x,z,w (height1).
 * Loaded record: x+0,z+4,layer+8,object+C (G+1FD1C..1FD30).
 * Type9 GetLayoutClass returns actor+90; world-point pointer L+134 (actor+1C4).
 * L+151 is set on immediate flush (M+75E60). Native normalized getter
 * G+245E0 exactly matches G+221B4..221F0 arithmetic; positive bounded output
 * converts to containing cells by truncation, matching native CVT.W.S.
 *
 * Logical execution identity: K+1D850 isysGetThisSubThread loads D_40FA0.
 * isysWakeupSubThread writes the selected object there at K+1D144 before
 * entering/restoring its execution context. K+1D4EC isysSleepSubThread saves
 * the context and transfers to the scheduler restore path. The getter is a
 * GLOBAL, so require the EE kernel thread AND this ISYS object token.
 * G+1FF70 calls allocating/request-building functions (including K+3678
 * iosMallocAlign, whose K+36B0 WaitSema can block). A kernel semaphore wait is
 * not itself proof of a same-kernel-thread ISYS switch. We deliberately make
 * NO no-yield assumption: the bound batch thunk may suspend, with scope state
 * retained until that invocation returns. Only matching logical execution and
 * an active per-call nonce may observe the override. Identity adapters must be
 * synchronous/read-only; tokens must not be recycled during this invocation. */

static int region(uint32_t a, uint32_t n)
{
    return a >= 0x80000u && n && a <= SP_EE_END && n <= SP_EE_END - a;
}

int sp_ee_read(void *unused, uint32_t a, void *out, uint32_t n)
{
    uint32_t i;
    unsigned char *dst = (unsigned char *)out;
    volatile const unsigned char *src;
    (void)unused;
    if (!out || !region(a, n)) return 0;
    src = (volatile const unsigned char *)(uintptr_t)a;
    for (i = 0; i < n; ++i) dst[i] = src[i];
    return 1;
}

static void fault(sp_provider *p, sp_fault code)
{
    if (p->fault == SP_OK) {
        p->fault = code;
        if (p->config.on_fault) p->config.on_fault(p->config.user, code);
    }
}

static int read_bytes(sp_provider *p, uint32_t a, void *dst, uint32_t n)
{
    int ok;
    if (!region(a, n)) { fault(p, SP_READ); return 0; }
    ok = (p->config.read ? p->config.read : sp_ee_read)(p->config.user, a, dst, n);
    if (!ok) fault(p, SP_READ);
    return ok;
}

static uint32_t little32(const unsigned char *b)
{
    return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
}

static int32_t little16(const unsigned char *b)
{
    uint32_t v = (uint32_t)b[0] | (uint32_t)b[1] << 8;
    return v & 0x8000u ? (int32_t)v - 65536 : (int32_t)v;
}

static int word(sp_provider *p, uint32_t a, uint32_t *v)
{
    unsigned char b[4];
    if ((a & 3u) || !read_bytes(p, a, b, 4)) { fault(p, SP_READ); return 0; }
    *v = little32(b);
    return 1;
}

static float as_float(uint32_t bits)
{
    union { uint32_t u; float f; } value;
    value.u = bits;
    return value.f;
}

static int finite_bits(uint32_t bits)
{
    return (bits & 0x7f800000u) != 0x7f800000u;
}

static int finite_float(float f)
{
    union { uint32_t u; float f; } value;
    value.f = f;
    return finite_bits(value.u);
}

static sp_fault owner_status(sp_provider *p)
{
    if (p->config.thread_id(p->config.user) != p->config.owner_thread) return SP_THREAD;
    if (p->config.execution_id(p->config.user) != p->config.owner_execution) return SP_EXECUTION;
    return SP_OK;
}

static void clear_scope(sp_provider *p)
{
    p->scope_active = p->active_batch = p->active_iteration = 0;
}

static int enter(sp_provider *p)
{
    sp_fault status;
    if (!p || p->fault != SP_OK) return 0;
    status = owner_status(p);
    if (status != SP_OK) { fault(p, status); return 0; }
    if (p->busy) { fault(p, SP_REENTRY); return 0; }
    p->busy = 1;
    return 1;
}

static int refs_now(sp_provider *p, sp_actor_ref refs[2])
{
    uint32_t i;
    for (i = 0; i < 2; ++i) {
        uint32_t flags;
        refs[i].actor = refs[i].generation = refs[i].active = 0;
        if (!p->config.resolve(p->config.user, i, &refs[i]) || refs[i].active > 1 ||
            (refs[i].active && (!refs[i].generation || !region(refs[i].actor, 0x220) || (refs[i].actor & 15u)))) {
            fault(p, SP_ACTOR); return 0;
        }
        if (refs[i].active) {
            if (!word(p, refs[i].actor + 8, &flags)) return 0;
            if ((flags & 0xffu) != 9 || (flags & 0x10000u)) { fault(p, SP_ACTOR); return 0; }
        }
    }
    if (!refs[0].active || (refs[1].active && refs[0].actor == refs[1].actor)) {
        fault(p, SP_ACTOR); return 0;
    }
    return 1;
}

static int same_refs(sp_provider *p)
{
    sp_actor_ref refs[2];
    uint32_t i;
    if (!refs_now(p, refs)) return 0;
    for (i = 0; i < 2; ++i)
        if (refs[i].active != p->refs[i].active || refs[i].actor != p->refs[i].actor ||
            refs[i].generation != p->refs[i].generation) {
            fault(p, SP_GENERATION); return 0;
        }
    return 1;
}

static int header(sp_provider *p, sp_map_header *h)
{
    uint32_t s = p->config.stream_state, active, suspended, near, outer;
    if (!word(p, s, &active) || !word(p, s + 4, &suspended) ||
        !word(p, s + 8, &h->table) || !word(p, s + 0x40, &h->size_x) ||
        !word(p, s + 0x44, &h->size_z) || !word(p, s + 0x48, &h->width) ||
        !word(p, s + 0x4c, &h->height) || !word(p, s + 0x50, &h->origin_x) ||
        !word(p, s + 0x54, &h->origin_z) || !word(p, s - 0x2c, &near) ||
        !word(p, s - 0x28, &outer)) return 0;
    if (!active || suspended || h->width != p->config.width || h->height != p->config.height ||
        !region(h->table, h->width * h->height * 24u) || (h->table & 3u) ||
        near > INT32_MAX || outer > INT32_MAX || outer > INT32_MAX - near ||
        !finite_bits(h->size_x) || !finite_bits(h->size_z) ||
        !(as_float(h->size_x) > 0) || !(as_float(h->size_z) > 0) ||
        !finite_bits(h->origin_x) || !finite_bits(h->origin_z)) {
        fault(p, SP_MAP); return 0;
    }
    h->near_radius = (int32_t)near; h->outer_band = (int32_t)outer;
    return 1;
}

static int same_geometry(const sp_map_header *a, const sp_map_header *b)
{
    return a->table == b->table && a->width == b->width && a->height == b->height &&
           a->size_x == b->size_x && a->size_z == b->size_z &&
           a->origin_x == b->origin_x && a->origin_z == b->origin_z;
}

static int plan_epoch(sp_provider *p)
{
    sp_map_header h;
    sp_fault status = owner_status(p);
    if (status != SP_OK) { fault(p, status); return 0; }
    if (!same_refs(p) || !header(p, &h)) return 0;
    if (!same_geometry(&h, &p->geometry) ||
        h.near_radius != p->actors[0].near_radius || h.outer_band != p->actors[0].outer_band) {
        fault(p, SP_MAP); return 0;
    }
    return p->fault == SP_OK;
}

static int point(sp_provider *p, uint32_t address, float dst[4])
{
    unsigned char raw[16];
    uint32_t i, bits;
    if ((address & 15u) || !read_bytes(p, address, raw, 16)) { fault(p, SP_GEOMETRY); return 0; }
    for (i = 0; i < 4; ++i) {
        bits = little32(raw + i * 4);
        if (!finite_bits(bits) || (i == 3 && bits != 0x3f800000u)) {
            fault(p, SP_GEOMETRY); return 0;
        }
        dst[i] = as_float(bits);
    }
    return 1;
}

static int actor_position(sp_provider *p, uint32_t actor, float dst[4])
{
    uint32_t flags, layout, address, again;
    unsigned char flushed;
    if (!word(p, actor + 8, &flags)) return 0;
    if ((flags & 0xffu) != 9 || (flags & 0x10000u)) { fault(p, SP_GEOMETRY); return 0; }
    layout = p->config.get_layout(actor);
    if (layout != actor + 0x90 || !word(p, layout + 0x134, &address) ||
        !read_bytes(p, layout + 0x151, &flushed, 1)) { fault(p, SP_GEOMETRY); return 0; }
    if (flushed || !point(p, address, dst) || !word(p, layout + 0x134, &again) || address != again) {
        fault(p, SP_GEOMETRY); return 0;
    }
    return 1;
}

static int coordinates(sp_provider *p, uint32_t i)
{
    su_actor *a = &p->actors[i];
    float x = as_float(0x7fc00000u), z = x;
    a->rounded_x = a->rounded_z = INT32_MIN;
    p->config.get_chip(p->position[i], &a->rounded_x, &a->rounded_z);
    p->config.get_chip_float(p->position[i], &x, &z);
    if (!finite_float(x) || !finite_float(z) || x < 0 || z < 0 ||
        x >= (float)p->config.width || z >= (float)p->config.height ||
        a->rounded_x < 0 || a->rounded_z < 0 ||
        (uint32_t)a->rounded_x > p->config.width || (uint32_t)a->rounded_z > p->config.height) {
        fault(p, SP_GEOMETRY); return 0;
    }
    a->containing_x = (int32_t)x; a->containing_z = (int32_t)z;
    return 1;
}

void sp_begin(void *ctx)
{
    sp_provider *p = (sp_provider *)ctx;
    sp_map_header h;
    uint32_t i;
    if (!enter(p)) return;
    if (p->iteration == UINT32_MAX) { fault(p, SP_GENERATION); goto done; }
    if (p->snapshot_valid && !same_refs(p)) goto done;
    if (!header(p, &h)) goto done;
    if (p->snapshot_valid && !same_geometry(&h, &p->geometry)) { fault(p, SP_MAP); goto done; }
    p->geometry = h;
    p->iteration++; p->snapshot_valid = p->plan_valid = p->submitted = 0;
    if (!refs_now(p, p->refs) ||
        !point(p, p->config.gc_global + 0x340, p->position[0])) goto done;
    for (i = 0; i < 2; ++i) {
        p->actors[i].active = (uint8_t)p->refs[i].active;
        if (!p->refs[i].active) continue;
        if (i && !actor_position(p, p->refs[i].actor, p->position[i])) goto done;
        if (!coordinates(p, i)) goto done;
    }
    if (same_refs(p)) p->snapshot_valid = 1;
done:
    p->busy = 0;
}

static int views(sp_provider *p, const sp_map_header *h)
{
    uint32_t i, k, n = h->width * h->height;
    for (i = 0; i < n; ++i) {
        uint32_t desc, extra, mode = 0;
        if (!word(p, h->table + i * 24 + 16, &desc) ||
            !word(p, h->table + i * 24 + 20, &extra)) return 0;
        if (desc && !word(p, desc, &mode)) return 0;
        if (mode > 5) { fault(p, SP_MAP); return 0; }
        p->cells[i].descriptor = desc; p->cells[i].mode = (uint8_t)mode;
        p->cells[i].extra = (uint8_t)(extra != 0);
    }
    for (i = 0; i < 2; ++i) {
        su_actor *a = &p->actors[i];
        const su_cell *c;
        uint32_t count = 0, list = 0, stride;
        a->explicit_coords = 0; a->coords = 0; a->coord_count = 0;
        a->rects = p->rects[i]; a->rect_count = 0;
        a->near_radius = h->near_radius; a->outer_band = h->outer_band;
        if (!a->active) continue;
        c = &p->cells[(uint32_t)a->containing_z * h->width + (uint32_t)a->containing_x];
        a->descriptor = c->descriptor; a->mode = c->mode; a->extra = c->extra;
        if (!(a->mode == 5 || (a->mode >= 1 && a->mode <= 3))) continue;
        if (!word(p, a->descriptor + 0x14, &count) || !word(p, a->descriptor + 0x18, &list)) return 0;
        if (count > SP_RECT_CAP) { fault(p, SP_CAPACITY); return 0; }
        stride = a->mode == 5 ? 8u : 12u;
        if (count && ((list & 3u) || !region(list, count * stride))) { fault(p, SP_MAP); return 0; }
        for (k = 0; k < count; ++k) {
            unsigned char b[12];
            su_rect *r = &p->rects[i][k];
            if (!read_bytes(p, list + k * stride, b, stride)) return 0;
            r->x = little16(b); r->z = little16(b + 2); r->width = little16(b + 4);
            r->height = a->mode == 5 ? 1 : little16(b + 6);
        }
        a->rect_count = count;
    }
    return 1;
}

static int pure_policy(void *ctx, const su_actor *a, const su_cell *cell,
                       int32_t x, int32_t z, uint32_t layer)
{
    sp_provider *p = (sp_provider *)ctx;
    int result;
    (void)cell;
    if (p->fault != SP_OK) return -1;
    result = p->config.policy((uint32_t)x, (uint32_t)z, layer,
                             (uint32_t)a->rounded_x, (uint32_t)a->rounded_z,
                             (uint32_t)a->containing_x, (uint32_t)a->containing_z);
    if (result != 0 && result != 1) fault(p, SP_POLICY);
    return p->fault == SP_OK ? result : -1;
}

static int make_plan(sp_provider *p, const sp_batch_args *args)
{
    sp_map_header h, after;
    su_input in;
    su_status status;
    uint32_t i;
    if (!p->snapshot_valid) { fault(p, SP_NO_ITERATION); return 0; }
    if (!same_refs(p) || !header(p, &h)) return 0;
    if (!same_geometry(&h, &p->geometry)) { fault(p, SP_MAP); return 0; }
    if (!views(p, &h)) return 0;
    if (args) {
        const su_actor *a = &p->actors[0];
        if (args->rounded_x != (uint32_t)a->rounded_x || args->rounded_z != (uint32_t)a->rounded_z ||
            args->containing_x != (uint32_t)a->containing_x || args->containing_z != (uint32_t)a->containing_z ||
            args->count > SU_MAX_CELLS || !args->width || !args->height ||
            args->min_x >= h.width || args->min_z >= h.height ||
            args->width > h.width - args->min_x || args->height > h.height - args->min_z ||
            (args->count && ((args->coords & 15u) || !region(args->coords, args->count * 16u)))) {
            fault(p, SP_BATCH); return 0;
        }
        for (i = 0; i < args->count; ++i) {
            uint32_t x, z;
            if (!word(p, args->coords + i * 16, &x) || !word(p, args->coords + i * 16 + 4, &z)) return 0;
            if (x < args->min_x || z < args->min_z || x - args->min_x >= args->width || z - args->min_z >= args->height) {
                fault(p, SP_BATCH); return 0;
            }
            p->p1_coords[i].x = (int32_t)x; p->p1_coords[i].z = (int32_t)z;
        }
        p->actors[0].explicit_coords = 1;
        p->actors[0].coords = p->p1_coords; p->actors[0].coord_count = args->count;
    }
    in.width = h.width; in.height = h.height; in.cells = p->cells;
    in.actors[0] = p->actors[0]; in.actors[1] = p->actors[1];
    in.max_candidates = p->config.max_candidates; in.max_requests = p->config.max_requests;
    in.policy = pure_policy; in.policy_user = p;
    status = su_plan(&in, &p->workspace, &p->plan);
    if (status != SU_OK) { fault(p, status == SU_CAPACITY ? SP_CAPACITY : SP_POLICY); return 0; }
    if (!same_refs(p) || !header(p, &after)) return 0;
    if (!same_geometry(&h, &after) || h.near_radius != after.near_radius || h.outer_band != after.outer_band) {
        fault(p, SP_MAP); return 0;
    }
    p->plan_valid = 1;
    return 1;
}

static void submit_plan(sp_provider *p)
{
    su_tile_iterator it;
    int tile_result;
    uint32_t i, address;
    sp_batch_args args;
    su_tiles_begin(&it);
    while ((tile_result = su_tiles_next(&p->plan, p->config.width, p->config.height, &it, &p->tile)) == 1) {
        if (!plan_epoch(p) || p->fault != SP_OK) return;
        for (i = 0; i < p->tile.count; ++i) {
            p->native_coords[i].word[0] = (uint32_t)p->tile.coords[i].x;
            p->native_coords[i].word[1] = (uint32_t)p->tile.coords[i].z;
            p->native_coords[i].word[2] = p->native_coords[i].word[3] = 0;
        }
        address = p->config.buffer_address ? p->config.buffer_address(p->config.user, p->native_coords, p->tile.count * 16u) :
                  ((uintptr_t)p->native_coords <= UINT32_MAX ? (uint32_t)(uintptr_t)p->native_coords : 0);
        if ((address & 15u) || !region(address, p->tile.count * 16u)) { fault(p, SP_BATCH); return; }
        if (p->fault != SP_OK || !plan_epoch(p)) return;
        if (p->batch_sequence == UINT32_MAX) { fault(p, SP_BATCH); return; }
        args.coords = address; args.count = p->tile.count;
        args.min_x = p->tile.x; args.min_z = p->tile.z;
        args.width = p->tile.width; args.height = p->tile.height;
        args.rounded_x = (uint32_t)p->actors[0].rounded_x; args.rounded_z = (uint32_t)p->actors[0].rounded_z;
        args.containing_x = (uint32_t)p->actors[0].containing_x; args.containing_z = (uint32_t)p->actors[0].containing_z;
        p->active_batch = ++p->batch_sequence;
        p->active_iteration = p->iteration;
        p->scope_active = 1;
        i = p->config.batch(&args);
        clear_scope(p);
        if (i != 1) { fault(p, SP_BATCH); return; }
        if (!plan_epoch(p) || p->fault != SP_OK) return;
    }
    if (tile_result != 0) { fault(p, SP_BATCH); return; }
    p->submitted = 1;
}

void sp_submit(void *ctx, const sp_batch_args *args)
{
    sp_provider *p = (sp_provider *)ctx;
    if (!enter(p)) return;
    if (!args) fault(p, SP_BATCH);
    else if (!p->submitted && make_plan(p, args)) submit_plan(p);
    clear_scope(p); p->busy = 0;
}

void sp_refresh_keep(void *ctx)
{
    sp_provider *p = (sp_provider *)ctx;
    if (!enter(p)) return;
    (void)make_plan(p, 0);
    p->busy = 0;
}

uint32_t sp_predicate(void *ctx, uint32_t x, uint32_t z, uint32_t layer,
                      uint32_t rx, uint32_t rz, uint32_t cx, uint32_t cz)
{
    sp_provider *p = (sp_provider *)ctx;
    uint32_t state, index;
    if (!p) return 0;
    /* Other coroutines on the SAME kernel thread must not even query this
     * provider's fault, registry, plan or cell state. Preserve all seven args. */
    if (owner_status(p) != SP_OK)
        return p->config.original_enable(x, z, layer, rx, rz, cx, cz);
    if (!p->scope_active || !p->active_batch || p->active_batch != p->batch_sequence ||
        p->active_iteration != p->iteration)
        return p->config.original_enable(x, z, layer, rx, rz, cx, cz);
    if (p->fault != SP_OK || !p->plan_valid || !plan_epoch(p)) return 0;
    if (x >= p->config.width || z >= p->config.height || layer > 1) { fault(p, SP_BATCH); return 0; }
    index = z * p->config.width + x;
    if (!word(p, p->geometry.table + index * 24u + 8 + layer * 4, &state)) return 0;
    return (uint32_t)su_choose_layer(&p->plan, index, layer, state & 15u);
}

uint32_t sp_keep_record(void *ctx, uint32_t record)
{
    sp_provider *p = (sp_provider *)ctx;
    uint32_t x, z, layer, current;
    if (!p || p->fault != SP_OK) return 1;
    if (!enter(p)) return 1;
    if (!p->plan_valid || !plan_epoch(p)) { fault(p, SP_NO_ITERATION); goto hold; }
    if (!word(p, record, &x) || !word(p, record + 4, &z) || !word(p, record + 8, &layer)) goto hold;
    if (x >= p->config.width || z >= p->config.height || layer > 1 ||
        !word(p, p->geometry.table + (z * p->config.width + x) * 24u + layer * 4, &current) || current != record) {
        fault(p, SP_RECORD); goto hold;
    }
    p->busy = 0;
    return (p->plan.keep_p2[z * p->config.width + x] & (1u << layer)) != 0;
hold:
    p->busy = 0;
    return 1;
}

void sp_fallback(void *ctx)
{
    sp_provider *p = (sp_provider *)ctx;
    if (!enter(p)) return;
    if (!p->submitted && make_plan(p, 0)) submit_plan(p);
    clear_scope(p); p->busy = 0;
}

size_t sp_storage_size(void) { return sizeof(sp_provider); }

int sp_init(sp_provider *p, const sp_config *c)
{
    size_t i;
    unsigned char *bytes = (unsigned char *)p;
    if (!p || !c || ((uintptr_t)p & 15u) ||
        ((uintptr_t)c < (uintptr_t)p + sizeof(*p) && (uintptr_t)p < (uintptr_t)c + sizeof(*c))) return 0;
    if (!c->width || c->width > SU_MAX_CELLS || !c->height || c->height > SU_MAX_CELLS / c->width ||
        !region(c->stream_state, 0x58) || c->stream_state < 0x8002cu || (c->stream_state & 3u) ||
        !region(c->gc_global, 0x350) || (c->gc_global & 15u) || !c->owner_thread ||
        !region(c->owner_execution, 4) || (c->owner_execution & 3u) ||
        c->max_candidates > SU_MAX_CELLS || c->max_requests > SU_MAX_CELLS ||
        !c->resolve || !c->thread_id || !c->execution_id || !c->get_layout || !c->get_chip || !c->get_chip_float ||
        !c->policy || !c->original_enable || !c->batch || !c->on_fault) return 0;
    for (i = 0; i < sizeof(*p); ++i) bytes[i] = 0;
    p->config = *c;
    return 1;
}
