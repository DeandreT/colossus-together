#include "bank.h"

static rb_result fail(rb_bank *b, rb_result r) {
    if (b->fault == RB_OK) b->fault = r;
    return b->fault;
}
static int valid(rb_extent e) {
    return e.size && !(e.address & 3u) && !(e.size & 3u) &&
           e.address < RB_RAM_BYTES && e.size <= RB_RAM_BYTES - e.address;
}
static int overlap(rb_extent a, rb_extent b) {
    return a.address < b.address + b.size && b.address < a.address + a.size;
}
static int pointers_overlap(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    /* Subtraction avoids end-pointer overflow. */
    return x <= y ? y - x < an : x - y < bn;
}
static rb_result validate(rb_bank *b) {
    uint32_t i;
    rb_config *c = &b->config;
    if (!c->base || !c->p1 || !c->alive || !c->fence || !c->read ||
        !c->write || !b->workspace || !b->count || b->count > RB_MAX_RANGES)
        return RB_ARGUMENT;
    if (!valid(c->base_storage) || !valid(c->p1_storage) ||
        !valid(c->metadata_storage)) return RB_BOUNDS;
    if (c->metadata_storage.size < sizeof(*b) + sizeof(*b->workspace) ||
        c->base_storage.size != c->capacity || c->p1_storage.size != c->capacity ||
        b->bytes > c->capacity || b->bytes > c->max_bytes) return RB_CAPACITY;
    if (overlap(c->base_storage, c->p1_storage) ||
        overlap(c->base_storage, c->metadata_storage) ||
        overlap(c->p1_storage, c->metadata_storage)) return RB_ALIAS;
    for (i = 0; i < b->count; ++i) {
        rb_range *r = &b->workspace->original[i];
        rb_extent e = { r->address, r->size };
        if (!valid(e)) return RB_BOUNDS;
        if (overlap(e, c->base_storage) || overlap(e, c->p1_storage) ||
            overlap(e, c->metadata_storage)) return RB_ALIAS;
    }
    /* Do not short circuit duplicate owners: every original range is checked. */
    for (i = 0; i < b->count; ++i) {
        rb_range *r = &b->workspace->original[i];
        if (!c->alive(c->context, r)) return RB_OWNER;
    }
    return RB_OK;
}
rb_result rb_init(rb_bank *b, rb_workspace *w, const rb_config *c,
                  const rb_range *r, uint32_t count) {
    uint32_t i, j;
    rb_result result;
    if (!b) return RB_ARGUMENT;
    /* Caller must supply distinct, valid objects; detect aliases before writes. */
    if (!w || !c || !r || !count || count > RB_MAX_RANGES) {
        b->prepared = 0; b->fault = RB_ARGUMENT; return RB_ARGUMENT;
    }
    if (pointers_overlap(b, sizeof(*b), w, sizeof(*w)) ||
        pointers_overlap(b, sizeof(*b), c, sizeof(*c)) ||
        pointers_overlap(b, sizeof(*b), r, count * sizeof(*r)) ||
        pointers_overlap(w, sizeof(*w), c, sizeof(*c)) ||
        pointers_overlap(w, sizeof(*w), r, count * sizeof(*r))) return RB_ALIAS;
    /* No metadata writes are safe if a host buffer overlaps metadata/input. */
    if (pointers_overlap(c->base, c->capacity, c->p1, c->capacity) ||
        pointers_overlap(c->base, c->capacity, b, sizeof(*b)) ||
        pointers_overlap(c->p1, c->capacity, b, sizeof(*b)) ||
        pointers_overlap(c->base, c->capacity, w, sizeof(*w)) ||
        pointers_overlap(c->p1, c->capacity, w, sizeof(*w)) ||
        pointers_overlap(c->base, c->capacity, r, count * sizeof(*r)) ||
        pointers_overlap(c->p1, c->capacity, r, count * sizeof(*r)) ||
        pointers_overlap(c->base, c->capacity, c, sizeof(*c)) ||
        pointers_overlap(c->p1, c->capacity, c, sizeof(*c))) return RB_ALIAS;
    b->fault = RB_OK; b->phase = RB_IDLE; b->workspace = w; b->prepared = 0;
    /* Field-wise copy avoids freestanding compiler memcpy dependencies. */
    b->config.context = c->context; b->config.alive = c->alive;
    b->config.fence = c->fence; b->config.read = c->read; b->config.write = c->write;
    b->config.base = c->base; b->config.p1 = c->p1;
    b->config.capacity = c->capacity; b->config.max_bytes = c->max_bytes;
    b->config.base_storage = c->base_storage; b->config.p1_storage = c->p1_storage;
    b->config.metadata_storage = c->metadata_storage;
    b->count = count; b->union_count = 0; b->bytes = 0;
    for (i = 0; i < count; ++i) {
        w->original[i] = r[i];
    }
    result = validate(b);
    if (result != RB_OK) return fail(b, result);
    /* Insertion-sort extents only; original identity records stay intact. */
    for (i = 0; i < count; ++i) {
        rb_extent e = { r[i].address, r[i].size };
        j = i;
        while (j && w->merged[j - 1].extent.address > e.address) {
            w->merged[j].extent = w->merged[j - 1].extent; --j;
        }
        w->merged[j].extent = e;
    }
    for (i = 0; i < count; ++i) {
        rb_extent e = w->merged[i].extent;
        if (b->union_count) {
            rb_extent *last = &w->merged[b->union_count - 1].extent;
            uint32_t end = last->address + last->size;
            if (e.address <= end) {
                if (e.address + e.size > end) last->size = e.address + e.size - last->address;
                continue;
            }
        }
        w->merged[b->union_count++].extent = e;
    }
    for (i = 0; i < b->union_count; ++i) {
        w->merged[i].offset = b->bytes;
        b->bytes += w->merged[i].extent.size;
    }
    result = validate(b);
    if (result != RB_OK) return fail(b, result);
    b->prepared = 1;
    return RB_OK;
}
static rb_result ready(rb_bank *b, rb_phase phase) {
    rb_result r;
    if (!b) return RB_ARGUMENT;
    if (b->fault != RB_OK) return b->fault;
    if (!b->prepared) return fail(b, RB_ARGUMENT);
    if (b->phase != phase) return fail(b, RB_ORDER);
    if (!b->config.fence(b->config.context)) return fail(b, RB_FENCE);
    r = validate(b);
    return r == RB_OK ? RB_OK : fail(b, r);
}
static rb_result transfer(rb_bank *b, rb_phase from, rb_phase to, int write, int p1) {
    uint32_t i;
    rb_result r = ready(b, from);
    unsigned char *buffer;
    if (r != RB_OK) return r;
    buffer = p1 ? b->config.p1 : b->config.base;
    for (i = 0; i < b->union_count; ++i) {
        rb_union *u = &b->workspace->merged[i];
        int ok = write ? b->config.write(b->config.context, u->extent.address,
                                         buffer + u->offset, u->extent.size)
                       : b->config.read(b->config.context, u->extent.address,
                                        buffer + u->offset, u->extent.size);
        if (!ok) return fail(b, RB_INDETERMINATE);
    }
    b->phase = to;
    return RB_OK;
}
rb_result rb_begin_frame(rb_bank *b) { return transfer(b, RB_IDLE, RB_BASE_CAPTURED, 0, 0); }
rb_result rb_capture_p1(rb_bank *b) { return transfer(b, RB_BASE_CAPTURED, RB_P1_CAPTURED, 0, 1); }
rb_result rb_restore_base(rb_bank *b) { return transfer(b, RB_P1_CAPTURED, RB_P2_BASE_RESTORED, 1, 0); }
rb_result rb_restore_p1(rb_bank *b) { return transfer(b, RB_P2_BASE_RESTORED, RB_P1_RESTORED, 1, 1); }
rb_result rb_end_frame(rb_bank *b) {
    rb_result r = ready(b, RB_P1_RESTORED);
    if (r == RB_OK) b->phase = RB_IDLE;
    return r;
}
rb_result rb_cancel_before_render(rb_bank *b, int ack) {
    rb_result r;
    if (!b) return RB_ARGUMENT;
    if (!ack) return fail(b, RB_ARGUMENT);
    r = ready(b, RB_BASE_CAPTURED);
    if (r == RB_OK) b->phase = RB_IDLE;
    return r;
}
rb_result rb_abort_quiescent(rb_bank *b, int ack) {
    rb_result r;
    if (!b) return RB_ARGUMENT;
    if (!ack || !b->prepared || !b->workspace || !b->config.fence) return fail(b, RB_ARGUMENT);
    if (!b->config.fence(b->config.context)) return fail(b, RB_FENCE);
    r = validate(b);
    if (r != RB_OK) return fail(b, r);
    b->phase = RB_IDLE; b->fault = RB_OK;
    return RB_OK;
}
