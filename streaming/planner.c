#include "planner.h"

static int dimensions(uint32_t w, uint32_t h)
{
    return w && h && w <= SU_MAX_CELLS && h <= SU_MAX_CELLS / w;
}

static int overlap(const void *a, uintptr_t an, const void *b, uintptr_t bn)
{
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    if (!an || !bn) return 0;
    if (!a || !b || an > UINTPTR_MAX - av || bn > UINTPTR_MAX - bv) return 1;
    return av < bv + bn && bv < av + an;
}

static int storage_ok(const void *p, uintptr_t size, const su_workspace *w,
                      const su_output *o)
{
    return !overlap(p, size, w, sizeof(*w)) &&
           !overlap(p, size, o, sizeof(*o));
}

static int in_rect(const su_rect *r, int32_t x, int32_t z)
{
    /* Validated endpoints fit the map and therefore int32_t. */
    return x >= r->x && x < r->x + r->width &&
           z >= r->z && z < r->z + r->height;
}

static int listed(const su_actor *a, int32_t x, int32_t z)
{
    uint32_t j;
    for (j = 0; j < a->rect_count; ++j)
        if (in_rect(&a->rects[j], x, z)) return 1;
    return 0;
}

static int square(const su_actor *a, uint32_t w, uint32_t h,
                  int32_t x, int32_t z)
{
    int64_t r = (int64_t)a->near_radius + a->outer_band;
    int64_t xl = (int64_t)a->rounded_x - r;
    int64_t xr = (int64_t)a->rounded_x + r;
    int64_t zl = (int64_t)a->rounded_z - r;
    int64_t zr = (int64_t)a->rounded_z + r;
    if (xl < 0) xl = 0;
    if (zl < 0) zl = 0;
    if (xr > (int64_t)w - 1) xr = (int64_t)w - 1;
    if (zr > (int64_t)h - 1) zr = (int64_t)h - 1;
    /* Original exclusive upper bound even after clamping to dimension-1. */
    return x >= xl && x < xr && z >= zl && z < zr;
}

static int enumerated(const su_actor *a, uint32_t w, uint32_t h,
                      int32_t x, int32_t z)
{
    uint32_t j;
    if (a->explicit_coords) {
        for (j = 0; j < a->coord_count; ++j)
            if (a->coords[j].x == x && a->coords[j].z == z) return 1;
        return 0;
    }
    if (a->mode == 5 || (a->mode >= 1 && a->mode <= 3 && !a->extra))
        return listed(a, x, z);
    return square(a, w, h, x, z);
}

static int keep(const su_actor *a, const su_cell *c, int32_t x, int32_t z)
{
    int64_t r, dx, dz;
    if (!a->active) return 0;
    if (a->mode == 5) return listed(a, x, z);
    if (a->mode >= 1 && a->mode <= 3) {
        if (c->descriptor != a->descriptor && !a->extra) return 0;
    } else if (c->mode == 3 && !c->extra) return 0;
    r = (int64_t)a->near_radius + a->outer_band;
    dx = (int64_t)x - a->rounded_x;
    dz = (int64_t)z - a->rounded_z;
    /* abs(delta + 0.5) <= integer radius, without FP/rounding dependence. */
    return dx >= -r && dx < r && dz >= -r && dz < r;
}

static su_status validate(const su_input *in, su_workspace *w, su_output *out)
{
    uint32_t i, j, n;
    if (!in || !w || !out || !dimensions(in->width, in->height) ||
        !in->cells || !in->policy ||
        overlap(w, sizeof(*w), out, sizeof(*out)) ||
        !storage_ok(in, sizeof(*in), w, out)) return SU_INVALID;
    n = in->width * in->height;
    if (in->max_candidates > SU_MAX_CELLS || in->max_requests > SU_MAX_CELLS)
        return SU_INVALID;
    if (!storage_ok(in->cells, n * sizeof(*in->cells), w, out)) return SU_INVALID;
    for (i = 0; i < n; ++i)
        if (in->cells[i].mode > 5 || in->cells[i].extra > 1) return SU_INVALID;
    for (i = 0; i < 2; ++i) {
        const su_actor *a = &in->actors[i];
        const su_cell *c;
        if (a->active > 1) return SU_INVALID;
        if (!a->active) continue;
        if (a->mode > 5 || a->extra > 1 || a->explicit_coords > 1 ||
            (i && a->explicit_coords) || a->near_radius < 0 || a->outer_band < 0 ||
            (int64_t)a->near_radius + a->outer_band > INT32_MAX ||
            a->containing_x < 0 || a->containing_z < 0 ||
            (uint32_t)a->containing_x >= in->width ||
            (uint32_t)a->containing_z >= in->height ||
            a->rect_count > SU_MAX_RECTS || a->coord_count > SU_MAX_CELLS ||
            (a->rect_count && !a->rects) || (a->coord_count && !a->coords) ||
            (!a->explicit_coords && a->coord_count)) return SU_INVALID;
        c = &in->cells[(uint32_t)a->containing_z * in->width +
                       (uint32_t)a->containing_x];
        if (c->descriptor != a->descriptor || c->mode != a->mode ||
            c->extra != a->extra) return SU_INVALID;
        if (!storage_ok(a->rects, a->rect_count * sizeof(*a->rects), w, out) ||
            !storage_ok(a->coords, a->coord_count * sizeof(*a->coords), w, out))
            return SU_INVALID;
        for (j = 0; j < a->rect_count; ++j) {
            const su_rect *r = &a->rects[j];
            if (r->x < 0 || r->z < 0 || r->width <= 0 || r->height <= 0 ||
                (int64_t)r->x + r->width > in->width ||
                (int64_t)r->z + r->height > in->height ||
                (a->mode == 5 && r->height != 1)) return SU_INVALID;
        }
        for (j = 0; j < a->coord_count; ++j)
            if (a->coords[j].x < 0 || a->coords[j].z < 0 ||
                (uint32_t)a->coords[j].x >= in->width ||
                (uint32_t)a->coords[j].z >= in->height) return SU_INVALID;
    }
    return SU_OK;
}

su_status su_plan(const su_input *in, su_workspace *w, su_output *out)
{
    uint32_t i, j, n, candidates = 0, desired = 0;
    su_status status = validate(in, w, out);
    if (status != SU_OK) return status;
    n = in->width * in->height;
    for (i = 0; i < SU_MAX_CELLS; ++i) {
        w->candidates[i] = 0;
        w->staged.desired[i] = SU_NONE;
        w->staged.keep_p2[i] = 0;
    }
    for (i = 0; i < n; ++i) {
        int32_t x = (int32_t)(i % in->width), z = (int32_t)(i / in->width);
        for (j = 0; j < 2; ++j)
            if (in->actors[j].active && enumerated(&in->actors[j], in->width,
                                                  in->height, x, z))
                w->candidates[i] |= (uint8_t)(1u << j);
        if (w->candidates[i] && ++candidates > in->max_candidates)
            return SU_CAPACITY;
        if (keep(&in->actors[1], &in->cells[i], x, z))
            w->staged.keep_p2[i] = SU_KEEP_BOTH;
    }
    for (i = 0; i < n; ++i) {
        uint8_t layer = SU_NONE;
        for (j = 0; j < 2; ++j) {
            uint32_t k;
            if (!(w->candidates[i] & (1u << j))) continue;
            for (k = 0; k < 2; ++k) {
                int yes = in->policy(in->policy_user, &in->actors[j],
                                     &in->cells[i], (int32_t)(i % in->width),
                                     (int32_t)(i / in->width), k);
                if (yes != 0 && yes != 1) return SU_POLICY_ERROR;
                if (yes && k < layer) layer = (uint8_t)k;
            }
        }
        w->staged.desired[i] = layer;
        if (layer != SU_NONE && ++desired > in->max_requests) return SU_CAPACITY;
    }
    w->staged.cell_count = n;
    w->staged.candidate_count = candidates;
    w->staged.desired_count = desired;
    /* Explicit loops keep this freestanding; no memcpy/runtime dependency. */
    for (i = 0; i < SU_MAX_CELLS; ++i) {
        out->desired[i] = w->staged.desired[i];
        out->keep_p2[i] = w->staged.keep_p2[i];
    }
    out->cell_count = n;
    out->candidate_count = candidates;
    out->desired_count = desired;
    return SU_OK;
}

int su_choose_layer(const su_output *out, uint32_t cell, uint32_t layer,
                    uint32_t native_state)
{
    return out && out->cell_count <= SU_MAX_CELLS && cell < out->cell_count &&
           layer < 2 && out->desired[cell] == layer &&
           (native_state == 0 || native_state == 5);
}

void su_tiles_begin(su_tile_iterator *it)
{
    if (it) { it->x = 0; it->z = 0; }
}

int su_tiles_next(const su_output *out, uint32_t width, uint32_t height,
                  su_tile_iterator *it, su_tile *tile)
{
    uint32_t x, z, tx, tz, tw, th, n, i;
    if (!out || !it || !tile || !dimensions(width, height) ||
        out->cell_count != width * height || it->x >= width ||
        it->z > height || it->x % SU_TILE_SIDE ||
        (it->z != height && it->z % SU_TILE_SIDE) ||
        overlap(out, sizeof(*out), tile, sizeof(*tile)) ||
        overlap(out, sizeof(*out), it, sizeof(*it)) ||
        overlap(tile, sizeof(*tile), it, sizeof(*it))) return -1;
    for (i = 0; i < out->cell_count; ++i)
        if (out->desired[i] != SU_NONE && out->desired[i] > 1) return -1;
    tx = it->x; tz = it->z;
    while (tz < height) {
        tw = width - tx; if (tw > SU_TILE_SIDE) tw = SU_TILE_SIDE;
        th = height - tz; if (th > SU_TILE_SIDE) th = SU_TILE_SIDE;
        n = 0;
        for (z = tz; z < tz + th; ++z)
            for (x = tx; x < tx + tw; ++x)
                if (out->desired[z * width + x] != SU_NONE) ++n;
        if (n) {
            tile->x = tx; tile->z = tz; tile->width = tw; tile->height = th;
            tile->count = 0;
            for (z = tz; z < tz + th; ++z)
                for (x = tx; x < tx + tw; ++x)
                    if (out->desired[z * width + x] != SU_NONE) {
                        tile->coords[tile->count].x = (int32_t)x;
                        tile->coords[tile->count++].z = (int32_t)z;
                    }
        }
        tx += SU_TILE_SIDE;
        if (tx >= width) { tx = 0; tz += th; }
        if (n) { it->x = tx; it->z = tz; return 1; }
    }
    it->x = 0; it->z = height;
    return 0;
}
