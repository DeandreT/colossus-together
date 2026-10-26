#include "planner.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static su_cell cells[SU_MAX_CELLS];
static su_coord coords[SU_MAX_CELLS];
static su_workspace work;
static su_output out, saved;
static unsigned calls;

/* Test oracle for the documented G+1F028 policy contract, NOT shipped as
 * the native predicate. Candidate modes, not center modes, select this rule. */
static int policy(void *user, const su_actor *a, const su_cell *c,
                  int32_t x, int32_t z, uint32_t layer)
{
    int64_t dx = (int64_t)x - a->rounded_x;
    int64_t dz = (int64_t)z - a->rounded_z;
    int64_t near = a->near_radius;
    int64_t far = near + a->outer_band;
    int inside = dx >= -near && dx < near && dz >= -near && dz < near;
    ++calls;
    if (user) return *(int *)user;
    if (c->mode == 1) return c->descriptor == a->descriptor;
    if ((c->mode == 2 || c->mode == 3) &&
        c->descriptor != a->descriptor && !c->extra) return 0;
    if (!layer) return inside;
    return !inside && dx >= -far && dx < far && dz >= -far && dz < far;
}

static su_input setup(void)
{
    su_input in;
    memset(&in, 0, sizeof(in));
    memset(cells, 0, sizeof(cells));
    in.width = in.height = 60;
    in.cells = cells;
    in.max_candidates = in.max_requests = SU_MAX_CELLS;
    in.policy = policy;
    in.actors[0].active = 1;
    in.actors[0].rounded_x = in.actors[0].containing_x = 30;
    in.actors[0].rounded_z = in.actors[0].containing_z = 30;
    in.actors[0].near_radius = 1;
    in.actors[0].outer_band = 2;
    calls = 0;
    return in;
}

static unsigned idx(const su_input *in, unsigned x, unsigned z)
{
    return z * in->width + x;
}

static void unchanged(su_input *in, su_status expected)
{
    memset(&out, 0xa5, sizeof(out));
    saved = out;
    assert(su_plan(in, &work, &out) == expected);
    assert(memcmp(&out, &saved, sizeof(out)) == 0);
}

static void basic_and_union(void)
{
    su_input in = setup();
    unsigned x, z;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.candidate_count == 36 && out.desired_count == 36);
    for (z = 0; z < 60; ++z) for (x = 0; x < 60; ++x) {
        unsigned expected = SU_NONE;
        if (x >= 27 && x < 33 && z >= 27 && z < 33) expected = 1;
        if (x >= 29 && x < 31 && z >= 29 && z < 31) expected = 0;
        assert(out.desired[idx(&in, x, z)] == expected);
        assert(out.keep_p2[idx(&in, x, z)] == 0);
    }
    in.actors[1] = in.actors[0];
    in.actors[1].rounded_x = in.actors[1].containing_x = 40;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.desired_count == 72);
    assert(out.keep_p2[idx(&in, 40, 30)] == SU_KEEP_BOTH);
    /* Overlap: P1 far/P2 near, then reversed. */
    in.actors[1].rounded_x = in.actors[1].containing_x = 32;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.desired[idx(&in, 31, 30)] == 0);
    saved = out;
    { su_actor tmp = in.actors[0]; in.actors[0] = in.actors[1]; in.actors[1] = tmp; }
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(memcmp(saved.desired, out.desired, sizeof(out.desired)) == 0);
    /* Stationary P1, successive plans for moving P2: no motion trigger input. */
    in.actors[1].rounded_x = in.actors[1].containing_x = 45;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.desired[idx(&in, 45, 30)] == 0);
    assert(out.keep_p2[idx(&in, 29, 30)] == 0);
}

static void enumeration_and_keep(void)
{
    su_input in = setup();
    su_rect rect = {10, 10, 4, 2};
    unsigned mode;
    /* Native exclusive/clamped upper bug: last row/column omitted. */
    in.actors[0].rounded_x = in.actors[0].containing_x = 59;
    in.actors[0].rounded_z = in.actors[0].containing_z = 59;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.candidate_count == 9);
    assert(out.desired[idx(&in, 59, 59)] == SU_NONE);
    /* Explicit native P1 batch equals standalone enumeration. */
    in = setup();
    assert(su_plan(&in, &work, &saved) == SU_OK);
    in.actors[0].explicit_coords = 1;
    { unsigned x, z, n = 0;
      for (z = 27; z < 33; ++z) for (x = 27; x < 33; ++x)
          { coords[n].x = (int32_t)x; coords[n++].z = (int32_t)z; }
      coords[n] = coords[0]; in.actors[0].coord_count = n + 1; }
    in.actors[0].coords = coords;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(memcmp(&saved, &out, sizeof(out)) == 0);

    for (mode = 1; mode <= 3; ++mode) {
        in = setup();
        in.actors[0].mode = (uint8_t)mode; in.actors[0].descriptor = 100;
        in.actors[0].rects = &rect; in.actors[0].rect_count = 1;
        cells[idx(&in, 30, 30)].mode = (uint8_t)mode;
        cells[idx(&in, 30, 30)].descriptor = 100;
        cells[idx(&in, 10, 10)].mode = (uint8_t)mode;
        cells[idx(&in, 10, 10)].descriptor = 100;
        cells[idx(&in, 11, 10)].mode = (uint8_t)mode;
        cells[idx(&in, 11, 10)].descriptor = 101;
        assert(su_plan(&in, &work, &out) == SU_OK);
        assert(out.candidate_count == 8); /* descriptor rectangle, not square */
        assert(out.desired[idx(&in, 11, 10)] == SU_NONE);
        assert(out.desired[idx(&in, 10, 10)] == (mode == 1 ? 0 : SU_NONE));
        /* Center extra selects the ordinary square. Candidate extra permits
         * near requests for a different type-2/3 descriptor. */
        in.actors[0].extra = 1;
        cells[idx(&in, 30, 30)].extra = 1;
        cells[idx(&in, 29, 30)].mode = (uint8_t)mode;
        cells[idx(&in, 29, 30)].descriptor = 101;
        cells[idx(&in, 29, 30)].extra = 1;
        assert(su_plan(&in, &work, &out) == SU_OK);
        assert(out.candidate_count == 36);
        assert(out.desired[idx(&in, 29, 30)] == (mode == 1 ? SU_NONE : 0));
        in.actors[1] = in.actors[0]; in.actors[0].active = 0;
        assert(su_plan(&in, &work, &out) == SU_OK);
        assert(out.keep_p2[idx(&in, 29, 30)] == SU_KEEP_BOTH);
        in.actors[1].extra = 0; cells[idx(&in, 30, 30)].extra = 0;
        assert(su_plan(&in, &work, &out) == SU_OK);
        assert(out.keep_p2[idx(&in, 29, 30)] == 0);
        assert(out.keep_p2[idx(&in, 30, 30)] == SU_KEEP_BOTH);
    }
    /* Mode 0/4 native unload rule rejects a type-3 cell without extra. */
    for (mode = 0; mode <= 4; mode += 4) {
        in = setup(); in.actors[1] = in.actors[0]; in.actors[0].active = 0;
        in.actors[1].mode = (uint8_t)mode;
        cells[idx(&in, 30, 30)].mode = (uint8_t)mode;
        cells[idx(&in, 29, 30)].mode = 3;
        assert(su_plan(&in, &work, &out) == SU_OK);
        assert(out.keep_p2[idx(&in, 29, 30)] == 0);
        cells[idx(&in, 29, 30)].extra = 1;
        assert(su_plan(&in, &work, &out) == SU_OK);
        assert(out.keep_p2[idx(&in, 29, 30)] == SU_KEEP_BOTH);
    }
}

static void special_and_states(void)
{
    su_input in = setup();
    su_rect spans[2] = {{5, 8, 3, 1}, {45, 48, 2, 1}};
    int yes = 1;
    unsigned i, state;
    in.policy_user = &yes;
    for (i = 0; i < 2; ++i) {
        in.actors[i] = in.actors[0]; in.actors[i].active = 1;
        in.actors[i].rounded_x = in.actors[i].containing_x = spans[i].x;
        in.actors[i].rounded_z = in.actors[i].containing_z = spans[i].z;
        in.actors[i].mode = 5; in.actors[i].descriptor = 100 + i;
        in.actors[i].rects = &spans[i]; in.actors[i].rect_count = 1;
        cells[idx(&in, (unsigned)spans[i].x, (unsigned)spans[i].z)].mode = 5;
        cells[idx(&in, (unsigned)spans[i].x, (unsigned)spans[i].z)].descriptor = 100 + i;
    }
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.candidate_count == 5 && out.desired_count == 5);
    assert(out.keep_p2[idx(&in, 45, 48)] == SU_KEEP_BOTH);
    assert(out.keep_p2[idx(&in, 5, 8)] == 0);
    for (state = 0; state < 8; ++state)
        assert(su_choose_layer(&out, idx(&in, 45, 48), 0, state) ==
               (state == 0 || state == 5));
    /* State 3 does not erase interest; 5 remains selected, with no fallback
     * layer invented here. Native batcher must perform its state-5 trimming. */
    assert(out.desired[idx(&in, 45, 48)] == 0);
    assert(!su_choose_layer(&out, idx(&in, 45, 48), 1, 0));
    assert(!su_choose_layer(&out, SU_MAX_CELLS, 0, 0));
    assert(!su_choose_layer(0, 0, 0, 0));
}

static void rejected(void)
{
    su_input in = setup();
    su_rect rect = {0, 0, INT_MAX, 1};
    int bad = -1;
    in.max_candidates = 35; unchanged(&in, SU_CAPACITY); assert(calls == 0);
    in = setup(); in.max_requests = 35; unchanged(&in, SU_CAPACITY);
    in = setup(); in.policy_user = &bad; unchanged(&in, SU_POLICY_ERROR);
    bad = 2; unchanged(&in, SU_POLICY_ERROR);
    in = setup(); in.width = UINT_MAX; unchanged(&in, SU_INVALID);
    in = setup(); in.height = 0; unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].near_radius = -1; unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].near_radius = INT_MAX;
    in.actors[0].outer_band = 1; unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].containing_x = 60; unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].descriptor = 44; unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].rects = &rect; in.actors[0].rect_count = 1;
    unchanged(&in, SU_INVALID);
    rect.width = 1; rect.height = 2;
    in.actors[0].mode = 5; cells[idx(&in, 30, 30)].mode = 5;
    unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].rect_count = SU_MAX_RECTS + 1;
    unchanged(&in, SU_INVALID);
    in = setup(); in.actors[1] = in.actors[0]; in.actors[1].explicit_coords = 1;
    unchanged(&in, SU_INVALID);
    in = setup(); coords[0].x = -1; coords[0].z = 0;
    in.actors[0].explicit_coords = 1; in.actors[0].coords = coords;
    in.actors[0].coord_count = 1; unchanged(&in, SU_INVALID);
    in = setup(); cells[0].mode = 6; unchanged(&in, SU_INVALID);
    in = setup(); in.cells = (const su_cell *)&out; unchanged(&in, SU_INVALID);
    in = setup(); in.policy = 0; unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].rounded_x = INT_MIN;
    in.actors[0].rounded_z = INT_MAX;
    assert(su_plan(&in, &work, &out) == SU_OK && out.candidate_count == 0);
    in = setup(); in.actors[0].active = 0;
    in.max_candidates = in.max_requests = 0;
    assert(su_plan(&in, &work, &out) == SU_OK && !out.desired_count);
    in = setup(); in.max_requests = SU_MAX_CELLS + 1;
    unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].coords = 0; in.actors[0].coord_count = 1;
    in.actors[0].explicit_coords = 1; unchanged(&in, SU_INVALID);
    in = setup(); in.actors[0].rects = (const su_rect *)&work;
    in.actors[0].rect_count = 1; unchanged(&in, SU_INVALID);
    in = setup(); memset(&out, 0xa5, sizeof(out)); saved = out;
    assert(su_plan(&in, (su_workspace *)&out, &out) == SU_INVALID);
    assert(memcmp(&out, &saved, sizeof(out)) == 0);
}

static void keep_is_independent(void)
{
    su_input in = setup();
    int no = 0;
    in.policy_user = &no;
    in.actors[1] = in.actors[0];
    in.actors[1].mode = 3; in.actors[1].descriptor = 77;
    in.actors[1].extra = 1;
    cells[idx(&in, 30, 30)].mode = 3;
    cells[idx(&in, 30, 30)].descriptor = 77;
    cells[idx(&in, 30, 30)].extra = 1;
    /* P1's metadata must also match the containing cell. */
    in.actors[0].active = 0;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.desired_count == 0); /* no load interest from callback */
    assert(out.keep_p2[idx(&in, 27, 30)] == SU_KEEP_BOTH);
    assert(out.keep_p2[idx(&in, 32, 30)] == SU_KEEP_BOTH);
    assert(out.keep_p2[idx(&in, 26, 30)] == 0);
    assert(out.keep_p2[idx(&in, 33, 30)] == 0);
    /* Replanning after a supplied radius change does not retain old marks. */
    in.actors[1].near_radius = 0; in.actors[1].outer_band = 1;
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.keep_p2[idx(&in, 27, 30)] == 0);
    assert(out.keep_p2[idx(&in, 29, 30)] == SU_KEEP_BOTH);
}

static void tiles_and_maximum(void)
{
    su_input in = setup();
    su_tile_iterator it;
    su_tile tile, before;
    unsigned visited[SU_MAX_CELLS] = {0}, i, n = 0, tiles = 0;
    int yes = 1, result;
    in.width = in.height = 64;
    in.policy_user = &yes;
    in.actors[0].explicit_coords = 1;
    in.actors[0].coords = coords; in.actors[0].coord_count = SU_MAX_CELLS;
    for (i = 0; i < SU_MAX_CELLS; ++i) {
        coords[i].x = (int32_t)(i % 64); coords[i].z = (int32_t)(i / 64);
    }
    assert(su_plan(&in, &work, &out) == SU_OK);
    assert(out.candidate_count == SU_MAX_CELLS && out.desired_count == SU_MAX_CELLS);
    su_tiles_begin(&it);
    while ((result = su_tiles_next(&out, 64, 64, &it, &tile)) == 1) {
        assert(tile.width <= 16 && tile.height <= 16);
        assert(tile.width * tile.height * 4 <= 1024 && tile.count <= 256);
        ++tiles;
        for (i = 0; i < tile.count; ++i) {
            unsigned x = (unsigned)tile.coords[i].x, z = (unsigned)tile.coords[i].z;
            assert(x >= tile.x && x < tile.x + tile.width);
            assert(z >= tile.z && z < tile.z + tile.height);
            assert(!visited[z * 64 + x]++); ++n;
        }
    }
    assert(result == 0 && n == SU_MAX_CELLS && tiles == 16);
    assert(su_tiles_next(&out, 64, 64, &it, &tile) == 0);
    before = tile; it.x = 1;
    assert(su_tiles_next(&out, 64, 64, &it, &tile) == -1);
    assert(memcmp(&before, &tile, sizeof(tile)) == 0);
    in = setup(); assert(su_plan(&in, &work, &out) == SU_OK);
    su_tiles_begin(&it); memset(visited, 0, sizeof(visited)); n = 0;
    while (su_tiles_next(&out, 60, 60, &it, &tile) == 1)
        for (i = 0; i < tile.count; ++i) {
            unsigned p = (unsigned)tile.coords[i].z * 60 + (unsigned)tile.coords[i].x;
            assert(out.desired[p] != SU_NONE && !visited[p]++); ++n;
        }
    assert(n == out.desired_count);
    /* Explicit lists may include the last cell; partial edge tiles must too. */
    in.policy_user = &yes; in.actors[0].explicit_coords = 1;
    in.actors[0].coords = coords; in.actors[0].coord_count = 1;
    coords[0].x = coords[0].z = 59;
    assert(su_plan(&in, &work, &out) == SU_OK);
    su_tiles_begin(&it);
    assert(su_tiles_next(&out, 60, 60, &it, &tile) == 1);
    assert(tile.x == 48 && tile.z == 48 && tile.width == 12 && tile.height == 12);
    assert(tile.count == 1 && tile.coords[0].x == 59 && tile.coords[0].z == 59);
    assert(su_tiles_next(&out, 60, 60, &it, &tile) == 0);
    su_tiles_begin(&it); out.desired[0] = 7;
    assert(su_tiles_next(&out, 60, 60, &it, &tile) == -1 && it.x == 0 && it.z == 0);
}

int main(void)
{
    basic_and_union(); enumeration_and_keep(); special_and_states();
    rejected(); keep_is_independent(); tiles_and_maximum();
    puts("streaming planner checks passed");
    return 0;
}
