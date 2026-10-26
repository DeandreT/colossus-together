#ifndef SU_PLANNER_H
#define SU_PLANNER_H

#include <stdint.h>

#define SU_MAX_CELLS 4096u
#define SU_MAX_RECTS 4096u
#define SU_TILE_SIDE 16u
#define SU_NONE 255u
#define SU_KEEP_BOTH 3u

typedef struct { int32_t x, z; } su_coord;
/* Canonical validated view of native 12-byte rectangles / 8-byte row spans. */
typedef struct { int32_t x, z, width, height; } su_rect;
typedef struct {
    uint32_t descriptor;
    uint8_t mode, extra;
} su_cell;
typedef struct {
    uint8_t active, mode, extra, explicit_coords;
    uint32_t descriptor;
    int32_t rounded_x, rounded_z, containing_x, containing_z;
    int32_t near_radius, outer_band;
    const su_rect *rects;
    uint32_t rect_count;
    /* Supported for actor 0 only: the list passed by P1's native selector. */
    const su_coord *coords;
    uint32_t coord_count;
} su_actor;

/* Pure G+1F028 semantic policy, with native load-state prefix removed.
 * Return exactly 0 or 1; any other result rejects the whole transaction.
 * No retained pointers, output mutation, allocation, or native writes. */
typedef int (*su_policy)(void *user, const su_actor *actor,
                         const su_cell *candidate, int32_t x, int32_t z,
                         uint32_t layer);
typedef struct {
    uint32_t width, height;
    const su_cell *cells; /* width*height readable entries, row major */
    su_actor actors[2];
    uint32_t max_candidates, max_requests;
    su_policy policy;
    void *policy_user;
} su_input;
typedef struct {
    uint8_t desired[SU_MAX_CELLS];
    uint8_t keep_p2[SU_MAX_CELLS]; /* bit 0/1: retain layer 0/1 */
    uint32_t cell_count, candidate_count, desired_count;
} su_output;
typedef struct {
    uint8_t candidates[SU_MAX_CELLS]; /* actor bits; private, never native */
    su_output staged;
} su_workspace;
typedef enum {
    SU_OK = 0, SU_INVALID, SU_CAPACITY, SU_POLICY_ERROR
} su_status;

/* Caller owns all storage. Output is byte-for-byte unchanged on failure.
 * Workspace must not overlap input/views/output. Output must not overlap
 * input/views. Pointer readability and callback purity are caller contracts. */
su_status su_plan(const su_input *in, su_workspace *work, su_output *out);
int su_choose_layer(const su_output *out, uint32_t cell, uint32_t layer,
                    uint32_t native_state);

typedef struct { uint32_t x, z; } su_tile_iterator;
typedef struct {
    uint32_t x, z, width, height, count;
    su_coord coords[SU_TILE_SIDE * SU_TILE_SIDE];
} su_tile;
void su_tiles_begin(su_tile_iterator *it);
/* 1: nonempty tile; 0: end; -1: invalid input (no writes). The output must
 * come from su_plan; dims must match its cell_count. */
int su_tiles_next(const su_output *out, uint32_t width, uint32_t height,
                  su_tile_iterator *it, su_tile *tile);

#endif
