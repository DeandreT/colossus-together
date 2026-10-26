#ifndef RENDER_STATE_BANK_H
#define RENDER_STATE_BANK_H
#include <stdint.h>
#include <stddef.h>

#define RB_MAX_RANGES 1024u
#define RB_RAM_BYTES 0x02000000u
typedef struct { uint32_t address, size; } rb_extent;
typedef struct { uint32_t address, size, owner_id, generation; } rb_range;
typedef struct { rb_extent extent; uint32_t offset; } rb_union;
typedef struct {
    rb_range original[RB_MAX_RANGES];
    rb_union merged[RB_MAX_RANGES];
} rb_workspace;
typedef enum {
    RB_IDLE, RB_BASE_CAPTURED, RB_P1_CAPTURED,
    RB_P2_BASE_RESTORED, RB_P1_RESTORED
} rb_phase;
typedef enum {
    RB_OK, RB_ARGUMENT, RB_BOUNDS, RB_CAPACITY, RB_ALIAS,
    RB_ORDER, RB_OWNER, RB_FENCE, RB_INDETERMINATE
} rb_result;
typedef struct {
    void *context;
    /* Validate identity AND that the entire range is in its live allocation.
     * Nonzero means success. Checks must not mutate/free target storage. */
    int (*alive)(void *, const rb_range *);
    int (*fence)(void *);
    int (*read)(void *, uint32_t address, unsigned char *, uint32_t size);
    int (*write)(void *, uint32_t address, const unsigned char *, uint32_t size);
    unsigned char *base, *p1;
    uint32_t capacity, max_bytes;
    /* Full allocated buffer extents, each size == capacity. */
    rb_extent base_storage, p1_storage;
    /* Must cover bank, workspace and all other bank-owned EE metadata. */
    rb_extent metadata_storage;
} rb_config;
typedef struct {
    rb_config config;
    rb_workspace *workspace;
    uint32_t count, union_count, bytes, prepared;
    rb_phase phase;
    rb_result fault;
} rb_bank;

/* Fresh object only, or externally confirmed quiescent/repaired prior frame.
 * Source ranges/config must not alias bank, workspace or either buffer.
 * Failed initialization leaves fault latched; buffers are never cleared.
 * Exception: overlapping C objects are rejected without touching any object;
 * the bank is not initialized and cannot be used until fresh initialization. */
rb_result rb_init(rb_bank *, rb_workspace *, const rb_config *,
                  const rb_range *, uint32_t count);
rb_result rb_begin_frame(rb_bank *);
rb_result rb_capture_p1(rb_bank *);
rb_result rb_restore_base(rb_bank *);
rb_result rb_restore_p1(rb_bank *);
rb_result rb_end_frame(rb_bank *);
rb_result rb_cancel_before_render(rb_bank *, int no_render_acknowledged);
/* Acknowledgment includes external repair of any uncertain target state.
 * Rechecks fence and every original owner; never performs target writes. */
rb_result rb_abort_quiescent(rb_bank *, int quiescent_repaired_acknowledged);
#endif
