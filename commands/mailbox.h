/* Own protocol definition, not a game header. All words little-endian. */
#ifndef COOP_COMMAND_MAILBOX_H
#define COOP_COMMAND_MAILBOX_H
#include <stddef.h>
#include <stdint.h>
#define COOP_COMMAND_CALL 1u
#define COOP_COMMAND_OK 0u
#define COOP_COMMAND_BAD_OPERATION 1u
#define COOP_COMMAND_BAD_TARGET 2u
#define COOP_COMMAND_SEQUENCE_FAULT 3u
typedef struct {
    volatile uint32_t request_sequence; /* host publication, written last */
    volatile uint32_t reply_sequence;   /* EE publication, SYNC then store */
    volatile uint32_t busy;
    volatile uint32_t last_sequence;
    uint32_t target_index;
    uint32_t operation;
    uint32_t args[8];                   /* a0-a3, t0-t3; no stack arguments */
    uint32_t floats[3];                 /* raw bits for f12, f13, f14 */
    uint32_t status;
    uint32_t v0, v1, f0;                /* low uint32 / raw float bits */
    volatile uint32_t fault;            /* sticky, no in-place reset */
    uint32_t reserved[2];
} CoopCommandMailbox;                  /* 96 bytes, base aligned to 16 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(CoopCommandMailbox) == 96, "mailbox size");
_Static_assert(offsetof(CoopCommandMailbox, args) == 24, "argument offset");
_Static_assert(offsetof(CoopCommandMailbox, floats) == 56, "float offset");
_Static_assert(offsetof(CoopCommandMailbox, status) == 68, "status offset");
_Static_assert(offsetof(CoopCommandMailbox, v0) == 72, "result offset");
_Static_assert(offsetof(CoopCommandMailbox, fault) == 84, "fault offset");
#endif
#endif
