/* Project-authored registry bridge. No game addresses or stock implementation.
 *
 * Contract (also the integration/compile notes):
 * Zero-initialize NLBridge before its one allowed initialization. Provision
 * disjoint, reserved mod registry/bank/view regions and trusted stock
 * thunks with the correct module GP. Initialize once, bind to NLContext, register
 * P1 through nl_bridge_adopt_canonical with its explicit existing generation
 * (legacy allocation registration remains supported), then explicitly provision
 * Context epochs and canonical identity. All operations and final-free events are serialized
 * on the game thread; stock thunks must return without scheduler yield.
 * No network-supplied addresses, current-player swap, P1
 * group registration, campaign writes, or phase promotion are performed here.
 *
 * The 128 records retain tombstones until the owner explicitly acknowledges a
 * retired generation or exact final-freed identities. There is no automatic
 * eviction, ID reuse, wrap or reset.
 * Exhaustion fails without overwriting any record.
 * A raw allocation's final-free event must be delivered before that raw address
 * can be reused. An event containing only a raw address cannot disambiguate a
 * delayed old free from a new allocation at the same address.
 * Existing live P1 allocations retain their own generation when a new P2 epoch
 * starts. P2 publication requires its current generation; it preserves P1's
 * charge generation and the shared Agro identity.
 * A new canonical admission also rebinds view+0x140 and clears only that new
 * P1's selection progress at +0x1c8/+0x1cc, so rendering cannot retain a freed
 * canonical actor. P2 publication does not touch these P1 fields.
 *
 * Canonical admission is called ONLY after successful vanilla group insertion
 * and verification that GetFirst(group) equals the admitted actor. It must finish
 * before P1 initialization adapters run. This bridge does not inspect the group
 * or insert P2 into it. Admission advances canonical_generation, never the P2
 * transaction generation. Same-address admission is idempotent only while the
 * exact allocation is still live; final-free then reuse creates a fresh ID.
 * Admission writes only mod P1 identity/work and charge generation/epoch/flags.
 * It preserves P2 banks, routing, view, horse identity and actual P1 state.
 * Call refresh_canonical_work after P1 initializes its initially absent AI work.
 * A nonzero fault quarantines canonical operations and blocks P2 publication;
 * it must also stop the admission hook from proceeding to P1 init adapters.
 * Partial writes are not rolled back or retried. The retained canonical fields
 * identify the failed admission, not successful readiness. P2 unpublication is
 * still permitted so the old transaction can drain. No fault-reset API exists.
 *
 * Object+0 is the raw-allocation identity word and remains stable throughout
 * its lifetime. Visual parenting writes the P2 pointer into the private copied
 * geometry-pointer buffer, never into the actor's allocation header.
 *
 * Stock P2 construction still requires the separately qualified guard skipping
 * initWeapon/SCRPlayerGetWeapon and global alert/death stores. Not implemented
 * here. Failed BUILDING recovery remains an adapter gap: retain partial objects,
 * latch failure, and do not promote ACTIVE to bypass begin_retire's guard.
 *
 * Registry writes are ordered, not atomic. Read/write callbacks must provide
 * coherent aligned 32-bit operations. Any I/O failure is fatal to that action;
 * quarantine partial publication rather than retrying or rolling it back blindly.
 * Both bank payloads are complete before either READY=1 write, then registry P2
 * pointers are published, and routing is published last. View activation zeros
 * orbit magic at +0x180 and P2 selection progress at +0x1c0..+0x1c4, sets local mode
 * at +0xe0, and publishes the P2 view pointer at +0x144 last. Withdrawal clears
 * routing, bank READY flags, view pointer/local mode and matching P2 registry
 * slots; these P2 actions write no canonical P1 fields or P1 work memory.
 * With no memory callbacks, EE access uses checked physical aliases; range checks
 * are not proof of mapping, type, lifetime or exclusive ownership. Host tests
 * must supply BOTH callbacks. Configured regions must not overlap game objects,
 * P1 work/state or any unrelated storage; init checks pairwise mod-region overlap.
 *
 * Compile alongside lifecycle.c using PS2 EE GCC:
 * -std=c11 -O2 -ffreestanding -fno-builtin -mabi=eabi -mlong32 -mgp64
 * -march=r5900 -G0 -mno-abicalls -fno-pic -c bridge.c
 * Relocatable link: EE ld -m elf32lr5900 -r lifecycle.o bridge.o -o native_bridge.o
 * Link into the reserved payload; approve helper entry points through commands.
 * This is not an installer or a live-execution qualification.
 */
#ifndef COOP_NATIVE_LIFECYCLE_BRIDGE_H
#define COOP_NATIVE_LIFECYCLE_BRIDGE_H
#include "lifecycle.h"
#define NL_BRIDGE_CAPACITY 128u

typedef struct {
    void *memory_user;
    int (*read32)(void *, NLAddress, uint32_t *);
    int (*write32)(void *, NLAddress, uint32_t);
    NLAddress survival, survival_bank, charge, charge_bank, horse, routing, view;
    float (*get_max_hp)(NLAddress actor);
    float (*get_max_grip)(NLAddress actor);
    NLAddress (*get_ai_work)(NLAddress actor);
    /* Used only without get_ai_work. Verified per-build offset, not a default. */
    uint32_t ai_work_offset;
} NLBridgeConfig;
typedef struct {
    NLAddress object, raw_allocation;
    uint32_t id, generation;
    NLLifetime state;
} NLBridgeAllocation;
typedef struct {
    NLBridgeConfig config;
    NLBridgeAllocation allocations[NL_BRIDGE_CAPACITY];
    uint32_t count, last_id, generation, initialized;
    NLAddress canonical_object;
    uint32_t canonical_id, canonical_generation;
    NLResult fault;
} NLBridge;

int nl_bridge_init(NLBridge *, const NLBridgeConfig *, uint32_t generation);
int nl_bridge_bind(NLBridge *, NLContext *);
/* Does not change Context epochs: the adapter updates those explicitly. */
int nl_bridge_set_generation(NLBridge *, uint32_t generation);
/* Bootstrap only: no prior canonical ID, all mod P1 pointers and charge P1
 * generation must already match. Does not write game or registry memory. */
int nl_bridge_adopt_canonical(NLBridge *, NLAddress actor, uint32_t generation);
/* Trusted post-group hook callback. Inspect fault before allowing P1 init. */
void nl_bridge_canonical_admitted(void *, NLAddress actor);
int nl_bridge_refresh_canonical_work(NLBridge *);
uint32_t nl_bridge_new_allocation(void *, NLAddress object);
NLLifetime nl_bridge_lifetime(void *, NLAddress object, uint32_t id);
/* No object dereferences, including after free. Returns number marked. */
uint32_t nl_bridge_mark_final_free(NLBridge *, NLAddress raw_allocation);
/* Call only after all users of older, final-freed identities have acknowledged
 * retirement. Older IDs then resolve to MISMATCH without memory reads; live
 * records are retained and the monotonic ID counter is never rewound. */
uint32_t nl_bridge_acknowledge_retired_before(NLBridge *, uint32_t generation);
/* Serialized owner acknowledgement of exact final-freed identities, including
 * the current generation. Caller MUST first release every external reference.
 * Returns 1 (also for an empty list), or 0 with the registry unchanged. Rejects
 * unknown, duplicate-ID, LIVE/MISMATCH and canonical identities. No memory I/O,
 * heap allocation or ID reuse; retained record order and last_id are unchanged. */
int nl_bridge_acknowledge_retired_ids(NLBridge *, const NLObject *, uint32_t count);
int nl_bridge_publish_actor(void *, NLContext *);
int nl_bridge_unpublish_actor(void *, NLContext *);
int nl_bridge_publish_view(void *, NLContext *);
int nl_bridge_refresh_actor_work(NLBridge *, NLContext *);
#endif
