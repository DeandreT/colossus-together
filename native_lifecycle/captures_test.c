/* Synthetic host RAM only. These fixtures do not attest live-game hooks. */
#include "captures.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#define RAM_SIZE 0x100000u
static uint8_t ram[RAM_SIZE];
static NLBridge bridge;
static NLCaptures cap;
static uint32_t writes, reads;
static NLAddress forbidden[4];
static uint32_t forbidden_count;
static NLAddress first;
static int read_bytes(void *u, NLAddress a, uint8_t *v, uint32_t n) {
    uint32_t i;
    (void)u; ++reads;
    assert(a && a < 0x02000000u && n <= 0x02000000u - a);
    for (i = 0; i < forbidden_count; ++i)
        assert(a + n <= forbidden[i] || a >= forbidden[i] + 0x18);
    if (a >= RAM_SIZE || n > RAM_SIZE - a) return 0;
    memcpy(v, ram + a, n); return 1;
}
static int read32(void *u, NLAddress a, uint32_t *v) {
    uint8_t b[4];
    assert(a % 4 == 0);
    if (!read_bytes(u, a, b, 4)) return 0;
    *v = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    return 1;
}
static int write32(void *u, NLAddress a, uint32_t v) {
    (void)u; (void)a; (void)v; ++writes; return 0;
}
static void put(NLAddress a, uint32_t v) {
    assert(a + 4 <= RAM_SIZE);
    ram[a] = (uint8_t)v; ram[a+1] = (uint8_t)(v >> 8);
    ram[a+2] = (uint8_t)(v >> 16); ram[a+3] = (uint8_t)(v >> 24);
}
static NLAddress get_first(void *u) { (void)u; return first; }
static uint32_t hash(void) {
    uint32_t h = 2166136261u, i;
    for (i = 0; i < RAM_SIZE; ++i) h = (h ^ ram[i]) * 16777619u;
    return h;
}
static void reset(void) {
    memset(ram, 0, sizeof ram); memset(&bridge, 0, sizeof bridge);
    memset(&cap, 0, sizeof cap); first = 0; writes = reads = 0;
    forbidden_count = 0;
    bridge.initialized = 1; bridge.generation = 7;
    bridge.config.read32 = read32; bridge.config.write32 = write32;
    assert(nl_captures_init(&cap, &bridge, NULL, read32, read_bytes, get_first, 3));
}
static void object(NLAddress o, NLVisualKind f, uint32_t category) {
    put(o, o + 0x280); ram[o+8] = f == NL_ALIAS ? 11 : 9;
    put(o + 0x300 + 8, category);
}
static NLObject canonical(void) {
    NLObject p = { 0x1000, 0 };
    object(p.object, NL_CHARACTER, 2);
    p.allocation = nl_bridge_new_allocation(&bridge, p.object);
    assert(p.allocation);
    bridge.canonical_object = p.object; bridge.canonical_id = p.allocation;
    bridge.canonical_generation = 1; first = p.object;
    return p;
}
static void visual(NLAddress o, NLVisualKind family, const char *name) {
    object(o, family, 0);
    put(o + 0x180, 1); put(o + 0x150, bridge.canonical_object);
    put(o + 0x224, bridge.canonical_object);
    put(o + 0x1d4, o + 0x400); put(o + 0x400, o + 0x500);
    put(o + 0x520, o + 0x600); put(o + 0x600, 0x004f4d4e);
    put(o + 0x604, 3); put(o + 0x670, o + 0x700);
    strcpy((char *)ram + o + 0x700, name);
}
static void main_identity(void) {
    NLObject p;
    uint32_t before;
    reset(); object(0x1000, NL_CHARACTER, 2); before = hash();
    nl_captures_observe(&cap, 0x1000, 0x1300, NL_CHARACTER);
    assert(cap.count == 1 && bridge.count == 0 && !cap.entries[0].candidate.owned.allocation);
    assert(!nl_captures_canonical_definition(&cap, 0x1000, 0x1280));
    p = canonical();
    assert(!nl_captures_canonical_definition(&cap, p.object, 0x9990));
    assert(!nl_captures_canonical_definition(&cap, 0x2000, 0x1280));
    assert(nl_captures_canonical_definition(&cap, p.object, 0x1280) == 0x1300);
    assert(cap.entries[0].candidate.owned.allocation == p.allocation);
    first = 0x2000;
    assert(!nl_captures_canonical_definition(&cap, p.object, 0x1280));
    first = p.object;
    put(p.object, 0x1290);
    assert(!nl_captures_canonical_definition(&cap, p.object, 0x1280));
    put(p.object, 0x1280);
    assert(hash() == before && !writes && !cap.fault);
}
static void ignored(void) {
    uint32_t i, before;
    reset(); (void)canonical();
    visual(0x2000, NL_ALIAS, "weapon_sword.nmo");
    before = hash();
    for (i = 0; i < 512; ++i) nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    assert(!cap.count && bridge.count == 1 && !cap.fault);
    assert(hash() == before && !writes);
    put(0x2150, 0x9000); put(0x21d4, 0xffffffffu);
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    assert(!cap.fault && !cap.count);
    nl_captures_observe(&cap, 0xfffffffcu, 0x2300, NL_ALIAS);
    nl_captures_observe(&cap, 0x2000, 0xfffffffcu, NL_ALIAS);
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_CHARACTER);
    assert(!cap.fault && bridge.count == 1);
}
static void names_and_output(void) {
    static const char *names[] = { "player_A.nmo", "player_A_mantle_LV1.nmo",
        "player_A_head_LV4.nmo", "player_A_LV8.nmo", "player_A_mantle_LV12.nmo",
        "player_A_head_LV16.nmo" };
    uint32_t i, n = 999, before;
    NLVerifiedCandidate out[8], sentinel;
    NLObject p;
    reset(); p = canonical();
    for (i = 0; i < 6; ++i) {
        NLAddress o = 0x2000 + i * 0x1000;
        NLVisualKind f = i % 3 == 2 ? NL_CHARACTER : NL_ALIAS;
        visual(o, f, names[i]);
        before = hash();
        nl_captures_observe(&cap, o, o + 0x300, f);
        nl_captures_observe(&cap, o, o + 0x300, f);
        assert(hash() == before && !writes && !cap.fault);
    }
    assert(cap.count == 6 && bridge.count == 7);
    memset(out, 0xa5, sizeof out); sentinel = out[0];
    assert(!nl_captures_output_candidates(&cap, p, 3, out, 5, &n));
    assert(n == 999 && !memcmp(out, &sentinel, sizeof sentinel));
    assert(!nl_captures_output_candidates(&cap, p, 2, out, 8, &n));
    assert(nl_captures_output_candidates(&cap, p, 3, out, 8, &n) && n == 6);
    for (i = 0; i < n; ++i) {
        assert(out[i].definition_verified == 1 && out[i].resource_generation == 3);
        assert(out[i].owned.allocation == i + 2);
        assert(bridge.allocations[i+1].generation == 7);
    }
    visual(0x9000, NL_ALIAS, "player_A_LV2.nmo");
    nl_captures_observe(&cap, 0x9000, 0x9300, NL_ALIAS);
    assert(cap.count == 6 && !cap.fault);
    assert(!nl_captures_advance_generation(&cap, 4, 1));
    /* An externally changed epoch excludes but does not drop old records; no
     * old definition is touched. Normal callers must use the gated API. */
    cap.resource_generation = 4;
    assert(nl_captures_output_candidates(&cap, p, 4, out, 8, &n) && n == 0);
    assert(cap.count == 6);
}
static void malformed(void) {
    reset(); (void)canonical(); visual(0x2000, NL_ALIAS, "player_A.nmo");
    put(0x2600, 0);
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    assert(cap.fault == NL_CAPTURE_MALFORMED && !cap.count && bridge.count == 1);
    reset(); (void)canonical(); visual(0x2000, NL_ALIAS, "player_A.nmo");
    put(0x2670, 0xfffffff0u);
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    assert(cap.fault == NL_CAPTURE_MALFORMED);
    reset(); (void)canonical(); visual(0x2000, NL_ALIAS, "player_A.nmo");
    put(0x2604, 4);
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    assert(cap.fault == NL_CAPTURE_MALFORMED);
}
static void frees_and_reuse(void) {
    uint32_t old, before;
    NLObject p;
    NLVerifiedCandidate out[2];
    uint32_t n;
    reset(); p = canonical(); visual(0x2000, NL_ALIAS, "player_A.nmo");
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    old = cap.entries[0].candidate.owned.allocation;
    before = reads;
    assert(nl_captures_on_final_free(&cap, 0x2280) == 1);
    assert(reads == before);
    assert(nl_bridge_mark_final_free(&bridge, 0x2280) == 1);
    assert(nl_captures_output_candidates(&cap, p, 3, out, 2, &n) && !n);
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    assert(!cap.fault && cap.count == 2);
    assert(cap.entries[1].candidate.owned.allocation > old);
    assert(nl_bridge_lifetime(&bridge, 0x2000, old) == NL_FREED);
    assert(!nl_captures_purge_freed(&cap, 0));
    assert(nl_captures_purge_freed(&cap, 1) == 1 && cap.count == 1);
    assert(nl_captures_output_candidates(&cap, p, 3, out, 2, &n) && n == 1);
    assert(!nl_captures_advance_generation(&cap, 4, 1));
    nl_captures_on_final_free(&cap, 0x2280); nl_bridge_mark_final_free(&bridge, 0x2280);
    assert(!nl_captures_advance_generation(&cap, 4, 0));
    assert(nl_captures_advance_generation(&cap, 4, 1));
    assert(cap.count == 1 && cap.entries[0].candidate.resource_generation == 3);
    assert(nl_captures_purge_freed(&cap, 1) == 1);
}
static void capacity_and_proof(void) {
    uint32_t i;
    reset();
    object(0x1000, NL_CHARACTER, 2);
    assert(!nl_captures_seed(&cap, 0x1000, 0x1300, NL_CHARACTER, 3, 0));
    assert(!nl_captures_seed(&cap, 0x1000, 0x1300, NL_CHARACTER, 2, 1));
    assert(!cap.count && !cap.fault);
    assert(nl_captures_seed(&cap, 0x1000, 0x1300, NL_CHARACTER, 3, 1));
    for (i = 1; i < NL_CAPTURES_CAPACITY; ++i) {
        NLAddress o = 0x1000 + i * 0x1000;
        object(o, NL_CHARACTER, 2);
        nl_captures_observe(&cap, o, o + 0x300, NL_CHARACTER);
    }
    assert(cap.count == NL_CAPTURES_CAPACITY && !bridge.count && !cap.fault);
    object(0x50000, NL_CHARACTER, 2);
    nl_captures_observe(&cap, 0x50000, 0x50300, NL_CHARACTER);
    assert(cap.fault == NL_CAPTURE_OVERFLOW && cap.count == NL_CAPTURES_CAPACITY);
    assert(cap.entries[0].candidate.owned.object == 0x1000);
}
static void stale_identity(void) {
    NLObject p;
    NLVerifiedCandidate out[1];
    uint32_t n = 99;
    reset(); p = canonical(); visual(0x2000, NL_ALIAS, "player_A.nmo");
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    /* Missing the capture free callback must fail closed, not bless a new ID. */
    nl_bridge_mark_final_free(&bridge, 0x2280);
    assert(nl_bridge_new_allocation(&bridge, 0x2000));
    assert(!nl_captures_output_candidates(&cap, p, 3, out, 1, &n));
    assert(n == 99 && cap.fault == NL_CAPTURE_STALE);
}
static void replaced_canonical(void) {
    NLObject p;
    NLVerifiedCandidate out[1];
    uint32_t n = 99, old;
    reset(); p = canonical(); old = p.allocation;
    visual(0x2000, NL_ALIAS, "player_A.nmo");
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    /* A surviving visual must not transfer to a new canonical lifetime, even
     * when both the raw parent address and the header value are reused. */
    nl_bridge_mark_final_free(&bridge, 0x1280);
    p = canonical(); assert(p.allocation != old);
    assert(nl_captures_output_candidates(&cap, p, 3, out, 1, &n) && n == 0);
    assert(cap.count == 1 && cap.entries[0].state == NL_LIVE);
    assert(!nl_captures_advance_generation(&cap, 4, 1));
}
static NLObject admit_at(NLAddress address) {
    NLObject p;
    p.object = address;
    p.allocation = nl_bridge_new_allocation(&bridge, address);
    assert(p.allocation);
    bridge.canonical_object = address; bridge.canonical_id = p.allocation;
    ++bridge.canonical_generation; first = address;
    return p;
}
static void reject_epoch(uint32_t generation, NLObject p, uint32_t quiescent) {
    NLCaptures before = cap;
    assert(!nl_captures_admit_epoch(&cap, generation, p, quiescent));
    assert(!memcmp(&before, &cap, sizeof cap));
}
static void epoch_replacement(void) {
    NLObject old, next, fake;
    NLCaptureEntry old_main, old_visual;
    NLVerifiedCandidate out[2];
    uint32_t n, before, memory_before;
    reset(); old = canonical();
    nl_captures_observe(&cap, old.object, 0x1300, NL_CHARACTER);
    assert(nl_captures_canonical_definition(&cap, old.object, 0x1280) == 0x1300);
    assert(cap.last_epoch_canonical.allocation == old.allocation);
    visual(0x2000, NL_ALIAS, "player_A.nmo");
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    old_main = cap.entries[0]; old_visual = cap.entries[1];
    object(0x4000, NL_CHARACTER, 2);
    nl_captures_observe(&cap, 0x4000, 0x4300, NL_CHARACTER);
    assert(cap.entries[2].candidate.owned.allocation == 0);
    assert(cap.entries[2].candidate.resource_generation == 3);
    fake.object = 0x4000; fake.allocation = old.allocation;
    reject_epoch(4, fake, 1); /* not admitted */
    reject_epoch(4, old, 1); /* unchanged canonical */
    next = admit_at(0x4000);
    forbidden[forbidden_count++] = 0x1300;
    forbidden[forbidden_count++] = 0x2300;
    reject_epoch(4, next, 0);
    reject_epoch(3, next, 1); reject_epoch(2, next, 1); reject_epoch(0, next, 1);
    fake = next; ++fake.allocation; reject_epoch(4, fake, 1);
    first = old.object; reject_epoch(4, next, 1); first = next.object;
    put(next.object, 0x4990); reject_epoch(4, next, 1); put(next.object, 0x4280);
    cap.fault = NL_CAPTURE_STALE; reject_epoch(4, next, 1); cap.fault = NL_CAPTURE_OK;
    assert(!nl_captures_advance_generation(&cap, 4, 1));
    before = reads; memory_before = hash();
    assert(nl_captures_admit_epoch(&cap, 4, next, 1));
    assert(reads == before + 1); /* sole read: new actor's live raw header */
    assert(hash() == memory_before && !writes);
    assert(!memcmp(&old_main, &cap.entries[0], sizeof old_main));
    assert(!memcmp(&old_visual, &cap.entries[1], sizeof old_visual));
    assert(cap.count == 3 && cap.resource_generation == 4);
    assert(cap.last_epoch_canonical.allocation == next.allocation);
    assert(cap.entries[2].candidate.resource_generation == 4);
    assert(cap.entries[2].candidate.owned.allocation == next.allocation);
    assert(cap.entries[2].canonical_owner.allocation == next.allocation);
    assert(nl_captures_canonical_definition(&cap, next.object, 0x4280) == 0x4300);
    reject_epoch(5, next, 1);
    assert(nl_captures_output_candidates(&cap, next, 4, out, 2, &n) && n == 0);
    visual(0x6000, NL_ALIAS, "player_A_mantle.nmo");
    nl_captures_observe(&cap, 0x6000, 0x6300, NL_ALIAS);
    assert(nl_captures_output_candidates(&cap, next, 4, out, 2, &n) && n == 1);
    assert(out[0].owned.object == 0x6000 && out[0].resource_generation == 4);
    assert(!memcmp(&old_visual, &cap.entries[1], sizeof old_visual));
    /* No implicit eviction; late final frees and explicit purge retire only old
     * records, preserving the new main/child lifetime and resource provenance. */
    assert(cap.count == 4 && nl_captures_purge_freed(&cap, 1) == 0);
    assert(nl_captures_on_final_free(&cap, 0x1280) == 1);
    assert(nl_bridge_mark_final_free(&bridge, 0x1280) == 1);
    assert(nl_captures_on_final_free(&cap, 0x2280) == 1);
    assert(nl_bridge_mark_final_free(&bridge, 0x2280) == 1);
    assert(nl_captures_purge_freed(&cap, 1) == 2 && cap.count == 2);
    assert(nl_captures_output_candidates(&cap, next, 4, out, 2, &n) && n == 1);
    assert(!nl_captures_advance_generation(&cap, 5, 1));
}
static void epoch_same_address(void) {
    NLObject old, next;
    NLVerifiedCandidate out[1];
    NLCaptureEntry old_main, old_visual;
    uint32_t n;
    reset(); old = canonical();
    nl_captures_observe(&cap, old.object, 0x1300, NL_CHARACTER);
    assert(nl_captures_canonical_definition(&cap, old.object, 0x1280) == 0x1300);
    visual(0x2000, NL_ALIAS, "player_A.nmo");
    nl_captures_observe(&cap, 0x2000, 0x2300, NL_ALIAS);
    assert(nl_captures_on_final_free(&cap, 0x1280) == 1);
    assert(nl_bridge_mark_final_free(&bridge, 0x1280) == 1);
    old_main = cap.entries[0]; old_visual = cap.entries[1];
    object(old.object, NL_CHARACTER, 2);
    nl_captures_observe(&cap, old.object, 0x1300, NL_CHARACTER);
    next = admit_at(old.object); assert(next.allocation != old.allocation);
    forbidden[forbidden_count++] = 0x2300;
    assert(nl_captures_admit_epoch(&cap, 4, next, 1));
    assert(!memcmp(&old_main, &cap.entries[0], sizeof old_main));
    assert(!memcmp(&old_visual, &cap.entries[1], sizeof old_visual));
    assert(cap.entries[2].candidate.owned.allocation == next.allocation);
    assert(nl_captures_canonical_definition(&cap, next.object, 0x1280) == 0x1300);
    assert(nl_captures_output_candidates(&cap, next, 4, out, 1, &n) && n == 0);
    reject_epoch(5, next, 1);
    assert(nl_captures_purge_freed(&cap, 1) == 1 && cap.count == 2);
}
static void epoch_initialization(void) {
    NLObject p, next;
    NLCaptures initialized = {0};
    reset(); p = canonical();
    assert(nl_captures_init(&initialized, &bridge, NULL, read32, read_bytes, get_first, 3));
    assert(initialized.last_epoch_canonical.object == p.object);
    assert(initialized.last_epoch_canonical.allocation == p.allocation);
    cap = initialized; reject_epoch(4, p, 1);
    object(0x4000, NL_CHARACTER, 2); next = admit_at(0x4000);
    reject_epoch(4, next, 1); /* no trusted main capture */
    nl_captures_observe(&cap, next.object, 0x4300, NL_CHARACTER);
    cap.entries[0].raw_allocation += 4; reject_epoch(4, next, 1);
    cap.entries[0].raw_allocation -= 4;
    cap.entries[0].candidate.owned.allocation = p.allocation;
    reject_epoch(4, next, 1);
    cap.entries[0].candidate.owned.allocation = 0;
    /* A definition query may bind the freshly admitted ID before the boundary;
     * it must not replace the previous epoch's canonical marker. */
    assert(nl_captures_canonical_definition(&cap, next.object, 0x4280) == 0x4300);
    assert(cap.last_epoch_canonical.allocation == p.allocation);
    assert(nl_captures_admit_epoch(&cap, 4, next, 1));
    assert(nl_bridge_mark_final_free(&bridge, 0x4280) == 1);
    initialized = (NLCaptures){0};
    assert(nl_captures_init(&initialized, &bridge, NULL, read32, read_bytes, get_first, 4));
    assert(!initialized.last_epoch_canonical.object && !initialized.last_epoch_canonical.allocation);
}
int main(void) {
    main_identity(); ignored(); names_and_output(); malformed();
    frees_and_reuse(); capacity_and_proof(); stale_identity(); replaced_canonical();
    epoch_replacement(); epoch_same_address(); epoch_initialization();
    puts("ok"); return 0;
}
