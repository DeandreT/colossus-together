/* Synthetic offline physical memory. No game assets or emulator access. */
#include "metadata.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t ram[0x20000];
static NLVerifiedCandidate candidates[NL_METADATA_MAX_CANDIDATES + 1];
static NLMetadataInput input;
static unsigned reads, life_calls, fail_read, stale_call;
static NLAddress stale_object;
static int read_bytes(void *user, NLAddress a, uint8_t *out, uint32_t n) {
    (void)user;
    ++reads;
    if (fail_read || a >= sizeof ram || n > sizeof ram - a) return 0;
    memcpy(out, ram + a, n);
    return 1;
}
static int read32(void *user, NLAddress a, uint32_t *out) {
    uint8_t b[4];
    if (!read_bytes(user, a, b, 4)) return 0;
    *out = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    return 1;
}
static void put(NLAddress a, uint32_t v) {
    unsigned i;
    assert(a + 4 <= sizeof ram);
    for (i = 0; i < 4; ++i) ram[a + i] = (uint8_t)(v >> (8 * i));
}
static NLLifetime lifetime(void *user, NLAddress a, uint32_t id) {
    uint32_t i;
    (void)user;
    ++life_calls;
    if (a == stale_object || (stale_call && life_calls >= stale_call)) return NL_MISMATCH;
    if (a == input.canonical_p1.object)
        return id == 77 ? NL_LIVE : NL_MISMATCH;
    for (i = 0; i < input.candidate_count; ++i)
        if (a == candidates[i].owned.object)
            return id == 100 + i ? NL_LIVE : NL_MISMATCH;
    return NL_MISMATCH;
}
static void setup_candidate(uint32_t i, const char *name, NLVisualKind family) {
    NLVerifiedCandidate *c = &candidates[i];
    uint32_t obj = 0x2000 + i * 0x1000;
    uint32_t def = obj + 0x300, field = def + (family == NL_ALIAS ? 4 : 0x14);
    uint32_t symbol = obj + 0x400, desc = obj + 0x500, base = obj + 0x600;
    uint32_t display = obj + 0x700, resource = obj + 0x800, header = obj + 0x900;
    c->owned.object = obj; c->owned.allocation = 100 + i;
    c->definition = def; c->family = family;
    c->definition_verified = 1; c->resource_generation = 42;
    ram[obj + 8] = family == NL_ALIAS ? 11 : 9;
    put(obj + 0x1d4, display); put(display, resource);
    put(resource + 0x20, header); put(header, 0x004f4d4e); put(header + 4, 3);
    put(header + 0x70, obj + 0xa00); strcpy((char *)ram + obj + 0xa00, name);
    put(obj + 0x150, 0x1000); put(obj + 0x180, 1); put(obj + 0x224, 0x1000);
    ram[obj + 0x15c] = 0xab;
    /* Nonzero packed index verifies masked distance and descriptor stride. */
    put(field - 0x20, symbol); put(field, (2u << 18) | 0x20);
    put(symbol + 8, desc); put(desc + 0xc, 0x10); put(symbol + 0x10, base);
    put(base + 2 * 0x10 + 8, resource);
}
static void setup(void) {
    memset(ram, 0, sizeof ram); memset(candidates, 0, sizeof candidates);
    memset(&input, 0, sizeof input);
    reads = life_calls = fail_read = stale_call = 0; stale_object = 0;
    input.read32 = read32; input.read_bytes = read_bytes; input.lifetime = lifetime;
    input.canonical_p1.object = 0x1000; input.canonical_p1.allocation = 77;
    input.quiescent = 1; input.resource_generation = 42; input.undefined_symbol = 0xffffffffu;
    input.candidates = candidates; input.candidate_count = 3;
    ram[0x1008] = 9;
    setup_candidate(0, "player_A.nmo", NL_ALIAS);
    setup_candidate(1, "player_A_mantle.nmo", NL_ALIAS);
    setup_candidate(2, "player_A_head.nmo", NL_CHARACTER);
}
static void expect(NLMetadataResult status) {
    NLMetadata out, before;
    memset(&out, 0xa5, sizeof out); memcpy(&before, &out, sizeof out);
    assert(nl_metadata_discover(&input, &out) == status);
    if (status != NL_META_OK) assert(memcmp(&out, &before, sizeof out) == 0);
}
static void normal(void) {
    NLMetadata out;
    uint8_t before[sizeof ram];
    setup(); memcpy(before, ram, sizeof ram);
    assert(nl_metadata_discover(&input, &out) == NL_META_OK);
    assert(memcmp(before, ram, sizeof ram) == 0);
    assert(out.canonical_p1.allocation == 77 && out.resource_generation == 42);
    assert(out.visuals[0].definition == candidates[0].definition);
    assert(out.visuals[1].model_resource == 0x3800);
    assert(out.visuals[2].family == NL_CHARACTER);
    assert(out.visuals[0].private_gp_bytes[12] == 0xab);
    ram[0x215c] = 0; assert(out.visuals[0].private_gp_bytes[12] == 0xab);
    /* All Python suffixes apply to all three parts, not only the head. */
    {
        const char *suffix[] = {"", "_LV1", "_LV4", "_LV8", "_LV12", "_LV16"};
        const uint32_t levels[] = {0, 1, 4, 8, 12, 16};
        unsigned i;
        for (i = 0; i < 6; ++i) {
            char name[80];
            setup();
            snprintf(name, sizeof name, "player_A%s.nmo", suffix[i]);
            strcpy((char *)ram + 0x2a00, name);
            snprintf(name, sizeof name, "player_A_mantle%s.nmo", suffix[i]);
            strcpy((char *)ram + 0x3a00, name);
            snprintf(name, sizeof name, "player_A_head%s.nmo", suffix[i]);
            strcpy((char *)ram + 0x4a00, name);
            assert(nl_metadata_discover(&input, &out) == NL_META_OK);
            assert(out.visuals[0].level == levels[i] && out.visuals[1].level == levels[i] &&
                   out.visuals[2].level == levels[i]);
        }
    }
    setup(); input.candidate_count = 4;
    setup_candidate(3, "dummy.nmo", NL_ALIAS); expect(NL_META_OK);
    /* The maximum list is legal; repeated unrelated objects are not parts. */
    {
        unsigned i;
        for (i = 4; i < NL_METADATA_MAX_CANDIDATES; ++i) candidates[i] = candidates[3];
        input.candidate_count = NL_METADATA_MAX_CANDIDATES;
        expect(NL_META_OK);
    }
    /* New canonical + resource generation requires fresh, matching captures. */
    setup(); input.canonical_p1.object = 0x1100; ram[0x1108] = 9;
    input.resource_generation = 43;
    {
        unsigned i;
        for (i = 0; i < 3; ++i) {
            candidates[i].resource_generation = 43;
            put(candidates[i].owned.object + 0x150, 0x1100);
            put(candidates[i].owned.object + 0x224, 0x1100);
        }
    }
    expect(NL_META_OK);
}
static void guards(void) {
    setup(); input.quiescent = 0; expect(NL_META_INVALID); assert(reads == 0);
    setup(); input.candidate_count = 257; expect(NL_META_INVALID); assert(reads == 0);
    setup(); input.candidate_count = 0; expect(NL_META_INVALID);
    setup(); input.candidates = NULL; expect(NL_META_INVALID);
    setup(); input.read32 = NULL; expect(NL_META_INVALID); assert(reads == 0);
    setup(); input.read_bytes = NULL; expect(NL_META_INVALID); assert(reads == 0);
    setup(); input.lifetime = NULL; expect(NL_META_INVALID); assert(reads == 0);
    setup(); input.resource_generation = 0; expect(NL_META_INVALID);
    setup(); candidates[0].definition_verified = 0; expect(NL_META_INVALID); assert(reads == 0);
    setup(); candidates[0].definition = 0; expect(NL_META_INVALID);
    setup(); candidates[0].family = (NLVisualKind)42; expect(NL_META_INVALID);
    setup(); candidates[0].resource_generation = 41; expect(NL_META_STALE); assert(reads == 0);
    setup(); candidates[0].owned.object = 0x80002000; expect(NL_META_INVALID);
    setup(); candidates[0].owned.object = 0x01ffff00; expect(NL_META_INVALID);
    setup(); candidates[0].owned.allocation = 101; expect(NL_META_STALE);
    setup(); input.canonical_p1.allocation = 78; expect(NL_META_STALE); assert(reads == 0);
    setup(); stale_call = 3; expect(NL_META_STALE); /* after candidate reads */
    setup(); stale_call = 8; expect(NL_META_STALE); /* after complete enumeration */
    setup(); stale_object = 0x1000; expect(NL_META_STALE); assert(reads == 0);
    setup(); fail_read = 1; expect(NL_META_READ_FAILED);
    setup(); ram[0x1008] = 11; expect(NL_META_MALFORMED);
    setup(); ram[0x2008] = 9; expect(NL_META_MALFORMED);
    setup(); put(0x2150, 0x1100); expect(NL_META_MALFORMED);
    setup(); put(0x2180, 2); expect(NL_META_MALFORMED);
    setup(); put(0x2224, 0x1100); expect(NL_META_MALFORMED);
    setup(); setup_candidate(0, "player_A_head.nmo", NL_ALIAS); expect(NL_META_MALFORMED);
    setup(); setup_candidate(2, "player_A.nmo", NL_CHARACTER); expect(NL_META_MALFORMED);
    setup(); input.canonical_p1.object = 0x4000; expect(NL_META_MALFORMED);
    setup(); input.candidate_count = 2; expect(NL_META_MISSING);
    setup(); input.candidate_count = 4;
    setup_candidate(3, "player_A_LV4.nmo", NL_ALIAS); expect(NL_META_AMBIGUOUS);
    setup(); candidates[1] = candidates[0]; expect(NL_META_AMBIGUOUS);
}
static void malformed(void) {
    const char *bad[] = {"player_A_dummy.nmo", "PLAYER_A.nmo", "dir/player_A.nmo",
                         "player_A_LV2.nmo", "player_A.nmo.extra", "player_A_head_LV01.nmo"};
    unsigned i;
    for (i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        setup(); strcpy((char *)ram + 0x2a00, bad[i]); expect(NL_META_MISSING);
    }
    setup(); put(0x2900, 0); expect(NL_META_MALFORMED);
    setup(); put(0x2904, 4); expect(NL_META_MALFORMED);
    setup(); memset(ram + 0x2a00, 'a', 128); expect(NL_META_MALFORMED);
    setup(); ram[0x2a00] = 0xff; expect(NL_META_MALFORMED);
    setup(); put(0x2970, 0x01ffffff); expect(NL_META_READ_FAILED);
    setup(); put(0x2820, 0x01ffffa0); expect(NL_META_MALFORMED);
    setup(); put(0x2700, 0x80002800); expect(NL_META_MALFORMED);
    setup(); put(0x2700, 0x2801); expect(NL_META_MALFORMED);
    setup(); put(0x22e4, 0); expect(NL_META_MALFORMED); /* undefined symbol */
    setup(); put(0x22e4, 0xffffffffu); expect(NL_META_MALFORMED);
    setup(); put(0x2304, 0x3ffff); expect(NL_META_MALFORMED); /* subtraction underflow */
    setup(); put(0x250c, 0xb); expect(NL_META_MALFORMED);
    setup(); put(0x250c, 0xfffffffc); expect(NL_META_MALFORMED);
    setup(); put(0x2410, 0); expect(NL_META_MALFORMED);
    setup(); put(0x2628, 0x3800); expect(NL_META_MALFORMED); /* other name/resource */
    setup(); /* Same model name in distinct resource must also reject. */
    put(0x2628, 0x5800); put(0x5820, 0x5900); put(0x5900, 0x004f4d4e);
    put(0x5904, 3); put(0x5970, 0x2a00); expect(NL_META_MALFORMED);
}
int main(void) {
    normal(); guards(); malformed(); puts("ok"); return 0;
}
