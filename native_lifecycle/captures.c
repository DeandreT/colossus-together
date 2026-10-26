#include "captures.h"
#define EE_SIZE 0x02000000u
static int range(NLAddress a, uint32_t n, uint32_t alignment) {
    return a && a < EE_SIZE && n && n <= EE_SIZE - a && a % alignment == 0;
}
static int fail(NLCaptures *c, NLCaptureFault f) {
    if (c && c->fault == NL_CAPTURE_OK) c->fault = f;
    return 0;
}
static int ready(NLCaptures *c) {
    return c && !c->fault && c->bridge && c->bridge->initialized &&
        !c->bridge->fault && c->read32 && c->read_bytes && c->resource_generation;
}
static int word(NLCaptures *c, NLAddress a, uint32_t *v) {
    if (!range(a, 4, 4)) return fail(c, NL_CAPTURE_MALFORMED);
    return c->read32(c->user, a, v) || fail(c, NL_CAPTURE_READ_FAILED);
}
static int bytes(NLCaptures *c, NLAddress a, uint8_t *v, uint32_t n) {
    if (!range(a, n, 1)) return fail(c, NL_CAPTURE_MALFORMED);
    return c->read_bytes(c->user, a, v, n) || fail(c, NL_CAPTURE_READ_FAILED);
}
static int pointer(NLCaptures *c, NLAddress a, uint32_t n, uint32_t *v) {
    return word(c, a, v) && (range(*v, n, 4) || fail(c, NL_CAPTURE_MALFORMED));
}
static int prefix(const char **s, const char *p) {
    const char *v = *s;
    while (*p) if (*v++ != *p++) return 0;
    *s = v;
    return 1;
}
static int supported(const char *name) {
    const char *s = name;
    if (!prefix(&s, "player_A")) return 0;
    if (!prefix(&s, "_mantle")) (void)prefix(&s, "_head");
    if (prefix(&s, "_LV")) {
        if (!prefix(&s, "12") && !prefix(&s, "16") && !prefix(&s, "1") &&
            !prefix(&s, "4") && !prefix(&s, "8")) return 0;
    }
    if (!prefix(&s, ".nmo") || *s) return 0;
    return 1;
}
/* Ownership is proven before this function: malformed owned models quarantine. */
static int owned_model(NLCaptures *c, NLAddress object) {
    uint32_t display, resource, header, name, v, i;
    char text[NL_METADATA_NAME_BYTES];
    if (!pointer(c, object + 0x1d4, 4, &display) ||
        !pointer(c, display, 0x24, &resource) ||
        !pointer(c, resource + 0x20, 0x74, &header) || !word(c, header, &v)) return 0;
    if (v != 0x004f4d4eu) return fail(c, NL_CAPTURE_MALFORMED);
    if (!word(c, header + 4, &v)) return 0;
    if (v != 3) return fail(c, NL_CAPTURE_MALFORMED);
    if (!word(c, header + 0x70, &name)) return 0;
    for (i = 0; i < NL_METADATA_NAME_BYTES; ++i) {
        uint8_t ch;
        if (!bytes(c, name + i, &ch, 1)) return 0;
        if (ch > 127) return fail(c, NL_CAPTURE_MALFORMED);
        text[i] = (char)ch;
        if (!ch) return supported(text);
    }
    return fail(c, NL_CAPTURE_MALFORMED);
}
static int canonical(NLCaptures *, NLObject);
int nl_captures_init(NLCaptures *c, NLBridge *b, void *user,
                     int (*r)(void *, NLAddress, uint32_t *),
                     int (*rb)(void *, NLAddress, uint8_t *, uint32_t),
                     NLAddress (*first)(void *), uint32_t generation) {
    if (!c || c->bridge || c->count || c->fault || !b || !b->initialized ||
        b->fault || !r || !rb || !generation) return 0;
    c->bridge = b; c->user = user; c->read32 = r; c->read_bytes = rb;
    c->canonical_group_first = first; c->resource_generation = generation;
    c->last_epoch_canonical.object = b->canonical_object;
    c->last_epoch_canonical.allocation = b->canonical_id;
    if (!canonical(c, c->last_epoch_canonical)) {
        c->last_epoch_canonical.object = 0;
        c->last_epoch_canonical.allocation = 0;
    }
    return 1;
}
static int canonical(NLCaptures *c, NLObject object) {
    return range(object.object, 0x228, 4) && object.allocation &&
        object.object == c->bridge->canonical_object &&
        object.allocation == c->bridge->canonical_id &&
        (!c->canonical_group_first || c->canonical_group_first(c->user) == object.object) &&
        nl_bridge_lifetime(c->bridge, object.object, object.allocation) == NL_LIVE;
}
static int observe(NLCaptures *c, NLAddress object, NLAddress definition,
                    NLVisualKind family) {
    uint8_t type, category[2];
    uint32_t main = 0, kind, parent, raw, i, id = 0;
    NLCaptureEntry *e;
    if (!ready(c)) return 0;
    if (!object) return 1; /* constructor failure */
    /* Invalid/non-owned events must not consume records or poison capture. */
    if ((family != NL_CHARACTER && family != NL_ALIAS) ||
        !range(object, 0x228, 4) || !range(definition, 0x18, 4)) return 1;
    if (!c->read_bytes(c->user, object + 8, &type, 1)) return 1;
    if ((family == NL_CHARACTER && type != 9) || (family == NL_ALIAS && type != 11)) return 1;
    if (family == NL_CHARACTER) {
        if (!c->read_bytes(c->user, definition + 8, category, 2)) return 1;
        main = category[0] == 2 && category[1] == 0; /* signed int16 == 2 */
    }
    if (!main) {
        NLObject owner;
        if (!c->bridge->canonical_object ||
            !c->read32(c->user, object + 0x180, &kind) || kind != 1 ||
            !c->read32(c->user, object + 0x150, &parent) ||
            parent != c->bridge->canonical_object) return 1;
        owner.object = c->bridge->canonical_object;
        owner.allocation = c->bridge->canonical_id;
        if (!canonical(c, owner)) return fail(c, NL_CAPTURE_STALE);
        if (!c->last_epoch_canonical.allocation) c->last_epoch_canonical = owner;
        if (!owned_model(c, object)) return c->fault == NL_CAPTURE_OK;
    }
    if (!pointer(c, object, 4, &raw)) return 0;
    for (i = 0; i < c->count; ++i) {
        e = &c->entries[i];
        if (e->state != NL_LIVE) continue;
        if (e->candidate.owned.object != object && e->raw_allocation != raw) continue;
        if (e->candidate.owned.object != object || e->raw_allocation != raw ||
            e->candidate.definition != definition || e->candidate.family != family ||
            e->main_candidate != main ||
            e->candidate.resource_generation != c->resource_generation)
            return fail(c, NL_CAPTURE_STALE);
        if (e->candidate.owned.allocation &&
            nl_bridge_lifetime(c->bridge, object, e->candidate.owned.allocation) != NL_LIVE)
            return fail(c, NL_CAPTURE_STALE);
        return 1;
    }
    if (c->count >= NL_CAPTURES_CAPACITY) return fail(c, NL_CAPTURE_OVERFLOW);
    if (!main) {
        id = nl_bridge_new_allocation(c->bridge, object);
        if (!id) return fail(c, NL_CAPTURE_STALE);
    }
    e = &c->entries[c->count++];
    e->candidate.owned.object = object; e->candidate.owned.allocation = id;
    e->candidate.definition = definition; e->candidate.family = family;
    e->candidate.definition_verified = 1;
    e->candidate.resource_generation = c->resource_generation;
    e->raw_allocation = raw; e->state = NL_LIVE; e->main_candidate = main;
    e->canonical_owner.object = main ? 0 : c->bridge->canonical_object;
    e->canonical_owner.allocation = main ? 0 : c->bridge->canonical_id;
    return 1;
}
void nl_captures_observe(void *user, NLAddress object, NLAddress definition,
                         NLVisualKind family) {
    (void)observe((NLCaptures *)user, object, definition, family);
}
int nl_captures_seed(NLCaptures *c, NLAddress object, NLAddress definition,
                     NLVisualKind family, uint32_t generation, uint32_t proof) {
    if (!ready(c) || proof != 1 || generation != c->resource_generation) return 0;
    return observe(c, object, definition, family);
}
NLAddress nl_captures_canonical_definition(NLCaptures *c, NLAddress object, NLAddress raw) {
    uint32_t i, actual;
    NLObject identity;
    if (!ready(c)) return 0;
    identity.object = object; identity.allocation = c->bridge->canonical_id;
    if (!canonical(c, identity)) return 0;
    for (i = 0; i < c->count; ++i) {
        NLCaptureEntry *e = &c->entries[i];
        if (!e->main_candidate || e->state != NL_LIVE ||
            e->candidate.resource_generation != c->resource_generation ||
            e->candidate.owned.object != object || e->raw_allocation != raw) continue;
        if (e->candidate.owned.allocation && e->candidate.owned.allocation != identity.allocation)
            return 0;
        if (!word(c, object, &actual) || actual != raw) return 0;
        e->candidate.owned.allocation = identity.allocation;
        if (!c->last_epoch_canonical.allocation) c->last_epoch_canonical = identity;
        return e->candidate.definition;
    }
    return 0;
}
int nl_captures_output_candidates(NLCaptures *c, NLObject p1, uint32_t epoch,
                                  NLVerifiedCandidate *out, uint32_t capacity,
                                  uint32_t *count) {
    uint32_t i, n = 0, selected[NL_CAPTURES_CAPACITY];
    if (!ready(c) || !count || epoch != c->resource_generation || !canonical(c, p1)) return 0;
    for (i = 0; i < c->count; ++i) {
        NLCaptureEntry *e = &c->entries[i];
        uint32_t parent;
        if (e->state != NL_LIVE || e->main_candidate ||
            e->candidate.resource_generation != epoch ||
            e->canonical_owner.object != p1.object ||
            e->canonical_owner.allocation != p1.allocation) continue;
        if (nl_bridge_lifetime(c->bridge, e->candidate.owned.object,
                               e->candidate.owned.allocation) != NL_LIVE)
            return fail(c, NL_CAPTURE_STALE);
        if (!word(c, e->candidate.owned.object + 0x150, &parent)) return 0;
        /* Previous canonical's still-live visuals are retained but not output. */
        if (parent != p1.object) continue;
        selected[n++] = i;
    }
    if (n > capacity || (n && !out)) return 0;
    for (i = 0; i < n; ++i) out[i] = c->entries[selected[i]].candidate;
    *count = n;
    return 1;
}
uint32_t nl_captures_on_final_free(NLCaptures *c, NLAddress raw) {
    uint32_t i, n = 0;
    if (!c || !range(raw, 4, 4)) return 0;
    for (i = 0; i < c->count; ++i) {
        NLCaptureEntry *e = &c->entries[i];
        if (e->state == NL_LIVE && e->raw_allocation == raw) { e->state = NL_FREED; ++n; }
    }
    return n;
}
uint32_t nl_captures_purge_freed(NLCaptures *c, uint32_t quiescent) {
    uint32_t i, n = 0, old;
    if (!c || quiescent != 1) return 0;
    old = c->count;
    for (i = 0; i < old; ++i)
        if (c->entries[i].state != NL_FREED) c->entries[n++] = c->entries[i];
    c->count = n;
    return old - n;
}
int nl_captures_advance_generation(NLCaptures *c, uint32_t generation, uint32_t quiescent) {
    uint32_t i;
    if (!ready(c) || quiescent != 1 || generation <= c->resource_generation) return 0;
    for (i = 0; i < c->count; ++i) if (c->entries[i].state != NL_FREED) return 0;
    c->resource_generation = generation;
    return 1;
}
int nl_captures_admit_epoch(NLCaptures *c, uint32_t generation,
                            NLObject admitted, uint32_t quiescent) {
    uint32_t i, raw = 0;
    NLCaptureEntry *main = 0;
    if (!ready(c) || quiescent != 1 || generation <= c->resource_generation ||
        !range(admitted.object, 0x228, 4) || !admitted.allocation ||
        admitted.allocation == c->last_epoch_canonical.allocation ||
        !canonical(c, admitted)) return 0;
    /* canonical() has read the live header once through bridge lifetime. Use
     * that exact registry record for the raw proof, rather than rereading RAM. */
    for (i = 0; i < c->bridge->count; ++i) {
        const NLBridgeAllocation *a = &c->bridge->allocations[i];
        if (a->object == admitted.object && a->id == admitted.allocation &&
            a->state == NL_LIVE) { raw = a->raw_allocation; break; }
    }
    if (!raw) return 0;
    for (i = 0; i < c->count; ++i) {
        NLCaptureEntry *e = &c->entries[i];
        if (e->state != NL_LIVE || e->candidate.owned.object != admitted.object ||
            e->raw_allocation != raw) continue;
        if (main || !e->main_candidate || e->candidate.family != NL_CHARACTER ||
            e->candidate.definition_verified != 1 ||
            e->candidate.resource_generation != c->resource_generation ||
            (e->candidate.owned.allocation &&
             e->candidate.owned.allocation != admitted.allocation)) return 0;
        main = e;
    }
    if (!main) return 0;
    main->candidate.owned.allocation = admitted.allocation;
    main->candidate.resource_generation = generation;
    main->canonical_owner = admitted;
    c->resource_generation = generation;
    c->last_epoch_canonical = admitted;
    return 1;
}
