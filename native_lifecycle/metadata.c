#include "metadata.h"

#define EE_SIZE 0x02000000u
/* Volatile stores prevent the freestanding compiler from importing memset. */
static void clear_bytes(void *p, uint32_t size) {
    volatile uint8_t *b = (volatile uint8_t *)p;
    while (size--) *b++ = 0;
}
static int range(NLAddress a, uint32_t n, uint32_t align) {
    return a != 0 && a < EE_SIZE && n != 0 && n <= EE_SIZE - a && a % align == 0;
}
static NLMetadataResult bytes(const NLMetadataInput *in, NLAddress a,
                              uint8_t *out, uint32_t n) {
    if (!range(a, n, 1)) return NL_META_MALFORMED;
    return in->read_bytes(in->user, a, out, n) ? NL_META_OK : NL_META_READ_FAILED;
}
static NLMetadataResult word(const NLMetadataInput *in, NLAddress a, uint32_t *out) {
    if (!range(a, 4, 4)) return NL_META_MALFORMED;
    return in->read32(in->user, a, out) ? NL_META_OK : NL_META_READ_FAILED;
}
static NLMetadataResult pointer(const NLMetadataInput *in, NLAddress a,
                                uint32_t n, uint32_t align, uint32_t *out) {
    NLMetadataResult r = word(in, a, out);
    if (r != NL_META_OK) return r;
    return range(*out, n, align) ? NL_META_OK : NL_META_MALFORMED;
}
#define TRY(expr) do { NLMetadataResult r_ = (expr); if (r_ != NL_META_OK) return r_; } while (0)
static int same(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static int prefix(const char **name, const char *p) {
    const char *s = *name;
    while (*p) { if (*s++ != *p++) return 0; }
    *name = s;
    return 1;
}
static int classify(const char *name, NLMetadataPart *part, uint32_t *level) {
    const char *s = name;
    if (!prefix(&s, "player_A")) return 0;
    *part = NL_META_BODY;
    if (prefix(&s, "_mantle")) *part = NL_META_MANTLE;
    else if (prefix(&s, "_head")) *part = NL_META_HEAD;
    *level = 0;
    if (prefix(&s, "_LV")) {
        if (prefix(&s, "12")) *level = 12;
        else if (prefix(&s, "16")) *level = 16;
        else if (prefix(&s, "1")) *level = 1;
        else if (prefix(&s, "4")) *level = 4;
        else if (prefix(&s, "8")) *level = 8;
        else return 0;
    }
    return same(s, ".nmo");
}
static NLMetadataResult model(const NLMetadataInput *in, NLAddress resource,
                              char name[NL_METADATA_NAME_BYTES]) {
    uint32_t header, a, v, i;
    if (!range(resource, 0x24, 4)) return NL_META_MALFORMED;
    TRY(pointer(in, resource + 0x20, 0x74, 4, &header));
    TRY(word(in, header, &v));
    if (v != 0x004f4d4eu) return NL_META_MALFORMED;
    TRY(word(in, header + 4, &v));
    if (v != 3) return NL_META_MALFORMED;
    TRY(pointer(in, header + 0x70, 1, 1, &a));
    for (i = 0; i < NL_METADATA_NAME_BYTES; ++i) {
        uint8_t c;
        TRY(bytes(in, a + i, &c, 1));
        if (c > 127) return NL_META_MALFORMED;
        name[i] = (char)c;
        if (c == 0) return NL_META_OK;
    }
    return NL_META_MALFORMED;
}
static NLMetadataResult definition_resource(const NLMetadataInput *in,
                                             const NLVerifiedCandidate *c,
                                             uint32_t *resource) {
    uint32_t field, packed, distance, symbol, descriptor, stride, base, index;
    uint32_t offset = c->family == NL_ALIAS ? 4u : 0x14u;
    if (!range(c->definition, offset + 4, 4)) return NL_META_MALFORMED;
    field = c->definition + offset;
    TRY(word(in, field, &packed));
    distance = packed & 0x3ffffu;
    index = (packed >> 18) & 0xfffu;
    if (distance >= field) return NL_META_MALFORMED;
    TRY(word(in, field - distance, &symbol));
    if (!symbol || symbol == in->undefined_symbol || !range(symbol, 0x14, 4))
        return NL_META_MALFORMED;
    TRY(pointer(in, symbol + 8, 0x10, 4, &descriptor));
    TRY(word(in, descriptor + 0xc, &stride));
    if (stride < 0xc || stride % 4) return NL_META_MALFORMED;
    TRY(pointer(in, symbol + 0x10, 4, 4, &base));
    /* Divide before multiplying: index*stride must not wrap into physical RAM. */
    if (index && stride > (EE_SIZE - base) / index) return NL_META_MALFORMED;
    base += index * stride;
    if (!range(base, 0xc, 4)) return NL_META_MALFORMED;
    return pointer(in, base + 8, 0x24, 4, resource);
}
static int live(const NLMetadataInput *in, NLObject obj) {
    return in->lifetime(in->user, obj.object, obj.allocation) == NL_LIVE;
}
static NLMetadataResult candidate(const NLMetadataInput *in,
                                  const NLVerifiedCandidate *c,
                                  NLMetadataVisual *v, int *supported) {
    uint8_t type;
    uint32_t display, parent, kind, skeleton, def_resource;
    char def_name[NL_METADATA_NAME_BYTES];
    *supported = 0;
    if (!live(in, c->owned)) return NL_META_STALE;
    TRY(bytes(in, c->owned.object + 8, &type, 1));
    if ((c->family == NL_ALIAS && type != 11) ||
        (c->family == NL_CHARACTER && type != 9)) return NL_META_MALFORMED;
    TRY(pointer(in, c->owned.object + 0x1d4, 4, 4, &display));
    TRY(pointer(in, display, 0x24, 4, &v->model_resource));
    TRY(model(in, v->model_resource, v->model_name));
    if (!classify(v->model_name, &v->part, &v->level)) {
        return live(in, c->owned) ? NL_META_OK : NL_META_STALE;
    }
    if (c->owned.object == in->canonical_p1.object ||
        (v->part == NL_META_HEAD ? c->family != NL_CHARACTER : c->family != NL_ALIAS))
        return NL_META_MALFORMED;
    TRY(word(in, c->owned.object + 0x180, &kind));
    TRY(pointer(in, c->owned.object + 0x150, 9, 4, &parent));
    if (kind != 1 || parent != in->canonical_p1.object) return NL_META_MALFORMED;
    if (c->family == NL_ALIAS) {
        TRY(pointer(in, c->owned.object + 0x224, 9, 4, &skeleton));
        if (skeleton != in->canonical_p1.object) return NL_META_MALFORMED;
    }
    TRY(definition_resource(in, c, &def_resource));
    TRY(model(in, def_resource, def_name));
    if (def_resource != v->model_resource || !same(def_name, v->model_name))
        return NL_META_MALFORMED;
    TRY(bytes(in, c->owned.object + 0x150, v->private_gp_bytes, NL_METADATA_GP_BYTES));
    if (!live(in, c->owned)) return NL_META_STALE;
    v->owned = c->owned;
    v->definition = c->definition;
    v->family = c->family;
    *supported = 1;
    return NL_META_OK;
}
NLMetadataResult nl_metadata_discover(const NLMetadataInput *in, NLMetadata *out) {
    NLMetadata result;
    uint32_t i, mask = 0;
    uint8_t type;
    if (!in || !out || in->quiescent != 1 || !in->read32 || !in->read_bytes ||
        !in->lifetime || !in->resource_generation || !in->canonical_p1.allocation ||
        !range(in->canonical_p1.object, 9, 4) || !in->candidates ||
        !in->candidate_count || in->candidate_count > NL_METADATA_MAX_CANDIDATES)
        return NL_META_INVALID;
    /* Validate every supplied record before reading any candidate memory. */
    for (i = 0; i < in->candidate_count; ++i) {
        const NLVerifiedCandidate *c = &in->candidates[i];
        if (!c->owned.allocation || !range(c->owned.object, 0x228, 4) ||
            !range(c->definition, 4, 4) || c->definition_verified != 1 ||
            (c->family != NL_ALIAS && c->family != NL_CHARACTER)) return NL_META_INVALID;
        if (c->resource_generation != in->resource_generation) return NL_META_STALE;
    }
    if (!live(in, in->canonical_p1)) return NL_META_STALE;
    TRY(bytes(in, in->canonical_p1.object + 8, &type, 1));
    if (type != 9) return NL_META_MALFORMED;
    clear_bytes(&result, (uint32_t)sizeof result);
    for (i = 0; i < in->candidate_count; ++i) {
        NLMetadataVisual v;
        int supported;
        clear_bytes(&v, (uint32_t)sizeof v);
        TRY(candidate(in, &in->candidates[i], &v, &supported));
        if (supported) {
            uint32_t bit = 1u << (uint32_t)v.part;
            if (mask & bit) return NL_META_AMBIGUOUS;
            result.visuals[v.part] = v;
            mask |= bit;
        }
    }
    if (!live(in, in->canonical_p1)) return NL_META_STALE;
    for (i = 0; i < in->candidate_count; ++i)
        if (!live(in, in->candidates[i].owned)) return NL_META_STALE;
    if (mask != 7) return NL_META_MISSING;
    result.canonical_p1 = in->canonical_p1;
    result.resource_generation = in->resource_generation;
    *out = result;
    return NL_META_OK;
}
