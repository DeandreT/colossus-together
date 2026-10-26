#include "resource_safety.h"
#include <stddef.h>

#define LOW 0x80000u
#define END 0x2000000u
#define OPTIONAL 0x400u
#define RESIDENT 0x80000u
#define PENDING 0x10000u
#define MAX_NODES 4096u
#define NATIVE_HASH_SLOTS 1024u
enum { GRAPH_PROTECTED, GRAPH_STAGE, GRAPH_TEXTURE };

static int range(uint32_t a, uint32_t size) {
    return a >= LOW && a < END && size && size <= END - a;
}
static int word(const RSConfig *c, uint32_t a, uint32_t *v) {
    return !(a & 3u) && range(a, 4) && c->read32(c->user, a, v);
}
static int byte(const RSConfig *c, uint32_t a, uint8_t *v) {
    return range(a, 1) && c->read8(c->user, a, v);
}
static int array(uint32_t a, uint32_t count, uint32_t stride) {
    return stride && count <= (END - LOW) / stride &&
           (!count || range(a, count * stride));
}
static int boundary(const RSConfig *c) {
    uint32_t g, lang;
    return c && c->read32 && c->read8 && c->headers && c->header_count &&
        c->header_count <= MAX_NODES && c->list_limit && c->list_limit <= 16384u &&
        c->quiescent == 1 && c->source_guards_verified == 1 && c->generation &&
        c->language <= 15 && word(c, c->generation_address, &g) &&
        g == c->generation && word(c, c->language_address, &lang) && lang == c->language;
}
static int workspace(const RSWorkspace *w, uint32_t minimum) {
    return w && w->nodes && w->frames && w->capacity >= minimum &&
        w->capacity <= MAX_NODES && w->frame_capacity >= w->capacity &&
        w->frame_capacity <= MAX_NODES;
}
static int overlaps(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t x = (uintptr_t)a, y = (uintptr_t)b;
    if (an > UINTPTR_MAX - x || bn > UINTPTR_MAX - y) return 1;
    return x < y + bn && y < x + an;
}
static int disjoint(const RSWorkspace *a, const RSWorkspace *b) {
    size_t an = a->capacity * sizeof(RSNode), af = a->frame_capacity * sizeof(RSFrame);
    size_t bn = b->capacity * sizeof(RSNode), bf = b->frame_capacity * sizeof(RSFrame);
    return !overlaps(a->nodes, an, b->nodes, bn) &&
        !overlaps(a->nodes, an, b->frames, bf) &&
        !overlaps(a->frames, af, b->nodes, bn) &&
        !overlaps(a->frames, af, b->frames, bf);
}
static void reset(RSWorkspace *w, const RSConfig *c) {
    uint32_t i;
    w->count = w->complete = 0;
    w->generation = c->generation; w->language = c->language;
    w->extra_count = 0;
    for (i = 0; i < RS_MAX_EXTRA_DEFINITIONS; ++i)
        w->extras[i] = (RSExtraBinding){0};
    for (i = 0; i < 4; ++i) {
        w->definition_owners[i] = w->model_owners[i] = 0;
        w->definitions[i] = w->models[i] = 0;
    }
}
static int header(const RSConfig *c, uint32_t h, uint32_t *desc) {
    uint32_t i, flags, raw;
    for (i = 0; i < c->header_count; ++i) {
        if (c->headers[i].object != h) continue;
        return range(h, 0x44) && word(c, h, &raw) && range(raw, 4) &&
            word(c, h + 8, &flags) && (flags & 255u) == 4 && !(flags & PENDING) &&
            word(c, h + 0x38, desc) && *desc == c->headers[i].descriptor &&
            range(*desc, 0x30);
    }
    return 0;
}
static int member(const RSConfig *c, uint32_t h, uint32_t target) {
    uint32_t p, slow, fast, n, d, next, found = 0, parent, flags;
    if (!header(c, h, &d) || !word(c, h + 0x40, &p)) return 0;
    slow = fast = p;
    for (n = 0; p && n < c->list_limit; ++n) {
        if (!range(p, 0x60) || !word(c, p + 0x54, &next) ||
            !word(c, p + 0x3c, &parent) || parent != h ||
            !word(c, p + 8, &flags) || (flags & 255u) != 5) return 0;
        if (p == target) ++found;
        p = next;
        if (slow && !word(c, slow + 0x54, &slow)) return 0;
        if (fast && !word(c, fast + 0x54, &fast)) return 0;
        if (fast && !word(c, fast + 0x54, &fast)) return 0;
        if (slow && slow == fast) return 0;
    }
    return !p && found == 1;
}
static int known_type(const RSConfig *c, uint32_t type) {
    uint32_t i, d;
    for (i = 0; i < c->header_count; ++i)
        if (c->headers[i].descriptor == type)
            return header(c, c->headers[i].object, &d) && d == type;
    return 0;
}
static int read_node(const RSConfig *c, uint32_t o, RSNode *n, int check_membership) {
    uint32_t td, back, flags, i, v;
    if (!range(o, 0x60) || !word(c, o, &n->raw) || !range(n->raw, 4) ||
        !word(c, o + 8, &n->object_flags) || (n->object_flags & 255u) != 5 ||
        (n->object_flags & PENDING) || !word(c, o + 0x38, &n->descriptor) ||
        !range(n->descriptor, 0x28) || !word(c, o + 0x3c, &n->header) ||
        !header(c, n->header, &td) ||
        (check_membership && !member(c, n->header, o)) ||
        !word(c, n->header, &n->header_raw) ||
        !word(c, n->header + 8, &n->header_flags) ||
        !word(c, o + 0x44, &n->flags) || !word(c, o + 0x54, &n->next) ||
        /* A loaded symbol can name a different verified type descriptor
         * (e.g. motion-orient / ph_motion_orient). M+E28DC resolves it;
         * record stride comes from symbol+8, not its owner-list header. */
        !word(c, n->descriptor + 8, &n->type) || !known_type(c, n->type) ||
        !word(c, n->descriptor + 0x14, &back) || back != o ||
        !word(c, n->type + 0xc, &n->stride) || !n->stride ||
        !word(c, n->descriptor + 0xc, &n->count) ||
        !word(c, n->descriptor + 0x10, &n->base) ||
        !array(n->base, n->count, n->stride) ||
        !word(c, n->descriptor + 0x18, &n->reference_count) ||
        !word(c, n->descriptor + 0x1c, &n->references) ||
        n->reference_count > MAX_NODES || !array(n->references, n->reference_count, 12))
        return 0;
    /* Resident nodes cannot be released through this walk. Nonresident nodes
     * with zero counts are not a valid live protected/release snapshot. */
    flags = (n->flags >> 20) & 1023u;
    if (!(n->flags & RESIDENT) && !flags) return 0;
    n->reference_fingerprint = 2166136261u;
    for (i = 0; i < n->reference_count * 3; ++i) {
        if (!word(c, n->references + i * 4, &v)) return 0;
        n->reference_fingerprint = (n->reference_fingerprint ^ v) * 16777619u;
    }
    n->object = o; n->decrements = n->color = 0;
    return 1;
}
static int node(const RSConfig *c, uint32_t o, RSNode *n) {
    return read_node(c, o, n, 1);
}
/* Provisional graph records are read-only. No public success may expose them
 * until validate() proves both their fields and authoritative membership. */
static int node_fields(const RSConfig *c, uint32_t o, RSNode *n) {
    return read_node(c, o, n, 0);
}
static int same_node(const RSNode *a, const RSNode *b) {
    return a->object == b->object && a->raw == b->raw && a->header == b->header &&
        a->descriptor == b->descriptor && a->flags == b->flags &&
        a->object_flags == b->object_flags && a->type == b->type &&
        a->header_raw == b->header_raw && a->header_flags == b->header_flags &&
        a->count == b->count && a->base == b->base && a->stride == b->stride &&
        a->reference_count == b->reference_count && a->references == b->references &&
        a->next == b->next && a->reference_fingerprint == b->reference_fingerprint;
}
static int validate(const RSConfig *c, const RSWorkspace *w) {
    uint8_t seen[MAX_NODES / 8] = {0};
    uint32_t i, j, h, d, p, next, parent, flags, slow, fast, steps;
    RSNode n;
    if (!boundary(c) || w->count > w->capacity || w->count > MAX_NODES ||
        w->generation != c->generation || w->language != c->language)
        return 0;
    for (i = 0; i < w->count; ++i) {
        for (j = 0; j < i; ++j)
            if (w->nodes[j].object == w->nodes[i].object) return 0;
        if (!node_fields(c, w->nodes[i].object, &n) || !same_node(&n, &w->nodes[i]))
            return 0;
    }
    /* Every authoritative header list is walked once, never once per node.
     * A seen bit is set only by actual reachability from the verified head;
     * claimed owner/header fields alone cannot manufacture membership. */
    for (i = 0; i < c->header_count && w->count; ++i) {
        h = c->headers[i].object;
        for (j = 0; j < i; ++j)
            if (c->headers[j].object == h) return 0;
        if (!header(c, h, &d) || d != c->headers[i].descriptor ||
            !word(c, h + 0x40, &p)) return 0;
        slow = fast = p;
        for (steps = 0; p; ++steps) {
            if (steps >= c->list_limit || !range(p, 0x60) ||
                !word(c, p + 0x54, &next) || !word(c, p + 0x3c, &parent) ||
                parent != h || !word(c, p + 8, &flags) || (flags & 255u) != 5)
                return 0;
            for (j = 0; j < w->count; ++j) if (w->nodes[j].object == p) {
                uint8_t bit = (uint8_t)(1u << (j & 7u));
                if (w->nodes[j].header != h || (seen[j >> 3] & bit) ||
                    w->nodes[j].next != next || w->nodes[j].object_flags != flags)
                    return 0;
                seen[j >> 3] |= bit;
            }
            p = next;
            if (slow && !word(c, slow + 0x54, &slow)) return 0;
            if (fast && !word(c, fast + 0x54, &fast)) return 0;
            if (fast && !word(c, fast + 0x54, &fast)) return 0;
            if (slow && slow == fast) return 0;
        }
    }
    for (i = 0; i < w->count; ++i)
        if (!(seen[i >> 3] & (1u << (i & 7u)))) return 0;
    return boundary(c);
}
static int find(const RSWorkspace *w, uint32_t o) {
    uint32_t i;
    for (i = 0; i < w->count; ++i) if (w->nodes[i].object == o) return (int)i;
    return -1;
}
static int insert(const RSConfig *c, RSWorkspace *w, uint32_t o) {
    int i = find(w, o);
    RSNode n;
    if (i >= 0) return i;
    if (w->count >= w->capacity || !node_fields(c, o, &n)) return -1;
    w->nodes[w->count] = n;
    return (int)w->count++;
}
/* E2A40 and E2568: optional bit10 / language mismatch are nonowning;
 * resident bit19 is excluded from RELEASE only. Protection conservatively
 * follows resident owners too: no loader invariant proves their dependencies
 * permanently resident. Null and DldSysUndefSymbol are skipped. */
static int eligible(const RSConfig *c, uint32_t flags) {
    uint32_t lang = (flags >> 11) & 15u;
    return !(flags & OPTIONAL) && (!lang || lang == c->language);
}
static int symbol_owner(const RSConfig *c, uint32_t s, uint32_t *o, int protect) {
    RSNode n;
    uint32_t back;
    *o = 0;
    if (!s || s == c->undefined_symbol) return 1;
    if (!range(s, 0x28) || !word(c, s + 0x14, &back) || !node(c, back, &n) ||
        n.descriptor != s) return 0;
    if (protect || !(n.flags & RESIDENT)) *o = back;
    return 1;
}
static int dependency(const RSConfig *c, const RSNode *n, uint32_t i, uint32_t *o,
                       int protect) {
    uint32_t a, s, flags, descriptor;
    if (i >= n->reference_count) return 0;
    a = n->references + i * 12;
    if (!word(c, a + 8, &flags)) return 0;
    *o = 0;
    if (!eligible(c, flags)) return 1;
    if (!word(c, a, &s)) return 0;
    if (!s || s == c->undefined_symbol) return 1;
    if (!range(s, 0x28) || !word(c, s + 0x14, o) || !range(*o, 0x60) ||
        !word(c, *o + 0x38, &descriptor) || descriptor != s ||
        !word(c, *o + 0x44, &flags)) return 0;
    /* Nonresident/protected targets are inserted and batch-validated before
     * success. Excluded resident targets are not in that set, so prove them
     * here with the original full membership check. */
    if (!protect && (flags & RESIDENT)) return symbol_owner(c, s, o, 0);
    return 1;
}
static int increment(uint32_t *v) {
    if (*v == UINT32_MAX) return 0;
    ++*v; return 1;
}
/* Discover unique nodes without recursion; native E2A40 deduplicates cycles.
 * For releases,
 * E26D8 invokes E2568 once per UNIQUE node. E2568 decrements that node AND
 * every eligible direct dependency. Thus a diamond's shared leaf receives
 * 1+indegree decrements, NOT merely one decrement. Duplicate edges also count.
 * Colors reset per texture root, since op6 runs separate cleanup transactions.
 */
static int graph(const RSConfig *c, RSWorkspace *w, uint32_t root, int mode) {
    uint32_t depth = 0, i, o, transaction_nodes = 1;
    int release = mode == GRAPH_TEXTURE, protect = mode == GRAPH_PROTECTED;
    int k;
    for (i = 0; i < w->count; ++i) w->nodes[i].color = 0;
    k = insert(c, w, root);
    if (k < 0) return 0;
    if (!protect && (w->nodes[k].flags & RESIDENT)) return 1;
    /* M+E2E88/E2E8C and E2B94 wrap probes with &0x3ff and never detect
     * a full table. Op1 shares this table across ALL segment roots. Op6
     * clears it per texture, so its aggregate workspace may exceed 1024. */
    if (mode == GRAPH_STAGE && w->count > NATIVE_HASH_SLOTS) return 0;
    w->frames[depth++] = (RSFrame){(uint32_t)k, 0};
    w->nodes[k].color = 1;
    if (release && !increment(&w->nodes[k].decrements)) return 0;
    while (depth) {
        RSFrame *f = &w->frames[depth - 1];
        RSNode *n = &w->nodes[f->node];
        if (f->next_reference == n->reference_count) {
            n->color = 2; --depth; continue;
        }
        if (!dependency(c, n, f->next_reference++, &o, protect)) return 0;
        if (!o) continue;
        k = insert(c, w, o);
        if (k < 0) return 0;
        if (mode == GRAPH_STAGE && w->count > NATIVE_HASH_SLOTS) return 0;
        if (release && !increment(&w->nodes[k].decrements)) return 0;
        if (w->nodes[k].color) continue;
        if (mode == GRAPH_TEXTURE && ++transaction_nodes > NATIVE_HASH_SLOTS) return 0;
        if (depth >= w->frame_capacity) return 0;
        if (release && !increment(&w->nodes[k].decrements)) return 0;
        w->nodes[k].color = 1;
        w->frames[depth++] = (RSFrame){(uint32_t)k, 0};
    }
    return 1;
}
/* Add all roots as one stock E2CC8 transaction: root duplication is removed
 * before E2568. graph() resets colors; the current unique release set instead
 * supplies a final recount, which also avoids counting a shared edge twice. */
static int recount(const RSConfig *c, RSWorkspace *w) {
    uint32_t i, j, o;
    int k;
    for (i = 0; i < w->count; ++i) w->nodes[i].decrements = 0;
    for (i = 0; i < w->count; ++i) {
        RSNode *n = &w->nodes[i];
        if (n->flags & RESIDENT) continue;
        if (!increment(&n->decrements)) return 0;
        for (j = 0; j < n->reference_count; ++j) {
            if (!dependency(c, n, j, &o, 0)) return 0;
            if (!o) continue;
            k = find(w, o);
            if (k < 0 || !increment(&w->nodes[k].decrements)) return 0;
        }
    }
    return 1;
}
static int definition_owners(const RSConfig *c, const RSDefinition *defs,
                             uint32_t count, uint32_t *out) {
    uint8_t hits[RS_MAX_EXTRA_DEFINITIONS] = {0};
    uint32_t i, j, h, o, d, slow, fast, steps, k;
    RSNode n;
    if (count > RS_MAX_EXTRA_DEFINITIONS) return 0;
    for (k = 0; k < count; ++k) out[k] = 0;
    if (!count) return 1;
    for (i = 0; i < c->header_count; ++i) {
        h = c->headers[i].object;
        for (j = 0; j < i; ++j)
            if (c->headers[j].object == h) return 0;
        if (!header(c, h, &d) || d != c->headers[i].descriptor ||
            !word(c, h + 0x40, &o)) return 0;
        slow = fast = o;
        for (steps = 0; o; ++steps) {
            /* Reachability from this exact header proves membership. Validate
             * every node, not just a matching definition, and finish all lists
             * before accepting the unique owner. No cached proof survives here. */
            if (steps >= c->list_limit || !node_fields(c, o, &n) || n.header != h)
                return 0;
            for (k = 0; k < count; ++k)
                if (n.count && defs[k].address >= n.base &&
                    defs[k].address - n.base < n.count * n.stride &&
                    (defs[k].address - n.base) % n.stride == 0) {
                    out[k] = o;
                    if (++hits[k] > 1) return 0;
                }
            o = n.next;
            if (slow && !word(c, slow + 0x54, &slow)) return 0;
            if (fast && !word(c, fast + 0x54, &fast)) return 0;
            if (fast && !word(c, fast + 0x54, &fast)) return 0;
            if (slow && slow == fast) return 0;
        }
    }
    for (k = 0; k < count; ++k) if (hits[k] != 1) return 0;
    return 1;
}
static int model_owner(const RSConfig *c, uint32_t def, uint32_t family,
                       uint32_t *owner, uint32_t *resource) {
    uint32_t field, packed, dist, symbol, idx, record, nmo, flags, raw;
    RSNode n;
    if (family > RS_SCRIPT_LAYOUT || !range(def, 0x18)) return 0;
    /* M+82B24 retains the definition in t5; M+82B3C selects def+8,
     * M+82B90..82BBC applies the same symbol/index/stride/resource walk. */
    field = def + (family == RS_ALIAS ? 4u : family == RS_SCRIPT_LAYOUT ? 8u : 0x14u);
    if (!word(c, field, &packed)) return 0;
    dist = packed & 0x3ffffu; idx = (packed >> 18) & 4095u;
    if (!dist || dist > field - LOW || !word(c, field - dist, &symbol) ||
        !symbol || symbol == c->undefined_symbol || !range(symbol, 0x28) ||
        !word(c, symbol + 0x14, owner) || !node(c, *owner, &n) ||
        n.descriptor != symbol || idx >= n.count || n.stride < 12) return 0;
    record = n.base + idx * n.stride;
    if (!word(c, record + 8, resource) || !range(*resource, 0x24) ||
        !word(c, *resource, &raw) || !range(raw, 4) ||
        !word(c, *resource + 8, &flags) || (flags & 255u) != 1 || (flags & PENDING) ||
        !word(c, *resource + 0x20, &nmo) || !range(nmo, 0x74) ||
        !word(c, nmo, &flags) || flags != 0x004f4d4eu ||
        !word(c, nmo + 4, &flags) || flags != 3) return 0;
    return 1;
}
static int protected_models(const RSConfig *, const RSWorkspace *);
RSResult rs_build_protected(const RSConfig *c, const RSDefinition defs[4], RSWorkspace *w) {
    uint32_t i, j, owners[4], owner, model, resource;
    if (w) w->complete = 0;
    if (!boundary(c) || !defs || !workspace(w, 512)) return RS_UNKNOWN;
    reset(w, c);
    for (i = 0; i < 4; ++i) {
        if (defs[i].constructor_verified != 1 || defs[i].generation != c->generation ||
            defs[i].family > RS_ALIAS) return RS_UNKNOWN;
        for (j = 0; j < i; ++j) if (defs[i].address == defs[j].address) return RS_UNKNOWN;
    }
    if (!definition_owners(c, defs, 4, owners)) return RS_UNKNOWN;
    for (i = 0; i < 4; ++i) {
        owner = owners[i];
        if (!model_owner(c, defs[i].address, defs[i].family, &model, &resource) ||
            !graph(c, w, owner, GRAPH_PROTECTED) ||
            !graph(c, w, model, GRAPH_PROTECTED)) return RS_UNKNOWN;
        w->definitions[i] = defs[i].address; w->definition_owners[i] = owner;
        w->model_owners[i] = model; w->models[i] = resource;
        w->families[i] = defs[i].family;
        if (!word(c, resource, &w->model_raw[i]) ||
            !word(c, resource + 0x20, &w->model_headers[i])) return RS_UNKNOWN;
    }
    if (!protected_models(c, w) || !validate(c, w)) return RS_UNKNOWN;
    w->complete = 1;
    return RS_SAFE;
}
RSResult rs_extend_protected(const RSConfig *c, const RSDefinition *proofs,
                             uint32_t count, RSWorkspace *w) {
    uint32_t i, j, was_complete;
    if (!w) return RS_UNKNOWN;
    was_complete = w->complete;
    w->complete = 0;
    if (!was_complete || !boundary(c) || !workspace(w, 512) ||
        w->count > w->capacity || w->extra_count > RS_MAX_EXTRA_DEFINITIONS ||
        count > RS_MAX_EXTRA_DEFINITIONS - w->extra_count || (count && !proofs) ||
        !validate(c, w) || !protected_models(c, w)) return RS_UNKNOWN;
    for (i = 0; i < count; ++i) {
        RSExtraBinding b = {0};
        b.proof = proofs[i];
        if (b.proof.constructor_verified != 1 || b.proof.generation != c->generation ||
            b.proof.family > RS_SCRIPT_LAYOUT) return RS_UNKNOWN;
        for (j = 0; j < 4; ++j)
            if (b.proof.address == w->definitions[j]) return RS_UNKNOWN;
        for (j = 0; j < w->extra_count; ++j)
            if (b.proof.address == w->extras[j].proof.address) return RS_UNKNOWN;
        if (!definition_owners(c, &b.proof, 1, &b.definition_owner) ||
            !model_owner(c, b.proof.address, b.proof.family, &b.model_owner, &b.model) ||
            !graph(c, w, b.definition_owner, GRAPH_PROTECTED) ||
            !graph(c, w, b.model_owner, GRAPH_PROTECTED) ||
            !word(c, b.model, &b.model_raw) ||
            !word(c, b.model + 0x20, &b.model_header)) return RS_UNKNOWN;
        w->extras[w->extra_count++] = b;
    }
    if (!protected_models(c, w) || !validate(c, w)) return RS_UNKNOWN;
    w->complete = 1;
    return RS_SAFE;
}
static int stage(const RSConfig *c, uint32_t h, uint32_t seg, RSWorkspace *w) {
    RSNode n;
    uint32_t owner, type, cnt, off, a, v, dist, s, root, j;
    if (h != c->stage_descriptor || !range(h, 0x28) ||
        !word(c, h + 0x14, &owner) || !node(c, owner, &n) || n.descriptor != h ||
        seg >= n.count || seg >= c->segment_capacity ||
        !array(c->segment_counters, c->segment_capacity, 1)) return 0;
    type = n.type;
    if (!word(c, type + 0x10, &cnt) || cnt > MAX_NODES ||
        !word(c, type + 0x14, &off) || !array(off, cnt, 4)) return 0;
    for (j = 0; j < cnt; ++j) {
        if (!word(c, off + 4 * j, &v) || (v & 3u) || n.stride < 4 || v > n.stride - 4)
            return 0;
        a = n.base + seg * n.stride + v;
        if (!word(c, a, &v)) return 0;
        dist = v & 0x3ffffu;
        if (!dist) continue;
        if (dist > a - LOW || !word(c, a - dist, &s)) return 0;
        /* E2CC8 tests flags at the source symbol-reference word, +8. */
        if (!range(a - dist, 12) || !word(c, a - dist + 8, &v)) return 0;
        if (!eligible(c, v)) continue;
        if (!symbol_owner(c, s, &root, 0)) return 0;
        if (root && !graph(c, w, root, GRAPH_STAGE)) return 0;
    }
    return recount(c, w);
}
static int texture(const RSConfig *c, uint32_t index, RSWorkspace *w) {
    uint32_t o, d, root;
    RSNode n;
    if (index >= c->texture_capacity || !array(c->texture_table, c->texture_capacity, 8) ||
        !word(c, c->texture_table + 8 * index + 4, &o) || !range(o, 0x3c) ||
        !word(c, o + 0x38, &d) || !d || d == c->undefined_symbol ||
        (d & 3u) || !range(d, 0x28) || !symbol_owner(c, d, &root, 0)) return 0;
    if (!root) return 1;
    if (root != o || !node(c, root, &n) || n.descriptor != d) return 0;
    return graph(c, w, root, GRAPH_TEXTURE);
}
static int binding_valid(const RSConfig *c, const RSWorkspace *p,
                         uint32_t def, uint32_t family, uint32_t owner,
                         uint32_t modelowner, uint32_t model, uint32_t modelraw,
                         uint32_t modelheader) {
    uint32_t o, m, raw, hdr, offset;
    int k = find(p, owner);
    const RSNode *n;
    if (k < 0 || family > RS_SCRIPT_LAYOUT) return 0;
    n = &p->nodes[k];
    offset = family == RS_ALIAS ? 4u : family == RS_SCRIPT_LAYOUT ? 8u : 0x14u;
    if (n->stride < offset + 4 || def < n->base ||
        def - n->base >= n->count * n->stride || (def - n->base) % n->stride)
        return 0;
    return model_owner(c, def, family, &o, &m) && o == modelowner && m == model &&
        find(p, o) >= 0 && word(c, m, &raw) && raw == modelraw &&
        word(c, m + 0x20, &hdr) && hdr == modelheader;
}
static int protected_models(const RSConfig *c, const RSWorkspace *p) {
    uint32_t i, j, o;
    if (p->extra_count > RS_MAX_EXTRA_DEFINITIONS) return 0;
    for (i = 0; i < 4; ++i) {
        if (p->families[i] > RS_ALIAS || !binding_valid(c, p, p->definitions[i],
            p->families[i], p->definition_owners[i], p->model_owners[i],
            p->models[i], p->model_raw[i], p->model_headers[i])) return 0;
    }
    for (i = 0; i < p->extra_count; ++i) {
        const RSExtraBinding *b = &p->extras[i];
        if (b->proof.constructor_verified != 1 || b->proof.generation != c->generation ||
            !binding_valid(c, p, b->proof.address, b->proof.family, b->definition_owner,
                b->model_owner, b->model, b->model_raw, b->model_header)) return 0;
    }
    for (i = 0; i < p->count; ++i) {
        for (j = 0; j < p->nodes[i].reference_count; ++j) {
            if (!dependency(c, &p->nodes[i], j, &o, 1) || (o && find(p, o) < 0)) return 0;
        }
    }
    return 1;
}
RSResult rs_classify(const RSConfig *c, uint32_t request,
                     const RSWorkspace *p, RSWorkspace *w) {
    uint32_t op, cancel, h, seg, op2, cancel2, h2, seg2, i, count;
    uint8_t refs = 0, final_refs;
    RSNode stage_guard, after;
    int guarded_stage = 0;
    RSResult result = RS_SAFE;
    if (w && w != p) w->complete = 0;
    if (!boundary(c) || !p || !p->complete || !workspace(w, 1) ||
        !workspace(p, 512) || p->count > p->capacity ||
        p == w || !disjoint(p, w) ||
        !range(request, 0x30) || !word(c, request, &op) ||
        !word(c, request + 4, &cancel) || !word(c, request + 8, &h) ||
        !word(c, request + 12, &seg) || !validate(c, p) ||
        !protected_models(c, p)) return RS_UNKNOWN;
    reset(w, c);
    if (op > 12) return RS_UNKNOWN;
    if (!(cancel & 1u)) {
        if (op == 3) return RS_UNKNOWN; /* asynchronous map-group deletion */
        if (op == 1) {
            /* Validate the descriptor even on the count-only fast path. */
            RSNode n;
            uint32_t owner;
            if (h != c->stage_descriptor || !range(h, 0x28) ||
                !word(c, h + 20, &owner) || !node(c, owner, &n) ||
                n.descriptor != h || seg >= n.count || seg >= c->segment_capacity ||
                !array(c->segment_counters, c->segment_capacity, 1) ||
                !byte(c, c->segment_counters + seg, &refs) || !refs) return RS_UNKNOWN;
            stage_guard = n;
            guarded_stage = 1;
            if (refs == 1 && !stage(c, h, seg, w)) return RS_UNKNOWN;
        } else if (op == 5) {
            if (!(seg & 0x80000000u) && !texture(c, seg, w)) return RS_UNKNOWN;
        } else if (op == 6) {
            if (!c->texture_capacity || c->texture_capacity > MAX_NODES ||
                !array(c->texture_table, c->texture_capacity, 8)) return RS_UNKNOWN;
            for (i = 0; i < c->texture_capacity; ++i) {
                if (!word(c, c->texture_table + i * 8, &count)) return RS_UNKNOWN;
                /* E0868 selects ANY nonzero count, then forcibly clears it. */
                if (count && !texture(c, i, w)) return RS_UNKNOWN;
            }
        }
    }
    if (guarded_stage && (!node(c, stage_guard.object, &after) ||
        !same_node(&stage_guard, &after) ||
        !byte(c, c->segment_counters + seg, &final_refs) || final_refs != refs))
        return RS_UNKNOWN;
    for (i = 0; i < w->count; ++i) {
        RSNode *n = &w->nodes[i];
        int k = find(p, n->object);
        count = (n->flags >> 20) & 1023u;
        if (!(n->flags & RESIDENT) && count < n->decrements) return RS_UNKNOWN;
        if (k >= 0) {
            if (!same_node(n, &p->nodes[k])) return RS_UNKNOWN;
            if (!(n->flags & RESIDENT) && count == n->decrements && n->decrements)
                result = RS_RETIRE;
        }
    }
    if (!protected_models(c, p) || !validate(c, w) || !validate(c, p) ||
        !word(c, request, &op2) || op != op2 ||
        !word(c, request + 4, &cancel2) || cancel != cancel2 ||
        !word(c, request + 8, &h2) || h != h2 ||
        !word(c, request + 12, &seg2) || seg != seg2) return RS_UNKNOWN;
    w->complete = 1;
    return result;
}
