"""Offline bridge checks: real C, fake 32 MiB memory, and actual EE objects."""

import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from local_config import ee_tool

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "native_lifecycle"
EE = ee_tool("gcc")

HARNESS = r"""
#include "bridge.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define P1 0x1000u
#define P2 0x3000u
#define RAW1 0x2000u
#define RAW2 0x4000u
#define NEXT_P1 0x6000u
#define NEXT_RAW 0x8000u
#define S 0x10000u
#define SB 0x10100u
#define C 0x10200u
#define CB 0x10300u
#define H 0x10400u
#define INPUT 0x10500u
#define V 0x20000u
#define WORD(a) memory[(a)/4]
static uint32_t memory[0x02000000u / 4];
static NLBridge bridge;
static NLContext ctx;
static NLBridgeConfig cfg;
static uint32_t reads, writes, fail_write, fail_read, forbidden_object;
static uint32_t addresses[256], values[256], p1canary[128], ai_work;
static uint32_t hp_bits, grip_bits;
static uint32_t canonical_mode, canonical_action;

static float hp(NLAddress actor) {
    union { uint32_t u; float f; } n;
    assert(actor == P2); n.u = hp_bits; return n.f;
}
static float grip(NLAddress actor) {
    union { uint32_t u; float f; } n;
    assert(actor == P2); n.u = grip_bits; return n.f;
}
static NLAddress work(NLAddress actor) {
    assert(actor == P2 || (canonical_mode && (actor == P1 || actor == NEXT_P1)));
    return ai_work;
}
static int read_memory(void *u, NLAddress address, uint32_t *value) {
    uint32_t a = address & 0x1fffffffu;
    (void)u; assert(nl_address_valid(address, 4));
    assert(!forbidden_object || a != forbidden_object);
    ++reads;
    if (a == fail_read) return 0;
    *value = WORD(a); return 1;
}
static int permitted(uint32_t a) {
    if (canonical_mode && (a == S || a == S + 16 || a == C || a == C + 16 ||
        a == C + 20 || a == C + 24 || a == H || a == V + 0x140)) return 1;
    if (a >= SB && a < SB + 32) return 1;
    if (a >= CB && a < CB + 32) return 1;
    if (a >= S + 4 && a < S + 24 && a != S + 16) return 1;
    if (a >= C + 4 && a <= C + 12) return 1;
    if (a == H + 4 || a == H + 12 || a == H + 16) return 1;
    if (a == INPUT || a == V + 0x144 || a == V + 0x180 || a == V + 0xe0) return 1;
    return a >= V + 0x1c0 && a <= V + (canonical_action ? 0x1cc : 0x1c4);
}
static void complete_banks(void) {
    assert(WORD(SB) == P2 && WORD(SB + 4) == ctx.generation);
    assert(WORD(SB + 8) == hp_bits && WORD(SB + 12) == grip_bits);
    assert(WORD(SB + 20) == 0 && WORD(SB + 24) == 0 && WORD(SB + 28) == 0);
    assert(WORD(CB) == P2 && WORD(CB + 4) == ctx.generation);
    assert(WORD(CB + 12) == 0 && WORD(CB + 16) == 1);
    assert(WORD(CB + 20) == 0 && WORD(CB + 24) == 0 && WORD(CB + 28) == 0);
}
static int write_memory(void *u, NLAddress address, uint32_t value) {
    uint32_t a = address & 0x1fffffffu;
    (void)u; assert(nl_address_valid(address, 4)); assert(permitted(a));
    if (canonical_action) assert(a == S || a == S + 16 || a == C || a == C + 16 ||
        a == C + 20 || a == C + 24 || a == H || a == V + 0x140 ||
        a == V + 0x1c8 || a == V + 0x1cc);
    if (a == fail_write) return 0;
    assert(writes < 256);
    addresses[writes] = a; values[writes++] = value;
    if ((a == SB + 16 || a == CB + 8) && value == 1) complete_banks();
    if (a == INPUT && value) {
        complete_banks();
        assert(WORD(SB + 16) == 1 && WORD(CB + 8) == 1);
        assert(WORD(S + 4) == P2 && WORD(C + 4) == P2 && WORD(H + 4) == P2);
    }
    if (a == V + 0x144 && value) {
        assert(WORD(V + 0xe0) == 1 && WORD(V + 0x180) == 0);
        assert(WORD(V + 0x1c0) == 0 && WORD(V + 0x1c4) == 0);
        assert(WORD(V + 0x1c8) == 0xa5a5a5a5u && WORD(V + 0x1cc) == 0xa5a5a5a5u);
    }
    WORD(a) = value; return 1;
}
static void setup(int field_work) {
    memset(memory, 0xa5, sizeof(memory));
    memset(&bridge, 0, sizeof(bridge)); memset(&ctx, 0, sizeof(ctx));
    memset(&cfg, 0, sizeof(cfg));
    reads = writes = fail_write = fail_read = forbidden_object = ai_work = 0;
    canonical_mode = canonical_action = 0;
    hp_bits = 0x43fa0000u; grip_bits = 0x42c80000u;
    cfg.read32 = read_memory; cfg.write32 = write_memory;
    cfg.survival = S; cfg.survival_bank = SB; cfg.charge = C; cfg.charge_bank = CB;
    cfg.horse = H; cfg.routing = INPUT; cfg.view = V;
    cfg.get_max_hp = hp; cfg.get_max_grip = grip;
    cfg.get_ai_work = field_work ? NULL : work; cfg.ai_work_offset = 0x1220;
    WORD(P1) = RAW1; WORD(P2) = RAW2; WORD(P2 + 0x1220) = 0;
    WORD(S) = WORD(C) = WORD(H) = P1;
    WORD(S + 4) = WORD(C + 4) = WORD(H + 4) = WORD(INPUT) = 0;
    WORD(H + 8) = 0x7000;
    WORD(C + 16) = 9;
    WORD(V + 0x144) = 0;
    memcpy(p1canary, &WORD(P1), sizeof(p1canary));
    assert(nl_bridge_init(&bridge, &cfg, 9));
    assert(nl_bridge_bind(&bridge, &ctx));
    ctx.generation = ctx.current_generation = 9;
    ctx.canonical_p1.object = P1;
    ctx.canonical_p1.allocation = ctx.fn.new_allocation(ctx.user, P1);
    ctx.actor.object = P2; ctx.actor.allocation = ctx.fn.new_allocation(ctx.user, P2);
    ctx.canonical_p1_verified = 1; ctx.phase = NL_BUILDING;
    assert(ctx.canonical_p1.allocation && ctx.actor.allocation);
}
static void canaries(void) {
    assert(!memcmp(p1canary, &WORD(P1), sizeof(p1canary)));
    if (!canonical_mode) {
        assert(WORD(S) == P1 && WORD(S + 16) == 0xa5a5a5a5u);
        assert(WORD(C) == P1 && WORD(C + 16) == 9);
        assert(WORD(C + 20) == 0xa5a5a5a5u && WORD(C + 24) == 0xa5a5a5a5u);
        assert(WORD(H) == P1);
    }
    assert(WORD(C + 28) == 0xa5a5a5a5u);
    assert(WORD(H + 8) == 0x7000);
    assert(WORD(H + 20) == 0xa5a5a5a5u && WORD(H + 28) == 0xa5a5a5a5u);
    assert(WORD(S - 4) == 0xa5a5a5a5u && WORD(S + 24) == 0xa5a5a5a5u);
    assert(WORD(V + 0x1d0) == 0xa5a5a5a5u);
}
static void publish(void) {
    assert(ctx.fn.publish_actor(ctx.user, &ctx));
    assert(ctx.phase == NL_BUILDING);
    assert(addresses[writes - 1] == INPUT && values[writes - 1] == P2);
    assert(WORD(S + 20) == 0);
    complete_banks();
}
static void setup_canonical(int field_work) {
    setup(field_work);
    /* New installation fixture, not an in-place production reset. */
    memset(&bridge, 0, sizeof(bridge));
    assert(nl_bridge_init(&bridge, &cfg, 3));
    assert(nl_bridge_bind(&bridge, &ctx));
    ctx.generation = ctx.current_generation = 3;
    WORD(C + 16) = 1;
    WORD(P1 + 0x1220) = 0;
    WORD(NEXT_P1) = NEXT_RAW; WORD(NEXT_P1 + 0x1220) = 0;
    canonical_mode = 1;
    assert(nl_bridge_adopt_canonical(&bridge, P1, 1));
    ctx.canonical_p1.allocation = bridge.canonical_id;
    ctx.actor.allocation = nl_bridge_new_allocation(&bridge, P2);
    assert(bridge.canonical_id == 1 && ctx.actor.allocation == 2);
    assert(bridge.allocations[0].generation == 1 && bridge.allocations[1].generation == 3);
    assert(bridge.generation == 3 && bridge.canonical_generation == 1 && writes == 0);
}
static void admit(NLAddress actor) {
    canonical_action = 1;
    nl_bridge_canonical_admitted(&bridge, actor);
    canonical_action = 0;
}
static void refresh_canonical(void) {
    canonical_action = 1;
    assert(nl_bridge_refresh_canonical_work(&bridge));
    canonical_action = 0;
}
static void assert_canonical(NLAddress actor, uint32_t generation) {
    assert(bridge.fault == NL_OK && bridge.canonical_object == actor);
    assert(bridge.canonical_generation == generation && bridge.generation == 3);
    assert(WORD(S) == actor && WORD(C) == actor && WORD(H) == actor);
    assert(WORD(C + 16) == generation && WORD(C + 20) == 1 && WORD(C + 24) == 0);
    assert(WORD(H + 8) == 0x7000);
    assert(WORD(V + 0x140) == actor);
    assert(WORD(V + 0x1c8) == 0 && WORD(V + 0x1cc) == 0);
}
int main(int argc, char **argv) {
    uint32_t before, id, i;
    assert(argc == 2);
    if (!strcmp(argv[1], "exact_ack")) {
        NLBridge saved;
        NLObject ids[2];
        uint32_t next, last;
        setup(0);
        ids[0] = ctx.actor;
        assert(nl_bridge_mark_final_free(&bridge, RAW2) == 1);
        next = nl_bridge_new_allocation(&bridge, P2);
        assert(next > ids[0].allocation);
        last = bridge.last_id;
        saved = bridge;
        before = reads;
        /* Current-generation FREED record only: no object reads at all. */
        ids[1] = ids[0];
        assert(!nl_bridge_acknowledge_retired_ids(&bridge, ids, 2));
        assert(!memcmp(&saved, &bridge, sizeof bridge));
        ids[1].allocation = 99999;
        assert(!nl_bridge_acknowledge_retired_ids(&bridge, ids, 2));
        assert(!memcmp(&saved, &bridge, sizeof bridge));
        ids[1] = (NLObject){P2, next}; /* LIVE */
        assert(!nl_bridge_acknowledge_retired_ids(&bridge, ids, 2));
        assert(!memcmp(&saved, &bridge, sizeof bridge));
        ids[1] = ids[0]; ids[1].object = NEXT_P1; /* duplicate ID, wrong address */
        assert(!nl_bridge_acknowledge_retired_ids(&bridge, ids, 2));
        assert(!memcmp(&saved, &bridge, sizeof bridge));
        ids[1].allocation = ids[0].allocation;
        assert(!nl_bridge_acknowledge_retired_ids(&bridge, &ids[1], 1));
        assert(!memcmp(&saved, &bridge, sizeof bridge));
        bridge.canonical_object = P1; bridge.canonical_id = ctx.canonical_p1.allocation;
        assert(nl_bridge_mark_final_free(&bridge, RAW1) == 1);
        saved = bridge;
        assert(!nl_bridge_acknowledge_retired_ids(&bridge, &ctx.canonical_p1, 1));
        assert(!memcmp(&saved, &bridge, sizeof bridge));
        assert(nl_bridge_acknowledge_retired_ids(&bridge, ids, 1));
        assert(reads == before && bridge.last_id == last && bridge.count == saved.count - 1);
        assert(bridge.allocations[0].id == saved.allocations[0].id);
        assert(bridge.allocations[bridge.count - 1].id == next);
        assert(nl_bridge_lifetime(&bridge, P2, ids[0].allocation) == NL_MISMATCH);
        assert(nl_bridge_lifetime(&bridge, P2, next) == NL_LIVE);
        assert(nl_bridge_mark_final_free(&bridge, RAW2) == 1);
        assert(nl_bridge_new_allocation(&bridge, P2) == last + 1);
    } else if (!strcmp(argv[1], "publication")) {
        setup(0); publish(); before = writes;
        assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == before);
        ai_work = 0x5000;
        assert(nl_bridge_refresh_actor_work(&bridge, &ctx));
        assert(WORD(S + 20) == ai_work);
        WORD(SB + 16) = 3; /* READY plus diagnostic flag is still a ready bank. */
        assert(ctx.fn.publish_view(ctx.user, &ctx));
        assert(WORD(SB + 16) == 3);
        assert(ctx.phase == NL_BUILDING && addresses[writes - 1] == V + 0x144);
        assert(WORD(V + 0x144) == P2);
        assert(ctx.fn.unpublish_actor(ctx.user, &ctx));
        assert(WORD(INPUT) == 0 && WORD(S + 4) == 0 && WORD(C + 4) == 0);
        assert(WORD(SB + 16) == 0 && WORD(CB + 8) == 0);
        assert(WORD(V + 0x144) == 0 && WORD(V + 0xe0) == 0);
        before = writes; assert(!ctx.fn.unpublish_actor(ctx.user, &ctx));
        assert(writes == before);
    } else if (!strcmp(argv[1], "field_work")) {
        setup(1); publish(); WORD(P2 + 0x1220) = 0x5000;
        assert(nl_bridge_refresh_actor_work(&bridge, &ctx)); assert(WORD(S + 20) == 0x5000);
        WORD(P2 + 0x1220) = 0x5001; before = writes;
        assert(!nl_bridge_refresh_actor_work(&bridge, &ctx) && writes == before);
    } else if (!strcmp(argv[1], "lifetime")) {
        setup(0); id = ctx.actor.allocation;
        assert(nl_bridge_new_allocation(&bridge, P2) == id);
        assert(nl_bridge_lifetime(&bridge, P2 | 0x80000000u, id) == NL_LIVE);
        before = reads;
        assert(nl_bridge_lifetime(&bridge, P2, 987) == NL_MISMATCH && reads == before);
        assert(nl_bridge_lifetime(&bridge, P1, id) == NL_MISMATCH && reads == before);
        assert(nl_bridge_mark_final_free(&bridge, RAW2) == 1 && reads == before);
        forbidden_object = P2;
        assert(nl_bridge_lifetime(&bridge, P2, id) == NL_FREED && reads == before);
        assert(nl_bridge_mark_final_free(&bridge, RAW2) == 0 && reads == before);
        forbidden_object = 0;
        ctx.actor.allocation = nl_bridge_new_allocation(&bridge, P2);
        assert(ctx.actor.allocation > id);
        assert(nl_bridge_lifetime(&bridge, P2, id) == NL_FREED);
        assert(nl_bridge_lifetime(&bridge, P2, ctx.actor.allocation) == NL_LIVE);
        WORD(P2) = 0x6000;
        assert(nl_bridge_lifetime(&bridge, P2, ctx.actor.allocation) == NL_MISMATCH);
        assert(!nl_bridge_new_allocation(&bridge, P2));
        before = writes; assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == before);
    } else if (!strcmp(argv[1], "generation")) {
        setup(0); before = writes;
        ctx.current_generation = 10;
        assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == before);
        ctx.current_generation = 9;
        assert(nl_bridge_set_generation(&bridge, 10));
        assert(ctx.generation == 9 && ctx.current_generation == 9);
        assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == before);
        before = reads;
        assert(nl_bridge_lifetime(&bridge, P2, ctx.actor.allocation) == NL_LIVE);
        assert(reads > before);
        assert(!nl_bridge_set_generation(&bridge, 9) && !nl_bridge_set_generation(&bridge, 10));
        assert(!nl_bridge_new_allocation(&bridge, P2));
        /* Final-free remains valid across generation changes and reads nothing. */
        assert(nl_bridge_mark_final_free(&bridge, RAW2) == 1);
        forbidden_object = P2; before = reads;
        assert(nl_bridge_lifetime(&bridge, P2, ctx.actor.allocation) == NL_FREED && reads == before);
        forbidden_object = 0;
    } else if (!strcmp(argv[1], "independent_generations")) {
        setup(0);
        assert(nl_bridge_mark_final_free(&bridge, RAW2) == 1);
        assert(nl_bridge_set_generation(&bridge, 10));
        ctx.generation = ctx.current_generation = 10;
        ctx.actor.allocation = nl_bridge_new_allocation(&bridge, P2);
        assert(ctx.actor.allocation);
        assert(nl_bridge_lifetime(&bridge, P1, ctx.canonical_p1.allocation) == NL_LIVE);
        assert(WORD(C + 16) == 9);
        publish();
        assert(WORD(C + 8) == 10 && WORD(C + 16) == 9);
        assert(WORD(H + 8) == 0x7000);
    } else if (!strcmp(argv[1], "overflow")) {
        NLBridgeAllocation saved[NL_BRIDGE_CAPACITY];
        setup(0);
        for (i = bridge.count; i < NL_BRIDGE_CAPACITY; ++i) {
            WORD(0x8000 + i * 8) = 0x100000 + i * 16;
            assert(nl_bridge_new_allocation(&bridge, 0x8000 + i * 8) == i + 1);
        }
        memcpy(saved, bridge.allocations, sizeof(saved));
        WORD(0x9000) = 0x110000;
        assert(!nl_bridge_new_allocation(&bridge, 0x9000));
        assert(bridge.count == 128 && bridge.last_id == 128);
        assert(!memcmp(saved, bridge.allocations, sizeof(saved)));
        assert(nl_bridge_mark_final_free(&bridge, RAW2) == 1);
        assert(!nl_bridge_new_allocation(&bridge, 0x9000));
        id = ctx.actor.allocation;
        assert(nl_bridge_set_generation(&bridge, 10));
        assert(nl_bridge_acknowledge_retired_before(&bridge, 10) == 1);
        assert(bridge.count == 127 && bridge.last_id == 128);
        before = reads;
        assert(nl_bridge_lifetime(&bridge, P2, id) == NL_MISMATCH && reads == before);
        assert(nl_bridge_lifetime(&bridge, P1, ctx.canonical_p1.allocation) == NL_LIVE);
        assert(nl_bridge_new_allocation(&bridge, 0x9000) == 129);
        assert(bridge.count == 128 && bridge.last_id == 129);
        setup(0); bridge.last_id = UINT32_MAX;
        before = bridge.count; assert(!nl_bridge_new_allocation(&bridge, 0x9000));
        assert(bridge.count == before && bridge.last_id == UINT32_MAX);
    } else if (!strcmp(argv[1], "guards")) {
        setup(0); WORD(S) = 0x7000; assert(!ctx.fn.publish_actor(ctx.user, &ctx));
        assert(writes == 0); WORD(S) = 0xc0001000u;
        assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0);
        WORD(S) = P1;
        hp_bits = 0x7fc00001u; assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0);
        hp_bits = 0x7f800001u; assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0);
        hp_bits = 0x7f800000u; assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0);
        hp_bits = 0x80000000u; assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0);
        hp_bits = 0xbf800000u; assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0);
        hp_bits = 0x43fa0000u; grip_bits = 0; assert(!ctx.fn.publish_actor(ctx.user, &ctx));
        grip_bits = 0x42c80000u; ai_work = 0x02000000;
        assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0); ai_work = 0;
        publish(); WORD(C + 8) = 10; before = writes;
        assert(!ctx.fn.unpublish_actor(ctx.user, &ctx) && writes == before);
        assert(!ctx.fn.publish_view(ctx.user, &ctx) && writes == before);
        WORD(C + 8) = 9; WORD(INPUT) = 0x7000;
        assert(!ctx.fn.unpublish_actor(ctx.user, &ctx) && writes == before);
        WORD(INPUT) = P2;
        {
        NLBridge fresh = {0};
        assert(!nl_bridge_init(&bridge, &cfg, 9)); /* never reset IDs */
        cfg.charge_bank = cfg.survival_bank | 0x80000000u;
        assert(!nl_bridge_init(&fresh, &cfg, 9));
        cfg.charge_bank = CB; cfg.view = 0x01ffff00;
        assert(!nl_bridge_init(&fresh, &cfg, 9));
        cfg.view = V; cfg.read32 = NULL;
        assert(!nl_bridge_init(&fresh, &cfg, 9));
        }
    } else if (!strcmp(argv[1], "p1_freed")) {
        setup(0); publish();
        assert(nl_bridge_mark_final_free(&bridge, RAW1) == 1);
        forbidden_object = P1;
        ctx.canonical_p1_verified = 0;
        assert(ctx.fn.unpublish_actor(ctx.user, &ctx));
        assert(WORD(INPUT) == 0 && WORD(S + 4) == 0 && WORD(C + 4) == 0);
    } else if (!strcmp(argv[1], "io_failure")) {
        setup(0); fail_read = P2;
        assert(!ctx.fn.publish_actor(ctx.user, &ctx) && writes == 0);
        fail_read = 0; fail_write = SB + 8;
        assert(!ctx.fn.publish_actor(ctx.user, &ctx));
        assert(WORD(INPUT) == 0 && WORD(S + 4) == 0 && WORD(C + 4) == 0);
        assert(WORD(SB + 16) == 0 && WORD(CB + 8) == 0);
        /* Caller quarantines; no retry is modeled. */
    } else if (!strcmp(argv[1], "canonical_adopt")) {
        NLBridge fresh = {0};
        setup_canonical(0);
        assert(!nl_bridge_adopt_canonical(&bridge, P1, 1));
        assert(bridge.count == 2 && bridge.last_id == 2 && writes == 0);
        assert(nl_bridge_init(&fresh, &cfg, 3));
        WORD(C + 16) = 2;
        assert(!nl_bridge_adopt_canonical(&fresh, P1, 1) && fresh.count == 0);
        WORD(C + 16) = 1; WORD(H) = NEXT_P1;
        assert(!nl_bridge_adopt_canonical(&fresh, P1, 1) && fresh.count == 0);
        WORD(H) = P1; WORD(P1) = 0x02000000u;
        assert(!nl_bridge_adopt_canonical(&fresh, P1, 1) && fresh.count == 0);
        WORD(P1) = RAW1;
        assert(!nl_bridge_adopt_canonical(&fresh, P1 + 1, 1));
        assert(!nl_bridge_adopt_canonical(&fresh, P1, 0));
        assert(nl_bridge_adopt_canonical(&fresh, P1, 1));
        assert(fresh.allocations[0].generation == 1 && fresh.generation == 3 && writes == 0);
    } else if (!strcmp(argv[1], "canonical_new")) {
        uint32_t banks[16], oldid;
        setup_canonical(0); publish();
        memcpy(banks, &WORD(SB), 32); memcpy(banks + 8, &WORD(CB), 32);
        oldid = bridge.canonical_id;
        admit(NEXT_P1); assert_canonical(NEXT_P1, 2);
        assert(bridge.canonical_id == 3 && WORD(S + 16) == 0);
        assert(nl_bridge_lifetime(&bridge, P1, oldid) == NL_LIVE); /* held old P1 */
        assert(!memcmp(banks, &WORD(SB), 32) && !memcmp(banks + 8, &WORD(CB), 32));
        assert(WORD(S + 4) == P2 && WORD(C + 4) == P2 && WORD(INPUT) == P2);
        before = writes; id = bridge.last_id;
        admit(NEXT_P1 | 0x80000000u);
        assert(writes == before && bridge.last_id == id && bridge.canonical_generation == 2);
        ai_work = 0x9000; refresh_canonical(); assert(WORD(S + 16) == 0x9000);
        assert(ctx.canonical_p1.object == P1 && ctx.generation == 3); /* host owns Context */
        assert(ctx.fn.unpublish_actor(ctx.user, &ctx)); /* old P2 can drain */
        assert_canonical(NEXT_P1, 2);
    } else if (!strcmp(argv[1], "canonical_reused")) {
        setup_canonical(1); id = bridge.canonical_id;
        before = reads; assert(nl_bridge_mark_final_free(&bridge, RAW1) == 1);
        forbidden_object = P1;
        assert(nl_bridge_lifetime(&bridge, P1, id) == NL_FREED && reads == before);
        forbidden_object = 0; /* constructor has created a new lifetime here */
        admit(P1); assert_canonical(P1, 2); assert(bridge.canonical_id > id);
        forbidden_object = P1; before = reads;
        assert(nl_bridge_lifetime(&bridge, P1, id) == NL_FREED && reads == before);
        forbidden_object = 0;
        WORD(P1 + 0x1220) = 0x9000; refresh_canonical(); assert(WORD(S + 16) == 0x9000);
        before = writes; id = bridge.canonical_id;
        admit(P1); assert(writes == before && bridge.canonical_id == id);
    } else if (!strcmp(argv[1], "canonical_old_freed")) {
        setup_canonical(0); id = bridge.canonical_id;
        assert(nl_bridge_mark_final_free(&bridge, RAW1) == 1);
        forbidden_object = P1;
        admit(NEXT_P1); assert_canonical(NEXT_P1, 2);
        before = reads;
        assert(nl_bridge_lifetime(&bridge, P1, id) == NL_FREED && reads == before);
        refresh_canonical();
    } else if (!strcmp(argv[1], "canonical_overflow")) {
        setup_canonical(0); publish();
        bridge.canonical_generation = UINT32_MAX;
        before = writes; id = bridge.last_id;
        admit(P1); /* duplicates remain harmless even at generation exhaustion */
        assert(!bridge.fault && bridge.last_id == id && writes == before);
        admit(NEXT_P1);
        assert(bridge.fault && bridge.last_id == id && writes == before);
        assert(bridge.canonical_object == P1 && bridge.generation == 3);
        id = reads; admit(NEXT_P1);
        assert(reads == id && writes == before);
        assert(!nl_bridge_refresh_canonical_work(&bridge));
        assert(ctx.fn.unpublish_actor(ctx.user, &ctx));
    } else if (!strcmp(argv[1], "canonical_partial")) {
        const uint32_t targets[] = {V + 0x140, V + 0x1c8, V + 0x1cc,
            C + 24, C + 20, C + 16, S + 16, S, H, C};
        for (i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
            uint32_t written, read_count;
            setup_canonical(0); publish(); before = writes;
            fail_write = targets[i]; admit(NEXT_P1);
            assert(bridge.fault == NL_BAD_MEMORY && bridge.canonical_object == NEXT_P1);
            assert(bridge.canonical_generation == 2 && bridge.canonical_id == 3);
            assert(bridge.generation == 3 && ctx.phase == NL_BUILDING);
            assert(writes == before + i && WORD(S + 4) == P2 && WORD(INPUT) == P2);
            written = writes; read_count = reads; fail_write = 0;
            admit(NEXT_P1); assert(writes == written && reads == read_count);
            assert(!nl_bridge_refresh_canonical_work(&bridge));
            assert(ctx.fn.unpublish_actor(ctx.user, &ctx));
        }
    } else if (!strcmp(argv[1], "canonical_guards")) {
        setup_canonical(0); before = writes;
        admit(0x02000000u); assert(bridge.fault && writes == before);
        setup_canonical(0); WORD(NEXT_P1) = 0xc0008000u;
        admit(NEXT_P1); assert(bridge.fault && writes == 0 && bridge.canonical_object == P1);
        setup_canonical(1); fail_read = NEXT_P1 + 0x1220;
        admit(NEXT_P1); assert(bridge.fault == NL_BAD_MEMORY && writes == 0);
        assert(bridge.canonical_object == NEXT_P1 && bridge.canonical_id == 3);
        setup_canonical(0); assert(nl_bridge_mark_final_free(&bridge, RAW1) == 1);
        forbidden_object = P1; before = reads;
        assert(!nl_bridge_refresh_canonical_work(&bridge));
        assert(bridge.fault == NL_STALE && reads == before && writes == 0);
        setup_canonical(0);
        for (i = bridge.count; i < NL_BRIDGE_CAPACITY; ++i) {
            WORD(0x9000 + i * 8) = 0x100000 + i * 16;
            assert(nl_bridge_new_allocation(&bridge, 0x9000 + i * 8));
        }
        id = bridge.last_id; admit(NEXT_P1);
        assert(bridge.fault && bridge.last_id == id && bridge.count == NL_BRIDGE_CAPACITY);
        assert(bridge.canonical_object == P1 && bridge.canonical_generation == 1 && writes == 0);
    } else return 2;
    canaries(); puts("ok"); return 0;
}
"""


class NativeLifecycleBridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cc = shutil.which("cc")
        if not cc:
            raise unittest.SkipTest("host C compiler unavailable")
        cls.temp = tempfile.TemporaryDirectory(prefix="native-bridge-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.harness = Path(cls.temp.name) / "harness.c"
        cls.harness.write_text(HARNESS)
        cls.binary = Path(cls.temp.name) / "host"
        subprocess.run(
            [
                cc,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pedantic",
                "-DNL_HOST_TEST",
                "-O2",
                "-I",
                str(SOURCE),
                str(SOURCE / "lifecycle.c"),
                str(SOURCE / "bridge.c"),
                str(cls.harness),
                "-o",
                str(cls.binary),
            ],
            check=True,
        )

    def test_host_bridge(self):
        for scenario in (
            "exact_ack",
            "publication",
            "field_work",
            "lifetime",
            "generation",
            "independent_generations",
            "overflow",
            "guards",
            "io_failure",
            "p1_freed",
            "canonical_adopt",
            "canonical_new",
            "canonical_reused",
            "canonical_old_freed",
            "canonical_overflow",
            "canonical_partial",
            "canonical_guards",
        ):
            with self.subTest(scenario=scenario):
                result = subprocess.run(
                    [str(self.binary), scenario],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.stdout.strip(), "ok")

    def test_ee_bindable_object(self):
        compiler = Path(os.environ.get("SOTC_EE_CC", EE))
        if not compiler.is_file():
            self.skipTest("PS2 EE compiler unavailable")
        common = [
            str(compiler),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-mabi=eabi",
            "-mlong32",
            "-mgp64",
            "-march=r5900",
            "-G0",
            "-mno-abicalls",
            "-fno-pic",
            "-O2",
            "-ffreestanding",
            "-fno-builtin",
        ]
        objects = []
        for source in ("lifecycle", "bridge"):
            obj = Path(self.temp.name) / (source + ".o")
            subprocess.run(
                common + ["-c", str(SOURCE / (source + ".c")), "-o", str(obj)],
                check=True,
            )
            objects.append(obj)
        # A relocatable linked object is directly consumable by the payload
        # installer/linker; all internal bridge/lifecycle references resolve.
        linked = Path(self.temp.name) / "native_bridge.o"
        subprocess.run(
            [
                str(compiler).removesuffix("gcc") + "ld",
                "-m",
                "elf32lr5900",
                "-r",
                *map(str, objects),
                "-o",
                str(linked),
            ],
            check=True,
        )
        data = linked.read_bytes()
        self.assertEqual(data[:7], b"\x7fELF\x01\x01\x01")
        self.assertEqual(struct.unpack_from("<H", data, 18)[0], 8)
        flags = struct.unpack_from("<I", data, 36)[0]
        self.assertEqual(flags & 0x00FF0000, 0x00920000)
        self.assertEqual(flags & 0x0000F000, 0x00004000)
        nm = subprocess.run(
            [str(compiler).removesuffix("gcc") + "nm", "-u", str(linked)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertEqual(nm.strip(), "", nm)
        disassembly = subprocess.run(
            [str(compiler).removesuffix("gcc") + "objdump", "-dr", str(objects[1])],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        for symbol in (
            "nl_bridge_publish_actor",
            "nl_bridge_unpublish_actor",
            "nl_bridge_publish_view",
            "nl_bridge_lifetime",
            "nl_bridge_bind",
            "nl_bridge_adopt_canonical",
            "nl_bridge_canonical_admitted",
            "nl_bridge_refresh_canonical_work",
        ):
            self.assertIn(f"<{symbol}>:", disassembly)
        # Float returns may move between FPR/GPR, but all validation is integer
        # bit checking. Forbid every COP1 comparison (quiet or signaling), so
        # signaling NaNs cannot trigger a floating comparison exception here.
        for line in disassembly.splitlines():
            fields = line.split("\t")
            if len(fields) >= 3 and fields[2].split():
                self.assertFalse(fields[2].split()[0].startswith("c."), line)


if __name__ == "__main__":
    unittest.main()
