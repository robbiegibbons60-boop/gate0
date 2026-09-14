#include "shadow.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

static ShadowEntry table[SHADOW_TABLE_MAX];
static int table_count = 0;

void shadow_init(void) {
    memset(table, 0, sizeof(table));
    table_count = 0;
}

ShadowEntry *shadow_lookup(const struct sockaddr_in *addr) {
    for (int i = 0; i < table_count; i++) {
        if (table[i].attacker_addr.sin_addr.s_addr ==
            addr->sin_addr.s_addr)
            return &table[i];
    }
    return NULL;
}

ShadowEntry *shadow_register(const struct sockaddr_in *addr,
                              AttackPattern p) {
    if (table_count >= SHADOW_TABLE_MAX) return NULL;
    ShadowEntry *e = &table[table_count++];
    memset(e, 0, sizeof(*e));
    e->attacker_addr = *addr;
    e->pattern = p;
    e->shadow_active = 1;
    e->tarpit_fd = -1;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    e->first_seen_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    e->last_seen_ns = e->first_seen_ns;
    e->attempt_count = 1;
    return e;
}

void shadow_feed_decoy(ShadowEntry *e) {
    if (!e || !e->shadow_active) return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    e->last_seen_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    e->decoy_issued_ns = e->last_seen_ns;
    e->decoy_seq++;
    memset(e->shadow_envelope, 0xAA, sizeof(e->shadow_envelope));
}

void shadow_evict_expired(uint64_t now_ns) {
    for (int i = 0; i < table_count; i++) {
        if (now_ns - table[i].last_seen_ns > TARPIT_DELAY_NS && atomic_load_explicit(&table[i].refcount, memory_order_acquire) == 0) {
            table[i] = table[--table_count];
            i--;
        }
    }
}
