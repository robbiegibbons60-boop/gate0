#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sodium.h>
#include "gate0.h"

#define WAL_CAPACITY 65536

typedef struct {
    uint64_t sequence;
    uint64_t timestamp_ns;
    unsigned char prev_hash[crypto_hash_sha256_BYTES];
    unsigned char entry_hash[crypto_hash_sha256_BYTES];
    uint32_t agent_id;
    uint32_t action_code;
    int32_t result;
} WalRecord;

static WalRecord g_wal_buffer[WAL_CAPACITY];
static size_t g_wal_head = 0;
static unsigned char g_latest_hash[crypto_hash_sha256_BYTES];
static bool g_wal_initialized = false;

void wal_init(void) {
    memset(g_wal_buffer, 0, sizeof(g_wal_buffer));
    memset(g_latest_hash, 0, sizeof(g_latest_hash));
    g_wal_head = 0;
    g_wal_initialized = true;
}

int wal_append(uint32_t agent_id, uint32_t action_code, int32_t result, uint64_t timestamp_ns) {
    if (!g_wal_initialized) { wal_init(); }
    size_t idx = g_wal_head % WAL_CAPACITY;
    WalRecord *rec = &g_wal_buffer[idx];
    rec->sequence = g_wal_head;
    rec->timestamp_ns = timestamp_ns;
    rec->agent_id = agent_id;
    rec->action_code = action_code;
    rec->result = result;
    memcpy(rec->prev_hash, g_latest_hash, crypto_hash_sha256_BYTES);

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, (const unsigned char *)rec, sizeof(WalRecord) - crypto_hash_sha256_BYTES);
    crypto_hash_sha256_final(&state, rec->entry_hash);

    memcpy(g_latest_hash, rec->entry_hash, crypto_hash_sha256_BYTES);
    g_wal_head++;
    return 0;
}

bool wal_verify_integrity(void) {
    if (g_wal_head == 0) return true;
    size_t count = g_wal_head < WAL_CAPACITY ? g_wal_head : WAL_CAPACITY;
    unsigned char expected_prev[crypto_hash_sha256_BYTES];
    memset(expected_prev, 0, sizeof(expected_prev));
    for (size_t i = 0; i < count; i++) {
        WalRecord *rec = &g_wal_buffer[i];
        if (sodium_memcmp(rec->prev_hash, expected_prev, crypto_hash_sha256_BYTES) != 0) return false;
        unsigned char recomputed[crypto_hash_sha256_BYTES];
        crypto_hash_sha256_state state;
        crypto_hash_sha256_init(&state);
        crypto_hash_sha256_update(&state, (const unsigned char *)rec, sizeof(WalRecord) - crypto_hash_sha256_BYTES);
        crypto_hash_sha256_final(&state, recomputed);
        if (sodium_memcmp(rec->entry_hash, recomputed, crypto_hash_sha256_BYTES) != 0) return false;
        memcpy(expected_prev, rec->entry_hash, crypto_hash_sha256_BYTES);
    }
    return true;
}
