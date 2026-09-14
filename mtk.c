#include "mtk.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL
           + ts.tv_nsec;
}

void mtk_init(MTKState *m, const uint8_t *seed) {
    memset(m, 0, sizeof(*m));
    memcpy(m->seed, seed, MTK_SEED_LEN);
    m->counter = 0;
    m->last_rotation_ns = now_ns();
    mtk_derive(m, m->current_key);
}

void mtk_derive(MTKState *m, uint8_t *out) {
    uint8_t buf[40];
    memcpy(buf, m->seed, MTK_SEED_LEN);
    memcpy(buf+32, &m->counter, 8);
    crypto_generichash(out, MTK_KEY_LEN,buf, sizeof(buf), NULL, 0);
}

void mtk_rotate(MTKState *m) {
    m->counter++;
    m->access_attempts++;
    m->last_rotation_ns = now_ns();
    mtk_derive(m, m->current_key);
    printf("[MTK] rotated counter=%llu\n",
        (unsigned long long)m->counter);
}

int mtk_verify(MTKState *m, const uint8_t *key) {
    m->access_attempts++;uint8_t expected[MTK_KEY_LEN];
    mtk_derive(m, expected);
    int valid = (sodium_memcmp(key, expected,
                               MTK_KEY_LEN) == 0);
    mtk_rotate(m);
    if (valid) m->legitimate_accesses++;
    printf("[MTK] %s counter=%llu\n",
        valid ? "valid" : "invalid",
        (unsigned long long)m->counter);
    return valid;
}

uint64_t mtk_counter(MTKState *m) {
    return m->counter;
}
