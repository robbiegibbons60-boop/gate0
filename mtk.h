#ifndef MTK_H
#define MTK_H
#include <stdint.h>
#include <sodium.h>
#define MTK_KEY_LEN 32
#define MTK_SEED_LEN 32
typedef struct {
    uint8_t  seed[MTK_SEED_LEN];
    uint8_t  current_key[MTK_KEY_LEN];
    uint64_t counter;
    uint64_t last_rotation_ns;
    uint32_t access_attempts;
    uint32_t legitimate_accesses;
} MTKState;
void mtk_init(MTKState *m, const uint8_t *seed);
void mtk_rotate(MTKState *m);
int  mtk_verify(MTKState *m, const uint8_t *key);
void mtk_derive(MTKState *m, uint8_t *out);
uint64_t mtk_counter(MTKState *m);
#endif
