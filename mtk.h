#ifndef MTK_H
#define MTK_H
#include <stdint.h>
#include <sodium.h>
#include <stdatomic.h>
#define MTK_KEY_LEN 32
#define MTK_SEED_LEN 32
typedef struct {
    uint8_t  seed[MTK_SEED_LEN];
    uint8_t  current_key[MTK_KEY_LEN];
    uint64_t counter;
    uint64_t last_rotation_ns;
    uint32_t access_attempts;
    uint32_t legitimate_accesses;
    _Atomic uintptr_t hazard[8];
} MTKState;

#define MTK_MAX_READERS 8
static inline void mtk_hazard_acquire(MTKState *m, int slot, uintptr_t ptr) {
    atomic_store_explicit(&m->hazard[slot], ptr, memory_order_seq_cst);
}
static inline void mtk_hazard_release(MTKState *m, int slot) {
    atomic_store_explicit(&m->hazard[slot], 0, memory_order_release);
}
void mtk_init(MTKState *m, const uint8_t *seed);
void mtk_rotate(MTKState *m);
int  mtk_verify(MTKState *m, const uint8_t *key);
void mtk_derive(MTKState *m, uint8_t *out);
uint64_t mtk_counter(MTKState *m);
#endif
