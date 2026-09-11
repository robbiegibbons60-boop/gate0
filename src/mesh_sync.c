#ifndef RING_POOL_H
#define RING_POOL_H

#include <stdint.h>
#include <stdbool.h>

#define RING_CAPACITY 1024  // Must be power of 2

typedef struct {
    uint32_t id;
    uint32_t length;
    uint8_t data[256];
} __attribute__((packed)) ring_msg_t;

typedef struct {
    volatile uint32_t head;
    volatile uint32_t tail;
    ring_msg_t buffer[RING_CAPACITY];
} ring_pool_t;

static inline void ring_init(ring_pool_t *pool) {
    pool->head = 0;
    pool->tail = 0;
}

static inline bool ring_push(ring_pool_t *pool, const ring_msg_t *msg) {
    uint32_t next_head = (pool->head + 1) & (RING_CAPACITY - 1);
    if (next_head == pool->tail) {
        return false; // Pool exhausted (overflow guard)
    }
    pool->buffer[pool->head] = *msg;
    pool->head = next_head;
    return true;
}

static inline bool ring_pop(ring_pool_t *pool, ring_msg_t *msg) {
    if (pool->tail == pool->head) {
        return false; // Pool empty
    }
    *msg = pool->buffer[pool->tail];
    pool->tail = (pool->tail + 1) & (RING_CAPACITY - 1);
    return true;
}

#endif // RING_POOL_H
