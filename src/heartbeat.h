#ifndef GATE0_HEARTBEAT_H
#define GATE0_HEARTBEAT_H
#include <stdint.h>
#include <sodium.h>
#include "gate0.h"
#define HB_INTERVAL_MS 2000
#define HB_MISS_LIMIT 2
#define HB_WINDOW_NS 5000000000ULL
typedef struct __attribute__((packed)) {
    uint8_t node_id[32];
    uint64_t sequence;
    uint64_t timestamp_ns;
    uint32_t interval_ms;
    uint8_t signature[64];
} HeartbeatPacket;
typedef struct {
    uint64_t last_seen_ns;
    uint64_t sequence;
    uint32_t miss_count;
} HeartbeatState;
GateOResult heartbeat_verify(const HeartbeatPacket *pkt, HeartbeatState *state, uint64_t now_ns);
void heartbeat_init(HeartbeatState *state);
#endif /* GATE0_HEARTBEAT_H */
