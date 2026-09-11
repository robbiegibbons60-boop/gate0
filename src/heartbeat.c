#include "heartbeat.h"
#include <string.h>

void heartbeat_init(HeartbeatState *state) {
    memset(state, 0, sizeof(HeartbeatState));
}

GateOResult heartbeat_verify(
    const HeartbeatPacket *pkt,
    HeartbeatState *state,
    uint64_t now_ns) {
    if (pkt == NULL || state == NULL) return GO_HEARTBEAT_INVALID;
    int64_t delta = (int64_t)now_ns - (int64_t)pkt->timestamp_ns;
    if (delta < 0) delta = -delta;
    if ((uint64_t)delta > HB_WINDOW_NS) return GO_EXPIRED;
    if (state->last_seen_ns != 0 && pkt->sequence <= state->sequence) return GO_SEQUENCE_INVALID;
    uint64_t gap_ns = now_ns - state->last_seen_ns;
    uint64_t miss_window = (uint64_t)HB_MISS_LIMIT * (uint64_t)pkt->interval_ms * 1000000ULL;
    if (state->last_seen_ns != 0 && gap_ns > miss_window) {
        state->miss_count++;
        return GO_HEARTBEAT_MISSED;
    }
    state->last_seen_ns = now_ns;
    state->sequence = pkt->sequence;
    state->miss_count = 0;
    return GO_HEARTBEAT_OK;
}
