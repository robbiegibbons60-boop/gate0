#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "gate0.h"

#define TELEMETRY_RING_SIZE 1024

typedef struct {
    uint64_t timestamps[TELEMETRY_RING_SIZE];
    Gate0Result results[TELEMETRY_RING_SIZE];
    uint32_t head;
    uint32_t tail;
    bool full;
} TelemetryRing;

static TelemetryRing telemetry_buffer = {0};

void telemetry_push(uint64_t timestamp_ns, Gate0Result result) {
    telemetry_buffer.timestamps[telemetry_buffer.head] = timestamp_ns;
    telemetry_buffer.results[telemetry_buffer.head] = result;

    if (telemetry_buffer.full) {
        telemetry_buffer.tail = (telemetry_buffer.tail + 1) % TELEMETRY_RING_SIZE;
    }

    telemetry_buffer.head = (telemetry_buffer.head + 1) % TELEMETRY_RING_SIZE;
    if (telemetry_buffer.head == telemetry_buffer.tail) {
        telemetry_buffer.full = true;
    }
}
