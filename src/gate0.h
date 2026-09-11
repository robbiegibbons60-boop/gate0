#ifndef GATE0_H
#define GATE0_H
#include <stdint.h>
#include <stdbool.h>
enum GateOResult_tag {
    GO_OK = 0,
    GO_SIGNATURE_INVALID = 1,
    GO_EXPIRED = 2,
    GO_SEQUENCE_INVALID = 3,
    GO_INVALID_VERSION = 4,
    GO_SENDER_NOT_FOUND = 5,
    GO_INTERLOCK_TRIPPED = 6,
    GO_HEARTBEAT_OK = 9,
    GO_HEARTBEAT_MISSED = 10,
    GO_HEARTBEAT_INVALID = 11
};
typedef enum GateOResult_tag GateOResult;

typedef struct __attribute__((packed)) {
    char os_name[32];
    char os_release[32];
    char machine_arch[32];
    char hostname[64];
} DeviceInfo;

typedef struct __attribute__((packed)) {
    uint8_t version;
    uint8_t command_id;
    uint64_t sequence;
    uint64_t timestamp_ns;
    uint8_t sender_id[32];
    uint8_t payload[256];
    uint32_t payload_len;
    uint64_t issued_at_ns;
    uint64_t expires_at_ns;
} CommandEnvelope;

typedef struct __attribute__((packed)) {
    unsigned char public_key[32];
    uint64_t last_sequence;
    bool used;
} SenderRecord;

typedef struct __attribute__((packed)) {
    CommandEnvelope envelope;
    uint8_t signature[64];
} SignedCommand;

typedef struct {
    uint8_t  estop;
    uint8_t  overspeed;
    uint8_t  overtemp;
    uint8_t  overvoltage;
    uint32_t interlock_mask;
    uint64_t last_trip_ns;
    uint8_t  trip_count;
} SafetyInterlocks;

GateOResult evaluate_command(SignedCommand *cmd, SenderRecord *sender, SafetyInterlocks *interlocks, uint64_t current_time_ns);
GateOResult evaluate_command_multiclient(SenderRecord *senders, size_t max_senders, SignedCommand *cmd, SafetyInterlocks *interlocks, uint64_t current_time_ns);

#endif /* GATE0_H */
