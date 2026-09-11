#ifndef GATE0_H
#define GATE0_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    GO_OK = 0,
    GO_SIGNATURE_INVALID = 1,
    GO_EXPIRED = 2,
    GO_SEQUENCE_INVALID = 3,
    GO_INVALID_VERSION = 4,
    GO_SENDER_NOT_FOUND = 5,
    GO_INTERLOCK_TRIPPED = 6
} Gate0Result;

typedef struct __attribute__((packed)) {
    char os_name[32];
    char os_release[32];
    char machine_arch[32];
    char hostname[64];
} DeviceInfo;

typedef struct __attribute__((packed)) {
    uint32_t version;
    uint64_t sequence;
    uint64_t issued_at_ns;
    uint64_t expires_at_ns;
    uint8_t payload[256];
    uint32_t required_authority;
    DeviceInfo device;
} CommandEnvelope;

typedef struct __attribute__((packed)) {
    unsigned char public_key[32];
    uint64_t last_sequence;
    bool used;
} SenderRecord;

typedef struct __attribute__((packed)) {
    unsigned char signature[64];
    CommandEnvelope envelope;
} SignedCommand;

typedef struct __attribute__((packed)) {
    bool estop;
    bool overspeed;
    bool overtemp;
    bool overvoltage;
} SafetyInterlocks;

Gate0Result evaluate_command(SignedCommand *cmd, SenderRecord *sender, SafetyInterlocks *interlocks, uint64_t current_time_ns);

#endif
