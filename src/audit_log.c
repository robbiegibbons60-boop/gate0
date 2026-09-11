#include "gate0.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sodium.h>

#define AUDIT_LOG_PATH "/data/data/com.termux/files/home/gate0/gate0_audit.log"

typedef struct {
    uint64_t timestamp_ns;
    uint32_t command_id;
    uint32_t node_id;
    uint64_t sequence;
    uint8_t command_type;
    uint16_t decision_code;
    unsigned char previous_hash[crypto_hash_sha256_BYTES];
    unsigned char event_hash[crypto_hash_sha256_BYTES];
} AuditRecord;

static unsigned char last_hash[crypto_hash_sha256_BYTES] = {0};
static int initialized = 0;

void audit_log_event(uint32_t cmd_id, uint32_t node_id, uint64_t seq, uint8_t cmd_type, uint16_t decision, uint64_t timestamp_ns) {
    int fd = open(AUDIT_LOG_PATH, O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) return;

    AuditRecord rec;
    memset(&rec, 0, sizeof(AuditRecord));
    rec.timestamp_ns = timestamp_ns;
    rec.command_id = cmd_id;
    rec.node_id = node_id;
    rec.sequence = seq;
    rec.command_type = cmd_type;
    rec.decision_code = decision;

    if (!initialized) {
        memset(rec.previous_hash, 0, crypto_hash_sha256_BYTES);
        initialized = 1;
    } else {
        memcpy(rec.previous_hash, last_hash, crypto_hash_sha256_BYTES);
    }

    crypto_hash_sha256(rec.event_hash, (const unsigned char *)&rec, sizeof(AuditRecord) - crypto_hash_sha256_BYTES);
    memcpy(last_hash, rec.event_hash, crypto_hash_sha256_BYTES);

    write(fd, &rec, sizeof(AuditRecord));
    close(fd);
}
