#include "gate0.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define WAL_PATH "/data/data/com.termux/files/home/gate0/gate0.wal"

typedef struct {
    uint64_t sequence;
    uint32_t length;
    unsigned char hash[32];
    unsigned char payload[256];
} WalRecord;

int persist_sender_state(const SenderRecord *sender, uint64_t seq) {
    int fd = open(WAL_PATH, O_CREAT | O_WRONLY | O_APPEND, 0600);
    if (fd < 0) return -1;

    WalRecord rec;
    memset(&rec, 0, sizeof(WalRecord));
    rec.sequence = seq;
    rec.length = sizeof(SenderRecord);
    memcpy(rec.payload, sender, sizeof(SenderRecord));

    ssize_t written = write(fd, &rec, sizeof(WalRecord));
    close(fd);
    return (written == sizeof(WalRecord)) ? 0 : -1;
}

int recover_sender_state(SenderRecord *sender) {
    int fd = open(WAL_PATH, O_RDONLY);
    if (fd < 0) return -1;

    WalRecord rec;
    WalRecord latest;
    int found = 0;

    while (read(fd, &rec, sizeof(WalRecord)) == sizeof(WalRecord)) {
        latest = rec;
        found = 1;
    }
    close(fd);

    if (found) {
        memcpy(sender, latest.payload, sizeof(SenderRecord));
        return 0;
    }
    return -1;
}
