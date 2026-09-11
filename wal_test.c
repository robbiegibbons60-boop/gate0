#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

typedef struct {
    uint64_t sequence;
    uint32_t length;
    unsigned char hash[32];
    unsigned char payload[256];
} wal_record_t;

int main() {
    const char *wal_path = "/data/data/com.termux/files/home/gate0/gate0.wal";
    int fd = open(wal_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        perror("[-] Failed to open WAL");
        return 1;
    }

    wal_record_t rec = { .sequence = 1, .length = 23 };
    memcpy(rec.payload, "wal_crash_recovery_test", 23);
    
    ssize_t written = write(fd, &rec, sizeof(wal_record_t));
    close(fd);

    if (written == sizeof(wal_record_t)) {
        printf("[+] WAL Writer: PASSED (Wrote %zd bytes to disk)\n", written);
    } else {
        fprintf(stderr, "[-] WAL Writer failed\n");
        return 1;
    }
    return 0;
}
