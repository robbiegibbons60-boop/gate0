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
    int fd = open(wal_path, O_RDONLY);
    if (fd < 0) {
        perror("[-] Failed to open WAL for recovery");
        return 1;
    }

    wal_record_t rec;
    ssize_t bytes_read = read(fd, &rec, sizeof(wal_record_t));
    close(fd);

    if (bytes_read != sizeof(wal_record_t)) {
        fprintf(stderr, "[-] WAL recovery failed: incomplete record read\n");
        return 1;
    }

    printf("[+] WAL Recover: PASSED\n    Recovered Sequence: %llu\n    Payload: %s\n", 
           (unsigned long long)rec.sequence, rec.payload);
    return 0;
}
