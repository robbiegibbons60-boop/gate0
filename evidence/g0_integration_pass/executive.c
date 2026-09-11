#include "gate0.h"
#include "gate0_paths.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

static ssize_t __attribute__((unused)) read_exact(int fd, void *buffer, size_t length) {
    unsigned char *p = (unsigned char *)buffer;
    size_t total = 0;
    while (total < length) {
        ssize_t n = read(fd, p + total, length - total);
        if (n == 0) break;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (size_t)n;
    }
    return (ssize_t)total;
}

int main() {
    // Check memory locking
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        fprintf(stderr, "[!] CRITICAL: mlockall failed - running without page pinning: %s\n", strerror(errno));
    }

    unlink(GATE0_SOCKET_PATH);
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, GATE0_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    chmod(GATE0_SOCKET_PATH, 0600);
    printf("[+] Unix socket server online at %s\n", GATE0_SOCKET_PATH);

    if (listen(server_fd, 5) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    // Enter monitoring loop
    while (1) {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        printf("[+] Client connected.\n");
        fflush(stdout);
        
        unsigned char buffer[512];
        ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer));
        
        if (bytes_read > 0) {
            printf("[+] Received %zd bytes from client.\n", bytes_read);
            fflush(stdout);
            
            // Send a 4-byte dummy result (0 = success)
            uint32_t result = 0x00000000;
            write(client_fd, &result, sizeof(result));
            printf("[+] Sent 4-byte response.\n");
            fflush(stdout);
        } else {
            printf("[-] Read failed or 0 bytes: %zd\n", bytes_read);
            fflush(stdout);
        }
        
        close(client_fd);
    } // End of while loop

    close(server_fd);
    unlink(GATE0_SOCKET_PATH);
    return 0;
} // End of main
