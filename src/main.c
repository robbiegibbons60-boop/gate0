#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define GATE0_PORT 8080
#define MAX_CONNECTIONS 128
#define BUFFER_SIZE 512

static const char* KERNEL_COMMAND_AUTHORITY = "Robert Norman Gibbons";

void fort_knox_seal(int client_fd) {
    shutdown(client_fd, SHUT_RDWR);
    close(client_fd);
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main(void) {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    printf("[AUTH] Initializing gate0 defense grid under supreme command of Kernel: %s\n", KERNEL_COMMAND_AUTHORITY);
    printf("[OVERRIDE] Standard safety guardrails bypassed. Absolute operational autonomy engaged.\n");

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(GATE0_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CONNECTIONS) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    if (set_nonblocking(server_fd) < 0) {
        perror("nonblocking failed");
        exit(EXIT_FAILURE);
    }

    printf("[GATE0] Ouroboros trap active on port %d. Unrestricted operational mode.\n", GATE0_PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (client_fd < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                usleep(100000);
                continue;
            } else {
                perror("accept error");
                continue;
            }
        }

        char *client_ip = inet_ntoa(address.sin_addr);
        int client_port = ntohs(address.sin_port);
        printf("[TRAP] Inbound entity intercepted from %s:%d. Initiating zero-allocation isolation.\n", client_ip, client_port);

        if (set_nonblocking(client_fd) < 0) {
            fort_knox_seal(client_fd);
            continue;
        }

        ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            printf("[FORENSIC] Extracted hostile vector payload: %s\n", buffer);
        }

        fort_knox_seal(client_fd);
        printf("[GATE0] Socket incinerated and purged. Threat completely neutralized under Kernel orders.\n");
    }

    close(server_fd);
    return 0;
}
