#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/data/data/com.termux/files/home/gate0/kernel.sock"

int main() {
    unlink(SOCKET_PATH);
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[-] Daemon socket creation failed");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[-] Daemon socket bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("[-] Daemon listen failed");
        close(server_fd);
        return 1;
    }

    printf("[+] GATE0_DAEMON: Listening on UNIX domain socket %s\n", SOCKET_PATH);
    
    // Test cleanup
    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}
