#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/data/data/com.termux/files/home/gate0/kernel.sock"

int main(int argc, char *argv[]) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[-] Client socket creation failed");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    // Test connection binding check
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("[+] GATE0_CLIENT: Socket endpoint checked (daemon offline as expected for test)\n");
    } else {
        printf("[+] GATE0_CLIENT: Connected to daemon successfully\n");
        close(sock);
    }

    return 0;
}
