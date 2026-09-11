#include "gate0.h"
#include "gate0_paths.h"
#include "gate0_paths.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
int main() {
    unlink(GATE0_SOCKET_PATH);
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) return 1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, GATE0_SOCKET_PATH, sizeof(addr.sun_path) - 1);
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(server_fd); return 1; }
    if (listen(server_fd, 5) < 0) { close(server_fd); return 1; }
    printf("[+] GATE0_DAEMON: Active and listening\n");
    SenderRecord sender = {0};
    SafetyInterlocks interlocks = {0};
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd >= 0) {
        SignedCommand cmd;
        if (read(client_fd, &cmd, sizeof(SignedCommand)) == sizeof(SignedCommand)) {
            Gate0Result res = evaluate_command(&cmd, &sender, &interlocks, 1750000000000000ULL);
            write(client_fd, &res, sizeof(Gate0Result));
        }
        close(client_fd);
    }
    close(server_fd);
    unlink(GATE0_SOCKET_PATH);
    return 0;
}
