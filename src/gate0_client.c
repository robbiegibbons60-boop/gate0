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
    if (sodium_init() < 0) return 1;

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[-] Client socket creation failed");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, GATE0_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[-] Client connect failed (is gate0_daemon running?)");
        close(sock);
        return 1;
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    SignedCommand cmd = {0};
    cmd.envelope.protocol_version = 0x01;
    cmd.envelope.command_id = 501;
    cmd.envelope.node_id = 0x01;
    cmd.envelope.issued_at_ns = 1750000000000000ULL;
    cmd.envelope.expires_at_ns = 1750000001000000ULL;
    cmd.envelope.sequence_number = 1;
    cmd.envelope.command_type = 0x01;
    cmd.envelope.required_authority = AUTH_OPERATOR;
    memcpy(cmd.sender_pubkey, pk, 32);

    crypto_sign_detached(cmd.signature, NULL, (const unsigned char *)&cmd.envelope, sizeof(CommandEnvelope), sk);

    write(sock, &cmd, sizeof(SignedCommand));

    Gate0Result res;
    ssize_t n = read(sock, &res, sizeof(Gate0Result));
    if (n == sizeof(Gate0Result)) {
        printf("[+] GATE0_CLIENT: Received kernel response code: %d (0 = OK)\n", res);
    } else {
        perror("[-] Failed to read response from daemon");
    }

    close(sock);
    return 0;
}
