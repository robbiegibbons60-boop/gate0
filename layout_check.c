#include <stdio.h>
#include <stddef.h>
#include "gate0.h"

int main() {
    size_t env_size = sizeof(CommandEnvelope);
    size_t sig_size = sizeof(SignedCommand);
    printf("ENV_SIZE=%lu\n", (unsigned long)env_size);
    printf("SIG_CMD_SIZE=%lu\n", (unsigned long)sig_size);
    return 0;
}
