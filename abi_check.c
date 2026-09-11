#include <stdio.h>
#include <stddef.h>
#include "src/gate0.h"

int main() {
    printf("[C] sizeof(CommandEnvelope): %zu\n", sizeof(CommandEnvelope));
    printf("[C] sizeof(SignedCommand): %zu\n", sizeof(SignedCommand));
    printf("[C] offsetof(SignedCommand, envelope): %zu\n", offsetof(SignedCommand, envelope));
    printf("[C] offsetof(SignedCommand, signature): %zu\n", offsetof(SignedCommand, signature));
    printf("[C] offsetof(SignedCommand, sender_pubkey): %zu\n", offsetof(SignedCommand, sender_pubkey));
    return 0;
}
