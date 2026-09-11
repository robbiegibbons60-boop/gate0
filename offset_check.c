#include <stdio.h>
#include <stddef.h>
#include "gate0.h"

int main() {
    printf("OFF_payload=%zu\n", offsetof(CommandEnvelope, payload));
    printf("OFF_issued=%zu\n", offsetof(CommandEnvelope, issued_at_ns));
    printf("OFF_expires=%zu\n", offsetof(CommandEnvelope, expires_at_ns));
    printf("OFF_seq=%zu\n", offsetof(CommandEnvelope, sequence_number));
    return 0;
}
