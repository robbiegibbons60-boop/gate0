
#include <stdio.h>
#include "gate0.h"

int main() {
    printf("sizeof(CommandEnvelope) = %zu\n", sizeof(CommandEnvelope));
    printf("sizeof(SignedCommand)   = %zu\n", sizeof(SignedCommand));
    printf("sizeof(Gate0Result)     = %zu\n", sizeof(Gate0Result));
    return 0;
}
