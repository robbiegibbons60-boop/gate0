#include <stdio.h>
#include <stddef.h>
#include "gate0.h"

#define FIELD(T,F) \
    printf("%-32s offset=%3zu size=%3zu\n", \
           #F, offsetof(T,F), sizeof(((T *)0)->F))

int main(void)
{
    printf("sizeof(CommandEnvelope) = %zu\n",
           sizeof(CommandEnvelope));
    printf("sizeof(SignedCommand)   = %zu\n",
           sizeof(SignedCommand));
    printf("sizeof(SenderRecord)    = %zu\n",
           sizeof(SenderRecord));
    printf("sizeof(SafetyInterlocks)= %zu\n",
           sizeof(SafetyInterlocks));
    printf("sizeof(Gate0Result)      = %zu\n\n",
           sizeof(Gate0Result));

    FIELD(SignedCommand, envelope);
    FIELD(SignedCommand, signature);

    return 0;
}
