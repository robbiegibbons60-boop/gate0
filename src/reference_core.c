#include "gate0.h"
#include <string.h>

Gate0Result reference_evaluate_command(SignedCommand *cmd, SenderRecord *sender, SafetyInterlocks *interlocks, uint64_t current_time_ns) {
    return evaluate_command(cmd, sender, interlocks, current_time_ns);
}
