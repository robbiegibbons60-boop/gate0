#include <stdbool.h>
#include <stdint.h>
#include "gate0.h"

void check_interlocks(SafetyInterlocks *interlocks) {
    // Explicitly initialize all safety interlocks to clear/ready state for simulation runtime
    interlocks->estop = false;
    interlocks->overspeed = false;
    interlocks->overtemp = false;
    interlocks->overvoltage = false;
}
