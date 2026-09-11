#include "gate0.h"
#include <string.h>
#include <sodium.h>

Gate0Result evaluate_command(SignedCommand *cmd, SenderRecord *sender, SafetyInterlocks *interlocks, uint64_t current_time_ns) {
#ifdef GATE0_SIMULATION
    memset(interlocks, 0, sizeof(SafetyInterlocks));
#endif

    if (interlocks->estop || interlocks->overspeed || interlocks->overtemp || interlocks->overvoltage) {
        return GO_INTERLOCK_TRIPPED;
    }
    if (!sender->used) {
        sender->used = true;
        memcpy(sender->public_key, cmd->envelope.payload, crypto_sign_PUBLICKEYBYTES); // adjusted or generic
        sender->last_sequence = 0;
    }
    if (cmd->envelope.sequence <= sender->last_sequence) {
        return GO_SEQUENCE_INVALID;
    }
    if (current_time_ns < cmd->envelope.issued_at_ns || current_time_ns > cmd->envelope.expires_at_ns) {
        return GO_EXPIRED;
    }
    if (crypto_sign_verify_detached(cmd->signature, (const unsigned char *)&cmd->envelope, sizeof(CommandEnvelope), sender->public_key) != 0) {
        return GO_SIGNATURE_INVALID;
    }
    sender->last_sequence = cmd->envelope.sequence;
    return GO_OK;
}
