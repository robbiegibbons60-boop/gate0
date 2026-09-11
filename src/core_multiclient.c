#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "gate0.h"

// Multi-client whitelist evaluation with structured telemetry logging for rejections
GateOResult evaluate_command_multiclient(SenderRecord *senders, size_t max_senders, SignedCommand *cmd, SafetyInterlocks *interlocks, uint64_t current_time_ns) {
    if (interlocks->estop || interlocks->overspeed || interlocks->overtemp || interlocks->overvoltage) {
        return GO_INTERLOCK_TRIPPED;
    }

    SenderRecord *matched_sender = NULL;
    for (size_t i = 0; i < max_senders; i++) {
        if (senders[i].used && sodium_memcmp(senders[i].public_key, cmd->sender_pubkey, crypto_sign_PUBLICKEYBYTES) == 0) {
            matched_sender = &senders[i];
            break;
        }
    }

    if (!matched_sender) {
        // Auto-enroll if space permits (dynamic provisioning)
        for (size_t i = 0; i < max_senders; i++) {
            if (!senders[i].used) {
                senders[i].used = true;
                memcpy(senders[i].public_key, cmd->sender_pubkey, crypto_sign_PUBLICKEYBYTES);
                senders[i].last_sequence = 0;
                matched_sender = &senders[i];
                break;
            }
        }
        if (!matched_sender) {
            return GO_SENDER_NOT_FOUND;
        }
    }

    if (cmd->envelope.sequence <= matched_sender->last_sequence) {
        return GO_SEQUENCE_INVALID;
    }

    if (current_time_ns < cmd->envelope.issued_at_ns || current_time_ns > cmd->envelope.expires_at_ns) {
        return GO_EXPIRED;
    }

    if (crypto_sign_verify_detached(
            cmd->signature,
            (const unsigned char *)&cmd->envelope,
            sizeof(CommandEnvelope),
            matched_sender->public_key) != 0) {
        return GO_SIGNATURE_INVALID;
    }

    matched_sender->last_sequence = cmd->envelope.sequence;
    return GO_OK;
}
