#include "gate0.h"
#include <string.h>

#define CMD_TYPE_SAFE_STATE 0xFF

static bool is_blocked_command(uint8_t cmd_type) {
    return (cmd_type >= 0xF0 && cmd_type <= 0xF7);
}

Gate0Result evaluate_command(SignedCommand *cmd, SenderRecord *sender, SafetyInterlocks *interlocks, uint64_t current_time_ns) {
    if (crypto_sign_verify_detached(cmd->signature, (const unsigned char *)&cmd->envelope, sizeof(CommandEnvelope), cmd->sender_pubkey) != 0) {
        return G0_SIGNATURE_INVALID;
    }

    if (!sender->used) {
        if (cmd->envelope.sequence_number == 1) {
            sender->used = true;
            memcpy(sender->public_key, cmd->sender_pubkey, 32);
            sender->current_sequence = 0;
            sender->allowed_nodes = cmd->envelope.node_id;
            sender->authority = (AuthorityLevel)cmd->envelope.required_authority;
        } else {
            return G0_UNKNOWN_SENDER;
        }
    } else {
        if (memcmp(sender->public_key, cmd->sender_pubkey, 32) != 0) {
            return G0_UNKNOWN_SENDER;
        }
    }

    if (cmd->envelope.expires_at_ns < current_time_ns) {
        return G0_EXPIRED;
    }
    if (cmd->envelope.issued_at_ns > current_time_ns + 500000000ULL) {
        return G0_FUTURE_TIMESTAMP;
    }

    if ((sender->allowed_nodes & cmd->envelope.node_id) == 0) {
        return G0_WRONG_NODE;
    }

    if (sender->authority < cmd->envelope.required_authority) {
        return G0_INSUFFICIENT_AUTHORITY;
    }

    uint64_t expected_seq = sender->current_sequence + 1;
    if (cmd->envelope.sequence_number <= sender->current_sequence) {
        return G0_SEQUENCE_REPLAY;
    }
    if (cmd->envelope.sequence_number > expected_seq) {
        return G0_SEQUENCE_GAP;
    }

    if (is_blocked_command(cmd->envelope.command_type)) {
        return G0_BLOCKED_COMMAND;
    }

    bool system_unsafe = interlocks->estop || interlocks->overspeed || interlocks->overtemp || interlocks->overvoltage;
    if (system_unsafe && cmd->envelope.command_type != CMD_TYPE_SAFE_STATE) {
        return G0_INTERLOCK_UNSAFE;
    }

    sender->current_sequence = cmd->envelope.sequence_number;
    return G0_OK;
}
