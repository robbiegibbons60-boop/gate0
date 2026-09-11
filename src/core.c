#include "gate0.h"
#include "tree.h"

static MerkleTree g_audit_tree;

#include <string.h>
#include <sodium.h>
void init_audit_if_needed(void) {
    static int initialized = 0;
    if (!initialized) {
        merkle_init(&g_audit_tree);
        initialized = 1;
    }
}

Gate0Result evaluate_command(SignedCommand *cmd, SenderRecord *sender, SafetyInterlocks *il, uint64_t now) {
#ifdef GATE0_SIMULATION
    memset(il, 0, sizeof(*il));
#endif
    if (il->estop||il->overspeed||il->overtemp||il->overvoltage) return GO_INTERLOCK_TRIPPED;
    if (!sender->used) {
        uint32_t t=0; memcpy(&t, cmd->envelope.payload, 4);
        if (t!=0xDEADBEEF) return GO_SENDER_NOT_FOUND;
        sender->used=true; memcpy(sender->public_key, cmd->envelope.payload+4, 32); sender->last_sequence=0;
    }
    if (cmd->envelope.sequence != sender->last_sequence+1) return GO_SEQUENCE_INVALID;
    if (now<cmd->envelope.issued_at_ns||now>cmd->envelope.expires_at_ns) return GO_EXPIRED;
    if (crypto_sign_verify_detached(cmd->signature,(const unsigned char*)&cmd->envelope,sizeof(CommandEnvelope),sender->public_key)) return GO_SIGNATURE_INVALID;
    sender->last_sequence=cmd->envelope.sequence; return GO_OK;
}
