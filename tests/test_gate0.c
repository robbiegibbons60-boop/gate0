#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>
#include "gate0.h"

extern Gate0Result evaluate_command(SignedCommand *cmd, SenderRecord *sender, SafetyInterlocks *interlocks, uint64_t current_time_ns);
extern void check_interlocks(SafetyInterlocks *interlocks);

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "[!] Sodium initialization failed\n");
        return 1;
    }

    printf("[+] Initializing Gate Zero Custom Test Suite...\n");

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    SenderRecord sender;
    memset(&sender, 0, sizeof(SenderRecord));
    memcpy(sender.public_key, pk, 32);
    sender.last_sequence = 10;
    sender.used = true;

    SafetyInterlocks interlocks;
    memset(&interlocks, 0, sizeof(SafetyInterlocks));

    SignedCommand cmd;
    memset(&cmd, 0, sizeof(SignedCommand));
    cmd.envelope.version = 1;
    cmd.envelope.sequence = 11;
    cmd.envelope.issued_at_ns = 1000ULL;
    cmd.envelope.expires_at_ns = 5000ULL;

    unsigned long long sig_len = 0;
    crypto_sign_detached(cmd.signature, &sig_len, (const unsigned char *)&(cmd.envelope), sizeof(CommandEnvelope), sk);

    uint64_t current_time = 2000ULL;

    Gate0Result res = evaluate_command(&cmd, &sender, &interlocks, current_time);
    assert(res == G0_OK);
    printf("[+] Test A (Valid Command & Signature): PASSED\n");

    res = evaluate_command(&cmd, &sender, &interlocks, current_time);
    assert(res == G0_SEQUENCE_INVALID);
    printf("[+] Test B (Replay Protection): PASSED\n");

    cmd.envelope.sequence = 12;
    crypto_sign_detached(cmd.signature, &sig_len, (const unsigned char *)&(cmd.envelope), sizeof(CommandEnvelope), sk);
    res = evaluate_command(&cmd, &sender, &interlocks, 6000ULL);
    assert(res == G0_EXPIRED);
    printf("[+] Test C (Expiration Bound Check): PASSED\n");

    interlocks.estop = true;
    check_interlocks(&interlocks);
    res = evaluate_command(&cmd, &sender, &interlocks, current_time);
    assert(res == G0_INTERLOCK_TRIPPED);
    printf("[+] Test D (Hardware Interlock Latch): PASSED\n");

    printf("[+] All Gate Zero test vectors verified successfully.\n");
    return 0;
}
