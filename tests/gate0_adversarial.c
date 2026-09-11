#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "../src/gate0.h"

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "[-] Failed to initialize libsodium in adversarial harness\n");
        return 1;
    }

    printf("[*] Initializing Gate Zero 100,000-Trial Adversarial Harness...\n");

    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    SenderRecord sender = {0};
    SafetyInterlocks interlocks = {0};
    uint64_t base_time = 1750000000000000ULL;

    SignedCommand cmd = {0};
    cmd.envelope.protocol_version = 0x01;
    cmd.envelope.command_id = 100;
    cmd.envelope.node_id = 0x01;
    cmd.envelope.issued_at_ns = base_time;
    cmd.envelope.expires_at_ns = base_time + 1000000000ULL;
    cmd.envelope.sequence_number = 1;
    cmd.envelope.command_type = 0x01;
    cmd.envelope.required_authority = AUTH_OPERATOR;
    memcpy(cmd.sender_pubkey, pk, 32);

    crypto_sign_detached(cmd.signature, NULL, (const unsigned char *)&cmd.envelope, sizeof(CommandEnvelope), sk);

    Gate0Result res = evaluate_command(&cmd, &sender, &interlocks, base_time);
    assert(res == G0_OK);
    assert(sender.current_sequence == 1);
    printf("[+] Test 1: Bootstrap Seq=1 PASSED\n");

    cmd.envelope.sequence_number = 2;
    crypto_sign_detached(cmd.signature, NULL, (const unsigned char *)&cmd.envelope, sizeof(CommandEnvelope), sk);
    res = evaluate_command(&cmd, &sender, &interlocks, base_time);
    assert(res == G0_OK);
    assert(sender.current_sequence == 2);
    printf("[+] Test 2: Sequential Seq=2 PASSED\n");

    cmd.envelope.sequence_number = 2;
    crypto_sign_detached(cmd.signature, NULL, (const unsigned char *)&cmd.envelope, sizeof(CommandEnvelope), sk);
    res = evaluate_command(&cmd, &sender, &interlocks, base_time);
    assert(res == G0_SEQUENCE_REPLAY);
    assert(sender.current_sequence == 2);
    printf("[+] Test 3: Sequence Replay rejection PASSED\n");

    cmd.envelope.sequence_number = 4;
    crypto_sign_detached(cmd.signature, NULL, (const unsigned char *)&cmd.envelope, sizeof(CommandEnvelope), sk);
    res = evaluate_command(&cmd, &sender, &interlocks, base_time);
    assert(res == G0_SEQUENCE_GAP);
    assert(sender.current_sequence == 2);
    printf("[+] Test 4: Sequence Gap rejection PASSED\n");

    uint64_t seq_before = sender.current_sequence;
    for (int i = 0; i < 100000; i++) {
        SignedCommand fuzz_cmd = cmd;
        if (i % 5 == 0) {
            fuzz_cmd.envelope.sequence_number = 999;
        } else if (i % 5 == 1) {
            fuzz_cmd.envelope.sequence_number = 2;
        } else if (i % 5 == 2) {
            fuzz_cmd.envelope.command_type = 0xF0;
        } else if (i % 5 == 3) {
            fuzz_cmd.signature[0] ^= 0xFF;
        } else {
            fuzz_cmd.envelope.sequence_number = seq_before + 1;
        }

        if (i % 5 != 3) {
            crypto_sign_detached(fuzz_cmd.signature, NULL, (const unsigned char *)&fuzz_cmd.envelope, sizeof(CommandEnvelope), sk);
        }

        uint64_t seq_prior_trial = sender.current_sequence;
        Gate0Result trial_res = evaluate_command(&fuzz_cmd, &sender, &interlocks, base_time);

        if (trial_res == G0_OK) {
            assert(sender.current_sequence == seq_prior_trial + 1);
            seq_before = sender.current_sequence;
        } else {
            assert(sender.current_sequence == seq_prior_trial);
        }
    }

    printf("[+] 100,000-Trial Adversarial Property Campaign: 100% PASSED (Zero invariant violations)\n");
    return 0;
}
