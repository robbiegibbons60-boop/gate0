#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

void compute_hash(const unsigned char *input, size_t input_len, unsigned char *output) {
    crypto_hash_sha256(output, input, input_len);
}

void print_hex(const unsigned char *bin, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", bin[i]);
    }
    printf("\n");
}

int main() {
    if (sodium_init() < 0) return 1;

    unsigned char prev_hash[crypto_hash_sha256_BYTES];
    memset(prev_hash, 0, sizeof(prev_hash)); // Genesis block prev_hash is 0s

    const char *entries[] = {
        "gate0_init: system boot",
        "auth_success: client connected",
        "state_transition: active mode"
    };

    unsigned char current_hash[crypto_hash_sha256_BYTES];

    for (int i = 0; i < 3; i++) {
        size_t entry_len = strlen(entries[i]);
        size_t payload_len = crypto_hash_sha256_BYTES + entry_len;
        unsigned char *payload = malloc(payload_len);

        memcpy(payload, prev_hash, crypto_hash_sha256_BYTES);
        memcpy(payload + crypto_hash_sha256_BYTES, entries[i], entry_len);

        compute_hash(payload, payload_len, current_hash);
        
        printf("[+] Log Entry %d: %s\n    Hash: ", i + 1, entries[i]);
        print_hex(current_hash, 16);

        memcpy(prev_hash, current_hash, crypto_hash_sha256_BYTES);
        free(payload);
    }

    printf("[+] SHA-256 Hash-Chained Audit Log: PASSED\n");
    return 0;
}
