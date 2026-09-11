#include "tree.h"
#include <string.h>

void merkle_init(MerkleTree *tree) {
    memset(tree, 0, sizeof(MerkleTree));
    tree->leaf_count = 0;
}

void merkle_append(MerkleTree *tree, const uint8_t *data, size_t len) {
    uint8_t current_hash[HASH_BYTES];
    crypto_generichash(current_hash, sizeof(current_hash), data, len, NULL, 0);

    uint64_t idx = tree->leaf_count++;
    for (int i = 0; i < MERKLE_MAX_DEPTH; i++) {
        if ((idx & (1ULL << i)) == 0) {
            memcpy(tree->frontier[i], current_hash, HASH_BYTES);
            break;
        } else {
            uint8_t combined[HASH_BYTES * 2];
            memcpy(combined, tree->frontier[i], HASH_BYTES);
            memcpy(combined + HASH_BYTES, current_hash, HASH_BYTES);
            crypto_generichash(current_hash, sizeof(current_hash), combined, sizeof(combined), NULL, 0);
        }
    }
}

void merkle_get_root(const MerkleTree *tree, uint8_t *root_out) {
    uint8_t current_hash[HASH_BYTES];
    memset(current_hash, 0, HASH_BYTES);
    int active = 0;

    for (int i = 0; i < MERKLE_MAX_DEPTH; i++) {
        if ((tree->leaf_count & (1ULL << i)) != 0) {
            if (!active) {
                memcpy(current_hash, tree->frontier[i], HASH_BYTES);
                active = 1;
            } else {
                uint8_t combined[HASH_BYTES * 2];
                memcpy(combined, tree->frontier[i], HASH_BYTES);
                memcpy(combined + HASH_BYTES, current_hash, HASH_BYTES);
                crypto_generichash(current_hash, sizeof(current_hash), combined, sizeof(combined), NULL, 0);
            }
        }
    }
    memcpy(root_out, current_hash, HASH_BYTES);
}
