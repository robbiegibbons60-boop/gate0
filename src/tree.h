#ifndef GATE0_TREE_H
#define GATE0_TREE_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

#define MERKLE_MAX_DEPTH 8
#define HASH_BYTES crypto_generichash_BYTES

typedef struct {
    uint8_t frontier[MERKLE_MAX_DEPTH][HASH_BYTES];
    uint64_t leaf_count;
} MerkleTree;

void merkle_init(MerkleTree *tree);
void merkle_append(MerkleTree *tree, const uint8_t *data, size_t len);
void merkle_get_root(const MerkleTree *tree, uint8_t *root_out);

#endif
