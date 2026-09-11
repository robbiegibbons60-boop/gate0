#ifndef GATE0_MESH_H
#define GATE0_MESH_H

#include <stdint.h>
#include <stddef.h>
#include "tree.h"
#include "gate0.h"

#define MESH_MAX_PEERS 4
#define MESH_SIGNATURE_BYTES crypto_sign_BYTES
#define MESH_PUBLIC_KEY_BYTES crypto_sign_PUBLICKEYBYTES

typedef struct {
    uint64_t sequence;
    uint8_t command_hash[HASH_BYTES];
    uint8_t merkle_root_before[HASH_BYTES];
    uint8_t merkle_root_after[HASH_BYTES];
    uint64_t timestamp;
    uint32_t sender_node_id;
} ConsensusProposal;

typedef struct {
    uint32_t voter_node_id;
    uint8_t proposal_hash[HASH_BYTES];
    uint8_t signature[MESH_SIGNATURE_BYTES];
    uint8_t decision;
} ConsensusVote;

typedef struct {
    uint32_t node_id;
    uint8_t public_key[MESH_PUBLIC_KEY_BYTES];
    int active;
} PeerNode;

typedef struct {
    PeerNode peers[MESH_MAX_PEERS];
    uint32_t peer_count;
    uint32_t threshold;
} MeshCluster;

void mesh_init_cluster(MeshCluster *cluster, uint32_t local_id, uint32_t threshold);
int mesh_sign_proposal(const ConsensusProposal *proposal, const uint8_t *secret_key, uint8_t *sig_out);
int mesh_verify_vote(const ConsensusVote *vote, const uint8_t *public_key, const uint8_t *proposal_hash);

#endif
