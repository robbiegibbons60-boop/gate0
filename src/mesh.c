#include "mesh.h"
#include <string.h>

void mesh_init_cluster(MeshCluster *cluster, uint32_t local_id, uint32_t threshold) {
    memset(cluster, 0, sizeof(MeshCluster));
    cluster->threshold = threshold;
    (void)local_id;
}

int mesh_sign_proposal(const ConsensusProposal *proposal, const uint8_t *secret_key, uint8_t *sig_out) {
    return crypto_sign_detached(
        sig_out, NULL,
        (const uint8_t *)proposal, sizeof(ConsensusProposal),
        secret_key
    );
}

int mesh_verify_vote(const ConsensusVote *vote, const uint8_t *public_key, const uint8_t *proposal_hash) {
    if (sodium_memcmp(vote->proposal_hash, proposal_hash, HASH_BYTES) != 0) {
        return -1;
    }
    return crypto_sign_verify_detached(
        vote->signature,
        vote->proposal_hash, HASH_BYTES,
        public_key
    );
}
