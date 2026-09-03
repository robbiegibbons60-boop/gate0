#ifndef GATE0_CRYPTO_H
#define GATE0_CRYPTO_H
#include <stdint.h>
#include <stddef.h>
#define GATE0_SHA256_BYTES 32
#define GATE0_ED25519_SIG_BYTES 64
#define GATE0_CHACHA20_KEY_BYTES 32
#define GATE0_CHACHA20_NONCE_BYTES 12
#define GATE0_POLY1305_TAG_BYTES 16
#define GATE0_ED25519_PUBKEY_BYTES 32
#define GATE0_ED25519_PRIVKEY_BYTES 64
#define GATE0_X25519_KEY_BYTES 32
typedef enum {
GATE0_OK=0,
GATE0_ERR_VERIFY=-1,
GATE0_ERR_DECRYPT=-2,
GATE0_ERR_NONCE_REUSE=-3,
GATE0_ERR_BADKEY=-4,
GATE0_ERR_REPLAY=-7,
GATE0_ERR_CAPABILITY=-8,
GATE0_ERR_CHAIN=-9,
} gate0_status_t;
typedef struct {
uint8_t pub[32];
uint8_t priv[64];
} gate0_ed25519_keypair_t;
typedef struct {
uint8_t pub[32];
uint8_t priv[32];
} gate0_x25519_keypair_t;
typedef struct {
uint8_t key[32];
uint64_t nonce_counter;
} gate0_aead_ctx_t;
typedef struct {
uint8_t prev_hash[32];
uint64_t seq;
uint64_t timestamp_us;
uint8_t entry_hash[32];
uint8_t chain_hash[32];
} gate0_chain_link_t;
gate0_status_t gate0_ed25519_keygen(gate0_ed25519_keypair_t *kp);
gate0_status_t gate0_ed25519_sign(const gate0_ed25519_keypair_t *kp,const uint8_t *msg,size_t len,uint8_t sig[64]);
gate0_status_t gate0_ed25519_verify(const uint8_t pub[32],const uint8_t *msg,size_t len,const uint8_t sig[64]);
gate0_status_t gate0_x25519_keygen(gate0_x25519_keypair_t *kp);
gate0_status_t gate0_x25519_dh(const gate0_x25519_keypair_t *local,const uint8_t remote[32],uint8_t secret[32]);
gate0_status_t gate0_aead_init(gate0_aead_ctx_t *ctx,const uint8_t key[32]);
gate0_status_t gate0_aead_encrypt(gate0_aead_ctx_t *ctx,const uint8_t *pt,size_t pt_len,uint8_t *ct,uint8_t tag[16],uint8_t nonce[12]);
gate0_status_t gate0_aead_decrypt(gate0_aead_ctx_t *ctx,const uint8_t *ct,size_t ct_len,const uint8_t tag[16],const uint8_t nonce[12],uint8_t *pt);
gate0_status_t gate0_sha256(const uint8_t *data,size_t len,uint8_t digest[32]);
gate0_status_t gate0_chain_init(gate0_chain_link_t *link,const uint8_t *entry,size_t len);
gate0_status_t gate0_chain_append(gate0_chain_link_t *prev,gate0_chain_link_t *next,const uint8_t *entry,size_t len);
gate0_status_t gate0_chain_verify(const gate0_chain_link_t *prev,const gate0_chain_link_t *next);
#endif
