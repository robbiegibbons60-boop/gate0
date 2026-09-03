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
#endif
