#include "gate0_crypto.h"
#include <sodium.h>
#include <string.h>
#include <time.h>
gate0_status_t gate0_ed25519_keygen(gate0_ed25519_keypair_t *kp){
if(!kp)return GATE0_ERR_BADKEY;
crypto_sign_ed25519_keypair(kp->pub,kp->priv);
return GATE0_OK;
}
gate0_status_t gate0_ed25519_sign(const gate0_ed25519_keypair_t *kp,const uint8_t *msg,size_t len,uint8_t sig[64]){
if(!kp||!msg||!sig)return GATE0_ERR_BADKEY;
unsigned long long siglen;
crypto_sign_ed25519_detached(sig,&siglen,msg,len,kp->priv);
return GATE0_OK;
}
gate0_status_t gate0_ed25519_verify(const uint8_t pub[32],const uint8_t *msg,size_t len,const uint8_t sig[64]){
if(!pub||!msg||!sig)return GATE0_ERR_BADKEY;
if(crypto_sign_ed25519_verify_detached(sig,msg,len,pub)!=0)return GATE0_ERR_VERIFY;
return GATE0_OK;
}
gate0_status_t gate0_x25519_keygen(gate0_x25519_keypair_t *kp){
if(!kp)return GATE0_ERR_BADKEY;
crypto_box_keypair(kp->pub,kp->priv);
return GATE0_OK;
}
gate0_status_t gate0_x25519_dh(const gate0_x25519_keypair_t *local,const uint8_t remote[32],uint8_t secret[32]){
if(!local||!remote||!secret)return GATE0_ERR_BADKEY;
if(crypto_scalarmult(secret,local->priv,remote)!=0)return GATE0_ERR_BADKEY;
return GATE0_OK;
}
gate0_status_t gate0_aead_init(gate0_aead_ctx_t *ctx,const uint8_t key[32]){
if(!ctx||!key)return GATE0_ERR_BADKEY;
memcpy(ctx->key,key,32);
ctx->nonce_counter=0;
return GATE0_OK;
}
gate0_status_t gate0_aead_encrypt(gate0_aead_ctx_t *ctx,const uint8_t *pt,size_t pt_len,uint8_t *ct,uint8_t tag[16],uint8_t nonce[12]){
if(!ctx||!pt||!ct||!tag||!nonce)return GATE0_ERR_BADKEY;
uint64_t c=ctx->nonce_counter++;
memcpy(nonce,&c,8);memset(nonce+8,0,4);
crypto_aead_chacha20poly1305_ietf_encrypt_detached(ct,tag,NULL,pt,pt_len,NULL,0,NULL,nonce,ctx->key);
return GATE0_OK;
}
gate0_status_t gate0_aead_decrypt(gate0_aead_ctx_t *ctx,const uint8_t *ct,size_t ct_len,const uint8_t tag[16],const uint8_t nonce[12],uint8_t *pt){
if(!ctx||!ct||!pt||!tag||!nonce)return GATE0_ERR_BADKEY;
if(crypto_aead_chacha20poly1305_ietf_decrypt_detached(pt,NULL,ct,ct_len,tag,NULL,0,nonce,ctx->key)!=0)return GATE0_ERR_DECRYPT;
return GATE0_OK;
}
gate0_status_t gate0_sha256(const uint8_t *data,size_t len,uint8_t digest[32]){
if(!data||!digest)return GATE0_ERR_BADKEY;
crypto_hash_sha256(digest,data,len);
return GATE0_OK;
}
gate0_status_t gate0_chain_verify(const gate0_chain_link_t *prev,const gate0_chain_link_t *next){
if(!prev||!next)return GATE0_ERR_BADKEY;
if(memcmp(next->prev_hash,prev->chain_hash,32)!=0)return GATE0_ERR_CHAIN;
if(next->seq!=prev->seq+1)return GATE0_ERR_CHAIN;
return GATE0_OK;
}
