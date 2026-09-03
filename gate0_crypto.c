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
