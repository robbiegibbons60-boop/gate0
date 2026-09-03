#include "gate0_crypto.h"
#include <sodium.h>
#include <stdio.h>
#include <string.h>
int main(){
if(sodium_init()<0){printf("sodium_init failed\n");return 1;}
gate0_ed25519_keypair_t kp;
gate0_ed25519_keygen(&kp);
uint8_t msg[]="gate0 test message";
uint8_t sig[64];
gate0_ed25519_sign(&kp,msg,sizeof(msg),sig);
gate0_status_t r=gate0_ed25519_verify(kp.pub,msg,sizeof(msg),sig);
if(r==GATE0_OK)printf("Ed25519 PASS\n");
else printf("Ed25519 FAIL\n");
return 0;
}
