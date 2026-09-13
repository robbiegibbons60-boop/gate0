#include "consequence_state.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "[-] Failed to initialize libsodium\n");
        return 1;
    }

    const char *message = (argc > 1) ? argv[1] : "default_gate0_authorization_payload";

    ConsequenceState cs;
    cs_init(&cs);
    cs_update_from_wal(&cs,"gate0.wal");
    int csr=cs_evaluate_token_request(&cs,"sign","default",0.0);
    if(csr!=CS_AUTHORIZED){fprintf(stderr,"[-] denied\n");return csr;}
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    unsigned char sig[crypto_sign_BYTES];
    unsigned long long sig_len;

    crypto_sign_detached(sig, &sig_len, (const unsigned char *)message, strlen(message), sk);

    printf("[+] GATE0_SIGNER: Success\n");
    printf("    Target Message: %s\n", message);
    printf("    Signature Length: %llu bytes\n", sig_len);
    
    printf("    PublicKey (prefix): ");
    for (int i = 0; i < 8; i++) printf("%02x", pk[i]);
    printf("\n    Signature (prefix): ");
    for (int i = 0; i < 8; i++) printf("%02x", sig[i]);
    printf("\n");

    return 0;
}
