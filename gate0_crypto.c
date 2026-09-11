#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

int main() {
    if (sodium_init() < 0) {
        fprintf(stderr, "[-] Failed to initialize libsodium\n");
        return 1;
    }

    unsigned char key[crypto_aead_chacha20poly1305_IETF_KEYBYTES];
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES];
    crypto_aead_chacha20poly1305_ietf_keygen(key);
    randombytes_buf(nonce, sizeof(nonce));

    const unsigned char *msg = (unsigned char *)"gate0 secure payload";
    unsigned long long msg_len = strlen((char *)msg);
    
    unsigned char ciphertext[msg_len + crypto_aead_chacha20poly1305_IETF_ABYTES];
    unsigned long long ciphertext_len;

    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &ciphertext_len,
        msg, msg_len,
        NULL, 0,
        NULL, nonce, key
    );

    unsigned char decrypted[msg_len];
    unsigned long long decrypted_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted, &decrypted_len,
        NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        nonce, key) != 0) {
        fprintf(stderr, "[-] ChaCha20-Poly1305 decryption failed!\n");
        return 1;
    }

    decrypted[decrypted_len] = '\0';
    printf("[+] ChaCha20-Poly1305 AEAD: PASSED\n    Decrypted: %s\n", decrypted);
    return 0;
}
