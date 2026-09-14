#include "shadow.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static void make_addr(struct sockaddr_in *a, const char *ip) {
    memset(a, 0, sizeof(*a));
    a->sin_family = AF_INET;
    inet_pton(AF_INET, ip, &a->sin_addr);
}

int main(void) {
    shadow_init();
    struct sockaddr_in a1, a2;
    make_addr(&a1, "10.0.0.1");
    make_addr(&a2, "10.0.0.2");

    /* T07 - sig flood registration */
    ShadowEntry *e1 = shadow_register(&a1, ATTACK_SIG_FLOOD);
    if (!e1) { puts("T07 FAIL: register"); return 1; }
    shadow_feed_decoy(e1);
    shadow_feed_decoy(e1);
    if (e1->decoy_seq != 2) { puts("T07 FAIL: decoy_seq"); return 1; }
    puts("T07 PASS: sig flood + decoy feed");

    /* T08 - replay storm, separate attacker */
    ShadowEntry *e2 = shadow_register(&a2, ATTACK_REPLAY);
    if (!e2) { puts("T08 FAIL: register"); return 1; }
    for (int i = 0; i < 10; i++) shadow_feed_decoy(e2);
    if (e2->decoy_seq != 10) { puts("T08 FAIL: decoy_seq"); return 1; }
    puts("T08 PASS: replay storm decoy feed");

    /* lookup verify */
    ShadowEntry *lk = shadow_lookup(&a1);
    if (!lk || lk->pattern != ATTACK_SIG_FLOOD) {
        puts("LOOKUP FAIL"); return 1;
    }
    puts("LOOKUP PASS");

    /* eviction */
    shadow_evict_expired(0xFFFFFFFFFFFFFFFFULL);
    if (shadow_lookup(&a1) != NULL) {
        puts("EVICT FAIL"); return 1;
    }
    puts("EVICT PASS");

    puts("ALL SHADOW TESTS PASS");
    return 0;
}
