#include "rolling_cage.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sodium.h>

static CageSession cages[CAGE_MAX];
static int cage_count = 0;

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL
           + ts.tv_nsec;
}

void cage_init(void) {
    memset(cages, 0, sizeof(cages));
    cage_count = 0;
}

CageSession *cage_lookup(uint64_t cage_id) {
    for (int i = 0; i < cage_count; i++)
        if (cages[i].cage_id == cage_id)
            return &cages[i];
    return NULL;
}

CageSession *cage_open(struct sockaddr_in *addr,
                       ThreatAttrib *a) {
    if (cage_count >= CAGE_MAX) return NULL;
    CageSession *c = &cages[cage_count++];
    memset(c, 0, sizeof(*c));
    c->attacker = *addr;
    c->attrib = a;
    c->state = CAGE_ACTIVE;
    c->entered_ns = now_ns();
    c->last_action_ns = c->entered_ns;
    c->round = 0;
    randombytes_buf(c->session_key, 32);
    uint8_t buf[13];
    memcpy(buf, &addr->sin_addr.s_addr, 4);
    memcpy(buf+4, &c->entered_ns, 8);
    buf[12] = c->round;
    uint8_t hash[32];
    crypto_generichash(hash, 32, buf, 13, NULL, 0);
    memcpy(&c->cage_id, hash, 8);
    c->tripwire_armed = 1;
    if (a) a->cage_sessions++;
    printf("[CAGE] opened id=%016llx\n",
        (unsigned long long)c->cage_id);
    return c;
}

void cage_roll(CageSession *c) {
    if (!c) return;
    c->round++;
    uint8_t buf[13];
    memcpy(buf, &c->attacker.sin_addr.s_addr, 4);
    uint64_t t = now_ns();
    memcpy(buf+4, &t, 8);
    buf[12] = c->round;
    uint8_t hash[32];
    crypto_generichash(hash, 32, buf, 13, NULL, 0);
    memcpy(&c->cage_id, hash, 8);
    randombytes_buf(c->session_key, 32);
    printf("[CAGE] rolled round=%u\n", c->round);
}

int cage_detect_escape(CageSession *c,
                       uint8_t *cmd, uint32_t len) {
    if (!c || !cmd || len< 4) return 0;
    uint32_t sig = 0;
    memcpy(&sig, cmd, 4);
    if (sig == 0xDEADBEEF || sig == 0xCAFEBABE) {
        c->escape_attempts++;
        return 1;
    }
    return 0;
}

void cage_recapture(CageSession *c) {
    if (!c) return;
    c->state = CAGE_RECAPTURED;
    c->escape_attempts++;
    cage_roll(c);
    c->state = CAGE_ACTIVE;
    c->tripwire_armed = 1;
    printf("[CAGE] recaptured round=%u\n", c->round);
}void cage_close(CageSession *c) {
    if (!c) return;
    c->state = CAGE_EMPTY;
    printf("[CAGE] closed attempts=%u\n",
        c->escape_attempts);
}
