/* shadow.h - Gate Zero Deception Layer */
#ifndef SHADOW_H
#define SHADOW_H
#include <stdint.h>
#include <netinet/in.h>
typedef enum {
    ATTACK_NONE = 0,
    ATTACK_SIG_FLOOD,
    ATTACK_SEQ_PROBE,
    ATTACK_REPLAY,
    ATTACK_MALFORMED,
    ATTACK_RESOURCE_EXHAUST
} AttackPattern;
typedef struct {
    struct sockaddr_in attacker_addr;
    uint32_t attempt_count;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    AttackPattern pattern;
    int shadow_active;
    char geo_ip[64];
    uint8_t shadow_envelope[374];
    uint32_t decoy_seq;
    uint64_t decoy_issued_ns;
    int tarpit_fd;
} ShadowEntry;
#define SHADOW_TABLE_MAX 256
#define TARPIT_DELAY_NS 2000000000ULL
void shadow_init(void);
ShadowEntry *shadow_lookup(const struct sockaddr_in *addr);
ShadowEntry *shadow_register(const struct sockaddr_in *addr, AttackPattern p);
void shadow_feed_decoy(ShadowEntry *e);
void shadow_evict_expired(uint64_t now_ns);
#endif
