#ifndef ATTRIB_H
#define ATTRIB_H
#include <stdint.h>
#include <netinet/in.h>
#include "shadow.h"
#define ATTRIB_FP_LEN 16
#define ATTRIB_SCORE_WARN 250
#define ATTRIB_SCORE_HIGH 500
#define ATTRIB_SCORE_CRITICAL 1000
#define ATTRIB_MAX_TRACKED 256
typedef enum {
    THREAT_UNKNOWN = 0,
    THREAT_OPPORTUNIST,
    THREAT_PERSISTENT,
    THREAT_ADVANCED,
    THREAT_APT
} ThreatClass;
typedef struct {
    uint64_t threat_id;
    uint32_t score;
    ThreatClass threat_class;
    uint8_t fingerprint[ATTRIB_FP_LEN];
    uint8_t fp_index;
    uint8_t multi_vector;
    uint8_t escalating;
    uint8_t cage_sessions;
    uint64_t first_seen_ns;
    uint64_t last_seen_ns;
    uint64_t total_attempts;
    char threat_id_hex[17];
} ThreatAttrib;
void attrib_init(void);
uint64_t attrib_generate_id(const struct sockaddr_in *addr, uint64_t ns);
void attrib_assign(ShadowEntry *e);
void attrib_update(ShadowEntry *e, AttackPattern p);
void attrib_score(ThreatAttrib *a, AttackPattern p);
ThreatClass attrib_classify(ThreatAttrib *a);
int attrib_is_critical(ThreatAttrib *a);
void attrib_log(ThreatAttrib *a);
ThreatAttrib *attrib_lookup(uint64_t threat_id);
#endif
