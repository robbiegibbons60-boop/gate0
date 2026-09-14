#include "attrib.h"
#include <stdio.h>
#include <time.h>
#include <sodium.h>

static ThreatAttrib reg[ATTRIB_MAX_TRACKED];
static int reg_count = 0;

void attrib_init(void) {
    sodium_memzero(reg, sizeof(reg));
    reg_count = 0;
}

uint64_t attrib_generate_id(const struct sockaddr_in *addr,
                             uint64_t ns) {
    uint8_t buf[12], hash[32];
    uint32_t ip = addr->sin_addr.s_addr;
    memcpy(buf, &ip, 4);
    memcpy(buf+4, &ns, 8);
    crypto_generichash(hash, 32, buf, 12, NULL, 0);
    uint64_t id = 0;
    memcpy(&id, hash, 8);
    return id;
}

ThreatAttrib *attrib_lookup(uint64_t tid) {
    for (int i = 0; i < reg_count; i++)
        if (reg[i].threat_id == tid) return &reg[i];
    return NULL;
}

void attrib_assign(ShadowEntry *e) {
    if (!e || reg_count >= ATTRIB_MAX_TRACKED) return;
    ThreatAttrib *a = &reg[reg_count++];
    sodium_memzero(a, sizeof(*a));
    a->threat_id = attrib_generate_id(
        &e->attacker_addr, e->first_seen_ns);
    a->first_seen_ns = e->first_seen_ns;
    a->last_seen_ns = e->last_seen_ns;
    a->total_attempts = 1;
    snprintf(a->threat_id_hex, 17, "%016llx",
        (unsigned long long)a->threat_id);
}

void attrib_score(ThreatAttrib *a, AttackPattern p) {
    if (!a) return;
    switch(p) {
        case ATTACK_SIG_FLOOD: a->score += 50; break;
        case ATTACK_SEQ_PROBE: a->score += 30; break;
        case ATTACK_REPLAY: a->score += 40; break;
        case ATTACK_MALFORMED: a->score += 20; break;
        case ATTACK_RESOURCE_EXHAUST: a->score += 75; break;
        default: a->score += 10; break;
    }
    a->fingerprint[a->fp_index % ATTRIB_FP_LEN] = (uint8_t)p;
    a->fp_index++;
    if (a->fp_index > 1) {
        uint8_t prev = a->fingerprint[
            (a->fp_index-2) % ATTRIB_FP_LEN];
        if ((uint8_t)p > prev) a->escalating = 1;
    }
}

ThreatClass attrib_classify(ThreatAttrib *a) {
    if (!a) return THREAT_UNKNOWN;
    if (a->score >= ATTRIB_SCORE_CRITICAL
        && a->multi_vector && a->escalating)
        return THREAT_APT;
    if (a->score >= ATTRIB_SCORE_HIGH && a->multi_vector)
        return THREAT_ADVANCED;
    if (a->score >= ATTRIB_SCORE_HIGH)
        return THREAT_PERSISTENT;
    if (a->score >= ATTRIB_SCORE_WARN)
        return THREAT_OPPORTUNIST;
    return THREAT_UNKNOWN;
}

void attrib_update(ShadowEntry *e, AttackPattern p) {
    if (!e) return;
    uint64_t tid = attrib_generate_id(
        &e->attacker_addr, e->first_seen_ns);
    ThreatAttrib *a = attrib_lookup(tid);
    if (!a) { attrib_assign(e); a = attrib_lookup(tid); }
    if (!a) return;
    a->total_attempts++;
    a->last_seen_ns = e->last_seen_ns;
    attrib_score(a, p);
    a->threat_class = attrib_classify(a);
}

int attrib_is_critical(ThreatAttrib *a) {
    return a && a->score >= ATTRIB_SCORE_CRITICAL;
}

void attrib_log(ThreatAttrib *a) {
    if (!a) return;
    const char *cls[] = {"UNKNOWN","OPPORTUNIST",
        "PERSISTENT","ADVANCED","APT"};
    printf("[ATTRIB] ID=%s score=%u class=%s "
        "attempts=%llu esc=%d\n",
        a->threat_id_hex, a->score,
        cls[a->threat_class],
        (unsigned long long)a->total_attempts,
        a->escalating);
}
