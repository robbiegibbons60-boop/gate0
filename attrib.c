#include "attrib.h"
#include <string.h>
#include <time.h>

void attrib_init(AttribTable *t) { memset(t, 0, sizeof(AttribTable)); }

static int find_or_create(AttribTable *t, const uint8_t *fp) { int n = atomic_load(&t->count); for (int i = 0; i < n; i++) { if (memcmp(t->actors[i].fingerprint, fp, 32) == 0) return i; } if (n >= ATTRIB_MAX_ACTORS) return -1; memcpy(t->actors[n].fingerprint, fp, 32); struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); t->actors[n].first_seen_ns = (uint64_t)ts.tv_sec*1000000000ULL + ts.tv_nsec; t->actors[n].tier = TIER_UNKNOWN; atomic_store(&t->actors[n].active, 1); atomic_fetch_add(&t->count, 1); return n; }

static uint32_t score_for(AttribEvent evt) { switch(evt) { case EVT_REPLAY: return SCORE_REPLAY; case EVT_SIG_FLOOD: return SCORE_SIG_FLOOD; case EVT_TIMING_ANOMALY: return SCORE_TIMING_ANOMALY; case EVT_SEQ_VIOLATION: return SCORE_SEQ_VIOLATION; default: return 5; } }

int attrib_record_event(AttribTable *t, const uint8_t *fp, AttribEvent evt) { int idx = find_or_create(t, fp); if (idx < 0) return -1; ActorRecord *a = &t->actors[idx]; a->score += score_for(evt); if (a->score >= 60) a->tier = TIER_PERSISTENT; else if (a->score >= 35) a->tier = TIER_ACTIVE; else if (a->score >= 15) a->tier = TIER_PROBING; uint32_t slot = a->event_count % ATTRIB_EVENT_LOG_SIZE; a->log[slot].type = evt; struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); a->log[slot].timestamp_ns = (uint64_t)ts.tv_sec*1000000000ULL + ts.tv_nsec; a->last_seen_ns = a->log[slot].timestamp_ns; a->event_count++; return 0; }

ThreatTier attrib_score(AttribTable *t, const uint8_t *fp) { int n = atomic_load(&t->count); for (int i = 0; i < n; i++) { if (memcmp(t->actors[i].fingerprint, fp, 32) == 0) return t->actors[i].tier; } return TIER_UNKNOWN; }

void attrib_compute_fp(const uint8_t *src_addr, uint16_t src_port, uint8_t *fp_out) { memset(fp_out, 0, 32); memcpy(fp_out, src_addr, 4); fp_out[4] = src_port & 0xFF; fp_out[5] = (src_port >> 8) & 0xFF; }
