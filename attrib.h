#ifndef ATTRIB_H
#define ATTRIB_H

#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

#define ATTRIB_MAX_ACTORS 256
#define ATTRIB_EVENT_LOG_SIZE 16
#define ATTRIB_FP_LEN 32

#define SCORE_REPLAY 10
#define SCORE_SIG_FLOOD 25
#define SCORE_TIMING_ANOMALY 5
#define SCORE_SEQ_VIOLATION 15

typedef enum { TIER_UNKNOWN=0, TIER_PROBING=1, TIER_ACTIVE=2, TIER_PERSISTENT=3 } ThreatTier;

typedef enum { EVT_REPLAY=0, EVT_SIG_FLOOD=1, EVT_TIMING_ANOMALY=2, EVT_SEQ_VIOLATION=3, EVT_AUTH_FAIL=4 } AttribEvent;

typedef struct { AttribEvent type; uint64_t timestamp_ns; } EventRecord;

typedef struct { uint8_t fingerprint[32]; uint32_t score; ThreatTier tier; uint64_t first_seen_ns; uint64_t last_seen_ns; uint32_t event_count; EventRecord log[16]; atomic_int active; } ActorRecord;

typedef struct { ActorRecord actors[256]; atomic_int count; } AttribTable;

void attrib_init(AttribTable *t);
int attrib_record_event(AttribTable *t, const uint8_t *fp, AttribEvent evt);
ThreatTier attrib_score(AttribTable *t, const uint8_t *fp);
void attrib_compute_fp(const uint8_t *src_addr, uint16_t src_port, uint8_t *fp_out);
#endif
