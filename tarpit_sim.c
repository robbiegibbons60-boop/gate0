#include "tarpit_sim.h"
#include <string.h>
#include <time.h>
#include <stdio.h>

void tarpit_init(TarpitTable *t) { memset(t, 0, sizeof(TarpitTable)); }

static int find_session(TarpitTable *t, const uint8_t *fp) { for (uint32_t i = 0; i < t->count; i++) { if (memcmp(t->sessions[i].fingerprint, fp, 32) == 0) return (int)i; } return -1; }

int tarpit_engage(TarpitTable *t, const uint8_t *fp) { if (find_session(t, fp) >= 0) return 0; if (t->count >= TARPIT_MAX_SESSIONS) return -1; TarpitSession *s = &t->sessions[t->count++]; memcpy(s->fingerprint, fp, 32); s->state = SIM_RUNNING; s->tick = 0; s->pressure = 14.7f; s->flow_rate = 120.0f; s->valve_pos = 0.72f; struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); s->last_update_ns = (uint64_t)ts.tv_sec*1000000000ULL + ts.tv_nsec; return 0; }

void tarpit_tick_all(TarpitTable *t) { for (uint32_t i = 0; i < t->count; i++) { TarpitSession *s = &t->sessions[i]; if (s->state != SIM_RUNNING) continue; s->tick++; s->pressure += (float)(s->tick % 7) * 0.03f; s->flow_rate -= (float)(s->tick % 5) * 0.1f; s->valve_pos = 0.70f + (float)(s->tick % 11) * 0.005f; if (s->tick > 500) s->state = SIM_STALLED; } }

int tarpit_response(TarpitTable *t, const uint8_t *fp, uint8_t *buf_out, uint32_t *len_out) { int idx = find_session(t, fp); if (idx < 0) return -1; TarpitSession *s = &t->sessions[idx]; int n = snprintf((char*)buf_out, TARPIT_RESPONSE_LEN, "{\"p\":%.2f,\"f\":%.2f,\"v\":%.3f,\"t\":%u}", s->pressure, s->flow_rate, s->valve_pos, s->tick); *len_out = (uint32_t)n; return 0; }
