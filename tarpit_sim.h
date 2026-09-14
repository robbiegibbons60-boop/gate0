#ifndef TARPIT_SIM_H
#define TARPIT_SIM_H

#include <stdint.h>
#include "attrib.h"

#define TARPIT_MAX_SESSIONS 64
#define TARPIT_RESPONSE_LEN 128

typedef enum { SIM_IDLE=0, SIM_RUNNING=1, SIM_STALLED=2 } SimState;

typedef struct { uint8_t fingerprint[32]; SimState state; uint32_t tick; float pressure; float flow_rate; float valve_pos; uint64_t last_update_ns; } TarpitSession;

typedef struct { TarpitSession sessions[64]; uint32_t count; } TarpitTable;

void tarpit_init(TarpitTable *t);
int tarpit_engage(TarpitTable *t, const uint8_t *fp);
int tarpit_response(TarpitTable *t, const uint8_t *fp, uint8_t *buf_out, uint32_t *len_out);
void tarpit_tick_all(TarpitTable *t);

#endif
