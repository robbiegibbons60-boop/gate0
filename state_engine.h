#ifndef STATE_ENGINE_H
#define STATE_ENGINE_H

#include<stdint.h>
#include "attrib.h"

typedef enum {
    STATE_INIT     = 0,
    STATE_ACTIVE   = 1,
    STATE_DEGRADED = 2,
    STATE_FAILSAFE = 3,
    STATE_LOCKOUT  = 4
} ControllerState;

typedef enum {
    EVT_HEARTBEAT_OK    = 0,
    EVT_HEARTBEAT_MISS  = 1,
    EVT_THREAT_HIGH     = 2,
    EVT_THREAT_CRITICAL = 3,
    EVT_PROXY_RESTORED  = 4,
    EVT_MANUAL_RESET    = 5
} StateEvent;

typedef struct {
    ControllerState  current;
    ControllerState  previous;uint64_t         entered_at_ns;
    uint32_t         heartbeat_misses;
    uint32_t         transition_count;
    uint8_t          lockout_hard;
} StateEngine;

void state_init(StateEngine *s);void state_event(StateEngine *s, StateEvent e);
void state_tick(StateEngine *s, uint64_t now_ns);
int  state_allows_command(StateEngine *s);
void state_log(StateEngine *s);

#endif
