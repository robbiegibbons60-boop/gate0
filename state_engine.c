#include "state_engine.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL
           + ts.tv_nsec;
}

static void transition(StateEngine *s,
                        ControllerState next) {
    s->previous    = s->current;
    s->current     = next;
    s->entered_at_ns = now_ns();
    s->transition_count++;
}

void state_init(StateEngine *s) {
    memset(s, 0, sizeof(*s));
    s->current = STATE_INIT;
    s->entered_at_ns = now_ns();
}

void state_event(StateEngine *s, StateEvent e) {
    if (s->lockout_hard) return;
    switch (e) {
        case EVT_HEARTBEAT_OK:
            s->heartbeat_misses = 0;
            if (s->current == STATE_DEGRADED ||
                s->current == STATE_INIT)
                transition(s, STATE_ACTIVE);
            break;
        case EVT_HEARTBEAT_MISS:
            s->heartbeat_misses++;
            if (s->heartbeat_misses >= 3)
                transition(s, STATE_DEGRADED);
            if (s->heartbeat_misses >= 6)
                transition(s, STATE_FAILSAFE);
            break;
        case EVT_THREAT_HIGH:
            if (s->current == STATE_ACTIVE)
                transition(s, STATE_DEGRADED);
            break;
        case EVT_THREAT_CRITICAL:
            transition(s, STATE_LOCKOUT);
            s->lockout_hard = 1;
            break;
        case EVT_PROXY_RESTORED:
            if (s->current != STATE_LOCKOUT)
                transition(s, STATE_ACTIVE);
            break;
        case EVT_MANUAL_RESET:
            s->lockout_hard = 0;
            s->heartbeat_misses = 0;
            transition(s, STATE_INIT);
            break;
    }
}

void state_tick(StateEngine *s, uint64_t now) {
    (void)now;
    if (s->current == STATE_FAILSAFE &&
        s->heartbeat_misses >= 10) {
        s->lockout_hard = 1;
        transition(s, STATE_LOCKOUT);
    }
}

int state_allows_command(StateEngine *s) {
    return (s->current == STATE_ACTIVE);
}

void state_log(StateEngine *s) {
    printf("[STATE] current=%d previous=%d "
           "misses=%u transitions=%u locked=%d\n",
           s->current, s->previous,
           s->heartbeat_misses,
           s->transition_count,
           s->lockout_hard);

}
