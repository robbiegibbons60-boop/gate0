#include "dark_controller.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL
           + ts.tv_nsec;
}

void dark_init(DarkController *d) {
    memset(d, 0, sizeof(*d));
    d->mode = DARK_OFF;
}

void dark_activate(DarkController *d, DarkMode m) {
    d->mode = m;
    d->activated_at_ns = now_ns();
    d->trigger_count++;
}

void dark_deactivate(DarkController *d) {
    d->mode = DARK_OFF;
    d->activated_at_ns = 0;
}

int dark_should_suppress(DarkController *d) {
    if (d->mode == DARK_OFF) return 0;
    d->packets_suppressed++;
    return 1;
}

void dark_tick(DarkController *d, StateEngine *s) {
    if (s->current == STATE_LOCKOUT) {
        dark_activate(d, DARK_HARD);
        return;
    }
    if (s->current == STATE_FAILSAFE ||
        s->current == STATE_DEGRADED) {
        if (d->mode == DARK_OFF)
            dark_activate(d, DARK_ON);
        return;
    }
    if (s->current == STATE_ACTIVE &&
        d->mode == DARK_ON)
        dark_deactivate(d);
}

void dark_log(DarkController *d) {
    printf("[DARK] mode=%d triggers=%u "
           "suppressed=%llu\n",
           d->mode, d->trigger_count,
           (unsigned long long)d->packets_suppressed);
}
