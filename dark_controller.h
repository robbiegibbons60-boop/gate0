#ifndef DARK_CONTROLLER_H
#define DARK_CONTROLLER_H

#include <stdint.h>
#include "state_engine.h"

typedef enum {
    DARK_OFF  = 0,
    DARK_ON   = 1,
    DARK_HARD = 2
} DarkMode;

typedef struct {
    DarkMode         mode;
    uint64_t         activated_at_ns;
    uint64_t         packets_suppressed;
    uint32_t         trigger_count;
    uint8_t          silent_on_error;
} DarkController;

void dark_init(DarkController *d);
void dark_activate(DarkController *d, DarkMode m);
void dark_deactivate(DarkController *d);
int  dark_should_suppress(DarkController *d);
void dark_tick(DarkController *d,
               StateEngine *s);
void dark_log(DarkController *d);

#endif
