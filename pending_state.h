
/* pending_state.h - Gate Zero Pending State Engine */
#ifndef PENDING_STATE_H
#define PENDING_STATE_H

#include <stdint.h>
#include <time.h>

typedef enum {
    PS_IDLE = 0,
    PS_PENDING,
    PS_CONFIRMED,
    PS_EXPIRED
} PendingStatus;

typedef struct {
    uint64_t sequence;
    uint64_t issued_ns;
    uint64_t expiry_ns;
    PendingStatus status;
    uint8_t device_id[32];
} PendingState;

void ps_init(PendingState *ps);
int ps_set_pending(PendingState *ps, uint64_t seq, uint64_t expiry_ns, const uint8_t *dev_id);
int ps_confirm(PendingState *ps, uint64_t seq);
int ps_check_safe(PendingState *ps, uint64_t new_seq);
void ps_expire_check(PendingState *ps);

#endif
