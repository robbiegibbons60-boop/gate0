
#include "pending_state.h"
#include <string.h>
#include <time.h>

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void ps_init(PendingState *ps) {
    memset(ps, 0, sizeof(PendingState));
    ps->status = PS_IDLE;
}

int ps_set_pending(PendingState *ps, uint64_t seq, uint64_t expiry_ns, const uint8_t *dev_id) {
    ps_expire_check(ps);
    if (ps->status == PS_PENDING) return -1; /* already pending */
    ps->sequence = seq;
    ps->issued_ns = now_ns();
    ps->expiry_ns = expiry_ns;
    ps->status = PS_PENDING;
    memcpy(ps->device_id, dev_id, 32);
    return 0;
}

int ps_confirm(PendingState *ps, uint64_t seq) {
    if (ps->status != PS_PENDING) return -1;
    if (ps->sequence != seq) return -1;
    ps->status = PS_CONFIRMED;
    return 0;
}

int ps_check_safe(PendingState *ps, uint64_t new_seq) {
    ps_expire_check(ps);
    if (ps->status == PS_PENDING) return -1; /* deny — unconfirmed pending */
    return 0;
}

void ps_expire_check(PendingState *ps) {
    if (ps->status != PS_PENDING) return;
    if (now_ns() > ps->expiry_ns) {
        ps->status = PS_EXPIRED;
    }
}
