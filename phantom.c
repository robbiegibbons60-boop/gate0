#include "phantom.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sodium.h>

static PhantomController farm[PHANTOM_COUNT];

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL
           + ts.tv_nsec;
}

void phantom_init(void) {
    for (int i = 0; i < PHANTOM_COUNT; i++) {
        PhantomController *p = &farm[i];
        memset(p, 0, sizeof(*p));
        p->port = PHANTOM_BASE_PORT + i;
        p->fd = -1;
        p->state = PHANTOM_IDLE;
        p->device_id[0] = 0xDE;
        p->device_id[1] = 0xC0;
        p->device_id[2] = (uint8_t)(i >> 8);
        p->device_id[3] = (uint8_t)(i & 0xFF);
        randombytes_buf(p->decoy_serial,
                        sizeof(p->decoy_serial));
    }
}

int phantom_bind_all(void) {
    int bound = 0;
    for (int i = 0; i < PHANTOM_COUNT; i++) {
        PhantomController *p = &farm[i];
        p->fd = socket(AF_INET, SOCK_STREAM, 0);
        if (p->fd < 0) continue;
        int opt = 1;
        setsockopt(p->fd, SOL_SOCKET,
                   SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(p->port);
        if (bind(p->fd, (struct sockaddr*)&addr,
                 sizeof(addr)) < 0) {
            close(p->fd);
            p->fd = -1;
            continue;
        }
        listen(p->fd, 4);
        p->state = PHANTOM_ACTIVE;
        bound++;
    }
    return bound;
}

PhantomController *phantom_get(int fd) {
    for (int i = 0; i < PHANTOM_COUNT; i++)
        if (farm[i].fd == fd) return &farm[i];
    return NULL;
}

void phantom_trip(PhantomController *p,
                  struct sockaddr_in *attacker) {
    if (!p) return;
    p->state = PHANTOM_TRIPPED;
    p->hit_count++;
    p->trip_time_ns = now_ns();
    printf("[PHANTOM] port=%u tripped hits=%u\n",
           p->port, p->hit_count);
}

void phantom_reset(PhantomController *p) {
    if (!p) return;
    p->state = PHANTOM_ACTIVE;p->captured_attrib = NULL;
    randombytes_buf(p->decoy_serial,
                    sizeof(p->decoy_serial));
}

void phantom_status(void) {
    int active = 0, tripped = 0, caged = 0;
    for (int i = 0; i < PHANTOM_COUNT; i++) {
        switch(farm[i].state) {
            case PHANTOM_ACTIVE:  active++;  break;
            case PHANTOM_TRIPPED: tripped++; break;
            case PHANTOM_CAGED:   caged++;   break;
            default: break;
        }
    }
    printf("[PHANTOM] active=%d tripped=%d caged=%d\n",
           active, tripped, caged);
}
