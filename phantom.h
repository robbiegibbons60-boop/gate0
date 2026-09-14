#ifndef PHANTOM_H
#define PHANTOM_H
#include <stdint.h>
#include <netinet/in.h>
#include "attrib.h"
#define PHANTOM_COUNT 100
#define PHANTOM_BASE_PORT 5000
typedef enum {
    PHANTOM_IDLE = 0,
    PHANTOM_ACTIVE,
    PHANTOM_TRIPPED,
    PHANTOM_CAGED
} PhantomState;
typedef struct {
    uint8_t  device_id[4];
    uint16_t port;
    int      fd;
    PhantomState state;
    uint64_t trip_time_ns;
    uint32_t hit_count;
    uint8_t  decoy_serial[16];
    ThreatAttrib *captured_attrib;
} PhantomController;
void phantom_init(void);
int  phantom_bind_all(void);
PhantomController *phantom_get(int fd);
void phantom_trip(PhantomController *p,
                  struct sockaddr_in *attacker);
void phantom_reset(PhantomController *p);
void phantom_status(void);
#endif
