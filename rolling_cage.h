#ifndef ROLLING_CAGE_H
#define ROLLING_CAGE_H
#include <stdint.h>
#include <netinet/in.h>
#include "attrib.h"
#define CAGE_MAX 64
#define CAGE_ROUNDS_MAX 255
typedef enum {
    CAGE_EMPTY = 0,
    CAGE_ACTIVE,
    CAGE_ESCAPED,
    CAGE_RECAPTURED
} CageState;
typedef struct {
    uint64_t cage_id;
    uint8_t  round;
    CageState state;
    struct sockaddr_in attacker;
    uint64_t entered_ns;
    uint64_t last_action_ns;
    uint32_t escape_attempts;
    uint8_t  session_key[32];
    uint8_t  tripwire_armed;
    ThreatAttrib *attrib;
} CageSession;
void cage_init(void);
CageSession *cage_open(struct sockaddr_in *addr,
                       ThreatAttrib *a);
void cage_roll(CageSession *c);
int  cage_detect_escape(CageSession *c,
                        uint8_t *cmd, uint32_t len);
void cage_recapture(CageSession *c);
void cage_close(CageSession *c);
CageSession *cage_lookup(uint64_t cage_id);
#endif
