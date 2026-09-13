#ifndef CONSEQUENCE_STATE_H
#define CONSEQUENCE_STATE_H
#include <stdint.h>
#include <time.h>
#define CS_MAX_PROCESS_VARS 32
#define CS_VAR_NAME_LEN 32
typedef struct {
    char name[32];
    double value;
    double min_safe;
    double max_safe;
    uint8_t in_violation;
} ProcessVar;
typedef struct {
    uint64_t last_sequence;
    uint64_t commands_executed;
    struct timespec last_update;
    uint32_t var_count;
    ProcessVar vars[32];
    uint8_t authority_suspended;
    char suspension_reason[128];
} ConsequenceState;
#define CS_AUTHORIZED 0
#define CS_DENIED_UNSAFE 1
#define CS_DENIED_SUSPEND 2
#define CS_WAL_READ_ERR 3
int cs_init(ConsequenceState *cs);
int cs_update_from_wal(ConsequenceState *cs, const char *wal_path);
int cs_evaluate_token_request(const ConsequenceState *cs, const char *cap, const char *var, double val);
void cs_suspend_authority(ConsequenceState *cs, const char *reason);
void cs_print_state(const ConsequenceState *cs);
#endif
