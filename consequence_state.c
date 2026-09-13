#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "consequence_state.h"

int cs_init(ConsequenceState *cs){
    if(!cs)return CS_WAL_READ_ERR;
    memset(cs,0,sizeof(ConsequenceState));
    clock_gettime(CLOCK_REALTIME,&cs->last_update);
    return CS_AUTHORIZED;
}

int cs_update_from_wal(ConsequenceState *cs,const char *wal_path){
    if(!cs||!wal_path)return CS_WAL_READ_ERR;
    FILE *fp=fopen(wal_path,"r");
    if(!fp)return CS_WAL_READ_ERR;
    char line[512];
    while(fgets(line,sizeof(line),fp)){
        if(strncmp(line,"SEQ:",4)==0){
            cs->last_sequence=(uint64_t)strtoull(line+4,NULL,10);
            cs->commands_executed++;
        }
    }
    fclose(fp);
    clock_gettime(CLOCK_REALTIME,&cs->last_update);
    return CS_AUTHORIZED;
}

int cs_evaluate_token_request(const ConsequenceState *cs,const char *cap,const char *var,double val){
    if(!cs)return CS_WAL_READ_ERR;
    if(cs->authority_suspended)return CS_DENIED_SUSPEND;
    for(uint32_t i=0;i<cs->var_count;i++){
        if(strcmp(cs->vars[i].name,var)==0){
            if(val<cs->vars[i].min_safe||val>cs->vars[i].max_safe)return CS_DENIED_UNSAFE;
        }
    }
    return CS_AUTHORIZED;
}

void cs_suspend_authority(ConsequenceState *cs,const char *reason){
    if(!cs)return;
    cs->authority_suspended=1;
    strncpy(cs->suspension_reason,reason,127);
    cs->suspension_reason[127]=0;
}

void cs_print_state(const ConsequenceState *cs){
    if(!cs)return;
    puts(cs->suspension_reason);
}
