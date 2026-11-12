#include "ORBITPackageTransaction.h"

#include <stdlib.h>
#include <string.h>

static bool bounded_string(const char *value,size_t capacity) {
    return value&&value[0]!='\\0'&&memchr(value,'\\0',capacity)!=NULL;
}
static bool backend_valid(const orbit_transaction_journal_backend *j,
                          const orbit_transaction_package_backend *p) {
    return j&&j->load&&j->store_atomic&&j->clear_atomic&&
           p&&p->resolve&&p->apply&&p->rollback;
}
static bool journal_valid(const orbit_transaction_journal *j) {
    if(!j||j->version!=ORBIT_TRANSACTION_JOURNAL_VERSION||
       j->phase<ORBIT_TRANSACTION_PHASE_APPLYING||
       j->phase>ORBIT_TRANSACTION_PHASE_COMMITTED||
       j->operation_count==0U||
       j->operation_count>ORBIT_TRANSACTION_MAX_OPERATIONS||
       j->revision==0U||j->rollback_cursor>j->operation_count)return false;
    for(uint32_t i=0;i<j->operation_count;++i) {
        const uint32_t state=j->operations[i].state;
        if((j->operations[i].action!=ORBIT_TRANSACTION_INSTALL&&
            j->operations[i].action!=ORBIT_TRANSACTION_REMOVE)||
           state>ORBIT_TRANSACTION_STEP_ROLLED_BACK||
           !bounded_string(j->operations[i].name,sizeof(j->operations[i].name))||
           !bounded_string(j->operations[i].version_string,sizeof(j->operations[i].version_string))||
           !bounded_string(j->operations[i].architecture,sizeof(j->operations[i].architecture)))return false;
        if(j->phase==ORBIT_TRANSACTION_PHASE_APPLYING&&
           state==ORBIT_TRANSACTION_STEP_ROLLED_BACK)return false;
        if(j->phase==ORBIT_TRANSACTION_PHASE_COMMITTED&&
           state!=ORBIT_TRANSACTION_STEP_COMPLETE)return false;
        for(uint32_t k=0;k<i;++k)
            if(strcmp(j->operations[i].name,j->operations[k].name)==0&&
               strcmp(j->operations[i].version_string,j->operations[k].version_string)==0&&
               strcmp(j->operations[i].architecture,j->operations[k].architecture)==0)
                return false;
    }
    if(j->phase==ORBIT_TRANSACTION_PHASE_APPLYING&&j->rollback_cursor!=0U)return false;
    if(j->phase==ORBIT_TRANSACTION_PHASE_COMMITTED&&j->rollback_cursor!=0U)return false;
    return true;
}
static bool persist(orbit_transaction_journal *j,
                    const orbit_transaction_journal_backend *backend) {
    if(j->revision==UINT64_MAX)return false;
    ++j->revision;
    return backend->store_atomic(backend->context,j);
}
static bool rollback_journal(orbit_transaction_journal *j,
    const orbit_transaction_journal_backend *jb,
    const orbit_transaction_package_backend *pb) {
    j->phase=ORBIT_TRANSACTION_PHASE_ROLLING_BACK;
    if(!persist(j,jb))return false;
    for(uint32_t cursor=j->operation_count;cursor>0U;--cursor) {
        uint32_t i=cursor-1U;
        uint32_t state=j->operations[i].state;
        if(state==ORBIT_TRANSACTION_STEP_PENDING||
           state==ORBIT_TRANSACTION_STEP_ROLLED_BACK)continue;
        const orbit_package_record *p=pb->resolve(pb->context,
            j->operations[i].name,j->operations[i].version_string,
            j->operations[i].architecture);
        if(!p)return false;
        orbit_transaction_action action=(orbit_transaction_action)j->operations[i].action;
        if(!pb->rollback(pb->context,action,p))return false;
        j->operations[i].state=ORBIT_TRANSACTION_STEP_ROLLED_BACK;
        j->rollback_cursor=i;
        if(!persist(j,jb))return false;
    }
    return true;
}
static orbit_transaction_code finish_rollback(
    orbit_transaction_journal *j,
    const orbit_transaction_journal_backend *jb,
    const orbit_transaction_package_backend *pb,
    orbit_transaction_code original) {
    bool rolled_back=rollback_journal(j,jb,pb);
    bool cleared=rolled_back&&jb->clear_atomic(jb->context,j->revision);
    free(j);
    if(!cleared)return ORBIT_TRANSACTION_ROLLBACK_REQUIRED;
    return original;
}
orbit_transaction_code orbit_package_transaction_execute(
    const uint8_t transaction_id[ORBIT_TRANSACTION_ID_BYTES],
    const orbit_package_record *const *packages,
    const orbit_transaction_action *actions,size_t operation_count,
    const orbit_transaction_journal_backend *jb,
    const orbit_transaction_package_backend *pb) {
    if(!transaction_id||!packages||!actions||operation_count==0U||
       operation_count>ORBIT_TRANSACTION_MAX_OPERATIONS||!backend_valid(jb,pb))
        return ORBIT_TRANSACTION_INVALID_ARGUMENT;
    orbit_transaction_journal existing;
    memset(&existing,0,sizeof(existing));
    orbit_journal_status status=jb->load(jb->context,&existing);
    if(status==ORBIT_JOURNAL_OK)return ORBIT_TRANSACTION_BUSY;
    if(status!=ORBIT_JOURNAL_NOT_FOUND)return ORBIT_TRANSACTION_JOURNAL_ERROR;

    orbit_transaction_journal *j=calloc(1U,sizeof(*j));
    if(!j)return ORBIT_TRANSACTION_LIMIT;
    j->version=ORBIT_TRANSACTION_JOURNAL_VERSION;
    j->phase=ORBIT_TRANSACTION_PHASE_APPLYING;
    j->revision=1U;
    memcpy(j->transaction_id,transaction_id,ORBIT_TRANSACTION_ID_BYTES);
    j->operation_count=(uint32_t)operation_count;
    for(size_t i=0;i<operation_count;++i) {
        const orbit_package_record *p=packages[i];
        if(!p||(actions[i]!=ORBIT_TRANSACTION_INSTALL&&
                actions[i]!=ORBIT_TRANSACTION_REMOVE)||
           !bounded_string(p->name,sizeof(p->name))||
           !bounded_string(p->version,sizeof(p->version))||
           !bounded_string(p->architecture,sizeof(p->architecture))) {
            free(j);return ORBIT_TRANSACTION_INVALID_ARGUMENT;
        }
        j->operations[i].action=(uint32_t)actions[i];
        j->operations[i].state=ORBIT_TRANSACTION_STEP_PENDING;
        memcpy(j->operations[i].name,p->name,sizeof(j->operations[i].name));
        memcpy(j->operations[i].version_string,p->version,sizeof(j->operations[i].version_string));
        memcpy(j->operations[i].architecture,p->architecture,sizeof(j->operations[i].architecture));
    }
    if(!journal_valid(j)||!jb->store_atomic(jb->context,j)) {
        free(j);return ORBIT_TRANSACTION_JOURNAL_ERROR;
    }
    for(uint32_t i=0;i<j->operation_count;++i) {
        const orbit_package_record *p=pb->resolve(pb->context,
            j->operations[i].name,j->operations[i].version_string,
            j->operations[i].architecture);
        if(!p)return finish_rollback(j,jb,pb,ORBIT_TRANSACTION_RESOLUTION_ERROR);
        j->operations[i].state=ORBIT_TRANSACTION_STEP_IN_FLIGHT;
        if(!persist(j,jb)) {free(j);return ORBIT_TRANSACTION_RECOVERY_REQUIRED;}
        if(!pb->apply(pb->context,(orbit_transaction_action)j->operations[i].action,p))
            return finish_rollback(j,jb,pb,ORBIT_TRANSACTION_APPLY_ERROR);
        j->operations[i].state=ORBIT_TRANSACTION_STEP_COMPLETE;
        if(!persist(j,jb)){free(j);return ORBIT_TRANSACTION_RECOVERY_REQUIRED;}
    }
    j->phase=ORBIT_TRANSACTION_PHASE_COMMITTED;
    if(!persist(j,jb)){free(j);return ORBIT_TRANSACTION_RECOVERY_REQUIRED;}
    bool cleared=jb->clear_atomic(jb->context,j->revision);
    free(j);
    return cleared?ORBIT_TRANSACTION_OK:ORBIT_TRANSACTION_RECOVERY_REQUIRED;
}
orbit_transaction_code orbit_package_transaction_recover(
    const orbit_transaction_journal_backend *jb,
    const orbit_transaction_package_backend *pb) {
    if(!backend_valid(jb,pb))return ORBIT_TRANSACTION_INVALID_ARGUMENT;
    orbit_transaction_journal *j=calloc(1U,sizeof(*j));
    if(!j)return ORBIT_TRANSACTION_LIMIT;
    orbit_journal_status status=jb->load(jb->context,j);
    if(status==ORBIT_JOURNAL_NOT_FOUND){free(j);return ORBIT_TRANSACTION_OK;}
    if(status!=ORBIT_JOURNAL_OK||!journal_valid(j)) {
        free(j);return ORBIT_TRANSACTION_JOURNAL_ERROR;
    }
    if(j->phase==ORBIT_TRANSACTION_PHASE_COMMITTED) {
        bool ok=jb->clear_atomic(jb->context,j->revision);
        free(j);return ok?ORBIT_TRANSACTION_OK:ORBIT_TRANSACTION_RECOVERY_REQUIRED;
    }
    bool ok=rollback_journal(j,jb,pb);
    if(ok)ok=jb->clear_atomic(jb->context,j->revision);
    free(j);
    return ok?ORBIT_TRANSACTION_OK:ORBIT_TRANSACTION_RECOVERY_REQUIRED;
}
