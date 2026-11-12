#include "ORBITPackageTransaction.h"
#include <stdio.h>
#include <string.h>

typedef struct {
    orbit_transaction_journal journal;
    bool present;
    unsigned stores;
    unsigned fail_store_number;
    unsigned clears;
    unsigned applies;
    unsigned rollbacks;
    unsigned fail_apply_number;
    unsigned fail_rollback_number;
    bool corrupt_load;
    bool resolve_mismatch;
} fixture;
static unsigned checks=0,failures=0;
static void expect(const char *name,bool condition) {
    ++checks;if(!condition){++failures;fprintf(stderr,"FAIL %s\n",name);}
}
static orbit_journal_status load_journal(void *ctx,orbit_transaction_journal *out) {
    fixture *f=ctx;
    if(!f->present)return ORBIT_JOURNAL_NOT_FOUND;
    *out=f->journal;
    if(f->corrupt_load)out->version=999U;
    return ORBIT_JOURNAL_OK;
}
static bool store_journal(void *ctx,const orbit_transaction_journal *j) {
    fixture *f=ctx;++f->stores;
    if(f->fail_store_number&&f->stores==f->fail_store_number)return false;
    if(f->present&&j->revision<=f->journal.revision)return false;
    f->journal=*j;f->present=true;return true;
}
static bool clear_journal(void *ctx,uint64_t revision) {
    fixture *f=ctx;
    if(!f->present||revision!=f->journal.revision)return false;
    f->present=false;++f->clears;return true;
}
static const orbit_package_record *resolve_package(void *ctx,const char *name,
    const char *version,const char *architecture) {
    fixture *f=ctx;
    static orbit_package_record records[2];
    static const char *names[2]={"alpha","beta"};
    for(size_t i=0;i<2U;++i)if(strcmp(name,names[i])==0) {
        memset(&records[i],0,sizeof(records[i]));
        snprintf(records[i].name,sizeof(records[i].name),"%s",name);
        snprintf(records[i].version,sizeof(records[i].version),"%s",version);
        snprintf(records[i].architecture,sizeof(records[i].architecture),"%s",architecture);
        if(f->resolve_mismatch)
            snprintf(records[i].version,sizeof(records[i].version),"9.9");
        return &records[i];
    }
    return NULL;
}
static bool apply_package(void *ctx,orbit_transaction_action action,
                          const orbit_package_record *p) {
    fixture *f=ctx;(void)action;(void)p;++f->applies;
    return !f->fail_apply_number||f->applies!=f->fail_apply_number;
}
static bool rollback_package(void *ctx,orbit_transaction_action action,
                             const orbit_package_record *p) {
    fixture *f=ctx;(void)action;(void)p;++f->rollbacks;
    return !f->fail_rollback_number||f->rollbacks!=f->fail_rollback_number;
}
static void make_package(orbit_package_record *p,const char *name) {
    memset(p,0,sizeof(*p));
    snprintf(p->name,sizeof(p->name),"%s",name);
    snprintf(p->version,sizeof(p->version),"1.0");
    snprintf(p->architecture,sizeof(p->architecture),"iphoneos-arm64");
}
static orbit_transaction_journal_backend journal_backend(fixture *f) {
    orbit_transaction_journal_backend b={f,load_journal,store_journal,clear_journal};return b;
}
static orbit_transaction_package_backend package_backend(fixture *f) {
    orbit_transaction_package_backend b={f,resolve_package,apply_package,rollback_package};return b;
}
int main(void) {
    orbit_package_record a,b;make_package(&a,"alpha");make_package(&b,"beta");
    const orbit_package_record *packages[]={&a,&b};
    orbit_transaction_action actions[]={ORBIT_TRANSACTION_INSTALL,ORBIT_TRANSACTION_REMOVE};
    uint8_t id[ORBIT_TRANSACTION_ID_BYTES]={1U};
    fixture f={0};orbit_transaction_journal_backend jb=journal_backend(&f);
    orbit_transaction_package_backend pb=package_backend(&f);
    orbit_transaction_code code=orbit_package_transaction_execute(id,packages,actions,2U,&jb,&pb);
    expect("successful-transaction",code==ORBIT_TRANSACTION_OK);
    expect("both-operations-applied",f.applies==2U);
    expect("committed-journal-cleared",!f.present&&f.clears==1U);
    expect("successful-transaction-no-rollback",f.rollbacks==0U);

    memset(&f,0,sizeof(f));jb=journal_backend(&f);pb=package_backend(&f);
    f.fail_apply_number=2U;
    code=orbit_package_transaction_execute(id,packages,actions,2U,&jb,&pb);
    expect("failed-apply-reported",code==ORBIT_TRANSACTION_APPLY_ERROR);
    expect("partial-transaction-rolled-back-reverse",f.rollbacks==2U);
    expect("failed-transaction-journal-cleared",!f.present);

    memset(&f,0,sizeof(f));jb=journal_backend(&f);pb=package_backend(&f);
    f.fail_store_number=3U;
    code=orbit_package_transaction_execute(id,packages,actions,2U,&jb,&pb);
    expect("journal-write-failure-requires-recovery",
        code==ORBIT_TRANSACTION_RECOVERY_REQUIRED);
    expect("in-flight-operation-left-journaled",f.present&&
        f.journal.operations[0].state==ORBIT_TRANSACTION_STEP_IN_FLIGHT);
    f.fail_store_number=0U;
    code=orbit_package_transaction_recover(&jb,&pb);
    expect("crash-recovery-rolls-back-inflight",code==ORBIT_TRANSACTION_OK);
    expect("crash-recovery-restores-operation",f.rollbacks==1U&&!f.present);

    memset(&f,0,sizeof(f));jb=journal_backend(&f);pb=package_backend(&f);
    f.fail_apply_number=2U;f.fail_rollback_number=1U;
    code=orbit_package_transaction_execute(id,packages,actions,2U,&jb,&pb);
    expect("rollback-failure-retains-recovery-journal",
        code==ORBIT_TRANSACTION_ROLLBACK_REQUIRED&&f.present);
    f.fail_apply_number=0U;f.fail_rollback_number=0U;
    code=orbit_package_transaction_recover(&jb,&pb);
    expect("retry-recovers-after-rollback-backend-failure",
        code==ORBIT_TRANSACTION_OK&&!f.present);

    memset(&f,0,sizeof(f));jb=journal_backend(&f);pb=package_backend(&f);
    f.resolve_mismatch=true;
    code=orbit_package_transaction_execute(id,packages,actions,2U,&jb,&pb);
    expect("resolver-identity-mismatch-rejected",
        code==ORBIT_TRANSACTION_RESOLUTION_ERROR);
    expect("resolver-mismatch-never-applies-or-rolls-back-wrong-package",
        f.applies==0U&&f.rollbacks==0U&&!f.present);

    memset(&f,0,sizeof(f));jb=journal_backend(&f);pb=package_backend(&f);
    code=orbit_package_transaction_recover(&jb,&pb);
    expect("no-journal-recovery-is-noop",code==ORBIT_TRANSACTION_OK);

    memset(&f,0,sizeof(f));jb=journal_backend(&f);pb=package_backend(&f);
    f.present=true;f.journal.version=999U;
    code=orbit_package_transaction_recover(&jb,&pb);
    expect("corrupt-journal-fails-closed",code==ORBIT_TRANSACTION_JOURNAL_ERROR);

    printf("decision=%s checks=%u failures=%u\n",
           failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
