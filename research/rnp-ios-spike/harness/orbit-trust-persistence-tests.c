#include "ORBITTrustPersistence.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    uint64_t counter;
    uint8_t record[ORBIT_TRUST_STORE_RECORD_MAX];
    size_t length;
    uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES];
    bool has_record;
    bool locked;
    bool fail_read;
    bool fail_write;
    bool fail_advance;
} memory_store;

static unsigned checks=0U,failures=0U;
static void expect(const char *name,bool actual,bool wanted) {
    ++checks;
    if(actual!=wanted){fprintf(stderr,"FAIL %s actual=%d expected=%d\n",name,actual,wanted);++failures;}
    else printf("PASS %s\n",name);
}
static bool begin_transaction(void *ctx,const char *repo) {
    (void)repo;memory_store *m=ctx;if(m->locked)return false;m->locked=true;return true;
}
static void end_transaction(void *ctx,const char *repo) {
    (void)repo;memory_store *m=ctx;m->locked=false;
}
static bool read_counter(void *ctx,const char *repo,uint64_t *counter) {
    (void)repo;memory_store *m=ctx;*counter=m->counter;return true;
}
static bool advance_counter(void *ctx,const char *repo,uint64_t expected,uint64_t next) {
    (void)repo;memory_store *m=ctx;
    if(m->fail_advance||m->counter!=expected||next!=expected+1U)return false;
    m->counter=next;return true;
}
static orbit_trust_store_read_result read_record(void *ctx,const char *repo,uint8_t *out,size_t cap,
                        size_t *length,uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]) {
    (void)repo;memory_store *m=ctx;
    if(m->fail_read)return ORBIT_TRUST_BACKEND_ERROR;
    if(!m->has_record)return ORBIT_TRUST_BACKEND_NOT_FOUND;
    if(m->length>cap)return ORBIT_TRUST_BACKEND_ERROR;
    memcpy(out,m->record,m->length);*length=m->length;memcpy(mac,m->mac,sizeof(m->mac));
    return ORBIT_TRUST_BACKEND_OK;
}
static bool write_record(void *ctx,const char *repo,const uint8_t *record,size_t length,
                         const uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]) {
    (void)repo;memory_store *m=ctx;if(m->fail_write)return false;
    if(length>sizeof(m->record))return false;
    memcpy(m->record,record,length);m->length=length;memcpy(m->mac,mac,sizeof(m->mac));
    m->has_record=true;return true;
}
/* Deliberately non-cryptographic test MAC. Production adapters must use a
 * device-protected HMAC key and a hardware-backed monotonic counter. */
static bool test_mac(void *ctx,const char *repo,const uint8_t *data,size_t length,
                     uint8_t out[ORBIT_TRUST_STORE_MAC_BYTES]) {
    (void)ctx;uint32_t h=2166136261U;
    for(const unsigned char *p=(const unsigned char *)repo;*p;++p){h^=*p;h*=16777619U;}
    for(size_t i=0;i<length;++i){h^=data[i];h*=16777619U;}
    for(size_t i=0;i<ORBIT_TRUST_STORE_MAC_BYTES;++i){h^=(uint32_t)i+0x9e3779b9U;h*=16777619U;out[i]=(uint8_t)(h>>(8U*(i%4U)));}
    return true;
}
static orbit_trust_store_backend backend_for(memory_store *m) {
    orbit_trust_store_backend b={m,begin_transaction,end_transaction,read_counter,advance_counter,read_record,write_record,test_mac};return b;
}
int main(void) {
    const char *repo="orbit-official";
    const char *pin="0123456789ABCDEF0123456789ABCDEF01234567";
    memory_store storage;memset(&storage,0,sizeof(storage));
    orbit_trust_store_backend backend=backend_for(&storage);
    orbit_repository_trust_state state,loaded;
    storage.fail_read=true;
    expect("storage-read-error-is-not-missing-record",orbit_repository_trust_load_or_initialize(
        &state,repo,pin,&backend)==ORBIT_TRUST_STORE_IO_ERROR,true);
    storage.fail_read=false;
    expect("missing-record-bootstraps-and-persists",orbit_repository_trust_load_or_initialize(
        &state,repo,pin,&backend)==ORBIT_TRUST_STORE_OK,true);
    expect("counter-advanced-to-initial-revision",storage.counter==state.revision,true);
    expect("store-transaction-lock-released",!storage.locked,true);
    expect("state-restored",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_OK,true);
    expect("restored-pin-matches",strcmp(loaded.current_fingerprint,pin)==0,true);
    expect("restored-revision-matches",loaded.revision==state.revision,true);
    storage.locked=true;
    expect("store-lock-contention-fails-closed",
        orbit_repository_trust_store_load(&loaded,repo,&backend)==ORBIT_TRUST_STORE_IO_ERROR &&
        loaded.current_fingerprint[0]=='\\0',true);
    storage.locked=false;

    orbit_repository_trust_state changed=loaded;
    changed.revision++;
    expect("next-revision-saved",orbit_repository_trust_store_save(
        &changed,repo,&backend)==ORBIT_TRUST_STORE_OK,true);
    uint8_t newer_record[ORBIT_TRUST_STORE_RECORD_MAX],newer_mac[ORBIT_TRUST_STORE_MAC_BYTES];
    size_t newer_length=storage.length;
    memcpy(newer_record,storage.record,newer_length);memcpy(newer_mac,storage.mac,sizeof(newer_mac));
    expect("newer-state-loads",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_OK && loaded.revision==changed.revision,true);
    orbit_repository_trust_state same_revision_forgery=changed;
    same_revision_forgery.current_fingerprint[0]='F';
    expect("same-revision-state-substitution-rejected",orbit_repository_trust_store_save(
        &same_revision_forgery,repo,&backend)==ORBIT_TRUST_STORE_ROLLBACK_DETECTED,true);
    expect("identical-save-is-idempotent",orbit_repository_trust_store_save(
        &changed,repo,&backend)==ORBIT_TRUST_STORE_OK,true);

    memcpy(storage.record,newer_record,newer_length);
    storage.record[20]^=0x01U;
    expect("record-tampering-rejected",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_AUTHENTICATION_FAILED,true);
    expect("failed-load-invalidates-old-memory-state",
        loaded.current_fingerprint[0]=='\\0',true);
    expect("corruption-never-reinitializes-from-bootstrap-pin",
        orbit_repository_trust_load_or_initialize(&loaded,repo,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",&backend)
            ==ORBIT_TRUST_STORE_AUTHENTICATION_FAILED,true);
    memcpy(storage.record,newer_record,newer_length);memcpy(storage.mac,newer_mac,sizeof(newer_mac));

    orbit_repository_trust_state rollback=state;
    expect("older-revision-cannot-overwrite-counter",orbit_repository_trust_store_save(
        &rollback,repo,&backend)==ORBIT_TRUST_STORE_ROLLBACK_DETECTED,true);
    uint8_t old_record[ORBIT_TRUST_STORE_RECORD_MAX],old_mac[ORBIT_TRUST_STORE_MAC_BYTES];
    memcpy(old_record,storage.record,newer_length);memcpy(old_mac,storage.mac,sizeof(old_mac));
    expect("repository-binding-rejected",orbit_repository_trust_store_load(
        &loaded,"other-repository",&backend)==ORBIT_TRUST_STORE_AUTHENTICATION_FAILED,true);

    storage.record[20]=old_record[20];
    storage.record[20]^=0x01U;
    expect("invalid-mac-never-loads",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_AUTHENTICATION_FAILED,true);
    memcpy(storage.record,old_record,newer_length);memcpy(storage.mac,old_mac,sizeof(old_mac));

    orbit_repository_trust_state next=changed;next.revision++;
    storage.fail_write=true;
    expect("failed-atomic-write-reported",orbit_repository_trust_store_save(
        &next,repo,&backend)==ORBIT_TRUST_STORE_IO_ERROR,true);
    storage.fail_write=false;
    expect("failed-write-keeps-counter-unchanged",storage.counter==changed.revision,true);
    expect("old-record-remains-loadable-after-failed-write",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_OK && loaded.revision==changed.revision,true);
    storage.fail_advance=true;
    expect("counter-advance-interruption-reported",orbit_repository_trust_store_save(
        &next,repo,&backend)==ORBIT_TRUST_STORE_IO_ERROR,true);
    storage.fail_advance=false;
    expect("staged-record-does-not-prematurely-advance-counter",
        storage.counter==changed.revision,true);
    expect("load-recovers-authenticated-staged-record",
        orbit_repository_trust_store_load(&loaded,repo,&backend)==ORBIT_TRUST_STORE_OK &&
        loaded.revision==next.revision,true);
    expect("recovery-completes-monotonic-counter",storage.counter==next.revision,true);
    memory_store lifecycle_storage;memset(&lifecycle_storage,0,sizeof(lifecycle_storage));
    orbit_trust_store_backend lifecycle_backend=backend_for(&lifecycle_storage);
    orbit_repository_trust_state lifecycle_state;
    orbit_trust_store_code lifecycle_store_result=ORBIT_TRUST_STORE_OK;
    expect("lifecycle-bootstrap",orbit_repository_trust_load_or_initialize(
        &lifecycle_state,repo,pin,&lifecycle_backend)==ORBIT_TRUST_STORE_OK,true);
    expect("clock-floor-persisted-before-signer-authorization",
        orbit_repository_trust_fingerprint_allowed_and_store(&lifecycle_state,repo,pin,50U,
            &lifecycle_backend,&lifecycle_store_result),true);
    expect("clock-floor-survives-reload",
        orbit_repository_trust_store_load(&loaded,repo,&lifecycle_backend)==ORBIT_TRUST_STORE_OK &&
        loaded.last_observed_time==50U,true);
    expect("clock-rollback-rejected",
        !orbit_repository_trust_observe_time_and_store(&lifecycle_state,repo,49U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_ROLLBACK_DETECTED,true);
    expect("clock-floor-rejects-older-key-check-time",
        !orbit_repository_trust_fingerprint_allowed(&lifecycle_state,pin,49U),true);
    expect("clock-floor-allows-exact-observed-time",
        orbit_repository_trust_fingerprint_allowed(&lifecycle_state,pin,50U),true);
    strcpy(lifecycle_state.pending_fingerprint,
           "ABCDEF0123456789ABCDEF0123456789ABCDEF01");
    lifecycle_state.pending_activation=100U;
    lifecycle_state.previous_valid_until=200U;
    ++lifecycle_state.revision;
    expect("pending-state-committed",orbit_repository_trust_store_save(
        &lifecycle_state,repo,&lifecycle_backend)==ORBIT_TRUST_STORE_OK,true);
    orbit_repository_trust_state before_advance=lifecycle_state;
    lifecycle_storage.fail_write=true;
    expect("failed-activation-commit-rolls-back-memory",
        !orbit_repository_trust_advance_and_store(&lifecycle_state,repo,100U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_IO_ERROR &&
        lifecycle_state.revision==before_advance.revision &&
        strcmp(lifecycle_state.current_fingerprint,before_advance.current_fingerprint)==0 &&
        strcmp(lifecycle_state.pending_fingerprint,before_advance.pending_fingerprint)==0,true);
    lifecycle_storage.fail_write=false;
    expect("activation-commits-atomically",
        orbit_repository_trust_advance_and_store(&lifecycle_state,repo,100U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_OK &&
        lifecycle_state.generation==1U &&
        lifecycle_state.last_observed_time==100U,true);
    expect("grace-prune-waits-through-inclusive-deadline",
        !orbit_repository_trust_prune_previous_and_store(&lifecycle_state,repo,200U,
            &lifecycle_backend,&lifecycle_store_result),true);
    lifecycle_storage.fail_write=true;
    uint64_t before_prune=lifecycle_state.revision;
    expect("failed-prune-commit-rolls-back-memory",
        !orbit_repository_trust_prune_previous_and_store(&lifecycle_state,repo,201U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_IO_ERROR &&
        lifecycle_state.revision==before_prune &&
        lifecycle_state.previous_fingerprint[0]!='\0',true);
    lifecycle_storage.fail_write=false;
    expect("expired-key-prune-commits",
        orbit_repository_trust_prune_previous_and_store(&lifecycle_state,repo,201U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_OK &&
        lifecycle_state.previous_fingerprint[0]=='\0' &&
        lifecycle_state.last_observed_time==201U,true);
    expect("pruned-state-rejects-clock-rollback",
        !orbit_repository_trust_fingerprint_allowed(&lifecycle_state,pin,199U),true);


    printf("decision=%s checks=%u failures=%u\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
