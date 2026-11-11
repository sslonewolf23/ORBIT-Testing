#include "ORBITTrustPersistence.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    uint64_t counter;
    uint8_t record[ORBIT_TRUST_STORE_RECORD_MAX];
    size_t length;
    uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES];
    bool has_record;
    bool fail_write;
} memory_store;

static unsigned checks=0U,failures=0U;
static void expect(const char *name,bool actual,bool wanted) {
    ++checks;
    if(actual!=wanted){fprintf(stderr,"FAIL %s actual=%d expected=%d\\n",name,actual,wanted);++failures;}
    else printf("PASS %s\\n",name);
}
static bool read_counter(void *ctx,const char *repo,uint64_t *counter) {
    (void)repo;memory_store *m=ctx;*counter=m->counter;return true;
}
static bool advance_counter(void *ctx,const char *repo,uint64_t expected,uint64_t next) {
    (void)repo;memory_store *m=ctx;
    if(m->counter!=expected||next!=expected+1U)return false;
    m->counter=next;return true;
}
static bool read_record(void *ctx,const char *repo,uint8_t *out,size_t cap,
                        size_t *length,uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]) {
    (void)repo;memory_store *m=ctx;
    if(!m->has_record||m->length>cap)return false;
    memcpy(out,m->record,m->length);*length=m->length;memcpy(mac,m->mac,sizeof(m->mac));return true;
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
    orbit_trust_store_backend b={m,read_counter,advance_counter,read_record,write_record,test_mac};return b;
}
int main(void) {
    const char *repo="orbit-official";
    const char *pin="0123456789ABCDEF0123456789ABCDEF01234567";
    memory_store storage;memset(&storage,0,sizeof(storage));
    orbit_trust_store_backend backend=backend_for(&storage);
    orbit_repository_trust_state state,loaded;
    expect("initialize-pin",orbit_repository_trust_init(&state,pin),true);
    expect("missing-record-distinguished",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_NOT_FOUND,true);
    expect("first-state-saved",orbit_repository_trust_store_save(
        &state,repo,&backend)==ORBIT_TRUST_STORE_OK,true);
    expect("counter-advanced-to-initial-revision",storage.counter==state.revision,true);
    expect("state-restored",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_OK,true);
    expect("restored-pin-matches",strcmp(loaded.current_fingerprint,pin)==0,true);
    expect("restored-revision-matches",loaded.revision==state.revision,true);

    orbit_repository_trust_state changed=loaded;
    changed.generation=1U;changed.revision++;
    expect("next-revision-saved",orbit_repository_trust_store_save(
        &changed,repo,&backend)==ORBIT_TRUST_STORE_OK,true);
    uint8_t newer_record[ORBIT_TRUST_STORE_RECORD_MAX],newer_mac[ORBIT_TRUST_STORE_MAC_BYTES];
    size_t newer_length=storage.length;
    memcpy(newer_record,storage.record,newer_length);memcpy(newer_mac,storage.mac,sizeof(newer_mac));
    expect("newer-state-loads",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_OK && loaded.revision==changed.revision,true);
    orbit_repository_trust_state same_revision_forgery=changed;
    same_revision_forgery.generation=7U;
    expect("same-revision-state-substitution-rejected",orbit_repository_trust_store_save(
        &same_revision_forgery,repo,&backend)==ORBIT_TRUST_STORE_ROLLBACK_DETECTED,true);
    expect("identical-save-is-idempotent",orbit_repository_trust_store_save(
        &changed,repo,&backend)==ORBIT_TRUST_STORE_OK,true);

    memcpy(storage.record,newer_record,newer_length);
    storage.record[20]^=0x01U;
    expect("record-tampering-rejected",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_AUTHENTICATION_FAILED,true);
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
    expect("counter-advanced-before-failed-write",storage.counter==next.revision,true);
    expect("crash-window-fails-closed",orbit_repository_trust_store_load(
        &loaded,repo,&backend)==ORBIT_TRUST_STORE_ROLLBACK_DETECTED,true);

    printf("decision=%s checks=%u failures=%u\\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
