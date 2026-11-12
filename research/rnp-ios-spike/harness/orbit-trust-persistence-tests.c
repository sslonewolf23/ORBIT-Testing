#include "ORBITRepositoryVerifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    bool fail_write_on_call;
    unsigned writes_until_failure;
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
static uint8_t *read_fixture(const char *path,size_t *length) {
    FILE *f=fopen(path,"rb");if(!f)return NULL;
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return NULL;}
    long n=ftell(f);if(n<=0||n>4*1024*1024||fseek(f,0,SEEK_SET)!=0){fclose(f);return NULL;}
    uint8_t *data=malloc((size_t)n);if(!data){fclose(f);return NULL;}
    if(fread(data,1,(size_t)n,f)!=(size_t)n){free(data);fclose(f);return NULL;}
    fclose(f);*length=(size_t)n;return data;
}
static char *read_fixture_text(const char *path) {
    size_t n=0;uint8_t *data=read_fixture(path,&n);if(!data)return NULL;
    char *out=malloc(n+1U);if(!out){free(data);return NULL;}
    memcpy(out,data,n);out[n]='\0';free(data);return out;
}
static bool read_counter(void *ctx,const char *repo,uint64_t *counter) {
    (void)repo;memory_store *m=ctx;if(!m->locked)return false;*counter=m->counter;return true;
}
static bool advance_counter(void *ctx,const char *repo,uint64_t expected,uint64_t next) {
    (void)repo;memory_store *m=ctx;
    if(!m->locked)return false;
    if(m->fail_advance||m->counter!=expected||next!=expected+1U)return false;
    m->counter=next;return true;
}
static orbit_trust_store_read_result read_record(void *ctx,const char *repo,uint8_t *out,size_t cap,
                        size_t *length,uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]) {
    (void)repo;memory_store *m=ctx;
    if(!m->locked)return ORBIT_TRUST_BACKEND_ERROR;
    if(m->fail_read)return ORBIT_TRUST_BACKEND_ERROR;
    if(!m->has_record)return ORBIT_TRUST_BACKEND_NOT_FOUND;
    if(m->length>cap)return ORBIT_TRUST_BACKEND_ERROR;
    memcpy(out,m->record,m->length);*length=m->length;memcpy(mac,m->mac,sizeof(m->mac));
    return ORBIT_TRUST_BACKEND_OK;
}
static bool write_record(void *ctx,const char *repo,const uint8_t *record,size_t length,
                         const uint8_t mac[ORBIT_TRUST_STORE_MAC_BYTES]) {
    (void)repo;memory_store *m=ctx;
    if(!m->locked)return false;
    if(m->fail_write||(m->fail_write_on_call&&m->writes_until_failure==0U))return false;
    if(m->fail_write_on_call&&m->writes_until_failure>0U)--m->writes_until_failure;
    if(length>sizeof(m->record))return false;
    memcpy(m->record,record,length);m->length=length;memcpy(m->mac,mac,sizeof(m->mac));
    m->has_record=true;return true;
}
/* Deliberately non-cryptographic test MAC. Production adapters must use a
 * device-protected HMAC key and a hardware-backed monotonic counter. */
static bool test_mac(void *ctx,const char *repo,const uint8_t *data,size_t length,
                     uint8_t out[ORBIT_TRUST_STORE_MAC_BYTES]) {
    memory_store *m=ctx;if(!m->locked)return false;uint32_t h=2166136261U;
    for(const unsigned char *p=(const unsigned char *)repo;*p;++p){h^=*p;h*=16777619U;}
    for(size_t i=0;i<length;++i){h^=data[i];h*=16777619U;}
    for(size_t i=0;i<ORBIT_TRUST_STORE_MAC_BYTES;++i){h^=(uint32_t)i+0x9e3779b9U;h*=16777619U;out[i]=(uint8_t)(h>>(8U*(i%4U)));}
    return true;
}
static orbit_trust_store_backend backend_for(memory_store *m) {
    orbit_trust_store_backend b={m,begin_transaction,end_transaction,read_counter,advance_counter,read_record,write_record,test_mac};return b;
}
int main(int argc,char **argv) {
    if(argc!=13) {
        fprintf(stderr,"usage: %s trusted-fpr trusted-keyring normal-rotation.InRelease recovery-keyring recovery-fpr emergency.InRelease candidate-keyring candidate-fpr emergency-time valid-trusted.InRelease Packages orbit-fixture.deb\n",argv[0]);
        return 2;
    }
    size_t trusted_len=0,normal_rotation_len=0,recovery_len=0,emergency_len=0,candidate_len=0;
    char *trusted_fpr=read_fixture_text(argv[1]);
    uint8_t *trusted=read_fixture(argv[2],&trusted_len);
    uint8_t *normal_rotation=read_fixture(argv[3],&normal_rotation_len);
    uint8_t *recovery=read_fixture(argv[4],&recovery_len);
    char *recovery_fpr=read_fixture_text(argv[5]);
    uint8_t *emergency=read_fixture(argv[6],&emergency_len);
    uint8_t *candidate=read_fixture(argv[7],&candidate_len);
    char *candidate_fpr=read_fixture_text(argv[8]);
    char *time_text=read_fixture_text(argv[9]);
    size_t index_inrelease_len=0U,packages_len=0U,artifact_len=0U;
    uint8_t *index_inrelease=read_fixture(argv[10],&index_inrelease_len);
    uint8_t *packages=read_fixture(argv[11],&packages_len);\n    uint8_t *artifact=read_fixture(argv[12],&artifact_len);
    if(!trusted_fpr||!trusted||!normal_rotation||!recovery||!recovery_fpr||!emergency||!candidate||!candidate_fpr||!time_text||!index_inrelease||!packages||!artifact) {
        fprintf(stderr,"recovery fixture read failed\n");return 2;
    }
    trusted_fpr[strcspn(trusted_fpr,"\r\n")]='\0';
    recovery_fpr[strcspn(recovery_fpr,"\r\n")]='\0';
    candidate_fpr[strcspn(candidate_fpr,"\r\n")]='\0';
    time_text[strcspn(time_text,"\r\n")]='\0';
    char *time_end=NULL;
    uint64_t emergency_now=(uint64_t)strtoull(time_text,&time_end,10);
    if(!time_end||*time_end!='\0'||emergency_now==0U)return 2;

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
        loaded.current_fingerprint[0]=='\0',true);
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
        loaded.current_fingerprint[0]=='\0',true);
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
    orbit_repository_trust_state stale_lifecycle_state=lifecycle_state;
    expect("clock-floor-advances-from-stored-state",
        orbit_repository_trust_observe_time_and_store(&lifecycle_state,repo,60U,
            &lifecycle_backend,&lifecycle_store_result),true);
    expect("stale-caller-reloads-latest-trust-state",
        !orbit_repository_trust_observe_time_and_store(&stale_lifecycle_state,repo,55U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_ROLLBACK_DETECTED &&
        stale_lifecycle_state.last_observed_time==60U,true);
    expect("clock-floor-survives-reload",
        orbit_repository_trust_store_load(&loaded,repo,&lifecycle_backend)==ORBIT_TRUST_STORE_OK &&
        loaded.last_observed_time==60U,true);
    expect("clock-rollback-rejected",
        !orbit_repository_trust_observe_time_and_store(&lifecycle_state,repo,59U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_ROLLBACK_DETECTED,true);
    expect("clock-floor-rejects-older-key-check-time",
        !orbit_repository_trust_fingerprint_allowed(&lifecycle_state,pin,59U),true);
    expect("clock-floor-allows-exact-observed-time",
        orbit_repository_trust_fingerprint_allowed(&lifecycle_state,pin,60U),true);
    expect("transition-wrapper-rejects-backward-clock",
        !orbit_repository_trust_advance_and_store(&lifecycle_state,repo,59U,
            &lifecycle_backend,&lifecycle_store_result) &&
        lifecycle_store_result==ORBIT_TRUST_STORE_ROLLBACK_DETECTED,true);
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


    uint64_t normal_now=(uint64_t)time(NULL);
    memory_store normal_storage;memset(&normal_storage,0,sizeof(normal_storage));
    orbit_trust_store_backend normal_backend=backend_for(&normal_storage);
    orbit_repository_trust_state normal_state,normal_reloaded;
    expect("normal-rotation-bootstrap",orbit_repository_trust_load_or_initialize(
        &normal_state,repo,trusted_fpr,&normal_backend)==ORBIT_TRUST_STORE_OK,true);
    orbit_trust_code normal_decision=ORBIT_TRUST_INVALID_ARGUMENT;
    expect("normal-signed-rotation-and-persistence-commit",
        orbit_repository_trust_authorize_rotation_and_store(
            &normal_state,repo,repo,normal_rotation,normal_rotation_len,
            trusted,trusted_len,candidate,candidate_len,normal_now,
            &normal_backend,&normal_decision)==ORBIT_TRUST_STORE_OK &&
        normal_decision==ORBIT_TRUST_ACCEPTED &&
        strcmp(normal_state.current_fingerprint,trusted_fpr)==0 &&
        strcmp(normal_state.pending_fingerprint,candidate_fpr)==0 &&
        normal_state.pending_activation>normal_now,true);
    expect("normal-pending-rotation-survives-reload",
        orbit_repository_trust_store_load(&normal_reloaded,repo,&normal_backend)==ORBIT_TRUST_STORE_OK &&
        strcmp(normal_reloaded.pending_fingerprint,candidate_fpr)==0 &&
        normal_reloaded.last_observed_time==normal_now,true);
    expect("normal-new-key-not-accepted-before-activation",
        !orbit_repository_trust_fingerprint_allowed_and_store(
            &normal_state,repo,candidate_fpr,normal_now,&normal_backend,
            &lifecycle_store_result),true);
    expect("normal-old-key-remains-accepted-before-activation",
        orbit_repository_trust_fingerprint_allowed_and_store(
            &normal_state,repo,trusted_fpr,normal_now,&normal_backend,
            &lifecycle_store_result),true);

    uint64_t recovery_now=emergency_now+30U;
    memory_store recovery_storage;memset(&recovery_storage,0,sizeof(recovery_storage));
    orbit_trust_store_backend recovery_backend=backend_for(&recovery_storage);
    orbit_repository_trust_state persisted_recovery_state,reloaded_recovery_state;
    expect("persisted-recovery-bootstrap",orbit_repository_trust_load_or_initialize(
        &persisted_recovery_state,repo,trusted_fpr,&recovery_backend)==ORBIT_TRUST_STORE_OK,true);
    orbit_trust_code recovery_decision=ORBIT_TRUST_INVALID_ARGUMENT;
    expect("emergency-recovery-and-persistence-commit",
        orbit_repository_trust_authorize_recovery_rotation_and_store(
            &persisted_recovery_state,repo,repo,emergency,emergency_len,
            recovery,recovery_len,recovery_fpr,candidate,candidate_len,
            recovery_now,&recovery_backend,&recovery_decision)==ORBIT_TRUST_STORE_OK &&
        recovery_decision==ORBIT_TRUST_ACCEPTED &&
        strcmp(persisted_recovery_state.current_fingerprint,candidate_fpr)==0 &&
        persisted_recovery_state.generation==1U,true);
    expect("persisted-emergency-pin-survives-reload",
        orbit_repository_trust_store_load(&reloaded_recovery_state,repo,&recovery_backend)==ORBIT_TRUST_STORE_OK &&
        strcmp(reloaded_recovery_state.current_fingerprint,candidate_fpr)==0 &&
        reloaded_recovery_state.last_observed_time==recovery_now,true);
    expect("persisted-recovery-lookup-enforces-new-key",
        orbit_repository_trust_fingerprint_allowed_and_store(
            &persisted_recovery_state,repo,candidate_fpr,recovery_now+1U,
            &recovery_backend,&lifecycle_store_result),true);
    expect("persisted-recovery-rejects-compromised-old-key",
        !orbit_repository_trust_fingerprint_allowed_and_store(
            &persisted_recovery_state,repo,trusted_fpr,recovery_now+1U,
            &recovery_backend,&lifecycle_store_result),true);

    memory_store failed_recovery_storage;memset(&failed_recovery_storage,0,sizeof(failed_recovery_storage));
    orbit_trust_store_backend failed_recovery_backend=backend_for(&failed_recovery_storage);
    orbit_repository_trust_state failed_recovery_state;
    expect("failed-recovery-bootstrap",orbit_repository_trust_load_or_initialize(
        &failed_recovery_state,repo,trusted_fpr,&failed_recovery_backend)==ORBIT_TRUST_STORE_OK,true);
    failed_recovery_storage.fail_write_on_call=true;
    failed_recovery_storage.writes_until_failure=0U;
    orbit_trust_code failed_recovery_decision=ORBIT_TRUST_INVALID_ARGUMENT;
    expect("failed-emergency-state-commit-is-reported",
        orbit_repository_trust_authorize_recovery_rotation_and_store(
            &failed_recovery_state,repo,repo,emergency,emergency_len,
            recovery,recovery_len,recovery_fpr,candidate,candidate_len,
            recovery_now,&failed_recovery_backend,&failed_recovery_decision)
            ==ORBIT_TRUST_STORE_IO_ERROR &&
        failed_recovery_decision==ORBIT_TRUST_ACCEPTED,true);
    expect("failed-emergency-commit-reloads-last-durable-pin",
        strcmp(failed_recovery_state.current_fingerprint,trusted_fpr)==0 &&
        failed_recovery_state.pending_fingerprint[0]=='\0' &&
        failed_recovery_state.last_observed_time==0U,true);

    memory_store verify_storage;memset(&verify_storage,0,sizeof(verify_storage));
    orbit_trust_store_backend verify_backend=backend_for(&verify_storage);
    orbit_repository_trust_state verify_state;
    expect("repository-verification-bootstrap",
        orbit_repository_trust_load_or_initialize(&verify_state,repo,trusted_fpr,
            &verify_backend)==ORBIT_TRUST_STORE_OK,true);
    orbit_repository_verify_result verify_result;
    uint64_t verify_now=(uint64_t)time(NULL);
    orbit_repository_verify_code verify_code=orbit_repository_verify_packages_index(
        &verify_state,repo,trusted_fpr,trusted,trusted_len,
        index_inrelease,index_inrelease_len,"ORBIT Test","stable","fixture",
        "iphoneos-arm64","main","main/binary-iphoneos-arm64/Packages",
        packages,packages_len,verify_now,7ULL*24ULL*60ULL*60ULL,300U,
        &verify_backend,&verify_result);
    expect("complete-repository-verification-valid",
        verify_code==ORBIT_REPOSITORY_VERIFY_VALID &&
        verify_result.signature.code==ORBIT_RNP_VERIFY_VALID &&
        verify_result.verified_index_bytes==packages_len &&
        verify_result.package_count==1U &&
        verify_state.last_observed_time==verify_now,true);
    orbit_packages_index parsed_index;memset(&parsed_index,0,sizeof(parsed_index));
    bool parsed_ok=orbit_packages_index_parse(packages,packages_len,&parsed_index);
    expect("verified-Packages-index-parses-to-catalog",
        parsed_ok&&parsed_index.count==1U&&
        strcmp(parsed_index.packages[0].name,"orbit-fixture")==0&&
        strcmp(parsed_index.packages[0].architecture,"iphoneos-arm64")==0&&
        parsed_index.packages[0].size==(uint64_t)artifact_len&&
        strlen(parsed_index.packages[0].sha256)==64U&&
        strstr(parsed_index.packages[0].description,"disposable parser fixture")!=NULL,true);
    if(parsed_ok) {
        expect("downloaded-deb-size-and-SHA256-verified",
            orbit_package_verify_artifact(&parsed_index.packages[0],artifact,artifact_len),true);
        uint8_t *tampered_artifact=(uint8_t*)malloc(artifact_len);
        expect("artifact-tamper-fixture-allocation",tampered_artifact!=NULL,true);
        if(tampered_artifact!=NULL) {
            memcpy(tampered_artifact,artifact,artifact_len);
            tampered_artifact[0]^=0x01U;
            expect("tampered-deb-artifact-rejected",
                !orbit_package_verify_artifact(&parsed_index.packages[0],
                    tampered_artifact,artifact_len),true);
            free(tampered_artifact);
        }
        expect("truncated-deb-artifact-rejected",
            !orbit_package_verify_artifact(&parsed_index.packages[0],artifact,
                artifact_len-1U),true);
    }
    orbit_packages_index_destroy(&parsed_index);
    const char unsafe_package[]=
        "Package: orbit-bad\nVersion: 1.0\nArchitecture: iphoneos-arm64\n"
        "Filename: ../escape.deb\nSize: 1\n"
        "SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\n";
    expect("Packages-index-path-traversal-rejected",
        !orbit_packages_index_parse((const uint8_t*)unsafe_package,
            sizeof(unsafe_package)-1U,&parsed_index),true);
    const char incomplete_package[]=
        "Package: orbit-incomplete\nVersion: 1.0\nArchitecture: iphoneos-arm64\n"
        "Filename: pool/orbit.deb\nSize: 1\n\n";
    expect("Packages-index-missing-artifact-digest-rejected",
        !orbit_packages_index_parse((const uint8_t*)incomplete_package,
            sizeof(incomplete_package)-1U,&parsed_index),true);
    const char duplicate_field_package[]=
        "Package: orbit-duplicate\nPackage: orbit-second\nVersion: 1.0\n"
        "Architecture: iphoneos-arm64\nFilename: pool/orbit.deb\nSize: 1\n"
        "SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\n";
    expect("Packages-index-duplicate-field-rejected",
        !orbit_packages_index_parse((const uint8_t*)duplicate_field_package,
            sizeof(duplicate_field_package)-1U,&parsed_index),true);
    const char uppercase_package[]=
        "Package: ORBIT-BAD\nVersion: 1.0\nArchitecture: iphoneos-arm64\n"
        "Filename: pool/orbit.deb\nSize: 1\n"
        "SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\n";
    expect("Packages-index-invalid-package-name-rejected",
        !orbit_packages_index_parse((const uint8_t*)uppercase_package,
            sizeof(uppercase_package)-1U,&parsed_index),true);
    const char unknown_only_stanza[]="X-Unknown: value\n\n";
    expect("Packages-index-unknown-only-stanza-rejected",
        !orbit_packages_index_parse((const uint8_t*)unknown_only_stanza,
            sizeof(unknown_only_stanza)-1U,&parsed_index),true);

    uint8_t *tampered_packages=(uint8_t*)malloc(packages_len);
    expect("tampered-index-fixture-allocation",tampered_packages!=NULL,true);
    if(tampered_packages!=NULL) {
        memcpy(tampered_packages,packages,packages_len);
        tampered_packages[0]^=0x01U;
        verify_code=orbit_repository_verify_packages_index(
            &verify_state,repo,trusted_fpr,trusted,trusted_len,
            index_inrelease,index_inrelease_len,"ORBIT Test","stable","fixture",
            "iphoneos-arm64","main","main/binary-iphoneos-arm64/Packages",
            tampered_packages,packages_len,verify_now,7ULL*24ULL*60ULL*60ULL,300U,
            &verify_backend,&verify_result);
        expect("tampered-Packages-index-rejected",
            verify_code==ORBIT_REPOSITORY_VERIFY_INDEX_REJECTED,true);
        free(tampered_packages);
    }
    verify_code=orbit_repository_verify_packages_index(
        &verify_state,repo,trusted_fpr,trusted,trusted_len,
        index_inrelease,index_inrelease_len,"ORBIT Test","stable","wrong-codename",
        "iphoneos-arm64","main","main/binary-iphoneos-arm64/Packages",
        packages,packages_len,verify_now,7ULL*24ULL*60ULL*60ULL,300U,
        &verify_backend,&verify_result);
    expect("wrong-repository-codename-rejected",
        verify_code==ORBIT_REPOSITORY_VERIFY_REPOSITORY_POLICY_REJECTED,true);
    verify_code=orbit_repository_verify_packages_index(
        &verify_state,repo,trusted_fpr,trusted,trusted_len,
        index_inrelease,index_inrelease_len,"Wrong Origin","stable","fixture",
        "iphoneos-arm64","main","main/binary-iphoneos-arm64/Packages",
        packages,packages_len,verify_now,7ULL*24ULL*60ULL*60ULL,300U,
        &verify_backend,&verify_result);
    expect("wrong-signed-Release-origin-rejected",
        verify_code==ORBIT_REPOSITORY_VERIFY_REPOSITORY_POLICY_REJECTED,true);
    verify_code=orbit_repository_verify_packages_index(
        &verify_state,repo,trusted_fpr,trusted,trusted_len,
        index_inrelease,index_inrelease_len,"ORBIT Test","stable","fixture",
        "iphoneos-arm64","main","main/binary-iphoneos-arm64/Packages/../Packages",
        packages,packages_len,verify_now,7ULL*24ULL*60ULL*60ULL,300U,
        &verify_backend,&verify_result);
    expect("wrong-index-path-rejected",
        verify_code==ORBIT_REPOSITORY_VERIFY_INDEX_REJECTED,true);
    uint8_t *tampered_inrelease=(uint8_t*)malloc(index_inrelease_len);
    expect("tampered-InRelease-fixture-allocation",tampered_inrelease!=NULL,true);
    if(tampered_inrelease!=NULL) {
        memcpy(tampered_inrelease,index_inrelease,index_inrelease_len);
        tampered_inrelease[index_inrelease_len/2U]^=0x01U;
        verify_code=orbit_repository_verify_packages_index(
            &verify_state,repo,trusted_fpr,trusted,trusted_len,
            tampered_inrelease,index_inrelease_len,"ORBIT Test","stable","fixture",
            "iphoneos-arm64","main","main/binary-iphoneos-arm64/Packages",
            packages,packages_len,verify_now,7ULL*24ULL*60ULL*60ULL,300U,
            &verify_backend,&verify_result);
        expect("tampered-InRelease-signature-rejected",
            verify_code==ORBIT_REPOSITORY_VERIFY_SIGNATURE_REJECTED,true);
        free(tampered_inrelease);
    }
    verify_code=orbit_repository_verify_packages_index(
        &verify_state,repo,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        trusted,trusted_len,index_inrelease,index_inrelease_len,
        "ORBIT Test","stable","fixture","iphoneos-arm64","main",
        "main/binary-iphoneos-arm64/Packages",packages,packages_len,
        verify_now,7ULL*24ULL*60ULL*60ULL,300U,&verify_backend,&verify_result);
    expect("untrusted-primary-fingerprint-rejected",
        verify_code==ORBIT_REPOSITORY_VERIFY_SIGNER_NOT_TRUSTED,true);
    verify_code=orbit_repository_verify_packages_index(
        &verify_state,repo,trusted_fpr,trusted,trusted_len,
        index_inrelease,index_inrelease_len,"ORBIT Test","stable","fixture",
        "iphoneos-arm64","main","main/binary-iphoneos-arm64/Packages",
        packages,packages_len,verify_now+8ULL*24ULL*60ULL*60ULL,
        7ULL*24ULL*60ULL*60ULL,300U,&verify_backend,&verify_result);
    expect("expired-Release-valid-until-rejected",
        verify_code==ORBIT_REPOSITORY_VERIFY_FRESHNESS_REJECTED,true);
    free(trusted_fpr);free(recovery);free(recovery_fpr);free(emergency);
    free(candidate);free(candidate_fpr);free(time_text);free(index_inrelease);free(packages);free(artifact);
    printf("decision=%s checks=%u failures=%u\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
