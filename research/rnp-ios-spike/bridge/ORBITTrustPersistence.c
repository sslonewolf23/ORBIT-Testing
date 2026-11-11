#include "ORBITTrustPersistence.h"

#include <ctype.h>
#include <string.h>

#define STORE_MAGIC "ORBTTRST"
#define STORE_MAGIC_BYTES 8U
#define STORE_REPOSITORY_BYTES ORBIT_TRUST_REPOSITORY_CAPACITY
#define STORE_FINGERPRINT_BYTES ORBIT_TRUST_FINGERPRINT_CAPACITY
#define STORE_FIXED_BYTES (STORE_MAGIC_BYTES + 4U + 8U + 4U + 8U + 8U + 8U + \
                           STORE_REPOSITORY_BYTES + 3U * STORE_FINGERPRINT_BYTES)

static void put_u32(uint8_t *out, uint32_t value) {
    out[0]=(uint8_t)(value>>24); out[1]=(uint8_t)(value>>16);
    out[2]=(uint8_t)(value>>8); out[3]=(uint8_t)value;
}
static void put_u64(uint8_t *out, uint64_t value) {
    for (unsigned i=0;i<8U;++i) out[i]=(uint8_t)(value>>(56U-8U*i));
}
static uint32_t get_u32(const uint8_t *in) {
    return ((uint32_t)in[0]<<24)|((uint32_t)in[1]<<16)|
           ((uint32_t)in[2]<<8)|(uint32_t)in[3];
}
static uint64_t get_u64(const uint8_t *in) {
    uint64_t value=0; for(unsigned i=0;i<8U;++i)value=(value<<8)|in[i]; return value;
}
static size_t bounded_length(const char *value, size_t capacity) {
    size_t n=0U;
    while(n<capacity && value[n]!='\0') ++n;
    return n;
}
static bool bounded_string(const char *value, size_t capacity, bool empty_allowed) {
    if (!value) return false;
    size_t n=bounded_length(value,capacity);
    if (n==capacity || (!empty_allowed && n==0U)) return false;
    for(size_t i=0;i<n;++i) {
        unsigned char c=(unsigned char)value[i];
        if(c<0x20U || c>0x7eU) return false;
    }
    return true;
}
static bool valid_repo(const char *repo) {
    if(!bounded_string(repo,STORE_REPOSITORY_BYTES,false)) return false;
    for(const unsigned char *p=(const unsigned char *)repo;*p;++p)
        if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||
             (*p>='0'&&*p<='9')||*p=='.'||*p=='_'||*p=='-')) return false;
    return true;
}
static bool valid_fingerprint_or_empty(const char *value) {
    if(!bounded_string(value,STORE_FINGERPRINT_BYTES,true)) return false;
    size_t n=strlen(value); if(n==0U)return true;
    if(n!=40U&&n!=64U)return false;
    for(size_t i=0;i<n;++i)if(!isxdigit((unsigned char)value[i]))return false;
    return true;
}
static bool valid_state(const orbit_repository_trust_state *s) {
    if(!s || !bounded_string(s->current_fingerprint,STORE_FINGERPRINT_BYTES,false) ||
       !valid_fingerprint_or_empty(s->previous_fingerprint) ||
       !valid_fingerprint_or_empty(s->pending_fingerprint)) return false;
    size_t current=strlen(s->current_fingerprint);
    if((current!=40U&&current!=64U))return false;
    if(s->pending_fingerprint[0]=='\0') {
        if(s->pending_activation!=0U)return false;
    } else {
        if(strcmp(s->pending_fingerprint,s->current_fingerprint)==0 ||
           s->pending_activation==0U ||
           s->previous_valid_until<s->pending_activation)return false;
    }
    if(s->previous_fingerprint[0]=='\0' && s->previous_valid_until!=0U &&
       s->pending_fingerprint[0]=='\0')return false;
    if(s->previous_fingerprint[0]!='\0' &&
       strcmp(s->previous_fingerprint,s->current_fingerprint)==0)return false;
    if(s->pending_fingerprint[0]!='\0' &&
       s->previous_fingerprint[0]!='\0' &&
       strcmp(s->pending_fingerprint,s->previous_fingerprint)==0)return false;
    return s->revision!=0U;
}
static size_t encode_record(const orbit_repository_trust_state *s,const char *repo,
                            uint8_t out[ORBIT_TRUST_STORE_RECORD_MAX]) {
    size_t p=0; memcpy(out+p,STORE_MAGIC,STORE_MAGIC_BYTES);p+=STORE_MAGIC_BYTES;
    put_u32(out+p,ORBIT_TRUST_STORE_VERSION);p+=4U;
    put_u64(out+p,s->revision);p+=8U;
    put_u32(out+p,s->generation);p+=4U;
    put_u64(out+p,s->pending_activation);p+=8U;
    put_u64(out+p,s->previous_valid_until);p+=8U;
    put_u64(out+p,s->last_observed_time);p+=8U;
    memset(out+p,0,STORE_REPOSITORY_BYTES);memcpy(out+p,repo,strlen(repo));p+=STORE_REPOSITORY_BYTES;
    memcpy(out+p,s->current_fingerprint,STORE_FINGERPRINT_BYTES);p+=STORE_FINGERPRINT_BYTES;
    memcpy(out+p,s->previous_fingerprint,STORE_FINGERPRINT_BYTES);p+=STORE_FINGERPRINT_BYTES;
    memcpy(out+p,s->pending_fingerprint,STORE_FINGERPRINT_BYTES);p+=STORE_FINGERPRINT_BYTES;
    return p;
}
static bool decode_record(const uint8_t *in,size_t n,const char *repo,
                          orbit_repository_trust_state *state) {
    if(!in || n!=STORE_FIXED_BYTES || memcmp(in,STORE_MAGIC,STORE_MAGIC_BYTES)!=0 ||
       get_u32(in+8U)!=ORBIT_TRUST_STORE_VERSION)return false;
    size_t p=12U; orbit_repository_trust_state s;memset(&s,0,sizeof(s));
    s.revision=get_u64(in+p);p+=8U;s.generation=get_u32(in+p);p+=4U;
    s.pending_activation=get_u64(in+p);p+=8U;s.previous_valid_until=get_u64(in+p);p+=8U;
    s.last_observed_time=get_u64(in+p);p+=8U;
    if(!memchr(in+p,0,STORE_REPOSITORY_BYTES) ||
       strcmp((const char *)(in+p),repo)!=0)return false;
    p+=STORE_REPOSITORY_BYTES;
    memcpy(s.current_fingerprint,in+p,STORE_FINGERPRINT_BYTES);p+=STORE_FINGERPRINT_BYTES;
    memcpy(s.previous_fingerprint,in+p,STORE_FINGERPRINT_BYTES);p+=STORE_FINGERPRINT_BYTES;
    memcpy(s.pending_fingerprint,in+p,STORE_FINGERPRINT_BYTES);
    if(!valid_state(&s))return false;
    *state=s;return true;
}
static bool constant_time_equal(const uint8_t *a,const uint8_t *b,size_t n) {
    uint8_t diff=0;for(size_t i=0;i<n;++i)diff|=(uint8_t)(a[i]^b[i]);return diff==0U;
}
static bool backend_valid(const orbit_trust_store_backend *b) {
    return b&&b->begin_transaction&&b->end_transaction&&b->read_counter&&b->advance_counter&&b->read_record&&
           b->write_record_atomic&&b->mac_record;
}

static orbit_trust_store_code store_load_locked(
    orbit_repository_trust_state *state,const char *repository_id,
    const orbit_trust_store_backend *backend) {
    if(!state||!valid_repo(repository_id)||!backend_valid(backend))
        return ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    memset(state,0,sizeof(*state));
    uint64_t counter=0;if(!backend->read_counter(backend->context,repository_id,&counter))
        return ORBIT_TRUST_STORE_IO_ERROR;
    uint8_t record[ORBIT_TRUST_STORE_RECORD_MAX],stored_mac[ORBIT_TRUST_STORE_MAC_BYTES];
    uint8_t computed_mac[ORBIT_TRUST_STORE_MAC_BYTES];size_t length=0;
    memset(record,0,sizeof(record));memset(stored_mac,0,sizeof(stored_mac));
    memset(computed_mac,0,sizeof(computed_mac));
    orbit_trust_store_read_result read_result=backend->read_record(
        backend->context,repository_id,record,sizeof(record),&length,stored_mac);
    if(read_result!=ORBIT_TRUST_BACKEND_OK) {
        memset(record,0,sizeof(record));memset(stored_mac,0,sizeof(stored_mac));
        if(read_result==ORBIT_TRUST_BACKEND_NOT_FOUND)
            return counter==0U?ORBIT_TRUST_STORE_NOT_FOUND:ORBIT_TRUST_STORE_ROLLBACK_DETECTED;
        return ORBIT_TRUST_STORE_IO_ERROR;
    }
    if(length>sizeof(record)||length==0U) {
        memset(record,0,sizeof(record));memset(stored_mac,0,sizeof(stored_mac));
        return ORBIT_TRUST_STORE_FORMAT_REJECTED;
    }
    bool mac_ok=backend->mac_record(backend->context,repository_id,record,length,computed_mac)&&
                constant_time_equal(stored_mac,computed_mac,sizeof(stored_mac));
    orbit_repository_trust_state decoded;memset(&decoded,0,sizeof(decoded));
    bool decoded_ok=mac_ok&&decode_record(record,length,repository_id,&decoded);
    memset(record,0,sizeof(record));memset(stored_mac,0,sizeof(stored_mac));
    memset(computed_mac,0,sizeof(computed_mac));
    if(!mac_ok)return ORBIT_TRUST_STORE_AUTHENTICATION_FAILED;
    if(!decoded_ok)return ORBIT_TRUST_STORE_FORMAT_REJECTED;
    if(decoded.revision<counter ||
       (counter==UINT64_MAX && decoded.revision!=counter) ||
       (counter!=UINT64_MAX && decoded.revision>counter+1U))
        return ORBIT_TRUST_STORE_ROLLBACK_DETECTED;
    if(counter!=UINT64_MAX && decoded.revision==counter+1U) {
        if(!backend->advance_counter(backend->context,repository_id,counter,decoded.revision)) {
            uint64_t observed=0U;
            if(!backend->read_counter(backend->context,repository_id,&observed))
                return ORBIT_TRUST_STORE_IO_ERROR;
            if(observed!=decoded.revision)return ORBIT_TRUST_STORE_ROLLBACK_DETECTED;
        }
    }
    *state=decoded;return ORBIT_TRUST_STORE_OK;
}

static orbit_trust_store_code store_save_locked(
    const orbit_repository_trust_state *state,const char *repository_id,
    const orbit_trust_store_backend *backend) {
    if(!valid_state(state)||!valid_repo(repository_id)||!backend_valid(backend))
        return ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    uint64_t counter=0;if(!backend->read_counter(backend->context,repository_id,&counter))
        return ORBIT_TRUST_STORE_IO_ERROR;
    if(counter==UINT64_MAX || state->revision<counter||state->revision>counter+1U)
        return ORBIT_TRUST_STORE_ROLLBACK_DETECTED;
    uint8_t record[ORBIT_TRUST_STORE_RECORD_MAX],mac[ORBIT_TRUST_STORE_MAC_BYTES];
    memset(record,0,sizeof(record));memset(mac,0,sizeof(mac));
    size_t length=encode_record(state,repository_id,record);
    if(!backend->mac_record(backend->context,repository_id,record,length,mac)) {
        memset(record,0,sizeof(record));memset(mac,0,sizeof(mac));return ORBIT_TRUST_STORE_IO_ERROR;
    }
    if(state->revision==counter) {
        uint8_t existing[ORBIT_TRUST_STORE_RECORD_MAX];
        uint8_t existing_mac[ORBIT_TRUST_STORE_MAC_BYTES];
        size_t existing_length=0U;
        memset(existing,0,sizeof(existing));memset(existing_mac,0,sizeof(existing_mac));
        orbit_trust_store_read_result existing_status=backend->read_record(
            backend->context,repository_id,existing,sizeof(existing),&existing_length,existing_mac);
        bool identical=existing_status==ORBIT_TRUST_BACKEND_OK && existing_length==length &&
                       constant_time_equal(existing,record,length) &&
                       constant_time_equal(existing_mac,mac,sizeof(mac));
        memset(existing,0,sizeof(existing));memset(existing_mac,0,sizeof(existing_mac));
        memset(record,0,sizeof(record));memset(mac,0,sizeof(mac));
        if(existing_status==ORBIT_TRUST_BACKEND_ERROR)return ORBIT_TRUST_STORE_IO_ERROR;
        return identical?ORBIT_TRUST_STORE_OK:ORBIT_TRUST_STORE_ROLLBACK_DETECTED;
    }
    bool written=backend->write_record_atomic(backend->context,repository_id,record,length,mac);
    if(!written) {
        memset(record,0,sizeof(record));memset(mac,0,sizeof(mac));
        return ORBIT_TRUST_STORE_IO_ERROR;
    }
    bool advanced=backend->advance_counter(backend->context,repository_id,counter,state->revision);
    memset(record,0,sizeof(record));memset(mac,0,sizeof(mac));
    if(advanced)return ORBIT_TRUST_STORE_OK;
    uint64_t observed=0U;
    if(!backend->read_counter(backend->context,repository_id,&observed))
        return ORBIT_TRUST_STORE_IO_ERROR;
    return observed==state->revision?ORBIT_TRUST_STORE_OK:ORBIT_TRUST_STORE_IO_ERROR;
}


orbit_trust_store_code orbit_repository_trust_store_load(
    orbit_repository_trust_state *state,const char *repository_id,
    const orbit_trust_store_backend *backend) {
    if(!state||!valid_repo(repository_id)||!backend_valid(backend))
        return ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    if(!backend->begin_transaction(backend->context,repository_id))
        return ORBIT_TRUST_STORE_IO_ERROR;
    orbit_trust_store_code result=store_load_locked(state,repository_id,backend);
    backend->end_transaction(backend->context,repository_id);
    return result;
}

orbit_trust_store_code orbit_repository_trust_store_save(
    const orbit_repository_trust_state *state,const char *repository_id,
    const orbit_trust_store_backend *backend) {
    if(!state||!valid_repo(repository_id)||!backend_valid(backend))
        return ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    if(!backend->begin_transaction(backend->context,repository_id))
        return ORBIT_TRUST_STORE_IO_ERROR;
    orbit_trust_store_code result=store_save_locked(state,repository_id,backend);
    backend->end_transaction(backend->context,repository_id);
    return result;
}

static void reload_or_invalidate_state(
    orbit_repository_trust_state *state,const char *repository_id,
    const orbit_trust_store_backend *backend) {
    orbit_repository_trust_state recovered;
    memset(&recovered,0,sizeof(recovered));
    if(orbit_repository_trust_store_load(&recovered,repository_id,backend)==ORBIT_TRUST_STORE_OK)
        *state=recovered;
    else
        memset(state,0,sizeof(*state));
    memset(&recovered,0,sizeof(recovered));
}

orbit_trust_store_code orbit_repository_trust_load_or_initialize(
    orbit_repository_trust_state *state,const char *repository_id,
    const char *bootstrap_primary_fingerprint,
    const orbit_trust_store_backend *backend) {
    if(!state||!bootstrap_primary_fingerprint)
        return ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    orbit_trust_store_code loaded=orbit_repository_trust_store_load(
        state,repository_id,backend);
    if(loaded!=ORBIT_TRUST_STORE_NOT_FOUND)return loaded;
    orbit_repository_trust_state initial;
    memset(&initial,0,sizeof(initial));
    if(!orbit_repository_trust_init(&initial,bootstrap_primary_fingerprint))
        return ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    orbit_trust_store_code saved=orbit_repository_trust_store_save(
        &initial,repository_id,backend);
    if(saved!=ORBIT_TRUST_STORE_OK) {
        memset(state,0,sizeof(*state));
        memset(&initial,0,sizeof(initial));
        return saved;
    }
    *state=initial;
    memset(&initial,0,sizeof(initial));
    return ORBIT_TRUST_STORE_OK;
}

orbit_trust_store_code orbit_repository_trust_authorize_rotation_and_store(
    orbit_repository_trust_state *state,const char *repository_id,
    const char *expected_repository,const uint8_t *rotation_inrelease,
    size_t rotation_inrelease_length,const uint8_t *current_public_key_bundle,
    size_t current_bundle_length,const uint8_t *candidate_public_key_bundle,
    size_t candidate_bundle_length,uint64_t now_seconds,
    const orbit_trust_store_backend *backend,orbit_trust_code *trust_result) {
    if(!state||!trust_result)return ORBIT_TRUST_STORE_INVALID_ARGUMENT;
    if(!orbit_repository_trust_observe_time(state,now_seconds)) {
        *trust_result=ORBIT_TRUST_TIME_ROLLBACK_REJECTED;
        return ORBIT_TRUST_STORE_OK;
    }
    orbit_trust_store_code time_saved=orbit_repository_trust_store_save(
        state,repository_id,backend);
    if(time_saved!=ORBIT_TRUST_STORE_OK) {
        reload_or_invalidate_state(state,repository_id,backend);
        return time_saved;
    }
    orbit_repository_trust_state time_committed=*state;
    *trust_result=orbit_repository_trust_authorize_rotation(
        state,expected_repository,rotation_inrelease,rotation_inrelease_length,
        current_public_key_bundle,current_bundle_length,candidate_public_key_bundle,
        candidate_bundle_length,now_seconds);
    if(*trust_result==ORBIT_TRUST_ACCEPTED) {
        orbit_trust_store_code saved=orbit_repository_trust_store_save(
            state,repository_id,backend);
        if(saved!=ORBIT_TRUST_STORE_OK)
            reload_or_invalidate_state(state,repository_id,backend);
        memset(&time_committed,0,sizeof(time_committed));
        return saved;
    }
    memset(&time_committed,0,sizeof(time_committed));
    return ORBIT_TRUST_STORE_OK;
}

bool orbit_repository_trust_observe_time_and_store(
    orbit_repository_trust_state *state,const char *repository_id,
    uint64_t now_seconds,const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result) {
    if(!state||!store_result)return false;
    if(!orbit_repository_trust_observe_time(state,now_seconds)) {
        *store_result=ORBIT_TRUST_STORE_ROLLBACK_DETECTED;
        return false;
    }
    *store_result=orbit_repository_trust_store_save(state,repository_id,backend);
    if(*store_result!=ORBIT_TRUST_STORE_OK) {
        reload_or_invalidate_state(state,repository_id,backend);
        return false;
    }
    return true;
}


bool orbit_repository_trust_fingerprint_allowed_and_store(
    orbit_repository_trust_state *state,const char *repository_id,
    const char *primary_fingerprint,uint64_t now_seconds,
    const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result) {
    if(!state||!primary_fingerprint||!store_result)return false;
    if(!orbit_repository_trust_observe_time_and_store(
        state,repository_id,now_seconds,backend,store_result))return false;
    return orbit_repository_trust_fingerprint_allowed(
        state,primary_fingerprint,now_seconds);
}

bool orbit_repository_trust_advance_and_store(
    orbit_repository_trust_state *state,const char *repository_id,
    uint64_t now_seconds,const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result) {
    if(!state||!store_result){return false;}
    if(!orbit_repository_trust_advance(state,now_seconds)) {
        *store_result=ORBIT_TRUST_STORE_OK;
        return false;
    }
    *store_result=orbit_repository_trust_store_save(state,repository_id,backend);
    if(*store_result!=ORBIT_TRUST_STORE_OK) {
        reload_or_invalidate_state(state,repository_id,backend);
        return false;
    }
    return true;
}

bool orbit_repository_trust_prune_previous_and_store(
    orbit_repository_trust_state *state,const char *repository_id,
    uint64_t now_seconds,const orbit_trust_store_backend *backend,
    orbit_trust_store_code *store_result) {
    if(!state||!store_result)return false;
    if(!orbit_repository_trust_prune_previous(state,now_seconds)) {
        *store_result=ORBIT_TRUST_STORE_OK;
        return false;
    }
    *store_result=orbit_repository_trust_store_save(state,repository_id,backend);
    if(*store_result!=ORBIT_TRUST_STORE_OK) {
        reload_or_invalidate_state(state,repository_id,backend);
        return false;
    }
    return true;
}
