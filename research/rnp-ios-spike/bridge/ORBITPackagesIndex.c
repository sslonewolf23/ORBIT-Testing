#include "ORBITPackagesIndex.h"
#include <botan/ffi.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define PACKAGE_LINE_MAX 4096U
#define FIELD_NAME_MAX 64U

enum {
    SEEN_PACKAGE = 1U << 0,
    SEEN_VERSION = 1U << 1,
    SEEN_ARCH = 1U << 2,
    SEEN_FILENAME = 1U << 3,
    SEEN_SIZE = 1U << 4,
    SEEN_SHA256 = 1U << 5
};

typedef struct {
    orbit_package_record record;
    unsigned seen;
    char last_field[FIELD_NAME_MAX];
    char field_names[64U][FIELD_NAME_MAX];
    size_t field_count;
    bool has_field;
} package_stanza;

static bool copy_value(char *out,size_t capacity,const char *value,size_t length,
                       bool allow_empty) {
    if ((!allow_empty && length==0U) || length>=capacity) return false;
    for(size_t i=0U;i<length;++i) {
        unsigned char c=(unsigned char)value[i];
        if(c==0U || c=='\r' || c=='\n' || c==0x7fU || c<0x20U) return false;
    }
    memcpy(out,value,length);
    out[length]='\0';
    return true;
}

static bool valid_token(const char *value,bool allow_plus_dot) {
    if(!value||!value[0]||!isalnum((unsigned char)value[0]))return false;
    for(const unsigned char *p=(const unsigned char *)value;*p;++p) {
        if((*p>='a'&&*p<='z')||(*p>='0'&&*p<='9'))continue;
        if(*p=='-'||(allow_plus_dot&&(*p=='+'||*p=='.')))continue;
        return false;
    }
    return true;
}

static bool valid_version(const char *value) {
    if(!value||!value[0])return false;
    for(const unsigned char *p=(const unsigned char *)value;*p;++p)
        if(*p<=0x20U||*p>=0x7fU)return false;
    return true;
}

static bool valid_relative_path(const char *path) {
    if(!path||!path[0]||path[0]=='/'||strchr(path,'\\')||strchr(path,'\t'))return false;
    const char *segment=path;
    for(const char *p=path;;++p) {
        if(*p=='/'||*p=='\0') {
            size_t n=(size_t)(p-segment);
            if(n==0U||(n==1U&&segment[0]=='.')||
               (n==2U&&segment[0]=='.'&&segment[1]=='.'))return false;
            if(*p=='\0')break;
            segment=p+1;
        } else if((unsigned char)*p<0x21U||(unsigned char)*p>=0x7fU) return false;
    }
    return true;
}

static bool parse_size(const char *value,uint64_t *size) {
    if(!value||!value[0]||!size)return false;
    uint64_t n=0U;
    for(const unsigned char *p=(const unsigned char *)value;*p;++p) {
        if(*p<'0'||*p>'9')return false;
        unsigned digit=(unsigned)(*p-'0');
        if(n>(UINT64_MAX-digit)/10U)return false;
        n=n*10U+digit;
    }
    if(n==0U)return false;
    *size=n;
    return true;
}

static bool parse_sha256(const char *value,char output[65]) {
    if(!value||strlen(value)!=64U)return false;
    for(size_t i=0U;i<64U;++i) {
        unsigned char c=(unsigned char)value[i];
        if(!isxdigit(c))return false;
        output[i]=(char)tolower(c);
    }
    output[64]='\0';
    return true;
}

static bool append_description(char *description,const char *value,size_t length) {
    size_t used=strlen(description);
    if(used+length+1U>ORBIT_PACKAGE_DESCRIPTION_CAPACITY)return false;
    memcpy(description+used,value,length);
    description[used+length]='\0';
    return true;
}

static bool commit_stanza(package_stanza *stanza,orbit_packages_index *index) {
    const unsigned required=SEEN_PACKAGE|SEEN_VERSION|SEEN_ARCH|
        SEEN_FILENAME|SEEN_SIZE|SEEN_SHA256;
    if(stanza->field_count==0U)return true;
    if((stanza->seen&required)!=required||
       !valid_token(stanza->record.name,true)||
       !valid_version(stanza->record.version)||
       !valid_token(stanza->record.architecture,false)||
       !valid_relative_path(stanza->record.filename)||
       stanza->record.size==0U||stanza->record.sha256[0]=='\0'||
       index->count>=ORBIT_PACKAGES_INDEX_MAX_PACKAGES)return false;
    for(size_t i=0U;i<index->count;++i) {
        if(strcmp(index->packages[i].name,stanza->record.name)==0&&
           strcmp(index->packages[i].architecture,stanza->record.architecture)==0)
            return false;
    }
    if(index->count==index->capacity) {
        if(index->capacity>=ORBIT_PACKAGES_INDEX_MAX_PACKAGES)return false;
        size_t next=index->capacity*2U;
        if(next>ORBIT_PACKAGES_INDEX_MAX_PACKAGES)next=ORBIT_PACKAGES_INDEX_MAX_PACKAGES;
        orbit_package_record *grown=(orbit_package_record*)realloc(
            index->packages,next*sizeof(*index->packages));
        if(!grown)return false;
        memset(grown+index->capacity,0,(next-index->capacity)*sizeof(*grown));
        index->packages=grown;index->capacity=next;
    }
    index->packages[index->count++]=stanza->record;
    memset(stanza,0,sizeof(*stanza));
    return true;
}

static bool parse_field(package_stanza *stanza,char *line) {
    char *colon=strchr(line,':');
    if(!colon||colon==line)return false;
    size_t name_length=(size_t)(colon-line);
    if(name_length>=FIELD_NAME_MAX)return false;
    for(size_t i=0U;i<name_length;++i) {
        unsigned char c=(unsigned char)line[i];
        if(!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||
             (c>='0'&&c<='9')||c=='-'))return false;
    }
    char field[FIELD_NAME_MAX];
    memcpy(field,line,name_length);field[name_length]='\0';
    if(stanza->field_count>=64U)return false;
    for(size_t i=0U;i<stanza->field_count;++i)
        if(strcmp(stanza->field_names[i],field)==0)return false;
    memcpy(stanza->field_names[stanza->field_count++],field,name_length+1U);
    char *value=colon+1;
    if(*value==' ')++value;
    size_t value_length=strlen(value);
    unsigned bit=0U;
    if(strcmp(field,"Package")==0)bit=SEEN_PACKAGE;
    else if(strcmp(field,"Version")==0)bit=SEEN_VERSION;
    else if(strcmp(field,"Architecture")==0)bit=SEEN_ARCH;
    else if(strcmp(field,"Filename")==0)bit=SEEN_FILENAME;
    else if(strcmp(field,"Size")==0)bit=SEEN_SIZE;
    else if(strcmp(field,"SHA256")==0)bit=SEEN_SHA256;
    if(bit!=0U&&(stanza->seen&bit)!=0U)return false;
    if(bit==SEEN_PACKAGE) {
        if(!copy_value(stanza->record.name,sizeof(stanza->record.name),value,value_length,false))return false;
    } else if(bit==SEEN_VERSION) {
        if(!copy_value(stanza->record.version,sizeof(stanza->record.version),value,value_length,false))return false;
    } else if(bit==SEEN_ARCH) {
        if(!copy_value(stanza->record.architecture,sizeof(stanza->record.architecture),value,value_length,false))return false;
    } else if(bit==SEEN_FILENAME) {
        if(!copy_value(stanza->record.filename,sizeof(stanza->record.filename),value,value_length,false))return false;
    } else if(bit==SEEN_SIZE) {
        if(!parse_size(value,&stanza->record.size))return false;
    } else if(bit==SEEN_SHA256) {
        if(!parse_sha256(value,stanza->record.sha256))return false;
    } else if(strcmp(field,"Description")==0) {
        if(!copy_value(stanza->record.description,sizeof(stanza->record.description),
                       value,value_length,true))return false;
    } else if(strcmp(field,"Depends")==0) {
        if(!copy_value(stanza->record.depends,sizeof(stanza->record.depends),value,value_length,true))return false;
    } else if(strcmp(field,"Pre-Depends")==0) {
        if(!copy_value(stanza->record.pre_depends,sizeof(stanza->record.pre_depends),value,value_length,true))return false;
    } else if(strcmp(field,"Conflicts")==0) {
        if(!copy_value(stanza->record.conflicts,sizeof(stanza->record.conflicts),value,value_length,true))return false;
    } else if(strcmp(field,"Breaks")==0) {
        if(!copy_value(stanza->record.breaks,sizeof(stanza->record.breaks),value,value_length,true))return false;
    } else if(strcmp(field,"Provides")==0) {
        if(!copy_value(stanza->record.provides,sizeof(stanza->record.provides),value,value_length,true))return false;
    } else if(strcmp(field,"Replaces")==0) {
        if(!copy_value(stanza->record.replaces,sizeof(stanza->record.replaces),value,value_length,true))return false;
    } else if(strcmp(field,"Multi-Arch")==0) {
        if(!copy_value(stanza->record.multi_arch,sizeof(stanza->record.multi_arch),value,value_length,false))return false;
        if(strcmp(value,"same")!=0&&strcmp(value,"foreign")!=0&&strcmp(value,"allowed")!=0&&strcmp(value,"no")!=0)return false;
    } else {
        for(size_t i=0U;i<value_length;++i) {
            unsigned char c=(unsigned char)value[i];
            if(c<0x20U||c==0x7fU)return false;
        }
    }
    if(bit!=0U)stanza->seen|=bit;
    memcpy(stanza->last_field,field,name_length+1U);
    stanza->has_field=true;
    return true;
}

bool orbit_packages_index_parse(const uint8_t *data,size_t length,
                                orbit_packages_index *result) {
    if(!result)return false;
    result->packages=NULL;result->count=0U;result->capacity=0U;
    if(!data||length==0U||length>ORBIT_PACKAGES_INDEX_MAX_BYTES||
       memchr(data,0,length)!=NULL)return false;
    size_t initial_capacity=16U;
    if(initial_capacity>ORBIT_PACKAGES_INDEX_MAX_PACKAGES)
        initial_capacity=ORBIT_PACKAGES_INDEX_MAX_PACKAGES;
    orbit_package_record *records=(orbit_package_record*)calloc(
        initial_capacity,sizeof(*records));
    if(!records)return false;
    result->packages=records;result->capacity=initial_capacity;
    package_stanza stanza;memset(&stanza,0,sizeof(stanza));
    size_t offset=0U;
    bool ok=true;
    while(offset<length&&ok) {
        size_t end=offset;
        while(end<length&&data[end]!='\n')++end;
        size_t line_length=end-offset;
        if(line_length>PACKAGE_LINE_MAX){ok=false;break;}
        char line[PACKAGE_LINE_MAX+1U];
        memcpy(line,data+offset,line_length);line[line_length]='\0';
        if(line_length>0U&&line[line_length-1U]=='\r')line[--line_length]='\0';
        if(line_length==0U) {
            ok=commit_stanza(&stanza,result);
        } else if(line[0]==' '||line[0]=='\t') {
            if(!stanza.has_field)ok=false;
            else {
                const char *continuation=line+1;
                size_t continuation_length=line_length-1U;
                for(size_t i=0U;i<continuation_length;++i) {
                    unsigned char c=(unsigned char)continuation[i];
                    if(c<0x20U&&c!='\t'){ok=false;break;}
                    if(c==0x7fU){ok=false;break;}
                }
                if(ok&&strcmp(stanza.last_field,"Description")==0) {
                    bool blank=continuation_length==1U&&continuation[0]=='.';
                    ok=append_description(stanza.record.description,"\n",1U)&&
                       append_description(stanza.record.description,blank?"":continuation,blank?0U:continuation_length);
                } else if(ok) {
                    char *target=NULL;size_t capacity=0U;
                    if(strcmp(stanza.last_field,"Depends")==0){target=stanza.record.depends;capacity=sizeof(stanza.record.depends);}
                    else if(strcmp(stanza.last_field,"Pre-Depends")==0){target=stanza.record.pre_depends;capacity=sizeof(stanza.record.pre_depends);}
                    else if(strcmp(stanza.last_field,"Conflicts")==0){target=stanza.record.conflicts;capacity=sizeof(stanza.record.conflicts);}
                    else if(strcmp(stanza.last_field,"Breaks")==0){target=stanza.record.breaks;capacity=sizeof(stanza.record.breaks);}
                    else if(strcmp(stanza.last_field,"Provides")==0){target=stanza.record.provides;capacity=sizeof(stanza.record.provides);}
                    else if(strcmp(stanza.last_field,"Replaces")==0){target=stanza.record.replaces;capacity=sizeof(stanza.record.replaces);}
                    if(target) {
                        size_t used=strlen(target);
                        if(used+1U+continuation_length>=capacity)ok=false;
                        else {target[used]=' ';memcpy(target+used+1U,continuation,continuation_length);target[used+1U+continuation_length]='\\0';}
                    }
                }
            }
        } else {
            ok=parse_field(&stanza,line);
        }
        offset=end<length?end+1U:end;
    }
    if(ok)ok=commit_stanza(&stanza,result);
    memset(&stanza,0,sizeof(stanza));
    if(!ok||result->count==0U) {
        orbit_packages_index_destroy(result);
        return false;
    }
    return true;
}

void orbit_packages_index_destroy(orbit_packages_index *index) {
    if(!index)return;
    if(index->packages) {
        memset(index->packages,0,index->count*sizeof(*index->packages));
        free(index->packages);
    }
    index->packages=NULL;index->count=0U;index->capacity=0U;
}

static bool package_sha256_decode(const char *text,uint8_t digest[32]) {
    if(!text||strlen(text)!=64U)return false;
    for(size_t i=0U;i<32U;++i) {
        unsigned char a=(unsigned char)text[i*2U];
        unsigned char b=(unsigned char)text[i*2U+1U];
        if(!isxdigit(a)||!isxdigit(b))return false;
        unsigned high=(unsigned)(isdigit(a)?a-'0':tolower(a)-'a'+10);
        unsigned low=(unsigned)(isdigit(b)?b-'0':tolower(b)-'a'+10);
        digest[i]=(uint8_t)((high<<4U)|low);
    }
    return true;
}

void orbit_package_artifact_verifier_destroy(
    orbit_package_artifact_verifier *verifier) {
    if(!verifier)return;
    if(verifier->hash_context) {
        botan_hash_t hash=(botan_hash_t)verifier->hash_context;
        (void)botan_hash_destroy(hash);
    }
    (void)botan_scrub_mem(verifier->expected_digest,
                          sizeof(verifier->expected_digest));
    memset(verifier,0,sizeof(*verifier));
}

bool orbit_package_artifact_verifier_init(
    orbit_package_artifact_verifier *verifier,
    const orbit_package_record *package) {
    if(!verifier)return false;
    memset(verifier,0,sizeof(*verifier));
    if(!package||package->size==0U||
       !memchr(package->filename,'\0',sizeof(package->filename))||
       !memchr(package->sha256,'\0',sizeof(package->sha256))||
       !valid_relative_path(package->filename)||
       !package_sha256_decode(package->sha256,verifier->expected_digest)) {
        (void)botan_scrub_mem(verifier->expected_digest,
                              sizeof(verifier->expected_digest));
        return false;
    }
    botan_hash_t hash=NULL;
    if(botan_hash_init(&hash,"SHA-256",0)!=BOTAN_FFI_SUCCESS||!hash) {
        (void)botan_scrub_mem(verifier->expected_digest,
                              sizeof(verifier->expected_digest));
        return false;
    }
    size_t output_length=0U;
    if(botan_hash_output_length(hash,&output_length)!=BOTAN_FFI_SUCCESS||
       output_length!=sizeof(verifier->expected_digest)) {
        (void)botan_hash_destroy(hash);
        (void)botan_scrub_mem(verifier->expected_digest,
                              sizeof(verifier->expected_digest));
        return false;
    }
    verifier->hash_context=(void*)hash;
    verifier->expected_size=package->size;
    verifier->bytes_seen=0U;
    verifier->active=true;
    return true;
}

bool orbit_package_artifact_verifier_update(
    orbit_package_artifact_verifier *verifier,const uint8_t *chunk,
    size_t chunk_length) {
    if(!verifier||!verifier->active||
       (chunk_length>0U&&chunk==NULL)||
       (uint64_t)chunk_length>UINT64_MAX-verifier->bytes_seen||
       verifier->bytes_seen+(uint64_t)chunk_length>verifier->expected_size) {
        if(verifier)orbit_package_artifact_verifier_destroy(verifier);
        return false;
    }
    if(chunk_length==0U)return true;
    botan_hash_t hash=(botan_hash_t)verifier->hash_context;
    if(!hash||botan_hash_update(hash,chunk,chunk_length)!=BOTAN_FFI_SUCCESS) {
        orbit_package_artifact_verifier_destroy(verifier);
        return false;
    }
    verifier->bytes_seen+=(uint64_t)chunk_length;
    return true;
}

bool orbit_package_artifact_verifier_finalize(
    orbit_package_artifact_verifier *verifier) {
    if(!verifier||!verifier->active)return false;
    uint8_t actual[32];memset(actual,0,sizeof(actual));
    botan_hash_t hash=(botan_hash_t)verifier->hash_context;
    bool valid=hash!=NULL&&verifier->bytes_seen==verifier->expected_size&&
        botan_hash_final(hash,actual)==BOTAN_FFI_SUCCESS&&
        botan_constant_time_compare(verifier->expected_digest,actual,
                                    sizeof(actual))==0;
    (void)botan_scrub_mem(actual,sizeof(actual));
    orbit_package_artifact_verifier_destroy(verifier);
    return valid;
}

bool orbit_package_verify_artifact(const orbit_package_record *package,
                                   const uint8_t *artifact_data,
                                   size_t artifact_length) {
    if(!package||!artifact_data||artifact_length==0U)return false;
    orbit_package_artifact_verifier verifier;
    if(!orbit_package_artifact_verifier_init(&verifier,package))return false;
    if(!orbit_package_artifact_verifier_update(&verifier,artifact_data,
                                               artifact_length))return false;
    return orbit_package_artifact_verifier_finalize(&verifier);
}
