#include "ORBITPackageOwnershipCodec.h"
#include <string.h>
#define OWNERSHIP_CODEC_HEADER_SIZE 12U
static const uint8_t ownership_magic[4]={'O','R','O','W'};
static void write_u32(uint8_t *out,uint32_t v) {
    out[0]=(uint8_t)(v>>24U);out[1]=(uint8_t)(v>>16U);
    out[2]=(uint8_t)(v>>8U);out[3]=(uint8_t)v;
}
static uint32_t read_u32(const uint8_t *in) {
    return ((uint32_t)in[0]<<24U)|((uint32_t)in[1]<<16U)|
           ((uint32_t)in[2]<<8U)|(uint32_t)in[3];
}
static bool field_length(const char *value,size_t capacity,uint16_t *length) {
    if(!value||!length)return false;
    const char *end=memchr(value,'\0',capacity);
    if(!end)return false;
    size_t n=(size_t)(end-value);
    if(n==0U||n>UINT16_MAX)return false;
    for(size_t i=n+1U;i<capacity;i++)if(value[i]!='\0')return false;
    *length=(uint16_t)n;return true;
}
static bool add_size(size_t *total,size_t amount) {
    if(amount>SIZE_MAX-*total)return false;
    *total+=amount;return true;
}
static bool snapshot_valid(const orbit_package_ownership_snapshot *snapshot) {
    if(!snapshot||(snapshot->count&&!snapshot->records)||
       snapshot->count>ORBIT_OWNERSHIP_MAX_RECORDS)return false;
    orbit_package_record probe;memset(&probe,0,sizeof(probe));
    static const char name[]="orbit-ownership-codec-validation";
    static const char version[]="1";
    static const char architecture[]="iphoneos-arm64";
    memcpy(probe.name,name,sizeof(name));
    memcpy(probe.version,version,sizeof(version));
    memcpy(probe.architecture,architecture,sizeof(architecture));
    orbit_package_ownership_plan plan;memset(&plan,0,sizeof(plan));
    orbit_ownership_code result=orbit_package_ownership_plan_install(
        snapshot,&probe,NULL,0U,&plan);
    orbit_package_ownership_plan_destroy(&plan);
    return result==ORBIT_OWNERSHIP_OK;
}
static bool record_lengths(const orbit_package_ownership_record *r,uint16_t n[4]) {
    return r&&field_length(r->path,sizeof(r->path),&n[0])&&
      field_length(r->package_name,sizeof(r->package_name),&n[1])&&
      field_length(r->package_version,sizeof(r->package_version),&n[2])&&
      field_length(r->architecture,sizeof(r->architecture),&n[3]);
}
orbit_ownership_codec_code orbit_package_ownership_encode(
    const orbit_package_ownership_snapshot *snapshot,
    uint8_t *output,size_t capacity,size_t *output_length) {
    if(!snapshot||!output_length)return ORBIT_OWNERSHIP_CODEC_INVALID_ARGUMENT;
    *output_length=0U;
    if(!snapshot_valid(snapshot))return ORBIT_OWNERSHIP_CODEC_INVALID_SNAPSHOT;
    size_t required=OWNERSHIP_CODEC_HEADER_SIZE;
    for(size_t i=0;i<snapshot->count;i++) {
        uint16_t n[4];
        if(!record_lengths(&snapshot->records[i],n))
            return ORBIT_OWNERSHIP_CODEC_INVALID_SNAPSHOT;
        for(size_t j=0;j<4U;j++)
            if(!add_size(&required,2U+(size_t)n[j]))
                return ORBIT_OWNERSHIP_CODEC_LIMIT;
        if(!add_size(&required,1U)||required>ORBIT_OWNERSHIP_CODEC_MAX_PAYLOAD)
            return ORBIT_OWNERSHIP_CODEC_LIMIT;
    }
    *output_length=required;
    if(!output||capacity<required)return ORBIT_OWNERSHIP_CODEC_BUFFER_TOO_SMALL;
    uint8_t *cursor=output;
    memcpy(cursor,ownership_magic,4U);cursor+=4U;
    *cursor++=1U;*cursor++=0U;*cursor++=0U;*cursor++=0U;
    write_u32(cursor,(uint32_t)snapshot->count);cursor+=4U;
    for(size_t i=0;i<snapshot->count;i++) {
        const orbit_package_ownership_record *r=&snapshot->records[i];
        const char *v[4]={r->path,r->package_name,r->package_version,r->architecture};
        const size_t c[4]={sizeof(r->path),sizeof(r->package_name),
                           sizeof(r->package_version),sizeof(r->architecture)};
        for(size_t j=0;j<4U;j++) {
            uint16_t n=0U;(void)field_length(v[j],c[j],&n);
            cursor[0]=(uint8_t)(n>>8U);cursor[1]=(uint8_t)n;cursor+=2U;
            memcpy(cursor,v[j],n);cursor+=n;
        }
        *cursor++=r->directory?1U:0U;
    }
    return (size_t)(cursor-output)==required?
        ORBIT_OWNERSHIP_CODEC_OK:ORBIT_OWNERSHIP_CODEC_INVALID_SNAPSHOT;
}
orbit_ownership_codec_code orbit_package_ownership_decode(
    const uint8_t *payload,size_t length,
    orbit_package_ownership_record *records,size_t capacity,
    orbit_package_ownership_snapshot *snapshot) {
    if(!payload||!snapshot)return ORBIT_OWNERSHIP_CODEC_INVALID_ARGUMENT;
    memset(snapshot,0,sizeof(*snapshot));
    if(length<OWNERSHIP_CODEC_HEADER_SIZE||length>ORBIT_OWNERSHIP_CODEC_MAX_PAYLOAD||
       memcmp(payload,ownership_magic,4U)!=0||payload[4]!=1U||
       payload[5]!=0U||payload[6]!=0U||payload[7]!=0U)
        return ORBIT_OWNERSHIP_CODEC_MALFORMED;
    uint32_t count=read_u32(payload+8U);
    if(count>ORBIT_OWNERSHIP_MAX_RECORDS)return ORBIT_OWNERSHIP_CODEC_LIMIT;
    if((size_t)count>capacity||(count&&!records))
        return ORBIT_OWNERSHIP_CODEC_BUFFER_TOO_SMALL;
    const uint8_t *cursor=payload+OWNERSHIP_CODEC_HEADER_SIZE;
    const uint8_t *end=payload+length;
    if(count)memset(records,0,(size_t)count*sizeof(*records));
    for(uint32_t i=0;i<count;i++) {
        orbit_package_ownership_record *r=&records[i];
        char *v[4]={r->path,r->package_name,r->package_version,r->architecture};
        const size_t c[4]={sizeof(r->path),sizeof(r->package_name),
                           sizeof(r->package_version),sizeof(r->architecture)};
        for(size_t j=0;j<4U;j++) {
            if((size_t)(end-cursor)<2U)return ORBIT_OWNERSHIP_CODEC_MALFORMED;
            uint16_t n=(uint16_t)(((uint16_t)cursor[0]<<8U)|cursor[1]);cursor+=2U;
            if(n==0U||(size_t)(end-cursor)<n||(size_t)n>=c[j]||
               memchr(cursor,'\0',n)!=NULL)return ORBIT_OWNERSHIP_CODEC_MALFORMED;
            memcpy(v[j],cursor,n);v[j][n]='\0';cursor+=n;
        }
        if(cursor==end||*cursor>1U)return ORBIT_OWNERSHIP_CODEC_MALFORMED;
        r->directory=*cursor++==1U;
    }
    if(cursor!=end)return ORBIT_OWNERSHIP_CODEC_MALFORMED;
    snapshot->records=records;snapshot->count=count;
    if(!snapshot_valid(snapshot)) {
        memset(snapshot,0,sizeof(*snapshot));
        return ORBIT_OWNERSHIP_CODEC_INVALID_SNAPSHOT;
    }
    return ORBIT_OWNERSHIP_CODEC_OK;
}
