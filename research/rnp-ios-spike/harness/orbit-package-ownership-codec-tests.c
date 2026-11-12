#include "ORBITPackageOwnershipCodec.h"
#include <stdio.h>
#include <string.h>
static unsigned checks,failures;
#define EXPECT(n,e) do{++checks;if(!(e)){++failures;printf("FAIL %s\n",n);}}while(0)
static orbit_package_ownership_record make_record(const char *path,const char *pkg,bool dir) {
    orbit_package_ownership_record r;memset(&r,0,sizeof(r));
    snprintf(r.path,sizeof(r.path),"%s",path);
    snprintf(r.package_name,sizeof(r.package_name),"%s",pkg);
    snprintf(r.package_version,sizeof(r.package_version),"1.0");
    snprintf(r.architecture,sizeof(r.architecture),"iphoneos-arm64");
    r.directory=dir;return r;
}
int main(void) {
    orbit_package_ownership_record input[2]={
        make_record("Library/ORBIT","orbit-core",true),
        make_record("Library/ORBIT/core.dylib","orbit-core",false)};
    orbit_package_ownership_snapshot source={input,2U};
    uint8_t encoded[4096];size_t length=0U;
    orbit_ownership_codec_code code=orbit_package_ownership_encode(
        &source,encoded,sizeof(encoded),&length);
    EXPECT("encode-valid-snapshot",code==ORBIT_OWNERSHIP_CODEC_OK&&length>12U);
    orbit_package_ownership_record decoded[2];
    orbit_package_ownership_snapshot result={0};
    code=orbit_package_ownership_decode(encoded,length,decoded,2U,&result);
    EXPECT("decode-roundtrip",code==ORBIT_OWNERSHIP_CODEC_OK&&result.count==2U);
    EXPECT("roundtrip-preserves-records",strcmp(decoded[0].path,input[0].path)==0&&
        strcmp(decoded[1].package_name,input[1].package_name)==0&&
        decoded[0].directory&&!decoded[1].directory);
    EXPECT("undersized-output-reports-required-length",
        orbit_package_ownership_encode(&source,encoded,1U,&length)==
        ORBIT_OWNERSHIP_CODEC_BUFFER_TOO_SMALL&&length>1U);
    EXPECT("insufficient-record-capacity-rejected",
        orbit_package_ownership_decode(encoded,length,decoded,1U,&result)==
        ORBIT_OWNERSHIP_CODEC_BUFFER_TOO_SMALL);
    EXPECT("trailing-bytes-rejected",
        orbit_package_ownership_decode(encoded,length+1U,decoded,2U,&result)==
        ORBIT_OWNERSHIP_CODEC_MALFORMED);
    uint8_t malformed[4096];memcpy(malformed,encoded,length);
    malformed[4]=2U;
    EXPECT("unknown-version-rejected",
        orbit_package_ownership_decode(malformed,length,decoded,2U,&result)==
        ORBIT_OWNERSHIP_CODEC_MALFORMED);
    memcpy(malformed,encoded,length);malformed[length-1U]=2U;
    EXPECT("invalid-directory-flag-rejected",
        orbit_package_ownership_decode(malformed,length,decoded,2U,&result)==
        ORBIT_OWNERSHIP_CODEC_MALFORMED);
    orbit_package_ownership_record corrupt=make_record("../escape","bad",false);
    orbit_package_ownership_snapshot bad={&corrupt,1U};
    EXPECT("unsafe-snapshot-cannot-be-encoded",
        orbit_package_ownership_encode(&bad,encoded,sizeof(encoded),&length)==
        ORBIT_OWNERSHIP_CODEC_INVALID_SNAPSHOT);
    printf("checks=%u failures=%u\ndecision=%s\n",checks,failures,failures?"FAIL":"PASS");
    return failures?1:0;
}
