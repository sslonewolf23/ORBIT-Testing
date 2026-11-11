#include "ORBITReleaseMetadata.h"
#include <stdio.h>
#include <string.h>
static unsigned checks,failures;
static void expect(const char*n,bool got,bool want){checks++;if(got!=want){fprintf(stderr,"FAIL %s got=%d want=%d\n",n,got,want);failures++;}else printf("PASS %s\n",n);}
int main(void){
 const char good[]="Origin: ORBIT\nDate: Tue, 10 Nov 2026 12:00:00 UTC\nValid-Until: Tue, 17 Nov 2026 12:00:00 UTC\nSuite: stable\nCodename: orbit\nArchitectures: iphoneos-arm64\nComponents: main\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1234 main/binary-iphoneos-arm64/Packages\n";
 orbit_release_metadata m;
 expect("valid-release",orbit_release_metadata_parse((const uint8_t*)good,strlen(good),&m),true);
 expect("checksum-fields",m.checksum_count==1 && m.checksums[0].size==1234,true);
 char dup[sizeof(good)+32]; snprintf(dup,sizeof(dup),"%sDate: duplicate\n",good);
 expect("duplicate-date",orbit_release_metadata_parse((const uint8_t*)dup,strlen(dup),&m),false);
 const char unsafe[]="Date: x\nSuite: stable\nCodename: orbit\nArchitectures: arm64\nComponents: main\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 ../Packages\n";
 expect("path-traversal",orbit_release_metadata_parse((const uint8_t*)unsafe,strlen(unsafe),&m),false);
 const char duplicate_path[]="Date: x\nSuite: stable\nCodename: orbit\nArchitectures: arm64\nComponents: main\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 main/Packages\n bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 2 main/Packages\n";
 expect("duplicate-checksum-path",orbit_release_metadata_parse((const uint8_t*)duplicate_path,strlen(duplicate_path),&m),false);
 expect("fresh-before-valid-until",orbit_release_freshness_valid(100,200,199,1000,300),true);
 expect("fresh-at-valid-until",orbit_release_freshness_valid(100,200,200,1000,300),false);
 expect("future-date-outside-skew",orbit_release_freshness_valid(401,0,100,1000,300),false);
 expect("future-date-within-skew",orbit_release_freshness_valid(400,0,100,1000,300),true);
 expect("maximum-age-expired",orbit_release_freshness_valid(100,0,1100,1000,300),false);
 expect("missing-date",orbit_release_freshness_valid(0,0,100,1000,300),false);
 printf("decision=%s checks=%u failures=%u\n",failures?"FAIL":"PASS",checks,failures);
 return failures?1:0;
}
