#include "ORBITReleaseMetadata.h"
#include <stdio.h>
#include <string.h>
static unsigned checks,failures;
static void expect(const char*n,bool got,bool want){checks++;if(got!=want){fprintf(stderr,"FAIL %s got=%d want=%d\n",n,got,want);failures++;}else printf("PASS %s\n",n);}
int main(void){
 const char good[]="Origin: ORBIT\nDate: Tue, 10 Nov 2026 12:00:00 UTC\nValid-Until: Tue, 17 Nov 2026 12:00:00 UTC\nSuite: stable\nCodename: orbit\nArchitectures: iphoneos-arm64\nComponents: main\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1234 main/binary-iphoneos-arm64/Packages\n";
 orbit_release_metadata m;
 uint64_t date=0,until=0;
 expect("valid-release",orbit_release_metadata_parse((const uint8_t*)good,strlen(good),&m),true);
 expect("checksum-fields",m.checksum_count==1 && m.checksums[0].size==1234,true);

 expect("repository-policy-match",orbit_release_metadata_matches_policy(&m,"stable","orbit","iphoneos-arm64","main"),true);
 expect("repository-suite-mismatch",orbit_release_metadata_matches_policy(&m,"testing","orbit","iphoneos-arm64","main"),false);
 expect("repository-codename-mismatch",orbit_release_metadata_matches_policy(&m,"stable","other","iphoneos-arm64","main"),false);
 expect("repository-architecture-mismatch",orbit_release_metadata_matches_policy(&m,"stable","orbit","iphoneos","main"),false);
 expect("repository-component-mismatch",orbit_release_metadata_matches_policy(&m,"stable","orbit","iphoneos-arm64","extras"),false);
 expect("null-repository-policy",orbit_release_metadata_matches_policy(&m,NULL,"orbit","iphoneos-arm64","main"),false);

 expect("strict-date-fields",orbit_release_metadata_timestamps(&m,&date,&until),true);
 expect("date-epoch",date==1794312000ULL,true);
 expect("valid-until-epoch",until==1794916800ULL,true);
 char dup[sizeof(good)+32]; snprintf(dup,sizeof(dup),"%sDate: duplicate\n",good);
 expect("duplicate-date",orbit_release_metadata_parse((const uint8_t*)dup,strlen(dup),&m),false);
 const char unsafe[]="Date: x\nSuite: stable\nCodename: orbit\nArchitectures: arm64\nComponents: main\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 ../Packages\n";
 expect("path-traversal",orbit_release_metadata_parse((const uint8_t*)unsafe,strlen(unsafe),&m),false);

 const char truncated_checksum[]="Date: x\\nSuite: stable\\nCodename: orbit\\nArchitectures: arm64\\nComponents: main\\nSHA256:\\n abc\\n";
 expect("truncated-checksum-row",orbit_release_metadata_parse((const uint8_t*)truncated_checksum,strlen(truncated_checksum),&m),false);
 const char digest_without_fields[]="Date: x\\nSuite: stable\\nCodename: orbit\\nArchitectures: arm64\\nComponents: main\\nSHA256:\\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n";
 expect("checksum-missing-size-and-path",orbit_release_metadata_parse((const uint8_t*)digest_without_fields,strlen(digest_without_fields),&m),false);

 const char duplicate_path[]="Date: x\nSuite: stable\nCodename: orbit\nArchitectures: arm64\nComponents: main\nSHA256:\n aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 1 main/Packages\n bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 2 main/Packages\n";
 expect("duplicate-checksum-path",orbit_release_metadata_parse((const uint8_t*)duplicate_path,strlen(duplicate_path),&m),false);

 uint64_t parsed=0;
 expect("utc-date",orbit_release_parse_timestamp("Tue, 10 Nov 2026 12:00:00 UTC",&parsed),true);
 expect("utc-date-value",parsed==1794312000ULL,true);
 expect("numeric-zero-offset",orbit_release_parse_timestamp("Tue, 10 Nov 2026 12:00:00 +0000",&parsed),true);
 expect("numeric-offset-value",parsed==1794312000ULL,true);
 expect("positive-offset-conversion",orbit_release_parse_timestamp("Tue, 10 Nov 2026 07:00:00 -0500",&parsed),true);
 expect("negative-offset-conversion",parsed==1794312000ULL,true);
 expect("leap-day-valid",orbit_release_parse_timestamp("Sat, 29 Feb 2020 00:00:00 +0000",&parsed),true);
 expect("invalid-leap-day",orbit_release_parse_timestamp("Thu, 29 Feb 2023 00:00:00 +0000",&parsed),false);
 expect("weekday-mismatch",orbit_release_parse_timestamp("Mon, 10 Nov 2026 12:00:00 UTC",&parsed),false);
 expect("invalid-month",orbit_release_parse_timestamp("Tue, 10 Xxx 2026 12:00:00 UTC",&parsed),false);
 expect("invalid-hour",orbit_release_parse_timestamp("Tue, 10 Nov 2026 24:00:00 UTC",&parsed),false);
 expect("invalid-minute",orbit_release_parse_timestamp("Tue, 10 Nov 2026 12:60:00 UTC",&parsed),false);
 expect("invalid-timezone",orbit_release_parse_timestamp("Tue, 10 Nov 2026 12:00:00 PST",&parsed),false);
 expect("timezone-range",orbit_release_parse_timestamp("Tue, 10 Nov 2026 12:00:00 +2460",&parsed),false);
 expect("trailing-data",orbit_release_parse_timestamp("Tue, 10 Nov 2026 12:00:00 UTC junk",&parsed),false);
 expect("pre-epoch-rejected",orbit_release_parse_timestamp("Thu, 01 Jan 1970 00:00:00 +0100",&parsed),false);


 const char index_release[]="Date: Tue, 10 Nov 2026 12:00:00 UTC\\nSuite: stable\\nCodename: orbit\\nArchitectures: arm64\\nComponents: main\\nSHA256:\\n ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad 3 main/Packages\\n";
 const uint8_t package_index[]={'a','b','c'};
 expect("parse-index-release",orbit_release_metadata_parse((const uint8_t*)index_release,strlen(index_release),&m),true);
 expect("trusted-index-digest",orbit_release_verify_index(&m,ORBIT_RNP_VERIFY_VALID,"main/Packages",package_index,sizeof(package_index)),true);
 expect("untrusted-release-blocks-index",orbit_release_verify_index(&m,ORBIT_RNP_VERIFY_SIGNATURE_INVALID,"main/Packages",package_index,sizeof(package_index)),false);
 expect("index-path-mismatch",orbit_release_verify_index(&m,ORBIT_RNP_VERIFY_VALID,"main/Other",package_index,sizeof(package_index)),false);
 expect("index-size-mismatch",orbit_release_verify_index(&m,ORBIT_RNP_VERIFY_VALID,"main/Packages",package_index,sizeof(package_index)-1U),false);
 const uint8_t tampered_index[]={'a','b','d'};
 expect("index-content-tampering",orbit_release_verify_index(&m,ORBIT_RNP_VERIFY_VALID,"main/Packages",tampered_index,sizeof(tampered_index)),false);

 orbit_release_metadata malformed_metadata=m;
 memset(malformed_metadata.checksums[0].path,'x',sizeof(malformed_metadata.checksums[0].path));
 expect("unterminated-checksum-path-rejected",orbit_release_verify_index(&malformed_metadata,ORBIT_RNP_VERIFY_VALID,"main/Packages",package_index,sizeof(package_index)),false);
 malformed_metadata=m;
 memset(malformed_metadata.checksums[0].sha256,'a',sizeof(malformed_metadata.checksums[0].sha256));
 expect("unterminated-checksum-digest-rejected",orbit_release_verify_index(&malformed_metadata,ORBIT_RNP_VERIFY_VALID,"main/Packages",package_index,sizeof(package_index)),false);


 expect("fresh-before-valid-until",orbit_release_freshness_valid(100,200,199,1000,300),true);
 expect("fresh-at-valid-until",orbit_release_freshness_valid(100,200,200,1000,300),false);
 expect("future-date-outside-skew",orbit_release_freshness_valid(401,0,100,1000,300),false);
 expect("future-date-within-skew",orbit_release_freshness_valid(400,0,100,1000,300),true);
 expect("maximum-age-expired",orbit_release_freshness_valid(100,0,1100,1000,300),false);
 expect("missing-date",orbit_release_freshness_valid(0,0,100,1000,300),false);
 printf("decision=%s checks=%u failures=%u\n",failures?"FAIL":"PASS",checks,failures);
 return failures?1:0;
}
