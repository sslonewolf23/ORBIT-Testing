#include "ORBITRNPInReleaseVerifier.h"
#include "rnp-fault-injection.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static int read_file(const char *path, uint8_t **data, size_t *length) {
 FILE *f=fopen(path,"rb"); long n; uint8_t *p;
 if(!f) return 0;
 if(fseek(f,0,SEEK_END)||(n=ftell(f))<=0||fseek(f,0,SEEK_SET)){fclose(f);return 0;}
 p=(uint8_t*)malloc((size_t)n); if(!p){fclose(f);return 0;}
 if(fread(p,1,(size_t)n,f)!=(size_t)n){free(p);fclose(f);return 0;}
 if(fclose(f)){free(p);return 0;} *data=p; *length=(size_t)n; return 1;
}
static int run_case(orbit_fault_point point, unsigned occurrence,
 const uint8_t *key,size_t key_len,const uint8_t *doc,size_t doc_len,const char *fp) {
 orbit_rnp_verify_result result; orbit_rnp_verify_code code;
 orbit_fault_arm(point,occurrence);
 code=orbit_rnp_verify_inrelease(doc,doc_len,key,key_len,fp,&result);
 if(!orbit_fault_was_triggered()) {
  fprintf(stderr,"FAIL: fault point %s occurrence %u was not reached\n",orbit_fault_name(point),occurrence);
  return 0;
 }
 if(code==ORBIT_RNP_VERIFY_VALID || result.code!=code || result.error[0]=='\\0') {
  fprintf(stderr,"FAIL: %s did not fail closed (return=%d result=%d error=%s)\n",
    orbit_fault_name(point),(int)code,(int)result.code,result.error);
  return 0;
 }
 printf("PASS: %s occurrence %u -> blocked (code=%d)\n",orbit_fault_name(point),occurrence,(int)code);
 return 1;
}
int main(int argc,char **argv) {
 uint8_t *key=NULL,*doc=NULL,*subdoc=NULL; size_t kn=0,dn=0,sn=0; int failures=0;
 const char *fp;
 if(argc!=5){fprintf(stderr,"usage: %s <trusted-keyring> <valid-primary-InRelease> <valid-subkey-InRelease> <fingerprint>\n",argv[0]);return 64;}
 fp=argv[4];
 if(!read_file(argv[1],&key,&kn)||!read_file(argv[2],&doc,&dn)||!read_file(argv[3],&subdoc,&sn)){
  fprintf(stderr,"could not read fault-injection fixtures\n");free(key);free(doc);free(subdoc);return 64;
 }
 for(int p=0;p<ORBIT_FAULT_COUNT;p++) {
  unsigned occurrence=(p==ORBIT_FAULT_INPUT_MEMORY)?1U:1U;
  if(p==ORBIT_FAULT_PRIMARY_FPRINT||p==ORBIT_FAULT_LOCATE_PRIMARY) continue;
  if(!run_case((orbit_fault_point)p,occurrence,key,kn,doc,dn,fp)) ++failures;
 }
 if(!run_case(ORBIT_FAULT_INPUT_MEMORY,2U,key,kn,doc,dn,fp)) ++failures;
 if(!run_case(ORBIT_FAULT_PRIMARY_FPRINT,1U,key,kn,subdoc,sn,fp)) ++failures;
 if(!run_case(ORBIT_FAULT_LOCATE_PRIMARY,1U,key,kn,subdoc,sn,fp)) ++failures;
 /* On the subkey path, the first key validity/revocation calls are for the primary. */
 orbit_fault_arm(ORBIT_FAULT_KEY_IS_VALID,1U);
 {
  orbit_rnp_verify_result r; orbit_rnp_verify_code c=orbit_rnp_verify_inrelease(subdoc,sn,key,kn,fp,&r);
  if(!orbit_fault_was_triggered()||c==ORBIT_RNP_VERIFY_VALID||r.code!=c) {fprintf(stderr,"FAIL: primary key validity fault\n");++failures;}
  else puts("PASS: primary key validity fault -> blocked");
 }
 orbit_fault_arm(ORBIT_FAULT_KEY_IS_REVOKED,1U);
 {
  orbit_rnp_verify_result r; orbit_rnp_verify_code c=orbit_rnp_verify_inrelease(subdoc,sn,key,kn,fp,&r);
  if(!orbit_fault_was_triggered()||c==ORBIT_RNP_VERIFY_VALID||r.code!=c) {fprintf(stderr,"FAIL: primary key revocation fault\n");++failures;}
  else puts("PASS: primary key revocation fault -> blocked");
 }
 free(key);free(doc);free(subdoc);
 if(failures){fprintf(stderr,"decision=FAIL failures=%d\n",failures);return 1;}
 printf("decision=PASS fault_cases=%d\n",ORBIT_FAULT_COUNT+4);
 return 0;
}
