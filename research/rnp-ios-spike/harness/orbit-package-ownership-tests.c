#include "ORBITPackageOwnership.h"
#include <stdio.h>
#include <string.h>
static unsigned checks,failures;
#define EXPECT(n,e) do { ++checks; if(!(e)){++failures;printf("FAIL: %s\n",n);} } while(0)
static orbit_package_record pkg(const char*n,const char*v,const char*a){
 orbit_package_record p;memset(&p,0,sizeof(p));snprintf(p.name,sizeof(p.name),"%s",n);
 snprintf(p.version,sizeof(p.version),"%s",v);snprintf(p.architecture,sizeof(p.architecture),"%s",a);return p;
}
static orbit_package_ownership_record own(const char*p,const char*n,bool d){
 orbit_package_ownership_record r;memset(&r,0,sizeof(r));snprintf(r.path,sizeof(r.path),"%s",p);
 snprintf(r.package_name,sizeof(r.package_name),"%s",n);snprintf(r.package_version,sizeof(r.package_version),"1");
 snprintf(r.architecture,sizeof(r.architecture),"iphoneos-arm64");r.directory=d;return r;
}
int main(void){
 orbit_package_record a=pkg("orbit-core","2","iphoneos-arm64"), b=pkg("other","1","iphoneos-arm64");
 orbit_archive_entry files[]={{"Library/ORBIT",0,true},{"Library/ORBIT/core.dylib",4096,false}};
 orbit_package_ownership_record old[]={own("Library/ORBIT","old-core",true),own("Library/ORBIT/old.dylib","old-core",false)};
 orbit_package_ownership_snapshot s={old,2};orbit_package_ownership_plan p={0};
 EXPECT("shared directory accepted",orbit_package_ownership_plan_install(&s,&a,files,2,&p)==ORBIT_OWNERSHIP_OK && p.count==2);
 orbit_package_ownership_plan_destroy(&p);
 orbit_package_ownership_record clash=own("Library/ORBIT/core.dylib","other",false);
 orbit_package_ownership_snapshot cs={&clash,1};
 EXPECT("foreign file overwrite blocked",orbit_package_ownership_plan_install(&cs,&a,files,2,&p)==ORBIT_OWNERSHIP_FILE_CONFLICT);
 orbit_package_ownership_record self=own("Library/ORBIT/core.dylib","orbit-core",false);
 orbit_package_ownership_snapshot ss={&self,1};
 EXPECT("same package upgrade accepted",orbit_package_ownership_plan_install(&ss,&a,files,2,&p)==ORBIT_OWNERSHIP_OK);
 orbit_package_ownership_plan_destroy(&p);
 orbit_archive_entry dup[]={{"usr/lib/a",1,false},{"usr/lib/a",1,false}};
 EXPECT("duplicate candidate rejected",orbit_package_ownership_plan_install(&s,&a,dup,2,&p)==ORBIT_OWNERSHIP_DUPLICATE_CANDIDATE);
 orbit_archive_entry ancestor_files[]={{"usr/file",1,false},{"usr/file/child",1,false}};
 EXPECT("file ancestor collision blocked",orbit_package_ownership_plan_install(&s,&a,ancestor_files,2,&p)==ORBIT_OWNERSHIP_ANCESTOR_CONFLICT);
 orbit_package_ownership_record shared[]={own("Library/Shared","pkg-a",true),own("Library/Shared","pkg-b",true),own("Library/Shared/a.dylib","pkg-a",false)};
 orbit_package_ownership_snapshot sh={shared,3};orbit_package_record pa=pkg("pkg-a","1","iphoneos-arm64");
 EXPECT("shared directory retained on removal",orbit_package_ownership_plan_remove(&sh,&pa,&p)==ORBIT_OWNERSHIP_OK && p.count==1 && strcmp(p.records[0].path,"Library/Shared/a.dylib")==0);
 orbit_package_ownership_plan_destroy(&p);
 EXPECT("unknown package removal blocked",orbit_package_ownership_plan_remove(&s,&b,&p)==ORBIT_OWNERSHIP_NOT_OWNER);
 orbit_package_ownership_record bad=own("../escape","bad",false);orbit_package_ownership_snapshot bs={&bad,1};
 EXPECT("corrupt database fails closed",orbit_package_ownership_plan_install(&bs,&a,files,2,&p)==ORBIT_OWNERSHIP_CORRUPT_DATABASE);
 printf("checks=%u failures=%u\ndecision=%s\n",checks,failures,failures?"FAIL":"PASS");return failures?1:0;
}
