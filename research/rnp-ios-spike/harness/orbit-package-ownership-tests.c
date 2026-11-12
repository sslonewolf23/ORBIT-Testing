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

static void octal_field(unsigned char *p,size_t n,unsigned long long value){
 char b[32];snprintf(b,sizeof(b),"%0*llo",(int)(n-1U),value);memcpy(p,b,n-1U);p[n-1U]=0;
}
static size_t make_tar(unsigned char *tar,const char *path){
 memset(tar,0,1536U);memcpy(tar,path,strlen(path));
 octal_field(tar+100U,8U,0644U);octal_field(tar+108U,8U,0U);
 octal_field(tar+116U,8U,0U);octal_field(tar+124U,12U,0U);
 octal_field(tar+136U,12U,0U);memset(tar+148U,' ',8U);
 tar[156U]='0';memcpy(tar+257U,"ustar",5U);tar[262U]=0U;
 tar[263U]='0';tar[264U]='0';unsigned sum=0U;
 for(size_t i=0;i<512U;i++)sum+=tar[i];
 snprintf((char *)tar+148U,8U,"%06o",sum);tar[154U]=0U;tar[155U]=' ';return 1536U;
}
static size_t append_member(unsigned char *deb,size_t off,const char *name,
                            const unsigned char *body,size_t n){
 unsigned char *h=deb+off;memset(h,' ',60U);memcpy(h,name,strlen(name));
 char size[16];snprintf(size,sizeof(size),"%-10zu",n);memcpy(h+48U,size,10U);
 memcpy(h+58U,"`\n",2U);memcpy(h+60U,body,n);
 size_t next=off+60U+n;if(((60U+n)&1U)!=0U)deb[next++]='\n';return next;
}
static size_t make_deb(unsigned char *deb,const char *path){
 unsigned char tar[1536];size_t n=make_tar(tar,path);memcpy(deb,"!<arch>\n",8U);
 size_t off=8U;static const unsigned char ver[]="2.0\n";
 off=append_member(deb,off,"debian-binary",ver,4U);
 off=append_member(deb,off,"control.tar",tar,n);
 off=append_member(deb,off,"data.tar",tar,n);return off;
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
 unsigned char deb[8192];size_t deb_len=make_deb(deb,"Library/ORBIT/from-deb.dylib");
 orbit_package_ownership_snapshot empty={NULL,0};orbit_archive_report archive_report;
 EXPECT("Debian archive manifest feeds ownership planner",
   orbit_package_ownership_plan_install_deb(&empty,&a,deb,deb_len,&p,&archive_report)==ORBIT_OWNERSHIP_OK &&
   p.count==1U && strcmp(p.records[0].path,"Library/ORBIT/from-deb.dylib")==0);
 orbit_package_ownership_plan_destroy(&p);
 printf("checks=%u failures=%u\ndecision=%s\n",checks,failures,failures?"FAIL":"PASS");return failures?1:0;
}
