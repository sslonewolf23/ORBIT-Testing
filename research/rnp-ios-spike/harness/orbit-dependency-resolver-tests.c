#include "ORBITDependencyResolver.h"
#include <stdio.h>
#include <string.h>

static unsigned checks=0,failures=0;
static void expect(const char *name,bool condition) {
    ++checks;if(!condition){++failures;fprintf(stderr,"FAIL %s\n",name);}
}
static void package(orbit_package_record *p,const char *name,const char *version,
                    const char *arch,const char *depends,const char *pre,
                    const char *conflicts) {
    memset(p,0,sizeof(*p));
    snprintf(p->name,sizeof(p->name),"%s",name);
    snprintf(p->version,sizeof(p->version),"%s",version);
    snprintf(p->architecture,sizeof(p->architecture),"%s",arch);
    snprintf(p->filename,sizeof(p->filename),"pool/%s.deb",name);
    snprintf(p->sha256,sizeof(p->sha256),"%064d",0);
    p->size=1U;
    if(depends)snprintf(p->depends,sizeof(p->depends),"%s",depends);
    if(pre)snprintf(p->pre_depends,sizeof(p->pre_depends),"%s",pre);
    if(conflicts)snprintf(p->conflicts,sizeof(p->conflicts),"%s",conflicts);
}
int main(void) {
    int cmp=0;
    expect("tilde sorts before release",
        orbit_debian_version_compare("1.0~beta1","1.0",&cmp)&&cmp<0);
    expect("epoch has precedence",
        orbit_debian_version_compare("2:1.0","1:9.9",&cmp)&&cmp>0);
    expect("revision compared",
        orbit_debian_version_compare("1.0-2","1.0-10",&cmp)&&cmp<0);
    expect("leading zeroes compare equal",
        orbit_debian_version_compare("1.01","1.1",&cmp)&&cmp==0);
    expect("malformed epoch rejected",
        !orbit_debian_version_compare("x:1.0","1.0",&cmp));

    orbit_package_record records[5];
    package(&records[0],"orbit-app","1.0","iphoneos-arm64",
            "libhelper (>= 2.0) | libalternate, libbase (>= 1.0)",
            "libpre (>= 1.0)",NULL);
    package(&records[1],"libhelper","2.1","iphoneos-arm64",NULL,NULL,NULL);
    package(&records[2],"libalternate","9.0","iphoneos-arm64",NULL,NULL,NULL);
    package(&records[3],"libbase","1.0","iphoneos-arm64",NULL,NULL,NULL);
    package(&records[4],"libpre","1.2","iphoneos-arm64",NULL,NULL,NULL);
    orbit_packages_index catalog={records,5U,5U};
    orbit_package_record installed_base;
    package(&installed_base,"libbase","1.5","iphoneos-arm64",NULL,NULL,NULL);
    const orbit_package_record *installed[]={&installed_base};
    orbit_dependency_plan plan={0};
    orbit_dependency_code code=orbit_dependency_plan_build(
        &catalog,installed,1U,"orbit-app","iphoneos-arm64",&plan);
    expect("dependency-plan-builds",code==ORBIT_DEPENDENCY_OK);
    expect("dependency-first-order",
        plan.count==3U&&strcmp(plan.ordered[0]->name,"libpre")==0&&
        strcmp(plan.ordered[1]->name,"libhelper")==0&&
        strcmp(plan.ordered[2]->name,"orbit-app")==0);
    orbit_dependency_plan_destroy(&plan);

    orbit_package_record bad_installed;
    package(&bad_installed,"libhelper","2.1","iphoneos-arm64",NULL,NULL,NULL);
    const orbit_package_record *bad_set[]={&bad_installed};
    code=orbit_dependency_plan_build(&catalog,bad_set,1U,"orbit-app",
                                     "iphoneos-arm64",&plan);
    expect("installed-dependency-satisfies-version",
        code==ORBIT_DEPENDENCY_OK&&plan.count==2U);
    orbit_dependency_plan_destroy(&plan);

    orbit_package_record cycle[2];
    package(&cycle[0],"cycle-a","1.0","iphoneos-arm64","cycle-b",NULL,NULL);
    package(&cycle[1],"cycle-b","1.0","iphoneos-arm64","cycle-a",NULL,NULL);
    orbit_packages_index cycle_catalog={cycle,2U,2U};
    code=orbit_dependency_plan_build(&cycle_catalog,NULL,0U,"cycle-a",
                                     "iphoneos-arm64",&plan);
    expect("dependency-cycle-rejected",code==ORBIT_DEPENDENCY_CYCLE);

    orbit_package_record conflict[2];
    package(&conflict[0],"conflict-app","1.0","iphoneos-arm64",
            "conflict-lib",NULL,NULL);
    package(&conflict[1],"conflict-lib","1.0","iphoneos-arm64",NULL,NULL,
            "conflict-app");
    orbit_packages_index conflict_catalog={conflict,2U,2U};
    code=orbit_dependency_plan_build(&conflict_catalog,NULL,0U,"conflict-app",
                                     "iphoneos-arm64",&plan);
    expect("dependency-conflicting-with-parent-rejected",
        code==ORBIT_DEPENDENCY_CONFLICT);

    orbit_package_record missing;
    package(&missing,"missing-root","1.0","iphoneos-arm64",
            "not-in-catalog (>= 1.0)",NULL,NULL);
    orbit_packages_index missing_catalog={&missing,1U,1U};
    code=orbit_dependency_plan_build(&missing_catalog,NULL,0U,"missing-root",
                                     "iphoneos-arm64",&plan);
    expect("unsatisfied-dependency-rejected",code==ORBIT_DEPENDENCY_UNSATISFIED);

    package(&missing,"missing-root","1.0","iphoneos-arm64",
            "not-in-catalog [iphoneos-arm64]",NULL,NULL);
    code=orbit_dependency_plan_build(&missing_catalog,NULL,0U,"missing-root",
                                     "iphoneos-arm64",&plan);
    expect("unsupported-architecture-restriction-fails-closed",
        code==ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION);

    package(&missing,"missing-root","1.0","iphoneos-arm64",
            "not-in-catalog (>= 2.0)",NULL,NULL);
    orbit_package_record too_old;
    package(&too_old,"not-in-catalog","1.0","iphoneos-arm64",NULL,NULL,NULL);
    orbit_package_record pair[]={missing,too_old};
    orbit_packages_index version_catalog={pair,2U,2U};
    code=orbit_dependency_plan_build(&version_catalog,NULL,0U,"missing-root",
                                     "iphoneos-arm64",&plan);
    expect("dependency-version-minimum-enforced",
        code==ORBIT_DEPENDENCY_UNSATISFIED);

    package(&missing,"missing-root","1.0","iphoneos-arm64",
            "not-in-catalog (>=)",NULL,NULL);
    code=orbit_dependency_plan_build(&missing_catalog,NULL,0U,"missing-root",
                                     "iphoneos-arm64",&plan);
    expect("malformed-version-relation-fails-closed",
        code==ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION);

    package(&missing,"missing-root","1.0","iphoneos-arm64",NULL,NULL,
            "bad | other");
    code=orbit_dependency_plan_build(&missing_catalog,NULL,0U,"missing-root",
                                     "iphoneos-arm64",&plan);
    expect("unsupported-conflict-alternatives-fail-closed",
        code==ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION);

    orbit_package_record reverse_conflict_package;
    package(&reverse_conflict_package,"installed-blocker","1.0",
            "iphoneos-arm64",NULL,NULL,"missing-root");
    const orbit_package_record *reverse_installed[]={&reverse_conflict_package};
    package(&missing,"missing-root","1.0","iphoneos-arm64",NULL,NULL,NULL);
    code=orbit_dependency_plan_build(&missing_catalog,reverse_installed,1U,
                                     "missing-root","iphoneos-arm64",&plan);
    expect("installed-package-reverse-conflict-rejected",
        code==ORBIT_DEPENDENCY_CONFLICT);

    orbit_dependency_plan_destroy(&plan);
    printf("decision=%s checks=%u failures=%u\n",
           failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
