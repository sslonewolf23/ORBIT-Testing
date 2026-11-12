#include "ORBITPackageOwnership.h"
#include <stdlib.h>
#include <string.h>

static bool bounded_string(const char *s, size_t n) {
    return s && memchr(s, '\0', n) != NULL && s[0] != '\0';
}
static bool same_package(const orbit_package_ownership_record *a,
                         const orbit_package_ownership_record *b) {
    return strcmp(a->package_name,b->package_name)==0 &&
           strcmp(a->package_version,b->package_version)==0 &&
           strcmp(a->architecture,b->architecture)==0;
}
static bool same_identity(const orbit_package_ownership_record *a,
                          const orbit_package_record *b) {
    return strcmp(a->package_name,b->name)==0 &&
           strcmp(a->architecture,b->architecture)==0;
}
static bool ancestor(const char *a,const char *p) {
    size_t n=strlen(a);
    return strlen(p)>n && strncmp(a,p,n)==0 && p[n]=='/';
}
static bool append(orbit_package_ownership_plan *p,
                   const orbit_package_ownership_record *r) {
    if(p->count>=ORBIT_OWNERSHIP_MAX_RECORDS) return false;
    if(p->count==p->capacity) {
        size_t n=p->capacity ? p->capacity*2U : 32U;
        if(n>ORBIT_OWNERSHIP_MAX_RECORDS) n=ORBIT_OWNERSHIP_MAX_RECORDS;
        if(n<=p->capacity) return false;
        void *v=realloc(p->records,n*sizeof(*p->records));
        if(!v) return false;
        p->records=(orbit_package_ownership_record *)v; p->capacity=n;
    }
    p->records[p->count++]=*r; return true;
}
static bool valid_record(const orbit_package_ownership_record *r) {
    return r && bounded_string(r->path,sizeof(r->path)) &&
      orbit_package_archive_path_is_safe(r->path) &&
      bounded_string(r->package_name,sizeof(r->package_name)) &&
      bounded_string(r->package_version,sizeof(r->package_version)) &&
      bounded_string(r->architecture,sizeof(r->architecture));
}
static bool valid_package(const orbit_package_record *p) {
    return p && bounded_string(p->name,sizeof(p->name)) &&
      bounded_string(p->version,sizeof(p->version)) &&
      bounded_string(p->architecture,sizeof(p->architecture));
}
static orbit_ownership_code validate(const orbit_package_ownership_snapshot *s) {
    if(!s || (s->count && !s->records)) return ORBIT_OWNERSHIP_INVALID_ARGUMENT;
    if(s->count>ORBIT_OWNERSHIP_MAX_RECORDS) return ORBIT_OWNERSHIP_LIMIT;
    for(size_t i=0;i<s->count;i++) {
        const orbit_package_ownership_record *a=&s->records[i];
        if(!valid_record(a)) return ORBIT_OWNERSHIP_CORRUPT_DATABASE;
        for(size_t j=0;j<i;j++) {
            const orbit_package_ownership_record *b=&s->records[j];
            if(strcmp(a->path,b->path)==0 && same_package(a,b))
                return ORBIT_OWNERSHIP_CORRUPT_DATABASE;
            if(strcmp(a->path,b->path)==0 && (!a->directory || !b->directory))
                return ORBIT_OWNERSHIP_CORRUPT_DATABASE;
            if(ancestor(a->path,b->path) && !a->directory)
                return ORBIT_OWNERSHIP_CORRUPT_DATABASE;
            if(ancestor(b->path,a->path) && !b->directory)
                return ORBIT_OWNERSHIP_CORRUPT_DATABASE;
        }
    }
    return ORBIT_OWNERSHIP_OK;
}
void orbit_package_ownership_plan_destroy(orbit_package_ownership_plan *p) {
    if(!p) return; free(p->records); memset(p,0,sizeof(*p));
}
orbit_ownership_code orbit_package_ownership_plan_install(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *candidate,
    const orbit_archive_entry *entries,size_t count,
    orbit_package_ownership_plan *plan) {
    if(!plan || !valid_package(candidate) || (count && !entries))
        return ORBIT_OWNERSHIP_INVALID_ARGUMENT;
    memset(plan,0,sizeof(*plan));
    orbit_ownership_code rc=validate(installed);
    if(rc!=ORBIT_OWNERSHIP_OK) return rc;
    if(count>ORBIT_OWNERSHIP_MAX_PACKAGE_ENTRIES) return ORBIT_OWNERSHIP_LIMIT;
    for(size_t i=0;i<count;i++) {
        const orbit_archive_entry *e=&entries[i];
        if(!bounded_string(e->path,sizeof(e->path)) ||
           !orbit_package_archive_path_is_safe(e->path)) { rc=ORBIT_OWNERSHIP_UNSAFE_PATH; goto fail; }
        for(size_t j=0;j<i;j++) {
            if(strcmp(e->path,entries[j].path)==0) { rc=ORBIT_OWNERSHIP_DUPLICATE_CANDIDATE; goto fail; }
            if((ancestor(e->path,entries[j].path) && !e->directory) ||
               (ancestor(entries[j].path,e->path) && !entries[j].directory)) {
                rc=ORBIT_OWNERSHIP_ANCESTOR_CONFLICT; goto fail;
            }
        }
        for(size_t j=0;j<installed->count;j++) {
            const orbit_package_ownership_record *o=&installed->records[j];
            bool own=same_identity(o,candidate);
            if(strcmp(e->path,o->path)==0) {
                if((!e->directory || !o->directory) && !own) {
                    rc=ORBIT_OWNERSHIP_FILE_CONFLICT; goto fail;
                }
            } else if(((ancestor(e->path,o->path) && !e->directory) ||
                       (ancestor(o->path,e->path) && !o->directory)) && !own) {
                rc=ORBIT_OWNERSHIP_ANCESTOR_CONFLICT; goto fail;
            }
        }
        orbit_package_ownership_record r; memset(&r,0,sizeof(r));
        memcpy(r.path,e->path,strlen(e->path)+1U);
        memcpy(r.package_name,candidate->name,strlen(candidate->name)+1U);
        memcpy(r.package_version,candidate->version,strlen(candidate->version)+1U);
        memcpy(r.architecture,candidate->architecture,strlen(candidate->architecture)+1U);
        r.directory=e->directory;
        if(!append(plan,&r)) { rc=ORBIT_OWNERSHIP_LIMIT; goto fail; }
    }
    return ORBIT_OWNERSHIP_OK;
fail:
    orbit_package_ownership_plan_destroy(plan); return rc;
}
orbit_ownership_code orbit_package_ownership_plan_remove(
    const orbit_package_ownership_snapshot *installed,
    const orbit_package_record *package,orbit_package_ownership_plan *plan) {
    if(!plan || !valid_package(package)) return ORBIT_OWNERSHIP_INVALID_ARGUMENT;
    memset(plan,0,sizeof(*plan));
    orbit_ownership_code rc=validate(installed);
    if(rc!=ORBIT_OWNERSHIP_OK) return rc;
    bool found=false;
    for(size_t i=0;i<installed->count;i++) {
        const orbit_package_ownership_record *r=&installed->records[i];
        if(strcmp(r->package_name,package->name)!=0 ||
           strcmp(r->architecture,package->architecture)!=0) continue;
        found=true;
        if(r->directory) {
            bool shared=false;
            for(size_t j=0;j<installed->count;j++)
                if(i!=j && installed->records[j].directory &&
                   strcmp(r->path,installed->records[j].path)==0 &&
                   !same_package(r,&installed->records[j])) { shared=true; break; }
            if(shared) continue;
        }
        if(!append(plan,r)) { rc=ORBIT_OWNERSHIP_LIMIT; goto fail; }
    }
    if(!found) { rc=ORBIT_OWNERSHIP_NOT_OWNER; goto fail; }
    return ORBIT_OWNERSHIP_OK;
fail:
    orbit_package_ownership_plan_destroy(plan); return rc;
}
