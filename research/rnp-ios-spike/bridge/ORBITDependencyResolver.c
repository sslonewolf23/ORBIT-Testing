#define _POSIX_C_SOURCE 200809L
#include "ORBITDependencyResolver.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#define RELATION_MAX 2048U
#define TOKEN_MAX 256U

typedef struct {
    const orbit_packages_index *available;
    const orbit_package_record *const *installed;
    size_t installed_count;
    const char *architecture;
    const orbit_package_record **ordered;
    unsigned char *state;
    size_t count;
    orbit_dependency_code error;
} resolver;

static bool version_valid(const char *v) {
    if(!v||!*v)return false;
    for(const unsigned char *p=(const unsigned char*)v;*p;++p)
        if(*p<=0x20U||*p>=0x7fU||*p=='/')return false;
    return true;
}
static int order_char(int c) {
    if(c=='~')return -1;
    if(c==0)return 0;
    if(isalpha((unsigned char)c))return c;
    return c+256;
}
static int compare_part(const char *a,const char *b) {
    while(*a||*b) {
        while((*a&&!isdigit((unsigned char)*a))||(*b&&!isdigit((unsigned char)*b))) {
            int ac=order_char(*a),bc=order_char(*b);
            if(ac!=bc)return ac<bc?-1:1;
            if(*a)++a;
            if(*b)++b;
        }
        while(*a=='0')++a;
        while(*b=='0')++b;
        const char *ae=a,*be=b;
        while(isdigit((unsigned char)*ae))++ae;
        while(isdigit((unsigned char)*be))++be;
        size_t al=(size_t)(ae-a),bl=(size_t)(be-b);
        if(al!=bl)return al<bl?-1:1;
        int cmp=al?memcmp(a,b,al):0;
        if(cmp)return cmp<0?-1:1;
        a=ae;b=be;
    }
    return 0;
}
static bool split_epoch(const char *v,const char **rest,uint64_t *epoch) {
    *epoch=0;*rest=v;
    const char *colon=strchr(v,':');
    if(!colon)return true;
    if(colon==v)return false;
    uint64_t n=0;
    for(const char *p=v;p<colon;++p) {
        if(!isdigit((unsigned char)*p))return false;
        unsigned d=(unsigned)(*p-'0');
        if(n>(UINT64_MAX-d)/10U)return false;
        n=n*10U+d;
    }
    *epoch=n;*rest=colon+1;return **rest!='\0';
}
bool orbit_debian_version_compare(const char *left,const char *right,int *comparison) {
    if(!version_valid(left)||!version_valid(right)||!comparison)return false;
    const char *la,*ra;uint64_t le,re;
    if(!split_epoch(left,&la,&le)||!split_epoch(right,&ra,&re))return false;
    if(le!=re){*comparison=le<re?-1:1;return true;}
    const char *lh=strrchr(la,'-'),*rh=strrchr(ra,'-');
    char lup[128],rup[128],lrev[128],rrev[128];
    size_t lul=lh?(size_t)(lh-la):strlen(la),rul=rh?(size_t)(rh-ra):strlen(ra);
    const char *lv=lh?lh+1:"0",*rv=rh?rh+1:"0";
    if(lul==0||rul==0||lul>=sizeof(lup)||rul>=sizeof(rup)||
       strlen(lv)>=sizeof(lrev)||strlen(rv)>=sizeof(rrev))return false;
    memcpy(lup,la,lul);lup[lul]='\0';memcpy(rup,ra,rul);rup[rul]='\0';
    strcpy(lrev,lv);strcpy(rrev,rv);
    int c=compare_part(lup,rup);
    if(!c)c=compare_part(lrev,rrev);
    *comparison=c;return true;
}
static void trim(char *s) {
    size_t n=strlen(s),start=0;
    while(start<n&&isspace((unsigned char)s[start]))++start;
    while(n>start&&isspace((unsigned char)s[n-1]))--n;
    if(start)memmove(s,s+start,n-start);
    s[n-start]='\0';
}
static bool package_arch_ok(const orbit_package_record *p,const char *arch) {
    return strcmp(p->architecture,"all")==0||strcmp(p->architecture,arch)==0;
}
static bool relation_satisfied(const orbit_package_record *p,char *expr) {
    char *open=strchr(expr,'(');
    char name[TOKEN_MAX],op[3]="",version[TOKEN_MAX]="";
    if(open) {
        char *close=strchr(open,')');
        if(!close||close[1]!='\0')return false;
        *open='\0';*close='\0';
        char *v=open+1;trim(v);
        char *sp=v;while(*sp&&!isspace((unsigned char)*sp))++sp;
        if(!*sp)return false;
        size_t opl=(size_t)(sp-v);
        if(opl==0||opl>=sizeof(op))return false;
        memcpy(op,v,opl);op[opl]='\0';
        while(isspace((unsigned char)*sp))++sp;
        if(!*sp||strlen(sp)>=sizeof(version))return false;
        strcpy(version,sp);
        if(strcmp(op,"<<")&&strcmp(op,"<=")&&strcmp(op,"=")&&
           strcmp(op,">=")&&strcmp(op,">>"))return false;
    }
    trim(expr);
    if(!*expr||strlen(expr)>=sizeof(name))return false;
    strcpy(name,expr);
    if(strcmp(p->name,name)!=0)return false;
    if(!open)return true;
    int c=0;
    if(!orbit_debian_version_compare(p->version,version,&c))return false;
    if(strcmp(op,"<<")==0)return c<0;
    if(strcmp(op,"<=")==0)return c<=0;
    if(strcmp(op,"=")==0)return c==0;
    if(strcmp(op,">=")==0)return c>=0;
    return c>0;
}
static bool parse_relation_fields(const char *expression,
                                  char *name, size_t name_capacity,
                                  char *op, char *version,
                                  size_t version_capacity) {
    if (!expression || !*expression) return false;
    char copy[RELATION_MAX];
    if (strlen(expression) >= sizeof(copy)) return false;
    strcpy(copy, expression);
    trim(copy);
    char *open = strchr(copy, '(');
    op[0] = '\\0';
    version[0] = '\\0';
    if (open) {
        char *close = strchr(open, ')');
        if (!close || close[1] != '\\0') return false;
        *open = '\\0';
        *close = '\\0';
        char *value = open + 1;
        trim(value);
        char *space = value;
        while (*space && !isspace((unsigned char)*space)) ++space;
        size_t op_length = (size_t)(space - value);
        if (op_length == 0U || op_length >= 3U) return false;
        memcpy(op, value, op_length);
        op[op_length] = '\\0';
        if (strcmp(op, "<<") && strcmp(op, "<=") && strcmp(op, "=") &&
            strcmp(op, ">=") && strcmp(op, ">>")) return false;
        while (isspace((unsigned char)*space)) ++space;
        if (!*space || strlen(space) >= version_capacity) return false;
        strcpy(version, space);
        int self = 0;
        if (!orbit_debian_version_compare(version, version, &self)) return false;
    } else if (strchr(copy, ')')) {
        return false;
    }
    trim(copy);
    if (!*copy || strlen(copy) >= name_capacity ||
        !isalnum((unsigned char)copy[0])) return false;
    for (const unsigned char *p = (const unsigned char *)copy; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
              *p == '-' || *p == '+' || *p == '.')) return false;
    strcpy(name, copy);
    return true;
}
static bool version_matches_constraint(const char *actual,
                                       const char *op,
                                       const char *wanted) {
    int comparison = 0;
    if (!orbit_debian_version_compare(actual, wanted, &comparison)) return false;
    if (strcmp(op, "<<") == 0) return comparison < 0;
    if (strcmp(op, "<=") == 0) return comparison <= 0;
    if (strcmp(op, "=") == 0) return comparison == 0;
    if (strcmp(op, ">=") == 0) return comparison >= 0;
    if (strcmp(op, ">>") == 0) return comparison > 0;
    return false;
}
/* Debian versioned Provides only permits an exact provided version. */
static bool package_satisfies_relation(const orbit_package_record *package,
                                       const char *expression,
                                       bool *malformed_provides) {
    if (malformed_provides) *malformed_provides = false;
    char dependency_name[TOKEN_MAX], dependency_op[3], dependency_version[TOKEN_MAX];
    if (!parse_relation_fields(expression, dependency_name, sizeof(dependency_name),
                               dependency_op, dependency_version,
                               sizeof(dependency_version))) return false;
    char direct[RELATION_MAX];
    if (strlen(expression) < sizeof(direct)) {
        strcpy(direct, expression);
        if (relation_satisfied(package, direct)) return true;
    }
    if (!package->provides[0]) return false;
    if (strlen(package->provides) >= RELATION_MAX) {
        if (malformed_provides) *malformed_provides = true;
        return false;
    }
    char list[RELATION_MAX];
    strcpy(list, package->provides);
    /* strtok_r skips empty fields; reject malformed comma lists explicitly. */
    size_t provides_length = strlen(list);
    if (list[0] == ',' || list[provides_length - 1U] == ',' ||
        strstr(list, ",,") != NULL) {
        if (malformed_provides) *malformed_provides = true;
        return false;
    }
    char *save = NULL;
    for (char *item = strtok_r(list, ",", &save); item;
         item = strtok_r(NULL, ",", &save)) {
        trim(item);
        char provided_name[TOKEN_MAX], provided_op[3], provided_version[TOKEN_MAX];
        if (!parse_relation_fields(item, provided_name, sizeof(provided_name),
                                   provided_op, provided_version,
                                   sizeof(provided_version)) ||
            (provided_op[0] && strcmp(provided_op, "=") != 0)) {
            if (malformed_provides) *malformed_provides = true;
            return false;
        }
        if (strcmp(provided_name, dependency_name) != 0) continue;
        if (!dependency_op[0]) return true;
        if (!provided_op[0]) continue;
        if (version_matches_constraint(provided_version, dependency_op,
                                       dependency_version)) return true;
    }
    return false;
}
static bool relation_atom_valid(const char *expression) {
    if(!expression||!*expression||strlen(expression)>=RELATION_MAX)return false;
    char copy[RELATION_MAX];strcpy(copy,expression);trim(copy);
    char *open=strchr(copy,'(');
    if(open) {
        char *close=strchr(open,')');
        if(!close||close[1]!='\0')return false;
        *open='\0';*close='\0';
        char *value=open+1;trim(value);
        char *space=value;while(*space&&!isspace((unsigned char)*space))++space;
        size_t op_length=(size_t)(space-value);
        char op[3];
        if(op_length==0U||op_length>=sizeof(op))return false;
        memcpy(op,value,op_length);op[op_length]='\0';
        if(strcmp(op,"<<")&&strcmp(op,"<=")&&strcmp(op,"=")&&strcmp(op,">=")&&strcmp(op,">>"))return false;
        while(isspace((unsigned char)*space))++space;
        int comparison=0;
        if(!*space||!orbit_debian_version_compare(space,space,&comparison))return false;
    } else if(strchr(copy,')'))return false;
    trim(copy);
    if(!*copy||!isalnum((unsigned char)copy[0]))return false;
    for(const unsigned char *p=(const unsigned char*)copy;*p;++p)
        if(!((*p>='a'&&*p<='z')||(*p>='0'&&*p<='9')||*p=='-'||*p=='+'||*p=='.'))return false;
    return true;
}
static bool installed_satisfies(resolver *r,const char *expression) {
    for(size_t i=0;i<r->installed_count;++i) {
        const orbit_package_record *p=r->installed[i];
        if(!p||!package_arch_ok(p,r->architecture))continue;
        int self_check=0;
        if(!orbit_debian_version_compare(p->version,p->version,&self_check)) {
            r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;
        }
        char copy[RELATION_MAX];
        if(strlen(expression)>=sizeof(copy))return false;
        strcpy(copy,expression);
        bool malformed=false;
        if(package_satisfies_relation(p,copy,&malformed))return true;
        if(malformed){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
    }
    return false;
}
static bool available_candidate_satisfies(resolver *r,const char *expression,size_t *index) {
    bool found=false;
    for(size_t i=0;i<r->available->count;++i) {
        const orbit_package_record *p=&r->available->packages[i];
        if(!package_arch_ok(p,r->architecture))continue;
        int self_check=0;
        if(!orbit_debian_version_compare(p->version,p->version,&self_check)) {
            r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;
        }
        char copy[RELATION_MAX];
        if(strlen(expression)>=sizeof(copy))return false;
        strcpy(copy,expression);
        bool malformed=false;
        if(!package_satisfies_relation(p,copy,&malformed)) {
            if(malformed){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
            continue;
        }
        if(!found){*index=i;found=true;continue;}
        int comparison=0;
        if(!orbit_debian_version_compare(p->version,
             r->available->packages[*index].version,&comparison)) {
            r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;
        }
        if(comparison>0)*index=i;
    }
    return found;
}
static bool resolve_index(resolver *r,size_t index);
static bool resolve_relation(resolver *r,const char *relation) {
    if(!relation||!*relation)return true;
    if(strlen(relation)>=RELATION_MAX){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
    char expression[RELATION_MAX];strcpy(expression,relation);
    char *save=NULL;
    for(char *group=strtok_r(expression,",",&save);group;group=strtok_r(NULL,",",&save)) {
        trim(group);if(!*group){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
        bool satisfied=false;
        char *alt_save=NULL;
        for(char *alt=strtok_r(group,"|",&alt_save);alt;alt=strtok_r(NULL,"|",&alt_save)) {
            trim(alt);
            if(!relation_atom_valid(alt)){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
            if(installed_satisfies(r,alt)){satisfied=true;break;}
            if(r->error!=ORBIT_DEPENDENCY_OK)return false;
            size_t candidate=0;
            if(available_candidate_satisfies(r,alt,&candidate)) {
                if(!resolve_index(r,candidate))return false;
                satisfied=true;break;
            }
            if(r->error!=ORBIT_DEPENDENCY_OK)return false;
        }
        if(!satisfied){r->error=ORBIT_DEPENDENCY_UNSATISFIED;return false;}
    }
    return true;
}
static bool check_conflict_relation(resolver *r,const orbit_package_record *p,
                                    const char *relations) {
    if(!relations||!*relations)return true;
    if(strlen(relations)>=RELATION_MAX){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
    char buffer[RELATION_MAX];strcpy(buffer,relations);char *save=NULL;
    for(char *item=strtok_r(buffer,",",&save);item;item=strtok_r(NULL,",",&save)) {
        trim(item);
        if(strchr(item,'|')){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
        char validation[RELATION_MAX];strcpy(validation,item);
        char *validation_save=NULL;
        for(char *atom=strtok_r(validation,"|",&validation_save);atom;atom=strtok_r(NULL,"|",&validation_save)) {
            trim(atom);
            if(!relation_atom_valid(atom)){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
        }
        for(size_t i=0;i<r->installed_count;++i) {
            const orbit_package_record *q=r->installed[i];
            if(!q||!package_arch_ok(q,r->architecture))continue;
            char copy[RELATION_MAX];strcpy(copy,item);
            bool malformed=false;
            if(package_satisfies_relation(q,copy,&malformed)){r->error=ORBIT_DEPENDENCY_CONFLICT;return false;}
            if(malformed){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
        }
        for(size_t i=0;i<r->available->count;++i) {
            if(r->state[i]!=1U||!package_arch_ok(&r->available->packages[i],r->architecture))continue;
            char copy[RELATION_MAX];strcpy(copy,item);
            bool malformed=false;
            if(package_satisfies_relation(&r->available->packages[i],copy,&malformed)){r->error=ORBIT_DEPENDENCY_CONFLICT;return false;}
            if(malformed){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
        }
        for(size_t i=0;i<r->count;++i) {
            if(!package_arch_ok(r->ordered[i],r->architecture))continue;
            char copy[RELATION_MAX];strcpy(copy,item);
            bool malformed=false;
            if(package_satisfies_relation(r->ordered[i],copy,&malformed)){r->error=ORBIT_DEPENDENCY_CONFLICT;return false;}
            if(malformed){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return false;}
        }
    }
    (void)p;return true;
}
static bool record_rejects_candidate(resolver *r,
                                     const orbit_package_record *existing,
                                     const orbit_package_record *candidate) {
    const char *fields[2]={existing->conflicts,existing->breaks};
    for(size_t f=0;f<2U;++f) {
        if(!fields[f][0])continue;
        if(strlen(fields[f])>=RELATION_MAX) {
            r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return true;
        }
        char buffer[RELATION_MAX];strcpy(buffer,fields[f]);
        char *save=NULL;
        for(char *item=strtok_r(buffer,",",&save);item;item=strtok_r(NULL,",",&save)) {
            trim(item);
            if(strchr(item,'|')){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return true;}
            char validation[RELATION_MAX];strcpy(validation,item);
            char *validation_save=NULL;
            for(char *atom=strtok_r(validation,"|",&validation_save);atom;atom=strtok_r(NULL,"|",&validation_save)) {
                trim(atom);
                if(!relation_atom_valid(atom)){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return true;}
            }
            char *alt_save=NULL;
            for(char *alt=strtok_r(item,"|",&alt_save);alt;alt=strtok_r(NULL,"|",&alt_save)) {
                trim(alt);
                char copy[RELATION_MAX];strcpy(copy,alt);
                bool malformed=false;
                if(package_satisfies_relation(candidate,copy,&malformed)) {
                    r->error=ORBIT_DEPENDENCY_CONFLICT;return true;
                }
                if(malformed){r->error=ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;return true;}
            }
        }
    }
    return false;
}
static bool reverse_conflict(resolver *r,const orbit_package_record *candidate) {
    for(size_t i=0;i<r->installed_count;++i) {
        const orbit_package_record *existing=r->installed[i];
        if(existing&&package_arch_ok(existing,r->architecture)&&
           record_rejects_candidate(r,existing,candidate))return false;
    }
    for(size_t i=0;i<r->available->count;++i) {
        if(r->state[i]!=1U||
           !package_arch_ok(&r->available->packages[i],r->architecture))continue;
        if(record_rejects_candidate(r,&r->available->packages[i],candidate))return false;
    }
    return true;
}
static bool resolve_index(resolver *r,size_t index) {
    if(index>=r->available->count){r->error=ORBIT_DEPENDENCY_PACKAGE_NOT_FOUND;return false;}
    if(r->state[index]==2U)return true;
    if(r->state[index]==1U){r->error=ORBIT_DEPENDENCY_CYCLE;return false;}
    const orbit_package_record *p=&r->available->packages[index];
    r->state[index]=1U;
    if(!reverse_conflict(r,p)||!check_conflict_relation(r,p,p->conflicts)||
       !check_conflict_relation(r,p,p->breaks))return false;
    if(!resolve_relation(r,p->pre_depends)||!resolve_relation(r,p->depends))return false;
    if(r->count>=ORBIT_DEPENDENCY_PLAN_MAX){r->error=ORBIT_DEPENDENCY_LIMIT;return false;}
    r->ordered[r->count++]=p;r->state[index]=2U;return true;
}
orbit_dependency_code orbit_dependency_plan_build(
    const orbit_packages_index *available,const orbit_package_record *const *installed,
    size_t installed_count,const char *requested,const char *architecture,
    orbit_dependency_plan *plan) {
    if(!plan)return ORBIT_DEPENDENCY_INVALID_ARGUMENT;
    plan->ordered=NULL;plan->count=0U;
    if(!available||!available->packages||available->count==0U||
       !requested||!*requested||!architecture||!*architecture||
       (installed_count>0U&&!installed))return ORBIT_DEPENDENCY_INVALID_ARGUMENT;
    size_t root=SIZE_MAX;
    for(size_t i=0;i<available->count;++i) {
        const orbit_package_record *candidate=&available->packages[i];
        if(strcmp(candidate->name,requested)!=0||
           !package_arch_ok(candidate,architecture))continue;
        int self_check=0;
        if(!orbit_debian_version_compare(candidate->version,candidate->version,&self_check))
            return ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;
        if(root==SIZE_MAX){root=i;continue;}
        const orbit_package_record *current=&available->packages[root];
        bool candidate_exact=strcmp(candidate->architecture,architecture)==0;
        bool current_exact=strcmp(current->architecture,architecture)==0;
        int comparison=0;
        if(!orbit_debian_version_compare(candidate->version,current->version,&comparison))
            return ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;
        if((candidate_exact&&!current_exact)||
           (candidate_exact==current_exact&&comparison>0))root=i;
    }
    if(root==SIZE_MAX)return ORBIT_DEPENDENCY_PACKAGE_NOT_FOUND;
    int root_version_check=0;
    if(!orbit_debian_version_compare(available->packages[root].version,
                                     available->packages[root].version,
                                     &root_version_check))
        return ORBIT_DEPENDENCY_UNSUPPORTED_EXPRESSION;
    resolver r;memset(&r,0,sizeof(r));r.available=available;r.installed=installed;
    r.installed_count=installed_count;r.architecture=architecture;r.error=ORBIT_DEPENDENCY_OK;
    r.ordered=(const orbit_package_record**)calloc(ORBIT_DEPENDENCY_PLAN_MAX,sizeof(*r.ordered));
    r.state=(unsigned char*)calloc(available->count,1U);
    if(!r.ordered||!r.state){free(r.ordered);free(r.state);return ORBIT_DEPENDENCY_LIMIT;}
    bool ok=resolve_index(&r,root);
    free(r.state);
    if(!ok){free(r.ordered);return r.error==ORBIT_DEPENDENCY_OK?ORBIT_DEPENDENCY_UNSATISFIED:r.error;}
    plan->ordered=r.ordered;plan->count=r.count;return ORBIT_DEPENDENCY_OK;
}
void orbit_dependency_plan_destroy(orbit_dependency_plan *plan) {
    if(!plan)return;
    free(plan->ordered);
    plan->ordered=NULL;
    plan->count=0U;
}
