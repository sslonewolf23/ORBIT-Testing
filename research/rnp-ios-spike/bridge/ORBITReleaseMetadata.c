#include "ORBITReleaseMetadata.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool copy_field(char *out, size_t cap, const char *value, size_t n) {
    if (n == 0 || n >= cap) return false;
    for (size_t i=0;i<n;i++) if ((unsigned char)value[i] < 0x20 || (unsigned char)value[i] > 0x7e) return false;
    memcpy(out,value,n); out[n]='\0'; return true;
}
static bool safe_path(const char *p) {
    if (!p || !*p || *p=='/' || strchr(p,'\\') || strchr(p,'\t')) return false;
    const char *s=p;
    while (*s) {
        const char *e=strchr(s,'/'); size_t n=e?(size_t)(e-s):strlen(s);
        if (n==0 || (n==1 && s[0]=='.') || (n==2 && s[0]=='.' && s[1]=='.')) return false;
        for (size_t i=0;i<n;i++) if ((unsigned char)s[i] < 0x21 || (unsigned char)s[i] > 0x7e) return false;
        if (!e) break;
        s=e+1;
    }
    return true;
}
static int hexval(char c) {
    if (c>='0'&&c<='9') return c-'0';
    if (c>='a'&&c<='f') return c-'a'+10;
    if (c>='A'&&c<='F') return c-'A'+10;
    return -1;
}
static bool parse_checksum(char *line, orbit_release_metadata *m) {
    char *p=line; char digest[65];
    for (size_t i=0;i<64;i++) { if (hexval(p[i])<0) return false; digest[i]= (char)tolower((unsigned char)p[i]); }
    digest[64]='\0'; p+=64;
    if (*p!=' ' && *p!='\t') return false;
    while (*p==' ' || *p=='\t') p++;
    if (!isdigit((unsigned char)*p)) return false;
    uint64_t size=0;
    while (isdigit((unsigned char)*p)) {
        unsigned d=(unsigned)(*p-'0');
        if (size>(UINT64_MAX-d)/10U) return false;
        size=size*10U+d; p++;
    }
    if (*p!=' ' && *p!='\t') return false;
    while (*p==' ' || *p=='\t') p++;
    if (!safe_path(p) || m->checksum_count>=ORBIT_RELEASE_MAX_CHECKSUMS) return false;
    for (size_t i=0;i<m->checksum_count;i++) if (strcmp(m->checksums[i].path,p)==0) return false;
    orbit_release_checksum *c=&m->checksums[m->checksum_count++];
    memcpy(c->sha256,digest,sizeof(digest)); c->size=size;
    return copy_field(c->path,sizeof(c->path),p,strlen(p));
}
bool orbit_release_metadata_parse(const uint8_t *data,size_t length,orbit_release_metadata *out) {
    if (!data || !out || length==0 || length>ORBIT_RELEASE_MAX_BYTES || memchr(data,0,length)) return false;
    memset(out,0,sizeof(*out));
    char *buf=(char*)malloc(length+1); if(!buf) return false;
    memcpy(buf,data,length); buf[length]='\0';
    bool seen_date=false,seen_valid=false,seen_suite=false,seen_code=false,seen_arch=false,seen_comp=false,seen_sha=false;
    bool in_sha=false,ok=true; char *cursor=buf;
    while (*cursor && ok) {
        char *end=strchr(cursor,'\n'); if(end)*end='\0';
        size_t n=strlen(cursor); if(n && cursor[n-1]=='\r') cursor[--n]='\0';
        if(n==0) { in_sha=false; }
        else if(cursor[0]==' ' || cursor[0]=='\t') {
            if(!in_sha) ok=false;
            else { char *row=cursor; while(*row==' '||*row=='\t')row++; ok=parse_checksum(row,out); }
        } else {
            in_sha=false;
            char *colon=strchr(cursor,':');
            if(!colon || colon==cursor) { ok=false; }
            else {
                size_t keylen=(size_t)(colon-cursor); char *v=colon+1; if(*v==' ')v++;
                size_t vl=strlen(v);
                if(keylen==4 && memcmp(cursor,"Date",4)==0) { if(seen_date++)ok=false; else ok=copy_field(out->date,sizeof(out->date),v,vl); }
                else if(keylen==11 && memcmp(cursor,"Valid-Until",11)==0) { if(seen_valid++)ok=false; else ok=copy_field(out->valid_until,sizeof(out->valid_until),v,vl); }
                else if(keylen==5 && memcmp(cursor,"Suite",5)==0) { if(seen_suite++)ok=false; else ok=copy_field(out->suite,sizeof(out->suite),v,vl); }
                else if(keylen==8 && memcmp(cursor,"Codename",8)==0) { if(seen_code++)ok=false; else ok=copy_field(out->codename,sizeof(out->codename),v,vl); }
                else if(keylen==13 && memcmp(cursor,"Architectures",13)==0) { if(seen_arch++)ok=false; else ok=copy_field(out->architectures,sizeof(out->architectures),v,vl); }
                else if(keylen==10 && memcmp(cursor,"Components",10)==0) { if(seen_comp++)ok=false; else ok=copy_field(out->components,sizeof(out->components),v,vl); }
                else if(keylen==6 && memcmp(cursor,"SHA256",6)==0) {
                    if(seen_sha++ || vl!=0) ok=false;
                    else { in_sha=true; }
                }
            }
        }
        if(!end) break;
        cursor=end+1;
    }
    if(!seen_date || !seen_suite || !seen_code || !seen_arch || !seen_comp || !seen_sha || out->checksum_count==0) ok=false;
    free(buf); if(!ok) memset(out,0,sizeof(*out)); return ok;
}
bool orbit_release_freshness_valid(uint64_t date,uint64_t valid_until,uint64_t now,uint64_t max_age,uint64_t skew) {
    if(date==0 || max_age==0) return false;
    if(date>now && date-now>skew) return false;
    if(valid_until!=0) return valid_until>now && valid_until>date;
    if(date>UINT64_MAX-max_age) return false;
    return now<date+max_age;
}
