#include "ORBITReleaseMetadata.h"
#include <botan/ffi.h>
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
    if (!line || !m || strlen(line) < 66U) return false;
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
    bool seen_origin=false,seen_date=false,seen_valid=false,seen_suite=false,seen_code=false,seen_arch=false,seen_comp=false,seen_sha=false;
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
                if(keylen==6 && memcmp(cursor,"Origin",6)==0) { if(seen_origin++)ok=false; else ok=copy_field(out->origin,sizeof(out->origin),v,vl); }
                else if(keylen==4 && memcmp(cursor,"Date",4)==0) { if(seen_date++)ok=false; else ok=copy_field(out->date,sizeof(out->date),v,vl); }
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

static bool is_leap_year(unsigned year) {
    return (year % 4U == 0U && year % 100U != 0U) || year % 400U == 0U;
}
static unsigned month_days(unsigned year, unsigned month) {
    static const unsigned days[] = {31,28,31,30,31,30,31,31,30,31,30,31};
    if (month < 1U || month > 12U) return 0;
    return days[month - 1U] + (month == 2U && is_leap_year(year) ? 1U : 0U);
}
static bool take_digits(const char **p, unsigned min_digits, unsigned max_digits,
                        unsigned *value) {
    unsigned n = 0, v = 0;
    while (**p >= '0' && **p <= '9' && n < max_digits) {
        v = v * 10U + (unsigned)(**p - '0');
        ++*p; ++n;
    }
    if (n < min_digits) return false;
    if (**p >= '0' && **p <= '9') return false;
    *value = v;
    return true;
}
static bool take_literal(const char **p, const char *literal) {
    size_t n = strlen(literal);
    if (strncmp(*p, literal, n) != 0) return false;
    *p += n;
    return true;
}
static int month_number(const char *s) {
    static const char *const months[] =
        {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    for (int i = 0; i < 12; ++i) if (memcmp(s, months[i], 3) == 0) return i + 1;
    return 0;
}
static int weekday_number(const char *s) {
    static const char *const weekdays[] = {"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
    for (int i = 0; i < 7; ++i) if (memcmp(s, weekdays[i], 3) == 0) return i;
    return -1;
}
/* Days since 1970-01-01; caller restricts year to 1970..9999. */
static int64_t civil_days_since_epoch(int year, unsigned month, unsigned day) {
    year -= month <= 2U;
    const int era = year / 400;
    const unsigned yoe = (unsigned)(year - era * 400);
    const unsigned mp = month > 2U ? month - 3U : month + 9U;
    const unsigned doy = (153U * mp + 2U) / 5U + day - 1U;
    const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;
    return (int64_t)era * 146097 + (int64_t)doe - 719468;
}
bool orbit_release_parse_timestamp(const char *value, uint64_t *unix_seconds) {
    if (!value || !unix_seconds || strlen(value) < 24U) return false;
    const char *p = value;
    int weekday = weekday_number(p);
    if (weekday < 0) return false;
    p += 3;
    if (!take_literal(&p, ", ")) return false;

    unsigned day, year, hour, minute, second;
    if (!take_digits(&p, 1U, 2U, &day) || !take_literal(&p, " ")) return false;
    int month = month_number(p);
    if (!month) return false;
    p += 3;
    if (!take_literal(&p, " ") || !take_digits(&p, 4U, 4U, &year) ||
        !take_literal(&p, " ") || !take_digits(&p, 2U, 2U, &hour) ||
        !take_literal(&p, ":") || !take_digits(&p, 2U, 2U, &minute) ||
        !take_literal(&p, ":") || !take_digits(&p, 2U, 2U, &second) ||
        !take_literal(&p, " ")) return false;

    int offset_seconds = 0;
    if (strcmp(p, "UTC") == 0) {
        p += 3;
    } else {
        if ((*p != '+' && *p != '-') || strlen(p) != 5U) return false;
        int sign = *p++ == '+' ? 1 : -1;
        if (strlen(p) != 4U) return false;
        for (size_t i = 0; i < 4U; ++i) {
            if (p[i] < '0' || p[i] > '9') return false;
        }
        unsigned offset_hour = (unsigned)(p[0] - '0') * 10U +
                               (unsigned)(p[1] - '0');
        unsigned offset_minute = (unsigned)(p[2] - '0') * 10U +
                                 (unsigned)(p[3] - '0');
        if (offset_hour > 23U || offset_minute > 59U) return false;
        p += 4;
        offset_seconds = sign * (int)(offset_hour * 3600U + offset_minute * 60U);
    }
    if (*p != '\0' || year < 1970U || year > 9999U ||
        day < 1U || day > month_days(year, (unsigned)month) ||
        hour > 23U || minute > 59U || second > 59U) return false;

    int64_t days = civil_days_since_epoch((int)year, (unsigned)month, day);
    int actual_weekday = (int)((days + 4) % 7);
    if (actual_weekday != weekday) return false;

    int64_t local_seconds = days * 86400 + (int64_t)hour * 3600 +
                            (int64_t)minute * 60 + (int64_t)second;
    int64_t utc_seconds = local_seconds - offset_seconds;
    if (utc_seconds < 0) return false;
    *unix_seconds = (uint64_t)utc_seconds;
    return true;
}
bool orbit_release_metadata_timestamps(const orbit_release_metadata *metadata,
                                        uint64_t *date_seconds,
                                        uint64_t *valid_until_seconds) {
    if (!metadata || !date_seconds || !valid_until_seconds ||
        !orbit_release_parse_timestamp(metadata->date, date_seconds)) return false;
    *valid_until_seconds = 0;
    if (metadata->valid_until[0] != '\0' &&
        !orbit_release_parse_timestamp(metadata->valid_until, valid_until_seconds)) {
        *date_seconds = 0;
        return false;
    }
    if (*valid_until_seconds != 0 && *valid_until_seconds <= *date_seconds) {
        *date_seconds = 0;
        *valid_until_seconds = 0;
        return false;
    }
    return true;
}



static bool contains_token(const char *list, const char *wanted) {
    if (!list || !wanted || !*wanted) return false;
    size_t wanted_length = strlen(wanted);
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') ++p;
        size_t length = (size_t)(p - start);
        if (length == wanted_length && memcmp(start, wanted, length) == 0)
            return true;
    }
    return false;
}
bool orbit_release_metadata_matches_policy(const orbit_release_metadata *metadata,
                                            const char *expected_suite,
                                            const char *expected_codename,
                                            const char *required_architecture,
                                            const char *required_component) {
    if (!metadata || !expected_suite || !*expected_suite ||
        !expected_codename || !*expected_codename ||
        !required_architecture || !*required_architecture ||
        !required_component || !*required_component) return false;
    if (!memchr(metadata->suite, '\0', sizeof(metadata->suite)) ||
        !memchr(metadata->codename, '\0', sizeof(metadata->codename)) ||
        !memchr(metadata->architectures, '\0', sizeof(metadata->architectures)) ||
        !memchr(metadata->components, '\0', sizeof(metadata->components))) return false;
    return strcmp(metadata->suite, expected_suite) == 0 &&
           strcmp(metadata->codename, expected_codename) == 0 &&
           contains_token(metadata->architectures, required_architecture) &&
           contains_token(metadata->components, required_component);
}

bool orbit_release_verify_index(const orbit_release_metadata *metadata,
                                orbit_rnp_verify_code release_verification_code,
                                const char *relative_path,
                                const uint8_t *index_data,
                                size_t index_length) {
    if (!metadata || release_verification_code != ORBIT_RNP_VERIFY_VALID ||
        !relative_path || !index_data ||
        metadata->checksum_count == 0 ||
        metadata->checksum_count > ORBIT_RELEASE_MAX_CHECKSUMS ||
        !safe_path(relative_path)) return false;

    const orbit_release_checksum *expected = NULL;
    for (size_t i = 0; i < metadata->checksum_count; ++i) {
        const orbit_release_checksum *candidate = &metadata->checksums[i];
        if (!memchr(candidate->path, '\0', sizeof(candidate->path)) ||
            !memchr(candidate->sha256, '\0', sizeof(candidate->sha256)) ||
            strlen(candidate->sha256) != 64U || !safe_path(candidate->path)) return false;
        for (size_t j = 0; j < i; ++j) {
            if (strcmp(metadata->checksums[j].path, candidate->path) == 0)
                return false;
        }
        if (strcmp(candidate->path, relative_path) == 0) {
            if (expected) return false;
            expected = candidate;
        }
    }
    if (!expected || expected->size != (uint64_t)index_length) return false;

    uint8_t expected_digest[32];
    for (size_t i = 0; i < sizeof(expected_digest); ++i) {
        int high = hexval(expected->sha256[i * 2U]);
        int low = hexval(expected->sha256[i * 2U + 1U]);
        if (high < 0 || low < 0) return false;
        expected_digest[i] = (uint8_t)((high << 4) | low);
    }
    if (expected->sha256[64] != '\0') return false;

    botan_hash_t hash = NULL;
    if (botan_hash_init(&hash, "SHA-256", 0) != BOTAN_FFI_SUCCESS || !hash)
        return false;

    uint8_t actual_digest[32];
    size_t output_length = 0;
    bool ok = botan_hash_output_length(hash, &output_length) == BOTAN_FFI_SUCCESS &&
              output_length == sizeof(actual_digest) &&
              botan_hash_update(hash, index_data, index_length) == BOTAN_FFI_SUCCESS &&
              botan_hash_final(hash, actual_digest) == BOTAN_FFI_SUCCESS &&
              botan_constant_time_compare(expected_digest, actual_digest,
                                          sizeof(actual_digest)) == 0;
    (void)botan_hash_destroy(hash);
    (void)botan_scrub_mem(expected_digest, sizeof(expected_digest));
    (void)botan_scrub_mem(actual_digest, sizeof(actual_digest));
    return ok;
}

bool orbit_release_metadata_matches_repository_policy(
    const orbit_release_metadata *metadata,const char *expected_origin,
    const char *expected_suite,const char *expected_codename,
    const char *required_architecture,const char *required_component) {
    if(!metadata||!expected_origin||!expected_origin[0]||
       !metadata->origin[0]||strcmp(metadata->origin,expected_origin)!=0)
        return false;
    return orbit_release_metadata_matches_policy(metadata,expected_suite,
        expected_codename,required_architecture,required_component);
}

bool orbit_release_freshness_valid(uint64_t date,uint64_t valid_until,uint64_t now,uint64_t max_age,uint64_t skew) {
    if(date==0 || max_age==0) return false;
    if(date>now && date-now>skew) return false;
    if(valid_until!=0) return valid_until>now && valid_until>date;
    if(date>UINT64_MAX-max_age) return false;
    return now<date+max_age;
}
