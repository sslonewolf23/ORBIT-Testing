#include "ORBITRNPTimePolicy.h"
#include <stdint.h>

bool orbit_rnp_signature_time_policy_valid(uint32_t signature_created, uint32_t signature_expires, uint64_t now_seconds) {
    if (signature_created == 0) return false;
    if ((uint64_t) signature_created > now_seconds &&
        (uint64_t) signature_created - now_seconds > 300U) return false;
    if (signature_expires != 0 &&
        (uint64_t) signature_created + (uint64_t) signature_expires <= now_seconds) return false;
    return true;
}

bool orbit_rnp_key_time_policy_valid(uint32_t signature_created, uint32_t key_created, uint64_t key_valid_until, uint64_t now_seconds) {
    if (key_valid_until == 0 || signature_created < key_created) return false;
    if (key_valid_until != UINT64_MAX && now_seconds >= key_valid_until) return false;
    return true;
}
