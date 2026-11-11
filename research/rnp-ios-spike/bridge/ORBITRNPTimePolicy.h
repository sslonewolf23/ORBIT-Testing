#ifndef ORBIT_RNP_TIME_POLICY_H
#define ORBIT_RNP_TIME_POLICY_H
#include <stdbool.h>
#include <stdint.h>
bool orbit_rnp_signature_time_policy_valid(uint32_t signature_created, uint32_t signature_expires, uint64_t now_seconds);
bool orbit_rnp_key_time_policy_valid(uint32_t signature_created, uint32_t key_created, uint64_t key_valid_until, uint64_t now_seconds);
#endif
