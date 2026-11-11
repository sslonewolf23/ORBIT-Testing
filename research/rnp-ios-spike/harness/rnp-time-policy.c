#include "ORBITRNPTimePolicy.h"
#include <stdio.h>
#include <stdint.h>

static unsigned checks, failures;
static void expect(const char *name, bool actual, bool expected) {
    ++checks;
    if (actual != expected) { fprintf(stderr, "FAIL %s expected=%d actual=%d\n", name, expected, actual); ++failures; }
    else printf("PASS %s\n", name);
}
int main(void) {
    const uint32_t created=1000U, expires=100U;
    const uint64_t expiry=1100U;
    expect("signature-before-expiry", orbit_rnp_signature_time_policy_valid(created,expires,expiry-1U), true);
    expect("signature-at-expiry", orbit_rnp_signature_time_policy_valid(created,expires,expiry), false);
    expect("signature-after-expiry", orbit_rnp_signature_time_policy_valid(created,expires,expiry+1U), false);
    expect("signature-no-expiration", orbit_rnp_signature_time_policy_valid(created,0U,UINT64_C(9000000000)), true);
    expect("zero-signature-time", orbit_rnp_signature_time_policy_valid(0U,0U,1000U), false);
    expect("future-skew-300", orbit_rnp_signature_time_policy_valid(1300U,0U,1000U), true);
    expect("future-skew-301", orbit_rnp_signature_time_policy_valid(1301U,0U,1000U), false);
    expect("key-before-expiry", orbit_rnp_key_time_policy_valid(1000U,900U,2000U,1999U), true);
    expect("key-at-expiry", orbit_rnp_key_time_policy_valid(1000U,900U,2000U,2000U), false);
    expect("key-after-expiry", orbit_rnp_key_time_policy_valid(1000U,900U,2000U,2001U), false);
    expect("key-created-after-signature", orbit_rnp_key_time_policy_valid(999U,1000U,2000U,1500U), false);
    expect("zero-key-expiration-sentinel", orbit_rnp_key_time_policy_valid(1000U,900U,0U,1500U), false);
    expect("never-expiring-key-sentinel", orbit_rnp_key_time_policy_valid(1000U,900U,UINT64_MAX,UINT64_C(9000000000)), true);
    if (failures) { printf("decision=FAIL checks=%u failures=%u\n",checks,failures); return 1; }
    printf("decision=PASS checks=%u\n",checks); return 0;
}
