// pure 802.11 parsers for pwnfriend — hardware-free (only stdint/stddef) so host-testable
// (see tests/). anything touching esp_wifi/Serial belongs in Pwnfriend.cpp.
#pragma once
#include <stdint.h>
#include <stddef.h>

// does this beacon/probe-response require 802.11w PMF (RSN MFPR bit)? if so deauth is
// futile, PMKID only. walks tagged params to the RSN IE (id 48) caps. bounds-checked,
// false on malformed input.
static inline bool pwnfriend_rsn_requires_pmf(const uint8_t* f, int len) {
    int p = 36; // tagged params start after the 24-byte mgmt hdr + 12-byte fixed params
    while(p + 2 <= len) {
        int id = f[p], l = f[p + 1];
        if(p + 2 + l > len) break;
        if(id == 48 && l >= 2) { // RSN IE
            const uint8_t* r = f + p + 2;
            int off = 2; // version
            if(off + 4 > l) return false;
            off += 4; // group cipher suite
            if(off + 2 > l) return false;
            int pc = r[off] | (r[off + 1] << 8); // pairwise cipher count
            off += 2 + 4 * pc;
            if(off + 2 > l) return false;
            int ac = r[off] | (r[off + 1] << 8); // AKM suite count
            off += 2 + 4 * ac;
            if(off + 1 > l) return false;
            return (r[off] & 0x40) != 0; // RSN capabilities bit 6 = MFPR (required)
        }
        p += 2 + l;
    }
    return false;
}
