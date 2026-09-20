// Host unit tests for the pure 802.11 frame parsers in pwnfriend-marauder/pwnfriend_frames.h.
// No hardware / Arduino needed: compile with g++ and run (see tests/run.sh).
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "../pwnfriend-marauder/pwnfriend_frames.h"

static int failures = 0;
#define CHECK(cond, name)                       \
    do {                                        \
        if(cond) {                              \
            printf("  ok   %s\n", name);        \
        } else {                                \
            printf("  FAIL %s\n", name);        \
            failures++;                         \
        }                                       \
    } while(0)

// Wrap tagged-param bytes as a beacon: 36-byte header/fixed-params prefix, then the IEs.
static int beacon(uint8_t* buf, const uint8_t* ies, int ielen) {
    memset(buf, 0, 36);
    buf[0] = 0x80; // beacon subtype
    memcpy(buf + 36, ies, ielen);
    return 36 + ielen;
}

// An RSN IE (id 48, len 20) with the given capabilities low/high bytes.
// version, group=CCMP, 1 pairwise=CCMP, 1 AKM=PSK, caps.
#define RSN_IE(caplo, caphi)                                                          \
    48, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2,   \
        (caplo), (caphi)

int main(void) {
    uint8_t f[256];
    int n;

    printf("pwnfriend_rsn_requires_pmf:\n");

    {
        uint8_t ie[] = {RSN_IE(0x40, 0x00)}; // MFPR (bit6) set = PMF required
        n = beacon(f, ie, sizeof(ie));
        CHECK(pwnfriend_rsn_requires_pmf(f, n) == true, "MFPR set -> required");
    }
    {
        uint8_t ie[] = {RSN_IE(0x00, 0x00)}; // no PMF bits
        n = beacon(f, ie, sizeof(ie));
        CHECK(pwnfriend_rsn_requires_pmf(f, n) == false, "no PMF caps -> not required");
    }
    {
        uint8_t ie[] = {RSN_IE(0x80, 0x00)}; // MFPC only (capable, not required)
        n = beacon(f, ie, sizeof(ie));
        CHECK(pwnfriend_rsn_requires_pmf(f, n) == false, "MFPC only -> not required");
    }
    {
        uint8_t ie[] = {RSN_IE(0xC0, 0x00)}; // MFPC + MFPR
        n = beacon(f, ie, sizeof(ie));
        CHECK(pwnfriend_rsn_requires_pmf(f, n) == true, "MFPC+MFPR -> required");
    }
    {
        uint8_t ie[] = {0, 4, 't', 'e', 's', 't'}; // SSID IE only, no RSN
        n = beacon(f, ie, sizeof(ie));
        CHECK(pwnfriend_rsn_requires_pmf(f, n) == false, "no RSN IE -> not required");
    }
    {
        // SSID + Supported Rates before the RSN IE: the walker must reach it.
        uint8_t ie[] = {0, 3, 'a', 'b', 'c', 1, 4, 0x82, 0x84, 0x8b, 0x96, RSN_IE(0x40, 0x00)};
        n = beacon(f, ie, sizeof(ie));
        CHECK(pwnfriend_rsn_requires_pmf(f, n) == true, "RSN after other IEs -> required");
    }
    {
        // RSN IE claims len 20 but the frame is truncated: must not read past the end.
        uint8_t ie[] = {48, 20, 1, 0, 0, 0x0f}; // only 6 bytes present
        n = beacon(f, ie, sizeof(ie));
        CHECK(pwnfriend_rsn_requires_pmf(f, n) == false, "truncated RSN -> false (no overread)");
    }
    {
        // Too short to hold any tagged params.
        memset(f, 0, sizeof(f));
        f[0] = 0x80;
        CHECK(pwnfriend_rsn_requires_pmf(f, 20) == false, "short frame -> false");
    }

    if(failures) {
        printf("\n%d test(s) FAILED\n", failures);
        return 1;
    }
    printf("\nall tests passed\n");
    return 0;
}
