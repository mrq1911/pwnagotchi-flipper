// Pure geo / identity helpers for pwnfriend — NO Flipper/Furi dependencies (only stdint,
// stdbool, math), so they can be unit-tested on the host (see tests/test_geo.cpp). Anything
// touching the model / SDK stays in pwnfriend_app.c.
#pragma once
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Cap the triangulation sample count so the running centroid sums can't grow without bound
// (float rounding would otherwise slowly drift a long-lived estimate).
#define LOC_SAMPLE_CAP 4000

// Parse a decimal-degree string ("50.0784950" / "-14.42") without atof (no %f/newlib-nano
// float-format dependency). Returns 1e9 on empty/NULL so callers can treat it as "unknown".
static inline float parse_deg(const char* s) {
    if(!s || !s[0]) return 1e9f;
    float sign = 1.0f, v = 0.0f;
    const char* p = s;
    if(*p == '-') {
        sign = -1.0f;
        p++;
    } else if(*p == '+') {
        p++;
    }
    while(*p >= '0' && *p <= '9') {
        v = v * 10.0f + (float)(*p - '0');
        p++;
    }
    if(*p == '.') {
        p++;
        float f = 0.1f;
        while(*p >= '0' && *p <= '9') {
            v += (float)(*p - '0') * f;
            f *= 0.1f;
            p++;
        }
    }
    return sign * v;
}

// Sanity-check a lat/lon string pair before we trust it: in-range, and not "null island"
// (~0,0 — the classic no-fix GPS default, never a real location).
static inline bool coord_ok(const char* lat, const char* lon) {
    float la = parse_deg(lat), lo = parse_deg(lon);
    if(la < -90.0f || la > 90.0f || lo < -180.0f || lo > 180.0f) return false;
    if(la > -0.5f && la < 0.5f && lo > -0.5f && lo < 0.5f) return false;
    return true;
}

// Approx great-circle distance in km (equirectangular projection, single precision — plenty
// for the ~city-scale distances we show and the outlier guard).
static inline float geo_km(float lat1, float lon1, float lat2, float lon2) {
    float coslat = cosf(lat1 * 3.14159265f / 180.0f);
    float dn = lat2 - lat1, de = (lon2 - lon1) * coslat;
    return sqrtf(dn * dn + de * de) * 111.0f;
}

// A real pwngrid identity is exactly 64 hex chars (a SHA256 key fingerprint). A garbled or
// truncated sniffed beacon parses into something else, so reject it (mirrors pwngrid's own
// ^[a-fA-F0-9]{64}$ gate) — a mis-parse can't then spawn a bogus peer.
static inline bool identity_is_64hex(const char* s) {
    int n = 0;
    for(; s[n]; n++) {
        if(n >= 64) return false;
        char c = s[n];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if(!hex) return false;
    }
    return n == 64;
}

// Fold one geotagged sighting into a running RSSI-weighted centroid (weighted-centroid
// localization). Stronger signal -> more weight -> the estimate leans toward closest
// approach; averaging cancels per-sample GPS jitter. O(1) storage. rssi==0 (absent) is
// skipped, and accumulation stops at LOC_SAMPLE_CAP to bound float drift.
static inline void loc_accumulate(
    uint16_t* n, float* w_sum, float* wlat_sum, float* wlon_sum, float lat, float lon, int rssi) {
    if(rssi == 0) return;
    if(*n >= LOC_SAMPLE_CAP) return;
    float w = (float)(rssi + 100); // ~ -100dBm floor -> tiny weight, -30dBm close -> ~70
    if(w < 1.0f) w = 1.0f;
    *w_sum += w;
    *wlat_sum += w * lat;
    *wlon_sum += w * lon;
    if(*n < 0xFFFF) (*n)++;
}

// Best position estimate: the weighted centroid once we have >=2 samples and triangulation
// is enabled, else the single strongest fix (fix_lat 1e9 = none). Returns false if no loc.
static inline bool loc_estimate(
    bool tri, uint16_t n, float w_sum, float wlat_sum, float wlon_sum, float fix_lat,
    float fix_lon, float* out_lat, float* out_lon) {
    if(tri && n >= 2 && w_sum > 0.0f) {
        *out_lat = wlat_sum / w_sum;
        *out_lon = wlon_sum / w_sum;
        return true;
    }
    if(fix_lat < 1e8f) {
        *out_lat = fix_lat;
        *out_lon = fix_lon;
        return true;
    }
    return false;
}
