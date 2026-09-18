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

    Serial.print(F("PWNFRIEND_ADV name="));
    Serial.print(_name);
    Serial.print(F(" ch="));
    Serial.print(ch);
    Serial.print(F(" sent="));
    Serial.println(_sent);
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

    // One structured line the Flipper filters on its PWNFRIEND_ prefix.
    Serial.print(F("PWNFRIEND_PEER {\"name\":\""));
    Serial.print(safe_name);
    Serial.print(F("\",\"identity\":\""));
    Serial.print(safe_ident);
    Serial.print(F("\",\"pwnd_tot\":"));
    Serial.print(pwnd_tot);
    Serial.print(F(",\"pwnd_run\":"));
    Serial.print(pwnd_run);
    Serial.print(F(",\"uptime\":"));
    Serial.print(uptime);
    Serial.print(F(",\"rssi\":"));
    Serial.print(rssi);
    Serial.print(F(",\"channel\":"));
    Serial.print(channel);
    Serial.print(F(",\"deauth\":"));
    Serial.print(deauth ? F("true") : F("false"));
    Serial.println(F("}"));
}
