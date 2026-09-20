#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/text_input.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "../include/pwnfriend.h"
#include "../include/persona.h"
#include "../include/peers.h"
#include "../include/face.h"
#include "../include/pwnagotchi.h"
#include "../include/consent.h"
#include "../include/pcap.h"
#include "../include/wardrive.h"
#include "qrcodegen.h"
#include <storage/storage.h>

typedef enum {
    WorkerEventStop = (1 << 0),
    WorkerEventRx = (1 << 1),
    WorkerEventResend = (1 << 2), // fire pwnfriend_send_advertise off the worker's 2K stack
} WorkerEventFlags;

#define WORKER_EVENTS_MASK (WorkerEventStop | WorkerEventRx | WorkerEventResend)

// Distinct BSSIDs whose capture we've already counted this app session. Caps the
// per-session pwnd dedup table; a re-emitted PWNFRIEND_PWND (the Flipper re-sends
// the whole command every 15s) is then idempotent and can't inflate pwnd_run/tot.
#define PWND_SEEN_MAX 64

// Per-AP records: the browser + crackability progress + target/whitelist all read
// this. Also fixes the old pause/resume AP-count inflation (the firmware re-emits
// its whole recon list on resume; we key by BSSID so each network counts once).
#define AP_MAX 256 // browsable AP history (persisted across sessions to aps.bin)
#define WL_MAX 16 // whitelisted BSSIDs we send to the firmware (matches its MAX_WL)

// "Home" point — the GPS stat shows distance + compass direction to here. This is
// the default; "Set home" in the menu overrides it with the current fix (persisted).
#define HOME_LAT 50.081148f
#define HOME_LON 14.451144f
#define HOME_NAME "Home"
#define HOME_DB_PATH "/ext/apps_data/pwnfriend/home.bin"
#define HOME_DB_MAGIC 0x484D4E46u // 'FNMH'

// Persisted AP table (so you can browse APs/pwns from previous sessions).
#define AP_DB_PATH "/ext/apps_data/pwnfriend/aps.bin"
#define AP_DB_MAGIC 0x50414E46u // 'FNAP'
#define AP_DB_VERSION 1

typedef struct {
    char bssid[13]; // 12-hex key (no colons)
    char ssid[33]; // ESSID, empty if hidden/unknown
    int16_t channel;
    int16_t rssi; // most recent
    bool has_essid; // a named SSID was seen (a 22000 hashline needs it -> crackable)
    bool pmkid; // captured a PMKID (M1)
    bool handshake; // captured a 4-way handshake (M2)
    bool missed; // firmware reported a MISS (attacked, nothing caught)
    bool whitelisted; // user: never attack this one
    bool targeted; // user: focus the hunt on this one
} ApRec;

// Capture escalation. Default is Deauth (a full pwnagotchi), gated behind the
// one-time consent acknowledgement (cycled from the menu). Passive = record
// handshakes the firmware sniffs; Deauth = also associate + deauth (-deauth 1).
typedef enum {
    CaptureOff = 0,
    CapturePassive,
    CaptureDeauth,
} CaptureMode;

// Which stat the persona "speaks" on the home screen; cycled Left/Right.
typedef enum {
    StatPageMood = 0, // the pwnagotchi voice line (default)
    StatPageCounts, // "ate N shakes!"
    StatPageSocial, // "met N friends!"
    StatPageGps, // distance+direction to home ("Prague 12km SW"); full coords on the Stats screen
    StatPageCount,
} StatPage;

// App screens. Home is the pwnagotchi; OK opens the menu; the rest hang off it.
typedef enum {
    ScreenHome = 0,
    ScreenMenu,
    ScreenApList,
    ScreenApDetail,
    ScreenStats,
    ScreenAbout,
} Screen;

// Menu rows. The nav rows (OK opens a sub-screen) come first, then the live config
// rows (Left/Right adjust, or OK toggles/cycles).
typedef enum {
    MenuPwnedAps = 0,
    MenuAllAps,
    MenuStats,
    MenuAdvertise,
    MenuCapture,
    MenuName,
    MenuChannel,
    MenuMinRssi,
    MenuRecon,
    MenuSetHome,
    MenuAbout,
    MenuCount,
} MenuItem;

typedef struct {
    Persona* persona;
    PeerList peers;
    uint32_t tick_secs;
    bool advertising;
    uint32_t last_adv_sent;
    uint32_t adv_sent_count; // last "sent=" from the ESP32
    uint8_t adv_channel; // last channel it reported broadcasting on
    Pwnagotchi* pwn; // flipagotchi renderer state, repopulated each draw
    char last_pwnd_ssid[33]; // most recent capture, for the PWND/message readout
    CaptureMode capture_mode; // OFF by default; the deauth/capture gate
    bool consent_given; // cached consent_is_given() — capture UI is locked until true
    bool showing_consent; // modal: the one-time authorization acknowledgement

    // Per-session capture dedup: 12-hex (no-colon) BSSIDs we've already counted.
    char pwnd_seen[PWND_SEEN_MAX][13];
    uint8_t pwnd_seen_count;

    // Every AP we've seen this session (the browser reads this).
    ApRec aps[AP_MAX];
    uint16_t ap_count;

    // Channel tuning: 0 = auto (the pwnagotchi '*' sweep, default); 1..14 = pinned.
    int8_t tuned_channel;
    uint8_t stat_page; // home persona stat, cycled Left/Right
    int8_t min_rssi; // attack floor sent as -minrssi (default -78)
    uint16_t recon_secs; // recon_time sent as -recon (default 30)

    // View state.
    Screen screen;
    uint8_t menu_idx; // selected row in ScreenMenu
    uint16_t list_idx; // selected AP index (into the filtered list) in ScreenApList
    uint16_t list_top; // scroll window top in ScreenApList
    bool list_pwned_only; // ScreenApList filter
    uint16_t detail_ap; // aps[] index shown in ScreenApDetail

    // GPS: set once the firmware reports any lat/lon (geotag seen). last_lat/lon
    // are verbatim decimal-degree strings from the most recent fix.
    bool gps_seen;
    char last_lat[16];
    char last_lon[16];
    char gps_place[32]; // distance+direction to home, e.g. "Home 12km SW"
    float home_lat, home_lon; // the point the GPS compass points at (default Prague; settable)

    // ESP32-link watchdog: warn when the board stops answering (unplugged, rear
    // switch off ESP32, wrong firmware). All in tick_secs, written under the lock.
    uint32_t last_rx_secs; // tick of the last PWNFRIEND_* line seen
    uint32_t advertising_since; // tick advertising last (re)started — boot grace
    bool link_down; // computed each tick; true => the "no ESP32" screen shows

    // Setup QR (encoded once at alloc; the draw callback only reads modules).
    uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
    bool qr_ok;
} PwnfriendModel;

typedef struct {
    Gui* gui;
    NotificationApp* notification;
    ViewDispatcher* view_dispatcher;
    View* view;
    FuriThread* worker_thread;
    FuriStreamBuffer* rx_stream;
    FuriHalSerialHandle* serial_handle;
    FuriTimer* timer;
    Storage* storage; // for the handshake pcap writer
    TextInput* text_input; // "Set name" editor (view id 1)
    char name_buf[PERSONA_NAME_MAX]; // edit buffer for the name text input

    // Line assembly — touched only by the worker thread. Sized to hold a whole
    // hex-encoded EAPOL frame line (PWNFRIEND_HS <bssid> <~600 hex>), not just JSON.
    char line[1024];
    size_t line_len;
    bool got_new_friend; // set by worker, consumed for a notification blink
    bool got_pwnd; // set by worker, consumed for the capture blink
} PwnfriendApp;

static const NotificationSequence sequence_new_friend = {
    &message_display_backlight_on,
    &message_green_255,
    &message_vibro_on,
    &message_delay_50,
    &message_vibro_off,
    NULL,
};

// A louder blink for an actual handshake capture — this is the "got pwnd" moment.
static const NotificationSequence sequence_pwnd = {
    &message_display_backlight_on,
    &message_red_255,
    &message_blue_255,
    &message_vibro_on,
    &message_delay_50,
    &message_vibro_off,
    &message_delay_50,
    &message_vibro_on,
    &message_delay_50,
    &message_vibro_off,
    NULL,
};

// ---------------------------------------------------------------------------
// Serial: build + send the advertise command, and stop.
// ---------------------------------------------------------------------------

static void pwnfriend_send_advertise(PwnfriendApp* app) {
    char cmd[512]; // room for the base command + a whitelist of up to WL_MAX BSSIDs
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            Persona* p = model->persona;
            char safe_name[PERSONA_NAME_MAX];
            strncpy(safe_name, p->s.name, sizeof(safe_name));
            safe_name[sizeof(safe_name) - 1] = '\0';
            for(char* c = safe_name; *c; c++) {
                if(*c == ' ') *c = '_';
            }
            // -pr/-pt now carry REAL captured-handshake counts; -e the epoch.
            // -cap/-deauth are the honest firmware-side gates: both are sent as an
            // explicit 0/1 every advertise so a previously-armed radio is actively
            // disarmed (a "real gate" must be able to turn OFF, not just ON). -cap
            // is 1 in Passive/Deauth, -deauth is 1 only in Deauth. The firmware
            // mirrors -deauth into the beacon's policy.deauth, so the mesh always
            // sees the truth. Current firmware that doesn't know -cap ignores it.
            int cap = (model->capture_mode != CaptureOff) ? 1 : 0;
            int deauth = (model->capture_mode == CaptureDeauth) ? 1 : 0;
            // -ch: 0 tells the firmware to auto-hop (the '*' sweep); 1..14 pins it
            // to the channel the user tuned to with Up/Down.
            int ch = (model->tuned_channel >= 1 && model->tuned_channel <= 14) ?
                         model->tuned_channel : 0;
            // -target: the BSSID the user is focusing on (or "0" = none). -wl: the
            // whitelisted BSSIDs (capped at WL_MAX). -minrssi / -recon: pwnagotchi
            // params from the menu. Building the wl list first keeps the snprintf flat.
            char target[13] = "0";
            char wl[WL_MAX * 13 + 4];
            size_t wp = 0;
            size_t wn = 0;
            wl[0] = '\0';
            for(uint16_t i = 0; i < model->ap_count; i++) {
                if(model->aps[i].targeted) {
                    strncpy(target, model->aps[i].bssid, sizeof(target) - 1);
                    target[sizeof(target) - 1] = '\0';
                }
                if(model->aps[i].whitelisted && wn < WL_MAX && wp < sizeof(wl)) {
                    int n = snprintf(
                        wl + wp, sizeof(wl) - wp, "%s%s", wn ? "," : "", model->aps[i].bssid);
                    if(n > 0) wp += (size_t)n;
                    wn++;
                }
            }
            if(wn == 0) { wl[0] = '0'; wl[1] = '\0'; } // "0" = clear the whitelist
            snprintf(
                cmd,
                sizeof(cmd),
                "pwnfriend -n %s -id %s -f %d -pr %lu -pt %lu -u %lu -e %lu -cap %d "
                "-deauth %d -ch %d -minrssi %d -recon %u -target %s -wl %s\n",
                safe_name,
                p->s.identity,
                (int)persona_face(p),
                (unsigned long)p->pwnd_run, // REAL handshakes this run
                (unsigned long)p->s.pwnd_tot, // REAL handshakes lifetime
                (unsigned long)p->s.total_uptime,
                (unsigned long)p->epoch,
                cap,
                deauth,
                ch,
                (int)model->min_rssi,
                (unsigned)model->recon_secs,
                target,
                wl);
            model->last_adv_sent = model->tick_secs;
        },
        false);

    furi_hal_serial_tx(app->serial_handle, (const uint8_t*)cmd, strlen(cmd));
}

static void pwnfriend_send_stop(PwnfriendApp* app) {
    const char* cmd = "stopscan\n";
    furi_hal_serial_tx(app->serial_handle, (const uint8_t*)cmd, strlen(cmd));
}

// ---------------------------------------------------------------------------
// Serial: parse incoming PWNFRIEND_ lines.
// ---------------------------------------------------------------------------

static bool line_extract_str(const char* s, const char* key, char* out, size_t out_sz) {
    const char* pos = strstr(s, key);
    if(!pos) return false;
    pos += strlen(key);
    size_t i = 0;
    while(*pos && *pos != '"' && i < out_sz - 1) {
        out[i++] = *pos++;
    }
    out[i] = '\0';
    return true;
}

static bool line_extract_int(const char* s, const char* key, int* out) {
    const char* pos = strstr(s, key);
    if(!pos) return false;
    *out = atoi(pos + strlen(key));
    return true;
}

// Copy the numeric token after `key` verbatim (sign/digits/dot/exponent) into out.
// We never parse lat/lon to a float — the Flipper printf has %f disabled — so the
// firmware's decimal-degree text is passed straight through to the wardrive CSV.
static bool line_extract_number(const char* s, const char* key, char* out, size_t out_sz) {
    const char* pos = strstr(s, key);
    if(!pos) return false;
    pos += strlen(key);
    size_t i = 0;
    while(*pos && i < out_sz - 1) {
        char c = *pos;
        bool numeric = (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' ||
                       c == 'e' || c == 'E';
        if(!numeric) break;
        out[i++] = c;
        pos++;
    }
    out[i] = '\0';
    return i > 0;
}

static void pwnfriend_handle_peer_line(PwnfriendApp* app, const char* line) {
    char name[PEER_NAME_MAX] = {0};
    char identity[PEER_ID_MAX] = {0};
    int pwnd_tot = 0, rssi = 0, channel = 0;

    line_extract_str(line, "\"name\":\"", name, sizeof(name));
    line_extract_str(line, "\"identity\":\"", identity, sizeof(identity));
    line_extract_int(line, "\"pwnd_tot\":", &pwnd_tot);
    line_extract_int(line, "\"rssi\":", &rssi);
    line_extract_int(line, "\"channel\":", &channel);

    bool is_new = false;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            uint32_t now = model->tick_secs;
            is_new = peers_update(
                &model->peers, name, identity, pwnd_tot, rssi, channel, now);
            bool bonded = peers_any_bonded(&model->peers, now);
            persona_note_peer(model->persona, is_new, bonded);
        },
        true);

    if(is_new) app->got_new_friend = true;
}

static void pwnfriend_handle_adv_line(PwnfriendApp* app, const char* line) {
    int ch = 0, sent = 0;
    line_extract_int(line, "ch=", &ch);
    line_extract_int(line, "sent=", &sent);
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            model->adv_channel = (uint8_t)ch;
            model->adv_sent_count = (uint32_t)sent;
        },
        true);
}

static int hexval(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Normalise a bssid to a 12-char lowercase-hex key (colons dropped). Non-hex is
// skipped, so both "aa:bb:cc:dd:ee:ff" and "aabbccddeeff" collapse to one key.
static void bssid_key(char out[13], const char* in) {
    size_t n = 0;
    for(const char* c = in; *c && n < 12; c++) {
        if(hexval(*c) < 0) continue;
        out[n++] = (*c >= 'A' && *c <= 'F') ? (char)(*c + 32) : *c;
    }
    out[n] = '\0';
}

// Insert a bssid key into the per-session pwnd dedup set. Returns true only on the
// first sight of that bssid (so persona_note_pwnd fires once). When the table is
// full, returns false — mirrors the firmware's markPwnd cap so counts can't run away.
static bool pwnd_seen_insert(PwnfriendModel* model, const char* key) {
    if(!key[0]) return false;
    for(uint8_t i = 0; i < model->pwnd_seen_count; i++) {
        if(strcmp(model->pwnd_seen[i], key) == 0) return false;
    }
    if(model->pwnd_seen_count >= PWND_SEEN_MAX) return false;
    strncpy(model->pwnd_seen[model->pwnd_seen_count], key, 12);
    model->pwnd_seen[model->pwnd_seen_count][12] = '\0';
    model->pwnd_seen_count++;
    return true;
}

// Find the AP record for a 12-hex key, or -1.
static int ap_find(PwnfriendModel* model, const char* key) {
    for(uint16_t i = 0; i < model->ap_count; i++)
        if(strcmp(model->aps[i].bssid, key) == 0) return (int)i;
    return -1;
}

// Get (creating if needed) the AP record for `key`. Returns its index, or -1 when
// the key is empty or the table is full and the AP is new. *is_new is set when a
// record was just created (so the AP count / persona_note_ap fire once per BSSID).
static int ap_get(PwnfriendModel* model, const char* key, bool* is_new) {
    *is_new = false;
    if(!key[0]) return -1;
    int i = ap_find(model, key);
    if(i >= 0) return i;
    if(model->ap_count >= AP_MAX) return -1;
    i = (int)model->ap_count++;
    memset(&model->aps[i], 0, sizeof(ApRec));
    strncpy(model->aps[i].bssid, key, 12);
    model->aps[i].bssid[12] = '\0';
    *is_new = true;
    return i;
}

// Persisted AP table, so the browser shows APs/pwns from previous sessions too.
// `targeted` is session-only (cleared on load); whitelist persists and is re-sent to
// the firmware by the first advertise.
static void ap_db_load(Storage* storage, PwnfriendModel* model) {
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, AP_DB_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint32_t hdr[3] = {0};
        if(storage_file_read(f, hdr, sizeof(hdr)) == sizeof(hdr) && hdr[0] == AP_DB_MAGIC &&
           hdr[1] == AP_DB_VERSION) {
            uint32_t n = hdr[2] > AP_MAX ? AP_MAX : hdr[2];
            size_t got = storage_file_read(f, model->aps, n * sizeof(ApRec));
            model->ap_count = (uint16_t)(got / sizeof(ApRec));
            for(uint16_t i = 0; i < model->ap_count; i++) model->aps[i].targeted = false;
        }
    }
    storage_file_close(f);
    storage_file_free(f);
}

static void ap_db_save(Storage* storage, PwnfriendModel* model) {
    storage_common_mkdir(storage, "/ext/apps_data/pwnfriend");
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, AP_DB_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        uint32_t hdr[3] = {AP_DB_MAGIC, AP_DB_VERSION, model->ap_count};
        storage_file_write(f, hdr, sizeof(hdr));
        storage_file_write(f, model->aps, (size_t)model->ap_count * sizeof(ApRec));
    }
    storage_file_close(f);
    storage_file_free(f);
}

typedef struct {
    uint32_t magic;
    uint32_t version;
    float lat;
    float lon;
} HomeDb;

static void home_load(Storage* storage, PwnfriendModel* model) {
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, HOME_DB_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        HomeDb h = {0};
        if(storage_file_read(f, &h, sizeof(h)) == sizeof(h) && h.magic == HOME_DB_MAGIC) {
            model->home_lat = h.lat;
            model->home_lon = h.lon;
        }
    }
    storage_file_close(f);
    storage_file_free(f);
}

static void home_save(Storage* storage, PwnfriendModel* model) {
    storage_common_mkdir(storage, "/ext/apps_data/pwnfriend");
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, HOME_DB_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        HomeDb h = {HOME_DB_MAGIC, 1, model->home_lat, model->home_lon};
        storage_file_write(f, &h, sizeof(h));
    }
    storage_file_close(f);
    storage_file_free(f);
}

// Parse a decimal-degree string ("50.0784950" / "-14.42") to double without atof
// (avoids any %f/newlib-nano float-formatting dependency). Returns 1e9 on empty.
static float parse_deg(const char* s) {
    if(!s || !s[0]) return 1e9f;
    float sign = 1.0f, v = 0.0f;
    const char* p = s;
    if(*p == '-') { sign = -1.0f; p++; } else if(*p == '+') { p++; }
    while(*p >= '0' && *p <= '9') { v = v * 10.0f + (float)(*p - '0'); p++; }
    if(*p == '.') {
        p++;
        float f = 0.1f;
        while(*p >= '0' && *p <= '9') { v += (float)(*p - '0') * f; f *= 0.1f; p++; }
    }
    return sign * v;
}

// Format model->gps_place as distance + 8-point compass direction from the last fix
// to HOME (e.g. "Prague 12km SW", "Prague 320m NE", "At Prague!"). Single-precision
// math only (Cortex-M4F builds with -Werror=double-promotion).
static void pwnfriend_update_place(PwnfriendModel* model) {
    float lat = parse_deg(model->last_lat), lon = parse_deg(model->last_lon);
    if(lat >= 1e8f || lon >= 1e8f) { model->gps_place[0] = '\0'; return; }
    float coslat = cosf(lat * 3.14159265f / 180.0f);
    float north = model->home_lat - lat; // degrees north to home
    float east = (model->home_lon - lon) * coslat; // degrees east to home (longitude-corrected)
    float km = sqrtf(north * north + east * east) * 111.0f; // ~111 km / degree
    static const char* DIRS[8] = {"N", "NE", "E", "SE", "S", "SW", "W", "NW"};
    // atan2f: 0 = due north, +pi/2 = east. Round to eighths; &7 wraps negatives correctly.
    const char* dir = DIRS[((int)roundf(atan2f(east, north) / 0.78539816f)) & 7];
    if(km < 0.3f) {
        snprintf(model->gps_place, sizeof(model->gps_place), "At %s!", HOME_NAME);
    } else if(km < 1.0f) {
        snprintf(
            model->gps_place, sizeof(model->gps_place), "%s %dm %s", HOME_NAME,
            (int)(km * 1000.0f), dir);
    } else {
        snprintf(
            model->gps_place, sizeof(model->gps_place), "%s %dkm %s", HOME_NAME, (int)(km + 0.5f),
            dir);
    }
}

static void pwnfriend_handle_pwnd_line(PwnfriendApp* app, const char* line) {
    char bssid[18] = {0};
    char ssid[33] = {0};
    char type[12] = {0};
    char lat[16] = {0};
    char lon[16] = {0};
    int channel = 0, rssi = 0;

    line_extract_str(line, "\"bssid\":\"", bssid, sizeof(bssid));
    line_extract_str(line, "\"ssid\":\"", ssid, sizeof(ssid));
    line_extract_str(line, "\"type\":\"", type, sizeof(type));
    line_extract_int(line, "\"channel\":", &channel);
    line_extract_int(line, "\"rssi\":", &rssi);
    // lat/lon are present only when the GPS had a fix (contract v2); both or neither.
    bool have_gps = line_extract_number(line, "\"lat\":", lat, sizeof(lat)) &&
                    line_extract_number(line, "\"lon\":", lon, sizeof(lon));

    const char* label = ssid[0] ? ssid : bssid;
    char key[13];
    bssid_key(key, bssid);

    bool counted = false;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            // Gate the earned count behind the consent + capture opt-in: without
            // it we ignore whatever the firmware happens to report. Dedup by BSSID
            // across the session so a re-emitted PWND (every 15s) counts only once.
            if(model->capture_mode != CaptureOff && pwnd_seen_insert(model, key)) {
                persona_note_pwnd(model->persona);
                strncpy(model->last_pwnd_ssid, label, sizeof(model->last_pwnd_ssid) - 1);
                model->last_pwnd_ssid[sizeof(model->last_pwnd_ssid) - 1] = '\0';
                counted = true;
            }
            // Record the capture on the AP (browser + progress), regardless of the
            // count gate — it reflects what actually landed.
            bool ap_new = false;
            int ai = ap_get(model, key, &ap_new);
            if(ai >= 0) {
                ApRec* a = &model->aps[ai];
                if(ap_new) persona_note_ap(model->persona);
                if(channel) a->channel = (int16_t)channel;
                if(rssi) a->rssi = (int16_t)rssi;
                if(ssid[0] && !a->has_essid) {
                    strncpy(a->ssid, ssid, sizeof(a->ssid) - 1);
                    a->ssid[sizeof(a->ssid) - 1] = '\0';
                    a->has_essid = true;
                }
                if(strcmp(type, "pmkid") == 0) a->pmkid = true;
                else a->handshake = true;
            }
            if(have_gps) {
                model->gps_seen = true;
                strncpy(model->last_lat, lat, sizeof(model->last_lat) - 1);
                model->last_lat[sizeof(model->last_lat) - 1] = '\0';
                strncpy(model->last_lon, lon, sizeof(model->last_lon) - 1);
                model->last_lon[sizeof(model->last_lon) - 1] = '\0';
                pwnfriend_update_place(model); // nearest major city, offline
            }
        },
        true);

    // A captured handshake implies WPA/WPA2-PSK; log it (once) as a geotagged row.
    if(have_gps && counted) {
        wardrive_log(
            app->storage, bssid, ssid, "[WPA2-PSK-CCMP][ESS]", channel, rssi, lat, lon);
    }

    if(counted) app->got_pwnd = true; // capture blink
}

static void pwnfriend_handle_ap_line(PwnfriendApp* app, const char* line) {
    char bssid[18] = {0};
    char ssid[33] = {0};
    char lat[16] = {0};
    char lon[16] = {0};
    int channel = 0, rssi = 0;

    line_extract_str(line, "\"bssid\":\"", bssid, sizeof(bssid));
    line_extract_str(line, "\"ssid\":\"", ssid, sizeof(ssid));
    line_extract_int(line, "\"channel\":", &channel);
    line_extract_int(line, "\"rssi\":", &rssi);
    bool have_gps = line_extract_number(line, "\"lat\":", lat, sizeof(lat)) &&
                    line_extract_number(line, "\"lon\":", lon, sizeof(lon));

    char key[13];
    bssid_key(key, bssid);

    bool is_new_ap = false;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            // Upsert the AP record (browser + progress). New BSSID -> count it once,
            // so a pause/resume replay of the firmware's recon list can't inflate it.
            int ai = ap_get(model, key, &is_new_ap);
            if(ai >= 0) {
                ApRec* a = &model->aps[ai];
                a->channel = (int16_t)channel;
                a->rssi = (int16_t)rssi;
                if(ssid[0]) {
                    strncpy(a->ssid, ssid, sizeof(a->ssid) - 1);
                    a->ssid[sizeof(a->ssid) - 1] = '\0';
                    a->has_essid = true;
                }
            }
            if(is_new_ap) persona_note_ap(model->persona);
            if(have_gps) {
                model->gps_seen = true;
                strncpy(model->last_lat, lat, sizeof(model->last_lat) - 1);
                model->last_lat[sizeof(model->last_lat) - 1] = '\0';
                strncpy(model->last_lon, lon, sizeof(model->last_lon) - 1);
                model->last_lon[sizeof(model->last_lon) - 1] = '\0';
                pwnfriend_update_place(model); // nearest major city, offline
            }
        },
        true);

    // One geotagged wardrive row per network — only for a first-seen BSSID, so a
    // pause/resume replay doesn't write the same AP again. Encryption is unknown
    // from a beacon here.
    if(have_gps && is_new_ap) {
        wardrive_log(app->storage, bssid, ssid, "[ESS]", channel, rssi, lat, lon);
    }
}

static void pwnfriend_handle_hs_line(PwnfriendApp* app, const char* line) {
    // Contract v2, self-describing:
    //   line = "PWNFRIEND_HS <bssid12hex> <lowercase-hex-of-the-full-802.11-frame>"
    // The bssid on THIS line names the per-target pcap, so a beacon (streamed by
    // reportAP) and its EAPOL frames land in the same <bssid>.pcap without relying
    // on a preceding PWND — that's what makes the file ESSID-bearing and crackable.
    const char* p = line + 13; // past "PWNFRIEND_HS "

    // Parse exactly 12 hex chars for the bssid, then require the space separator.
    char bssid[13];
    size_t bi = 0;
    while(*p && *p != ' ' && bi < sizeof(bssid) - 1) {
        if(hexval(*p) < 0) return; // malformed bssid -> drop the line
        bssid[bi++] = (*p >= 'A' && *p <= 'F') ? (char)(*p + 32) : *p;
        p++;
    }
    bssid[bi] = '\0';
    if(bi != 12 || *p != ' ') return; // need 12 hex chars then a single space
    p++; // step past the separator to the frame hex

    // Only record if capture is opted in; otherwise silently drop the frame.
    bool record = false;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        { record = (model->capture_mode != CaptureOff); },
        false);
    if(!record) return;

    static uint8_t frame[PCAP_SNAPLEN];
    size_t flen = 0;
    while(p[0] && p[1] && flen < sizeof(frame)) {
        int hi = hexval(p[0]), lo = hexval(p[1]);
        if(hi < 0 || lo < 0) return; // corrupt line -> drop, don't write
        frame[flen++] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    if(flen == 0) return;

    // bssid is already fs-safe (12 lowercase hex), so it's the pcap filename.
    pcap_append_frame(app->storage, bssid, frame, (uint16_t)flen);
}

static void pwnfriend_handle_miss_line(PwnfriendApp* app, const char* line) {
    // pwnagotchi's on_miss: firmware attacked an AP MISS_ATTEMPTS times with no
    // capture. Flash the demotivated face + feed the epoch's miss tally, and mark the
    // AP so the browser shows it's been struggled with. Gated on capture being armed
    // (like the pwnd/hs handlers) so a stray MISS while Off/paused can't skew the mood.
    char key[13];
    bssid_key(key, line + 15); // past "PWNFRIEND_MISS "
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            if(model->capture_mode != CaptureOff) {
                persona_note_miss(model->persona);
                bool ap_new = false;
                int ai = ap_get(model, key, &ap_new);
                if(ai >= 0) {
                    if(ap_new) persona_note_ap(model->persona);
                    model->aps[ai].missed = true;
                }
            }
        },
        true);
}

static void pwnfriend_process_line(PwnfriendApp* app, const char* line) {
    // PWNFRIEND_PWND and PWNFRIEND_PEER share the PWNFRIEND_P prefix, so both
    // full comparisons are needed.
    if(strncmp(line, "PWNFRIEND_PEER ", 15) == 0) {
        pwnfriend_handle_peer_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_PWND ", 15) == 0) {
        pwnfriend_handle_pwnd_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_HS ", 13) == 0) {
        pwnfriend_handle_hs_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_AP ", 13) == 0) {
        pwnfriend_handle_ap_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_ADV ", 14) == 0) {
        pwnfriend_handle_adv_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_MISS ", 15) == 0) {
        pwnfriend_handle_miss_line(app, line);
    }
    // Any recognized PWNFRIEND_* line proves the board + firmware are alive; stamp
    // the link watchdog (in one place so it also scopes detection to OUR firmware).
    if(strncmp(line, "PWNFRIEND_", 10) == 0) {
        with_view_model(
            app->view,
            PwnfriendModel * model,
            {
                model->last_rx_secs = model->tick_secs;
                model->link_down = false; // instant recovery, don't wait for the timer
            },
            false);
    }
    // Any other line is ordinary Marauder chatter; ignore it.
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

// Map the persona + detected peers onto the flipagotchi Pwnagotchi struct so we
// render exactly like a real pwnagotchi screen (CH / APS / UP / PWND / message /
// friend slot). Repopulated each draw so it's always current.
static void pwnfriend_populate(PwnfriendModel* model) {
    Persona* p = model->persona;
    Pwnagotchi* pwn = model->pwn;

    furi_string_set(pwn->hostname, p->s.name);
    pwn->face = (enum PwnagotchiFace)persona_face(p);
    pwn->mode = PwnMode_Ai;

    // CH: the tuned channel, or '*' for auto (the pwnagotchi recon sweep) — matches
    // upstream, which shows '*' while hopping and a number when locked to a channel.
    if(model->tuned_channel >= 1 && model->tuned_channel <= 14) {
        furi_string_printf(pwn->channel, "%d", model->tuned_channel);
    } else {
        furi_string_set(pwn->channel, "*");
    }

    // AP: access points seen this session. Session-only keeps the compact top row
    // (CH/AP/UP) inside 128px even with a 3-digit count; lifetime stays in save data.
    furi_string_printf(pwn->apStat, "%lu", (unsigned long)p->aps_session);

    // UP: this session's uptime as hh:mm:ss (resets each app launch). Lifetime total
    // still lives in save data and is advertised via -u.
    uint32_t up = (uint32_t)p->session_uptime;
    furi_string_printf(
        pwn->uptime,
        "%02lu:%02lu:%02lu",
        (unsigned long)(up / 3600),
        (unsigned long)((up % 3600) / 60),
        (unsigned long)(up % 60));

    // PWND: real handshakes captured, this session (lifetime).
    furi_string_printf(
        pwn->handshakes,
        "%lu (%lu)",
        (unsigned long)p->pwnd_run,
        (unsigned long)p->s.pwnd_tot);

    // Message area: paused hint, else the stat page chosen with Left/Right. Page 0
    // (Mood) is the pwnagotchi voice line, with a fresh-catch shout taking over it.
    if(!model->advertising) {
        furi_string_set(pwn->message, "paused - OK for menu");
    } else if((p->mood == MoodHappy || p->mood == MoodCool) && model->last_pwnd_ssid[0]) {
        furi_string_printf(pwn->message, "pwnd %s!", model->last_pwnd_ssid);
    } else {
        // The persona SPEAKS the stat you scrolled to (Left/Right), in its own voice,
        // kept short so it never overflows the bubble. Precise figures (GPS coords,
        // beacons, epoch) live full-width on the Stats screen (OK -> Stats).
        switch(model->stat_page) {
        case StatPageCounts:
            furi_string_printf(pwn->message, "I ate %lu shakes!", (unsigned long)p->pwnd_run);
            break;
        case StatPageSocial:
            if(p->s.friends_met == 0)
                furi_string_set(pwn->message, "No friends yet...");
            else
                furi_string_printf(
                    pwn->message, "Met %lu friends!", (unsigned long)p->s.friends_met);
            break;
        case StatPageGps:
            if(model->gps_seen && model->gps_place[0])
                furi_string_set(pwn->message, model->gps_place); // "Near Prague"
            else if(model->gps_seen)
                furi_string_set(pwn->message, "I'm here!");
            else
                furi_string_set(pwn->message, "No GPS...");
            break;
        case StatPageMood:
        default:
            furi_string_set(pwn->message, persona_mood_label(p));
            break;
        }
    }

    // Friend slot: the closest (strongest) unit, with signal bars.
    Peer* best = NULL;
    for(int i = 0; i < MAX_PEERS; i++) {
        Peer* pe = &model->peers.items[i];
        if(!pe->used) continue;
        if(!best || pe->rssi > best->rssi) best = pe;
    }
    if(best) {
        int bars = peers_rssi_bars(best->rssi);
        furi_string_reset(pwn->friendStat);
        for(int b = 0; b < bars; b++) furi_string_cat_str(pwn->friendStat, "|");
        for(int b = bars; b < 4; b++) furi_string_cat_str(pwn->friendStat, ".");
        furi_string_cat_printf(pwn->friendStat, " %s %d", best->name, best->pwnd_tot);
    } else {
        furi_string_set(pwn->friendStat, "");
    }
}

// The one-time authorization acknowledgement, shown before capture can be armed.
static void pwnfriend_draw_consent(Canvas* canvas) {
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 9, "Capture & deauth");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 21, "Capture/deauth only on");
    canvas_draw_str(canvas, 2, 30, "networks you own or are");
    canvas_draw_str(canvas, 2, 39, "authorized to test.");
    canvas_draw_str(canvas, 2, 48, "You are responsible.");
    canvas_draw_str(canvas, 2, 62, "Hold OK=accept  Back=no");
}

// Encode the setup URL into the model's QR buffer, once. Runs on the app thread
// (never the draw callback, which is on the GUI service thread). maxVersion is
// capped at 4 so the two scratch/output buffers stay 138 B (a version-40 buffer
// would be ~3.9 KB and blow the stack).
static void pwnfriend_qr_encode(PwnfriendModel* model) {
    uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
    model->qr_ok = qrcodegen_encodeText(
        PWNFRIEND_SETUP_URL, tmp, model->qr, qrcodegen_Ecc_LOW, 1, 4,
        qrcodegen_Mask_AUTO, true);
}

// "No ESP32" full-screen warning shown when the board stops answering. The setup
// QR (left) points at the compatible-hardware + firmware doc; the text (right)
// says what to check. Modules are drawn as boxes so it scales crisply.
static void pwnfriend_draw_link_down(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    if(model->qr_ok) {
        int size = qrcodegen_getSize(model->qr); // 29 for this URL
        int scale = 2; // 29*2 = 58 px, fits the 64 px height with a small quiet zone
        int oy = (FLIPPER_SCREEN_HEIGHT - size * scale) / 2;
        for(int y = 0; y < size; y++) {
            for(int x = 0; x < size; x++) {
                if(qrcodegen_getModule(model->qr, x, y)) {
                    canvas_draw_box(canvas, 3 + x * scale, oy + y * scale, scale, scale);
                }
            }
        }
    }
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 66, 10, "No ESP32");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 66, 24, "No data from");
    canvas_draw_str(canvas, 66, 33, "the board.");
    canvas_draw_str(canvas, 66, 45, "Scan: setup");
    canvas_draw_str(canvas, 66, 54, "& firmware.");
}

// Bottom-right status cluster, in the corner freed by dropping the AI/AUTO/MANU
// mode tag. Laid out right-to-left so nothing overruns the screen edge or the
// PWND/friend rows on the left. The old status cluster (CAP/DEAUTH/GPS/dot) lived
// here but was noise — this space now shows the last pwned AP, right-aligned on the
// PWND baseline row, clamped so it never collides with the "PWND N (N)" count on the
// left. Capture mode moved to the Left/Right "counts" stat page; GPS to its own page.
#define PWNFRIEND_STATUS_LEFT_LIMIT 64
#define PWNFRIEND_STATUS_Y PWNAGOTCHI_HANDSHAKES_I // 63, the PWND baseline row

static void pwnfriend_draw_last_pwnd(Canvas* canvas, const PwnfriendModel* model) {
    if(!model->last_pwnd_ssid[0]) return; // nothing captured yet -> leave it blank
    canvas_set_font(canvas, FontSecondary);
    // Left limit = the actual width the "PWND N (N)" count occupies (measured, so a
    // big lifetime count can't be overlapped) + a gap. pwn->handshakes is already
    // populated for this frame by pwnfriend_populate().
    int left_limit = canvas_string_width(canvas, "PWND ") +
                     canvas_string_width(canvas, furi_string_get_cstr(model->pwn->handshakes)) + 4;
    // Truncate from the left so the freshest chars show, right-aligned to the edge.
    const char* s = model->last_pwnd_ssid;
    int right = FLIPPER_SCREEN_WIDTH - 1;
    while(*s) {
        int w = canvas_string_width(canvas, s);
        if(right - w >= left_limit) {
            canvas_draw_str(canvas, right - w, PWNFRIEND_STATUS_Y, s);
            return;
        }
        s++; // still too wide -> drop a leading char and retry
    }
}

// ---- shared little helpers for the menu / browser screens ----

// True once this AP has enough to crack: a named ESSID + a PMKID or handshake.
static bool ap_crackable(const ApRec* a) {
    return a->has_essid && (a->pmkid || a->handshake);
}

// Capture progress 1..4: discovered -> named -> key material -> crackable.
static int ap_progress(const ApRec* a) {
    int s = 1; // a record exists at all -> discovered
    if(a->has_essid) s++; // know its name (a hashline needs it)
    if(a->pmkid || a->handshake) s++; // grabbed key material
    if(ap_crackable(a)) s++; // both -> crackable
    return s;
}

// Draw text truncated with the current font to fit `maxw` px at (x,y).
static void draw_str_trunc(Canvas* c, int x, int y, const char* s, int maxw) {
    char buf[40];
    size_t n = 0;
    buf[0] = '\0';
    for(const char* p = s; *p && n < sizeof(buf) - 1; p++) {
        buf[n] = *p;
        buf[n + 1] = '\0';
        if((int)canvas_string_width(c, buf) > maxw) {
            buf[n] = '\0';
            break;
        }
        n++;
    }
    canvas_draw_str(c, x, y, buf);
}

// A framed progress bar filled `filled`/`total`.
static void draw_progress(Canvas* c, int x, int y, int w, int h, int filled, int total) {
    canvas_draw_frame(c, x, y, w, h);
    if(total <= 0 || filled <= 0) return;
    int inner = w - 2;
    int fw = (inner * filled) / total;
    if(fw > inner) fw = inner;
    if(fw > 0) canvas_draw_box(c, x + 1, y + 1, fw, h - 2);
}

// 12-hex key -> "aa:bb:cc:dd:ee:ff".
static void fmt_bssid_colons(const char* k, char out[18]) {
    int o = 0;
    for(int i = 0; i < 12 && k[i] && k[i + 1]; i += 2) {
        out[o++] = k[i];
        out[o++] = k[i + 1];
        if(i < 10) out[o++] = ':';
    }
    out[o] = '\0';
}

static const char* capture_name(CaptureMode m) {
    return m == CaptureDeauth ? "DEAUTH" : m == CapturePassive ? "CAP" : "off";
}

// Tiny d-pad/button glyphs drawn inline (this SDK exports no firmware button icons).
// Coordinates are the left edge x and the vertical CENTRE yc; drawn in the current color.
static void icon_left(Canvas* c, int x, int yc) { // solid ◄, 4x7
    for(int i = 0; i < 4; i++) canvas_draw_line(c, x + i, yc - i, x + i, yc + i);
}
static void icon_right(Canvas* c, int x, int yc) { // solid ►, 4x7
    for(int i = 0; i < 4; i++) canvas_draw_line(c, x + 3 - i, yc - i, x + 3 - i, yc + i);
}
// Title bar (inverted): title left, optional right-aligned text. Back is a universal
// Flipper button, so we don't waste pixels hinting it.
static void draw_titlebar(Canvas* c, const char* title, const char* right) {
    canvas_draw_box(c, 0, 0, FLIPPER_SCREEN_WIDTH, 11);
    canvas_set_color(c, ColorWhite);
    canvas_set_font(c, FontSecondary);
    canvas_draw_str(c, 2, 9, title);
    if(right)
        canvas_draw_str(c, FLIPPER_SCREEN_WIDTH - 2 - canvas_string_width(c, right), 9, right);
    canvas_set_color(c, ColorBlack);
}

// Fill out[] with aps[] indices matching the ScreenApList filter; return the count.
static uint16_t ap_filtered(const PwnfriendModel* m, uint16_t* out) {
    uint16_t n = 0;
    for(uint16_t i = 0; i < m->ap_count; i++) {
        if(m->list_pwned_only && !(m->aps[i].pmkid || m->aps[i].handshake)) continue;
        out[n++] = i;
    }
    return n;
}

#define APLIST_ROWS 5

static void pwnfriend_draw_menu(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    draw_titlebar(canvas, "pwnfriend menu", NULL);
    canvas_set_font(canvas, FontSecondary);

    uint16_t pwned = 0;
    for(uint16_t i = 0; i < model->ap_count; i++)
        if(model->aps[i].pmkid || model->aps[i].handshake) pwned++;

    int rows = APLIST_ROWS;
    int top = 0;
    if(model->menu_idx >= rows) top = model->menu_idx - rows + 1;
    for(int r = 0; r < rows && top + r < MenuCount; r++) {
        int it = top + r;
        char row[30];
        switch(it) {
        case MenuPwnedAps: snprintf(row, sizeof(row), "Pwned APs (%u)", pwned); break;
        case MenuAllAps: snprintf(row, sizeof(row), "All APs (%u)", model->ap_count); break;
        case MenuStats: snprintf(row, sizeof(row), "Stats"); break;
        case MenuName: snprintf(row, sizeof(row), "Name: %s", model->persona->s.name); break;
        case MenuAdvertise:
            snprintf(row, sizeof(row), "Advertise: %s", model->advertising ? "ON" : "off");
            break;
        case MenuCapture:
            snprintf(row, sizeof(row), "Capture: %s", capture_name(model->capture_mode));
            break;
        case MenuChannel:
            if(model->tuned_channel >= 1 && model->tuned_channel <= 14)
                snprintf(row, sizeof(row), "Channel: %d", model->tuned_channel);
            else
                snprintf(row, sizeof(row), "Channel: *");
            break;
        case MenuMinRssi: snprintf(row, sizeof(row), "Min RSSI: %d", model->min_rssi); break;
        case MenuRecon: snprintf(row, sizeof(row), "Recon: %us", model->recon_secs); break;
        case MenuSetHome:
            snprintf(row, sizeof(row), "Set home %s", model->gps_seen ? "(here)" : "(no GPS)");
            break;
        case MenuAbout: snprintf(row, sizeof(row), "About"); break;
        default: row[0] = '\0';
        }
        int y = 11 + (r + 1) * 10; // baseline of this row
        if(it == model->menu_idx) {
            canvas_draw_box(canvas, 0, y - 9, FLIPPER_SCREEN_WIDTH, 10);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 3, y, row);
        if(it == model->menu_idx) canvas_set_color(canvas, ColorBlack);
    }
}

static void pwnfriend_draw_aplist(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    char title[24];
    snprintf(title, sizeof(title), "%s", model->list_pwned_only ? "PWNED APS" : "ALL APS");
    uint16_t idx[AP_MAX];
    uint16_t n = ap_filtered(model, idx);
    char hint[10];
    snprintf(hint, sizeof(hint), "%u", n);
    draw_titlebar(canvas, title, hint);
    canvas_set_font(canvas, FontSecondary);
    if(n == 0) {
        canvas_draw_str(
            canvas, 2, 36, model->list_pwned_only ? "no pwned APs yet" : "no APs seen yet");
        return;
    }
    for(uint16_t r = 0; r < APLIST_ROWS && model->list_top + r < n; r++) {
        const ApRec* a = &model->aps[idx[model->list_top + r]];
        int y = 11 + (r + 1) * 10;
        bool sel = (model->list_top + r == model->list_idx);
        if(sel) {
            canvas_draw_box(canvas, 0, y - 9, FLIPPER_SCREEN_WIDTH, 10);
            canvas_set_color(canvas, ColorWhite);
        }
        const char* name = a->ssid[0] ? a->ssid : a->bssid;
        draw_str_trunc(canvas, 3, y, name, 80);
        if(a->targeted) canvas_draw_str(canvas, 84, y, "T");
        if(a->whitelisted) canvas_draw_str(canvas, 84, y, "W");
        draw_progress(canvas, 92, y - 7, 34, 7, ap_progress(a), 4);
        if(sel) canvas_set_color(canvas, ColorBlack);
    }
}

static void pwnfriend_draw_apdetail(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    const ApRec* a = &model->aps[model->detail_ap];
    draw_titlebar(canvas, "AP", NULL);
    canvas_set_font(canvas, FontSecondary);
    draw_str_trunc(canvas, 2, 21, a->ssid[0] ? a->ssid : "(hidden)", 124);
    char mac[18];
    fmt_bssid_colons(a->bssid, mac);
    char l[40];
    snprintf(l, sizeof(l), "%s  ch%d  %ddBm", mac, a->channel, a->rssi);
    canvas_draw_str(canvas, 2, 31, l);
    // progress bar (narrow enough that the stage word to its right still fits 128px)
    int stg = ap_progress(a);
    const char* word = ap_crackable(a) ? "CRACKABLE" :
                       (a->pmkid || a->handshake) ? "captured" :
                       a->missed ? "missed" : "seen";
    draw_progress(canvas, 2, 36, 60, 8, stg, 4);
    canvas_draw_str(canvas, 66, 43, word);
    // flags line
    snprintf(
        l,
        sizeof(l),
        "ESSID:%c PMKID:%c HS:%c",
        a->has_essid ? 'y' : '-',
        a->pmkid ? 'y' : '-',
        a->handshake ? 'y' : '-');
    canvas_draw_str(canvas, 2, 53, l);
    // actions: ◄ target[x]   ► wlist[x]  (glyphs instead of "L:/R:")
    icon_left(canvas, 2, 60);
    snprintf(l, sizeof(l), " tgt[%c]", a->targeted ? 'x' : ' ');
    canvas_draw_str(canvas, 8, 63, l);
    icon_right(canvas, 66, 60);
    snprintf(l, sizeof(l), " wl[%c]", a->whitelisted ? 'x' : ' ');
    canvas_draw_str(canvas, 72, 63, l);
}

static void pwnfriend_draw_stats(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    const Persona* p = model->persona;
    draw_titlebar(canvas, "STATS", NULL);
    canvas_set_font(canvas, FontSecondary);
    uint32_t up = (uint32_t)p->session_uptime;
    char l[40];
    snprintf(
        l, sizeof(l), "epoch %lu   up %02lu:%02lu:%02lu", (unsigned long)p->epoch,
        (unsigned long)(up / 3600), (unsigned long)((up % 3600) / 60), (unsigned long)(up % 60));
    canvas_draw_str(canvas, 2, 21, l);
    snprintf(
        l, sizeof(l), "pwnd %lu (%lu)   aps %lu", (unsigned long)p->pwnd_run,
        (unsigned long)p->s.pwnd_tot, (unsigned long)p->aps_session);
    canvas_draw_str(canvas, 2, 31, l);
    snprintf(
        l, sizeof(l), "friends %lu   cap %s", (unsigned long)p->s.friends_met,
        capture_name(model->capture_mode));
    canvas_draw_str(canvas, 2, 41, l);
    if(model->gps_seen) {
        snprintf(l, sizeof(l), "GPS %s, %s", model->last_lat, model->last_lon);
        canvas_draw_str(canvas, 2, 51, l);
    } else {
        canvas_draw_str(canvas, 2, 51, "GPS: no fix");
    }
    snprintf(l, sizeof(l), "tx %lu beacons", (unsigned long)model->adv_sent_count);
    canvas_draw_str(canvas, 2, 61, l);
}

// The <mrq> mark as actual text (from ~/mrq.min.ascii). It's mostly thin glyphs
// (/ \ _ spaces), so the proportional FontSecondary renders it well within 128px.
static const char* MRQ_ART[] = {
    "     _    __/\\_______  _______",
    "    / \\  /  \\_____   \\/  ___  \\",
    "   /   \\/    /  _/  _/     /  /",
    "  /         /   \\   \\     /  /",
    " /   /\\  /\\_\\___/\\   \\____   \\",
    "(___/  \\/  <mrq>  \\___)   \\___)",
};

static void pwnfriend_draw_about(Canvas* canvas) {
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);
    for(size_t i = 0; i < sizeof(MRQ_ART) / sizeof(MRQ_ART[0]); i++) {
        canvas_draw_str(canvas, 1, 8 + (int)i * 9, MRQ_ART[i]);
    }
    canvas_draw_str(canvas, 2, 63, "pwnfriend  v1.0");
}

static void pwnfriend_draw_home(Canvas* canvas, PwnfriendModel* model) {
    pwnfriend_populate(model);
    // Draw the pwnagotchi screen piece by piece, skipping pwnagotchi_draw_mode: the
    // AI/AUTO/MANU tag is meaningless here, and the bottom-right corner shows the
    // last pwned AP instead.
    Pwnagotchi* pwn = model->pwn;
    pwnagotchi_draw_face(pwn, canvas);
    pwnagotchi_draw_name(pwn, canvas);
    pwnagotchi_draw_channel(pwn, canvas);
    pwnagotchi_draw_aps(pwn, canvas);
    pwnagotchi_draw_uptime(pwn, canvas);
    pwnagotchi_draw_lines(pwn, canvas);
    pwnagotchi_draw_friend(pwn, canvas);
    pwnagotchi_draw_handshakes(pwn, canvas);
    pwnagotchi_draw_message(pwn, canvas);
    pwnfriend_draw_last_pwnd(canvas, model);
}

static void pwnfriend_draw_callback(Canvas* canvas, void* ctx) {
    PwnfriendModel* model = ctx;
    canvas_clear(canvas);
    if(model->showing_consent) {
        pwnfriend_draw_consent(canvas);
        return;
    }
    // The "no ESP32" warning only takes over the home screen; the menu/browser stay
    // usable (they show data we already gathered) even if the board goes quiet.
    if(model->link_down && model->screen == ScreenHome) {
        pwnfriend_draw_link_down(canvas, model);
        return;
    }
    switch(model->screen) {
    case ScreenMenu: pwnfriend_draw_menu(canvas, model); return;
    case ScreenApList: pwnfriend_draw_aplist(canvas, model); return;
    case ScreenApDetail: pwnfriend_draw_apdetail(canvas, model); return;
    case ScreenStats: pwnfriend_draw_stats(canvas, model); return;
    case ScreenAbout: pwnfriend_draw_about(canvas); return;
    case ScreenHome:
    default: pwnfriend_draw_home(canvas, model); return;
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// "Set name" text-input result (OK): apply + persist the new name, return to the
// menu, and refresh the beacon so the mesh sees the new name.
static void pwnfriend_name_result(void* ctx) {
    PwnfriendApp* app = ctx;
    bool advertising = false;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            persona_set_name(model->persona, app->name_buf);
            persona_save(model->persona);
            advertising = model->advertising;
        },
        true);
    view_dispatcher_switch_to_view(app->view_dispatcher, 0);
    if(advertising) pwnfriend_send_advertise(app);
}

// Back from the name editor -> the main view (which is sitting on the menu).
static uint32_t pwnfriend_name_prev(void* ctx) {
    UNUSED(ctx);
    return 0;
}

static bool pwnfriend_input_callback(InputEvent* event, void* ctx) {
    PwnfriendApp* app = ctx;

    // While the consent modal is up: long-press OK accepts, Back cancels; every
    // other input is swallowed so nothing leaks through to the pwnagotchi view.
    bool consent_modal = false;
    with_view_model(
        app->view, PwnfriendModel * model, { consent_modal = model->showing_consent; }, false);
    if(consent_modal) {
        if(event->key == InputKeyOk && event->type == InputTypeLong) {
            consent_record();
            bool advertising = false;
            with_view_model(
                app->view,
                PwnfriendModel * model,
                {
                    model->showing_consent = false;
                    model->consent_given = true;
                    model->capture_mode = CaptureDeauth; // default is a full pwnagotchi
                    advertising = model->advertising;
                },
                true);
            if(advertising) pwnfriend_send_advertise(app);
            return true;
        }
        if(event->key == InputKeyBack && event->type == InputTypeShort) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->showing_consent = false; }, true);
            return true; // consume so Back doesn't exit the app
        }
        return true; // modal swallows all other input
    }

    if(event->type != InputTypeShort) return false; // all navigation is short-press

    Screen screen = ScreenHome;
    with_view_model(app->view, PwnfriendModel * model, { screen = model->screen; }, false);
    bool need_advertise = false;

    switch(screen) {
    case ScreenHome:
        if(event->key == InputKeyOk) { // OK opens the menu
            with_view_model(
                app->view, PwnfriendModel * model,
                { model->screen = ScreenMenu; model->menu_idx = 0; }, true);
            return true;
        }
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            // scroll the stat the persona speaks
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    if(event->key == InputKeyRight)
                        model->stat_page = (model->stat_page + 1) % StatPageCount;
                    else
                        model->stat_page = (model->stat_page + StatPageCount - 1) % StatPageCount;
                },
                true);
            return true;
        }
        if(event->key == InputKeyUp || event->key == InputKeyDown) {
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    int8_t before = model->tuned_channel;
                    if(event->key == InputKeyUp) {
                        if(model->tuned_channel < 14) model->tuned_channel++;
                    } else {
                        if(model->tuned_channel > 0) model->tuned_channel--;
                    }
                    need_advertise = (model->tuned_channel != before) && model->advertising;
                },
                true);
            if(need_advertise) pwnfriend_send_advertise(app);
            return true;
        }
        return false; // Back on home -> exit the app

    case ScreenMenu:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenHome; }, true);
            return true;
        }
        if(event->key == InputKeyUp || event->key == InputKeyDown) {
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    if(event->key == InputKeyDown) {
                        if(model->menu_idx + 1 < MenuCount) model->menu_idx++;
                    } else if(model->menu_idx > 0) {
                        model->menu_idx--;
                    }
                },
                true);
            return true;
        }
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            int dir = (event->key == InputKeyRight) ? 1 : -1;
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    if(model->menu_idx == MenuChannel) {
                        int v = model->tuned_channel + dir;
                        if(v < 0) v = 0;
                        if(v > 14) v = 14;
                        if(v != model->tuned_channel) {
                            model->tuned_channel = (int8_t)v;
                            need_advertise = model->advertising;
                        }
                    } else if(model->menu_idx == MenuMinRssi) {
                        int v = model->min_rssi + dir * 2;
                        if(v < -90) v = -90;
                        if(v > -40) v = -40;
                        if(v != model->min_rssi) {
                            model->min_rssi = (int8_t)v;
                            need_advertise = model->advertising;
                        }
                    } else if(model->menu_idx == MenuRecon) {
                        int v = (int)model->recon_secs + dir * 5;
                        if(v < 10) v = 10;
                        if(v > 120) v = 120;
                        if(v != (int)model->recon_secs) {
                            model->recon_secs = (uint16_t)v;
                            need_advertise = model->advertising;
                        }
                    }
                },
                true);
            if(need_advertise) pwnfriend_send_advertise(app);
            return true;
        }
        if(event->key == InputKeyOk) {
            bool toggled_adv = false, now_adv = false, prompted = false, open_name = false;
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    switch(model->menu_idx) {
                    case MenuName:
                        // Prime the editor with the current name, opened below.
                        strncpy(app->name_buf, model->persona->s.name, sizeof(app->name_buf) - 1);
                        app->name_buf[sizeof(app->name_buf) - 1] = '\0';
                        open_name = true;
                        break;
                    case MenuPwnedAps:
                        model->screen = ScreenApList;
                        model->list_pwned_only = true;
                        model->list_idx = 0;
                        model->list_top = 0;
                        break;
                    case MenuAllAps:
                        model->screen = ScreenApList;
                        model->list_pwned_only = false;
                        model->list_idx = 0;
                        model->list_top = 0;
                        break;
                    case MenuStats: model->screen = ScreenStats; break;
                    case MenuAbout: model->screen = ScreenAbout; break;
                    case MenuSetHome:
                        // Capture the current fix as home (persisted). Needs a fix.
                        if(model->gps_seen) {
                            model->home_lat = parse_deg(model->last_lat);
                            model->home_lon = parse_deg(model->last_lon);
                            pwnfriend_update_place(model);
                            home_save(app->storage, model);
                        }
                        break;
                    case MenuAdvertise:
                        model->advertising = !model->advertising;
                        now_adv = model->advertising;
                        toggled_adv = true;
                        if(now_adv) {
                            model->advertising_since = model->tick_secs;
                            model->last_rx_secs = model->tick_secs;
                        } else {
                            model->link_down = false;
                        }
                        break;
                    case MenuCapture:
                        if(model->capture_mode == CaptureOff && !model->consent_given) {
                            model->showing_consent = true;
                            prompted = true;
                        } else {
                            model->capture_mode = (model->capture_mode + 1) % 3;
                            need_advertise = model->advertising;
                        }
                        break;
                    default: break; // Channel/MinRssi/Recon adjust with Left/Right
                    }
                },
                true);
            if(open_name) {
                text_input_set_header_text(app->text_input, "Persona name");
                text_input_set_result_callback(
                    app->text_input, pwnfriend_name_result, app, app->name_buf,
                    sizeof(app->name_buf), false);
                view_dispatcher_switch_to_view(app->view_dispatcher, 1);
            } else if(toggled_adv) {
                if(now_adv)
                    pwnfriend_send_advertise(app);
                else
                    pwnfriend_send_stop(app);
            } else if(need_advertise && !prompted) {
                pwnfriend_send_advertise(app);
            }
            return true;
        }
        return true; // swallow anything else in the menu

    case ScreenApList:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenMenu; }, true);
            return true;
        }
        if(event->key == InputKeyUp || event->key == InputKeyDown) {
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    uint16_t idx[AP_MAX];
                    uint16_t n = ap_filtered(model, idx);
                    if(n) {
                        if(event->key == InputKeyDown) {
                            if(model->list_idx + 1 < n) model->list_idx++;
                        } else if(model->list_idx > 0) {
                            model->list_idx--;
                        }
                        if(model->list_idx < model->list_top) model->list_top = model->list_idx;
                        if(model->list_idx >= model->list_top + APLIST_ROWS)
                            model->list_top = model->list_idx - APLIST_ROWS + 1;
                    }
                },
                true);
            return true;
        }
        if(event->key == InputKeyOk) {
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    uint16_t idx[AP_MAX];
                    uint16_t n = ap_filtered(model, idx);
                    if(n && model->list_idx < n) {
                        model->detail_ap = idx[model->list_idx];
                        model->screen = ScreenApDetail;
                    }
                },
                true);
            return true;
        }
        return true;

    case ScreenApDetail:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenApList; }, true);
            return true;
        }
        if(event->key == InputKeyLeft) { // toggle target (exclusive — one focus AP)
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    bool on = !model->aps[model->detail_ap].targeted;
                    for(uint16_t i = 0; i < model->ap_count; i++) model->aps[i].targeted = false;
                    model->aps[model->detail_ap].targeted = on;
                    if(on) model->aps[model->detail_ap].whitelisted = false; // exclusive
                    need_advertise = model->advertising;
                },
                true);
            if(need_advertise) pwnfriend_send_advertise(app);
            return true;
        }
        if(event->key == InputKeyRight) { // toggle whitelist (never attack)
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    ApRec* a = &model->aps[model->detail_ap];
                    a->whitelisted = !a->whitelisted;
                    if(a->whitelisted) a->targeted = false; // exclusive with target
                    need_advertise = model->advertising;
                },
                true);
            if(need_advertise) pwnfriend_send_advertise(app);
            return true;
        }
        return true;

    case ScreenStats:
    case ScreenAbout:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenMenu; }, true);
            return true;
        }
        return true;

    default: return false;
    }
}

static uint32_t pwnfriend_exit(void* ctx) {
    UNUSED(ctx);
    return VIEW_NONE;
}

// ---------------------------------------------------------------------------
// Timer: 1 Hz heartbeat that ages the persona, prunes peers, resends & saves.
// ---------------------------------------------------------------------------

static void pwnfriend_timer_callback(void* ctx) {
    PwnfriendApp* app = ctx;
    bool resend = false;
    bool save = false;

    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            model->tick_secs++;
            peers_prune(&model->peers, model->tick_secs);
            bool bonded = peers_any_bonded(&model->peers, model->tick_secs);
            model->persona->friend_near = bonded;
            // "Engaged" = advertising + capture armed + APs around. Keeps the friend
            // content while it works a populated area (the firmware reports each AP
            // only once, so per-epoch discovery dries up even mid-hunt).
            model->persona->hunting =
                model->advertising && model->capture_mode != CaptureOff && model->ap_count > 0;
            persona_tick(model->persona, 1);

            // ESP32-link watchdog: warn only while advertising, only after the boot
            // grace, and only once the board has been silent past the timeout.
            // Unsigned subtraction is safe: both stamps are always <= tick_secs.
            if(model->advertising) {
                uint32_t since_rx = model->tick_secs - model->last_rx_secs;
                uint32_t since_adv = model->tick_secs - model->advertising_since;
                model->link_down = (since_rx >= PWNFRIEND_LINK_TIMEOUT_SECS) &&
                                   (since_adv >= PWNFRIEND_LINK_GRACE_SECS);
            } else {
                model->link_down = false; // paused never warns
            }

            if(model->advertising &&
               (model->tick_secs - model->last_adv_sent >= PWNFRIEND_ADV_RESEND_SECS)) {
                resend = true;
            }
            if(model->tick_secs % PWNFRIEND_SAVE_SECS == 0) {
                save = true;
            }
        },
        true);

    // send_advertise builds ~760B of buffers (cmd[512] + wl) and a 14-arg snprintf —
    // too much for the 1KB timer-daemon stack. Kick the worker thread (2KB) to do it.
    if(resend) furi_thread_flags_set(furi_thread_get_id(app->worker_thread), WorkerEventResend);
    if(save) {
        // persona pointer lives for the app's lifetime; a save racing a note_peer
        // update at worst records a slightly stale count, which is harmless.
        with_view_model(
            app->view,
            PwnfriendModel * model,
            {
                persona_save(model->persona);
                ap_db_save(app->storage, model);
            },
            false);
    }
}

// ---------------------------------------------------------------------------
// Serial RX plumbing
// ---------------------------------------------------------------------------

static void pwnfriend_on_irq_cb(
    FuriHalSerialHandle* serial_handle,
    FuriHalSerialRxEvent ev,
    void* context) {
    furi_assert(context);
    PwnfriendApp* app = context;
    if(ev & FuriHalSerialRxEventData) {
        uint8_t data = furi_hal_serial_async_rx(serial_handle);
        furi_stream_buffer_send(app->rx_stream, &data, 1, 0);
        furi_thread_flags_set(furi_thread_get_id(app->worker_thread), WorkerEventRx);
    }
}

static int32_t pwnfriend_worker(void* context) {
    furi_assert(context);
    PwnfriendApp* app = context;

    while(true) {
        uint32_t events =
            furi_thread_flags_wait(WORKER_EVENTS_MASK, FuriFlagWaitAny, FuriWaitForever);
        furi_check((events & FuriFlagError) == 0);
        if(events & WorkerEventStop) break;

        if(events & WorkerEventResend) pwnfriend_send_advertise(app);

        if(events & WorkerEventRx) {
            uint8_t byte;
            while(furi_stream_buffer_receive(app->rx_stream, &byte, 1, 0) > 0) {
                if(byte == '\n' || byte == '\r') {
                    if(app->line_len > 0) {
                        app->line[app->line_len] = '\0';
                        pwnfriend_process_line(app, app->line);
                        app->line_len = 0;
                    }
                } else if(app->line_len < sizeof(app->line) - 1) {
                    app->line[app->line_len++] = (char)byte;
                } else {
                    // Overlong line — reset rather than overflow.
                    app->line_len = 0;
                }
            }

            if(app->got_new_friend) {
                app->got_new_friend = false;
                notification_message(app->notification, &sequence_new_friend);
            }
            if(app->got_pwnd) {
                app->got_pwnd = false;
                notification_message(app->notification, &sequence_pwnd);
            }
        }
    }
    return 0;
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------

static PwnfriendApp* pwnfriend_app_alloc(void) {
    PwnfriendApp* app = malloc(sizeof(PwnfriendApp));
    memset(app, 0, sizeof(PwnfriendApp));

    app->rx_stream = furi_stream_buffer_alloc(1024, 1);

    app->gui = furi_record_open(RECORD_GUI);
    app->notification = furi_record_open(RECORD_NOTIFICATION);
    app->storage = furi_record_open(RECORD_STORAGE);

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);

    app->view = view_alloc();
    view_set_context(app->view, app);
    view_set_draw_callback(app->view, pwnfriend_draw_callback);
    view_set_input_callback(app->view, pwnfriend_input_callback);
    view_allocate_model(app->view, ViewModelTypeLocking, sizeof(PwnfriendModel));
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            model->persona = persona_alloc();
            model->pwn = pwnagotchi_alloc();
            peers_init(&model->peers);
            model->tick_secs = 0;
            model->advertising = true; // say hi on launch; OK toggles pause/resume
            // A full pwnagotchi by default: capture + deauth ON. It's gated behind
            // the one-time authorization acknowledgement — if that's already been
            // given (a returning user), arm Deauth straight away; otherwise start
            // Off and raise the consent screen on launch, arming Deauth on accept.
            model->consent_given = consent_is_given();
            model->capture_mode = model->consent_given ? CaptureDeauth : CaptureOff;
            model->showing_consent = !model->consent_given;
            model->last_pwnd_ssid[0] = '\0';
            model->pwnd_seen_count = 0;
            model->ap_count = 0;
            ap_db_load(app->storage, model); // browse APs/pwns from previous sessions
            model->tuned_channel = 0; // auto (*) — the recon sweep
            model->stat_page = StatPageMood;
            model->min_rssi = -78; // matches the firmware default attack floor
            model->recon_secs = 30; // pwnagotchi recon_time
            model->screen = ScreenHome;
            model->menu_idx = 0;
            model->list_idx = 0;
            model->list_top = 0;
            model->list_pwned_only = false;
            model->detail_ap = 0;
            model->gps_seen = false;
            model->last_lat[0] = '\0';
            model->last_lon[0] = '\0';
            model->gps_place[0] = '\0';
            model->home_lat = HOME_LAT; // default; overridden by home.bin / "Set home"
            model->home_lon = HOME_LON;
            home_load(app->storage, model);
            model->last_rx_secs = 0;
            model->advertising_since = 0; // advertising starts now (tick 0) -> grace runs
            model->link_down = false;
            pwnfriend_qr_encode(model); // one-time; the draw callback only reads it
        },
        true);

    view_set_previous_callback(app->view, pwnfriend_exit);
    view_dispatcher_add_view(app->view_dispatcher, 0, app->view);

    // Name editor (view id 1): Back returns to the main view/menu.
    app->text_input = text_input_alloc();
    view_set_previous_callback(text_input_get_view(app->text_input), pwnfriend_name_prev);
    view_dispatcher_add_view(app->view_dispatcher, 1, text_input_get_view(app->text_input));

    view_dispatcher_switch_to_view(app->view_dispatcher, 0);

    // Serial
    app->serial_handle = furi_hal_serial_control_acquire(PWNFRIEND_UART_CHANNEL);
    furi_check(app->serial_handle);
    furi_hal_serial_init(app->serial_handle, PWNFRIEND_UART_BAUD);
    furi_hal_serial_async_rx_start(app->serial_handle, pwnfriend_on_irq_cb, app, true);

    // Worker
    app->worker_thread = furi_thread_alloc();
    furi_thread_set_name(app->worker_thread, "PwnfriendWorker");
    furi_thread_set_stack_size(app->worker_thread, 2048);
    furi_thread_set_context(app->worker_thread, app);
    furi_thread_set_callback(app->worker_thread, pwnfriend_worker);
    furi_thread_start(app->worker_thread);

    // 1 Hz heartbeat
    app->timer = furi_timer_alloc(pwnfriend_timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->timer, furi_kernel_get_tick_frequency());

    // Auto-start: start saying hi immediately (model->advertising is true). The timer
    // re-pushes every PWNFRIEND_ADV_RESEND_SECS; this is the initial greeting so the
    // user never has to press OK to begin. OK still toggles pause/resume afterwards.
    pwnfriend_send_advertise(app);

    return app;
}

static void pwnfriend_app_free(PwnfriendApp* app) {
    furi_assert(app);

    furi_timer_stop(app->timer);
    furi_timer_free(app->timer);

    // Stop advertising and persist a final time (serial still live).
    pwnfriend_send_stop(app);
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            persona_save(model->persona);
            ap_db_save(app->storage, model);
        },
        false);

    // Tear down serial (which silences the RX IRQ) BEFORE freeing the worker
    // thread, so a byte arriving mid-teardown can't poke a freed thread.
    furi_hal_serial_deinit(app->serial_handle);
    furi_hal_serial_control_release(app->serial_handle);

    furi_thread_flags_set(furi_thread_get_id(app->worker_thread), WorkerEventStop);
    furi_thread_join(app->worker_thread);
    furi_thread_free(app->worker_thread);

    view_dispatcher_remove_view(app->view_dispatcher, 1);
    text_input_free(app->text_input);
    view_dispatcher_remove_view(app->view_dispatcher, 0);
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            persona_free(model->persona);
            pwnagotchi_free(model->pwn);
        },
        false);
    view_free(app->view);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);
    furi_record_close(RECORD_STORAGE);
    app->gui = NULL;

    furi_stream_buffer_free(app->rx_stream);
    free(app);
}

int32_t pwnfriend_app(void* p) {
    UNUSED(p);
    PwnfriendApp* app = pwnfriend_app_alloc();
    view_dispatcher_run(app->view_dispatcher);
    pwnfriend_app_free(app);
    return 0;
}
