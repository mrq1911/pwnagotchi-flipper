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
#include <stddef.h>

#include "../include/pwnfriend.h"
#include "version.h"
#include "../include/persona.h"
#include "../include/peers.h"
#include "../include/face.h"
#include "../include/pwnagotchi.h"
#include "../include/consent.h"
#include "../include/pcap.h"
#include "../include/wardrive.h"
#include "pwnfriend_geo.h" // pure geo/identity helpers
#include "qrcodegen.h"
#include <storage/storage.h>

typedef enum {
    WorkerEventStop = (1 << 0),
    WorkerEventRx = (1 << 1),
    WorkerEventResend = (1 << 2), // send_advertise off the worker's 2K stack
} WorkerEventFlags;

#define WORKER_EVENTS_MASK (WorkerEventStop | WorkerEventRx | WorkerEventResend)

// per-session pwnd dedup cap: a re-emitted PWND (every 15s) can't inflate counts
#define PWND_SEEN_MAX 64

// per-AP records, keyed by BSSID so a resume replay can't double-count
#define AP_MAX 256 // browsable AP history (persisted to aps.bin)
#define WL_MAX 16 // whitelisted BSSIDs sent to firmware (matches its MAX_WL)
#define FRIEND_MAX 64 // browsable friend history (persisted to friends.bin)

// default "home" point; "Set home" overrides it with the current fix (persisted)
#define HOME_LAT 50.081148f
#define HOME_LON 14.451144f
#define HOME_NAME "Home"
#define HOME_DB_PATH "/ext/apps_data/pwnfriend/home.bin"
#define HOME_DB_MAGIC 0x484D4E46u // 'FNMH'

// persisted AP table
#define AP_DB_PATH "/ext/apps_data/pwnfriend/aps.bin"
#define AP_DB_MAGIC 0x50414E46u // 'FNAP'
#define AP_DB_VERSION 4 // v4: ApRec gained triangulation centroid sums

// persisted friends table
#define FRIEND_DB_PATH "/ext/apps_data/pwnfriend/friends.bin"
#define FRIEND_DB_MAGIC 0x52464E46u // 'FNFR'
#define FRIEND_DB_VERSION 3 // v3: triangulation centroid sums; pwnd_tot widened to int32

// dev telemetry: one CSV row per epoch, offline algo tuning
#define TELEMETRY_PATH "/ext/apps_data/pwnfriend/telemetry.csv"
// dev telemetry: one CSV row per capture
#define CAPTURES_PATH "/ext/apps_data/pwnfriend/captures.csv"
// one row per friend sighting; many spots = a triangulation set
#define PEERS_PATH "/ext/apps_data/pwnfriend/peers.csv"
// per-AP (position,rssi) samples, throttled per AP_TRACK_MIN_SECS
#define AP_TRACK_PATH "/ext/apps_data/pwnfriend/ap_track.csv"
#define AP_TRACK_MIN_SECS 10
// GPS fix-status samples for debugging slow acquisition / time-to-first-fix
#define GPS_PATH "/ext/apps_data/pwnfriend/gps.csv"
// per-AP pcap bookkeeping: EAPOL filed? ESSID beacon spliced?
#define APF_HS_SEEN 0x01
#define APF_BEACON_DONE 0x02

// timer fires ANIM_HZ/sec for smooth About scroll; brain work gated to every ANIM_HZ-th fire
#define ANIM_HZ 8
#define ABOUT_SPEED_DEFAULT 3 // px per animation fire
#define ABOUT_SPEED_MAX 12

// home stat panel: idle secs before reverting to the persona voice
#define HOME_STATS_TIMEOUT_SECS 8

// exit prompt self-cancels after CONFIRM_EXIT_TIMEOUT_SECS; "staying" beat lasts CONFIRM_STAY_SECS
#define CONFIRM_EXIT_TIMEOUT_SECS 5
#define CONFIRM_STAY_SECS 2

// AP unheard this long -> stale RSSI, hide the signal meter
#define AP_SIGNAL_TTL_SECS 60

typedef struct {
    char bssid[13]; // 12-hex key (no colons)
    char ssid[33]; // ESSID, empty if hidden/unknown
    int16_t channel;
    int16_t rssi; // most recent
    bool has_essid; // named SSID seen (a 22000 hashline needs it)
    bool pmkid; // captured a PMKID (M1)
    bool handshake; // captured a 4-way handshake (M2)
    bool missed; // firmware reported a MISS (attacked, nothing caught)
    bool whitelisted; // user: never attack this one
    bool targeted; // user: focus the hunt on this one
    uint32_t first_seq; // discovery order (set once); stable sort tiebreak
    float lat, lon; // where heard strongest (1e9 = unknown); for the map QR
    int8_t loc_rssi; // RSSI at which lat/lon was recorded (keep the closest fix)
    // triangulation (RSSI-weighted centroid): est = (wlat_sum/w_sum, wlon_sum/w_sum)
    uint16_t loc_n; // geotagged samples folded in
    float w_sum, wlat_sum, wlon_sum;
} ApRec;

// a pwngrid peer we've met (keyed by 64-hex identity), persisted to friends.bin
typedef struct {
    char identity[PEER_ID_MAX]; // 64-hex pwngrid id (the key)
    char name[PEER_NAME_MAX]; // last display name seen
    int16_t rssi; // most recent signal
    int16_t best_rssi; // strongest ever heard
    int32_t pwnd_tot; // their lifetime capture count (can exceed int16)
    uint16_t times_seen; // sightings (triangulation confidence)
    uint32_t first_seq; // discovery order (set once); stable sort tiebreak
    float lat, lon; // where heard strongest (1e9 = unknown); for the map QR
    int8_t loc_rssi; // RSSI at which lat/lon was recorded (keep the closest fix)
    uint16_t loc_n; // triangulation samples (RSSI-weighted centroid)
    float w_sum, wlat_sum, wlon_sum;
} FriendRec;

// capture escalation, cycled from the menu; default Deauth, gated behind consent.
// Passive = record sniffed handshakes; Deauth = also associate + deauth (-deauth 1)
typedef enum {
    CaptureOff = 0,
    CapturePassive, // listen only, no TX
    CapturePmkid, // associate (solicit PMKID) but no deauth — quieter
    CaptureDeauth, // associate + deauth (full pwnagotchi)
    CaptureModeCount,
} CaptureMode;

// Which stat the persona "speaks" on the home screen; cycled Left/Right.
typedef enum {
    StatPageMood = 0, // the pwnagotchi voice line (default)
    StatPageCounts, // "ate N shakes!"
    StatPageSocial, // "met N friends!"
    StatPageGps, // distance+direction to home; full coords on the Stats screen
    StatPageCount,
} StatPage;

// ScreenApList filter modes.
typedef enum {
    FilterAll = 0,
    FilterPwned,
    FilterWhitelist,
} ListFilter;

// App screens. Home is the pwnagotchi; OK opens the menu; the rest hang off it.
typedef enum {
    ScreenHome = 0,
    ScreenMenu,
    ScreenApList,
    ScreenApDetail,
    ScreenApQr, // QR of the AP's location
    ScreenFriendList,
    ScreenFriendDetail,
    ScreenFriendQr, // QR of a friend's last location
    ScreenStats,
    ScreenAbout,
} Screen;

// menu rows: OK-activated first, then Left/Right-adjustable; About pinned last
typedef enum {
    MenuPwnedAps = 0, // OK: AP list (pwned)
    MenuAllAps, // OK: AP list (all)
    MenuWhitelist, // OK: AP list (whitelisted)
    MenuFriends, // OK: friends list (pwngrid peers met)
    MenuTarget, // OK: clear the focus target
    MenuStats, // OK: stats
    MenuName, // OK: name editor
    MenuSetHome, // OK: capture GPS home
    // --- below: Left/Right adjusts the value ---
    MenuAdvertise, // toggle
    MenuCapture, // cycle
    MenuMinRssi, // adjust
    MenuRecon, // adjust
    MenuQuiet, // toggle
    MenuTriangulate, // toggle: on-device location estimate + sample logging
    MenuBattery, // cycle: off / light / deep battery saver
    MenuAbout, // OK: about (pinned last)
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

    // per-session capture dedup: 12-hex BSSIDs already counted
    char pwnd_seen[PWND_SEEN_MAX][13];
    uint8_t pwnd_seen_count;

    // every AP seen this session (the browser reads this)
    ApRec aps[AP_MAX];
    uint16_t ap_count;
    uint32_t ap_seq; // monotonic, stamped into ApRec.first_seq
    uint32_t ap_seen_tick[AP_MAX]; // tick_secs each AP was last heard (0 = not this session)
    uint32_t ap_track_tick[AP_MAX]; // tick each AP last wrote ap_track.csv (throttle)
    uint8_t ap_pcap_flags[AP_MAX]; // per-session APF_* bits: HS filed / ESSID beacon spliced

    // every friend met (the browser reads this; persisted)
    FriendRec friends[FRIEND_MAX];
    uint16_t friend_count;
    bool friend_overflow; // hit FRIEND_MAX and recycling -> show "N+"
    uint32_t friend_seq; // monotonic, stamped into FriendRec.first_seq
    uint32_t friend_seen_tick[FRIEND_MAX]; // tick_secs each friend was last heard (0 = not this session)
    uint32_t friend_track_tick[FRIEND_MAX]; // tick each friend last fed the centroid (throttle)

    // Channel tuning: 0 = auto (the pwnagotchi '*' sweep, default); 1..14 = pinned.
    int8_t tuned_channel;
    uint8_t stat_page; // home stat panel, cycled Left/Right (0 = persona voice)
    uint32_t stat_touch_secs; // tick of the last Left/Right on home (for auto-revert)
    uint8_t battery_pct; // cached battery %, refreshed once/sec (shown in the BAT slot)
    bool on_power; // external power connected (VBUS) -> saver forced off; slot shows PWR
    bool charge_done; // fully charged on power -> slot shows "PWR" without a %
    int8_t min_rssi; // attack floor sent as -minrssi (default -78)
    uint16_t recon_secs; // recon_time sent as -recon (default 30)
    uint8_t saver; // user's battery-saver choice: 0 off, 1 light, 2 deep, 3 auto (persisted)
    uint8_t last_saver_eff; // last effective level pushed to the ESP (for change-triggered resend)

    // View state.
    Screen screen;
    uint8_t menu_idx; // selected row in ScreenMenu
    uint16_t list_idx; // selected AP index (into the filtered list) in ScreenApList
    uint16_t list_top; // scroll window top in ScreenApList
    uint8_t list_filter; // ScreenApList filter: 0=all, 1=pwned, 2=whitelisted
    uint16_t detail_ap; // aps[] index shown in ScreenApDetail
    uint16_t fl_idx; // selected friend (into the ordered list) in ScreenFriendList
    uint16_t fl_top; // scroll window top in ScreenFriendList
    uint16_t detail_friend; // friends[] index shown in ScreenFriendDetail

    // GPS: last_lat/lon are verbatim decimal-degree strings from the latest fix
    bool gps_seen;
    int gps_sats; // satellites from the latest PWNFRIEND_GPS (live acquisition readout)
    bool gps_fix; // module reports a valid fix (leads gps_seen, which also needs coords)
    int gps_acc; // reported fix accuracy in metres from PWNFRIEND_GPS
    char last_lat[16];
    char last_lon[16];
    char gps_place[32]; // distance+direction to home, e.g. "Home 12km SW"
    char gps_course[16]; // bearing to home, e.g. "225°" (its own row so it fits)
    float home_lat, home_lon; // the point the GPS compass points at (default Prague; settable)
    bool home_set; // user set a home (else default Prague "Mother")
    bool quiet; // suppress the LED blink + vibro on pwn / new-friend (persisted)
    bool triangulate; // on-device location estimate + sample logging (persisted)
    bool confirm_exit; // Home: first Back raises a persona prompt; second Back quits
    uint32_t confirm_secs; // tick the exit prompt went up (auto-cancels after a timeout)
    uint32_t stayed_until; // tick_secs until which the happy "stayed" reaction shows (0 = off)
    int fw_proto; // ESP32 firmware protocol version from PWNFRIEND_ADV (0 = unknown)
    char fw_commit[16]; // ESP32 firmware build hash from PWNFRIEND_ADV fw= (empty = old/none)
    uint32_t pwn_active; // captures our own attack earned (via=active), this session
    uint32_t pwn_passive; // captures sniffed passively (via=passive), this session

    // About banner scroll (art wider than the screen)
    uint32_t about_scroll; // monotonic px accumulator, advanced by the timer
    uint8_t about_speed; // px advanced per animation fire (1..ABOUT_SPEED_MAX)
    bool about_infinite; // scroll mode: false = bounce, true = infinite wrap

    // ESP32-link watchdog: warn when the board goes silent (all in tick_secs)
    uint32_t last_rx_secs; // tick of the last PWNFRIEND_* line seen
    uint32_t advertising_since; // tick advertising last (re)started — boot grace
    bool link_down; // computed each tick; true => the "no ESP32" screen shows

    // Setup QR (encoded once at alloc; the draw callback only reads modules).
    uint8_t qr[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
    bool qr_ok;

    // AP-location QR (encoded on demand); holds a geo: URI
    uint8_t ap_qr[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
    bool ap_qr_ok;
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
    uint32_t anim_tick; // sub-second timer counter (ANIM_HZ fires per second)
    Storage* storage; // for the handshake pcap writer
    TextInput* text_input; // "Set name" editor (view id 1)
    char name_buf[PERSONA_NAME_MAX]; // edit buffer for the name text input

    // line assembly, worker-thread only; sized for a full hex EAPOL line, not just JSON
    char line[1024];
    size_t line_len;
    bool got_new_friend; // set by worker, consumed for a notification blink
    bool got_pwnd; // set by worker, consumed for the capture blink
} PwnfriendApp;

// rising two-note chirp for a spotted friend
static const NotificationMessage message_friend_note_a = {
    .type = NotificationMessageTypeSoundOn,
    .data.sound = {.frequency = 587.33f, .volume = 1.0f}, // D5
};
static const NotificationMessage message_friend_note_b = {
    .type = NotificationMessageTypeSoundOn,
    .data.sound = {.frequency = 880.0f, .volume = 1.0f}, // A5
};

static const NotificationSequence sequence_new_friend = {
    &message_display_backlight_on,
    &message_green_255,
    &message_vibro_on,
    &message_friend_note_a,
    &message_delay_100,
    &message_friend_note_b,
    &message_delay_100,
    &message_sound_off,
    &message_vibro_off,
    NULL,
};

// louder blink for an actual handshake capture
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

// resolve the user's saver choice into the level actually sent to the ESP (0 off, 1 light,
// 2 deep). external power forces it off; AUTO (3) engages deep only below 20% battery.
static uint8_t effective_saver(const PwnfriendModel* model) {
    if(model->on_power) return 0;
    if(model->saver == 3) return model->battery_pct < 20 ? 2 : 0;
    return model->saver;
}

// ---------------------------------------------------------------------------
// Serial: build + send the advertise command, and stop.
// ---------------------------------------------------------------------------

static void pwnfriend_send_advertise(PwnfriendApp* app) {
    char cmd[512]; // base command + up to WL_MAX whitelisted BSSIDs
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
            // -cap/-deauth sent as explicit 0/1 every advertise so a previously-armed radio disarms.
            // -cap=1 in Passive/Deauth, -deauth=1 only in Deauth; firmware mirrors -deauth into the beacon.
            int cap = (model->capture_mode != CaptureOff) ? 1 : 0;
            int deauth = (model->capture_mode == CaptureDeauth) ? 1 : 0;
            // -assoc: solicit PMKID (associate) in both PMKID and Deauth modes.
            int assoc = (model->capture_mode == CapturePmkid || model->capture_mode == CaptureDeauth) ? 1 : 0;
            // -ch: 0 = auto-hop ('*' sweep); 1..14 pins the tuned channel
            int ch = (model->tuned_channel >= 1 && model->tuned_channel <= 14) ?
                         model->tuned_channel : 0;
            // -target: focus BSSID ("0" = none). -wl: whitelist (<=WL_MAX). build wl first to keep the snprintf flat
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
                "-deauth %d -assoc %d -ch %d -minrssi %d -recon %u -saver %d -target %s -wl %s\n",
                safe_name,
                p->s.identity,
                (int)persona_face(p),
                (unsigned long)p->pwnd_run, // REAL handshakes this run
                (unsigned long)p->s.pwnd_tot, // REAL handshakes lifetime
                (unsigned long)p->s.total_uptime,
                (unsigned long)p->epoch,
                cap,
                deauth,
                assoc,
                ch,
                (int)model->min_rssi,
                (unsigned)model->recon_secs,
                (int)effective_saver(model),
                target,
                wl);
            model->last_adv_sent = model->tick_secs;
            model->last_saver_eff = effective_saver(model);
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

// copy the numeric token after key verbatim; we never float-parse lat/lon (%f disabled in newlib-nano), pass the text straight through
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

// RFC4180-quote a free-text CSV cell so a comma/quote in an SSID/name can't shift later columns
static void csv_quote(const char* in, char* out, size_t n) {
    if(n < 3) {
        if(n) out[0] = '\0';
        return;
    }
    size_t o = 0;
    out[o++] = '"';
    for(const char* p = in; *p; p++) {
        char c = *p;
        size_t need = (c == '"') ? 2 : 1; // a quote is escaped by doubling it
        if(o + need + 1 >= n) break; // leave room for the closing quote + NUL
        if(c == '"') out[o++] = '"';
        out[o++] = c;
    }
    out[o++] = '"';
    out[o] = '\0';
}

static bool gps_outlier(const PwnfriendModel* m, float la, float lo); // defined below
static int friend_get(PwnfriendModel* model, const char* identity, bool* is_new); // below
static bool ap_signal_recent(const PwnfriendModel* m, uint16_t i); // defined below

static void pwnfriend_handle_peer_line(PwnfriendApp* app, const char* line) {
    char name[PEER_NAME_MAX] = {0};
    char identity[PEER_ID_MAX] = {0};
    int pwnd_tot = 0, rssi = 0, channel = 0;

    line_extract_str(line, "\"name\":\"", name, sizeof(name));
    line_extract_str(line, "\"identity\":\"", identity, sizeof(identity));
    line_extract_int(line, "\"pwnd_tot\":", &pwnd_tot);
    line_extract_int(line, "\"rssi\":", &rssi);
    line_extract_int(line, "\"channel\":", &channel);

    // identity-64hex guard: only a clean 64-hex identity is a real peer
    if(!identity_is_64hex(identity)) return;

    // where we stood: prefer a fix on the PEER line, else the last recon fix; logged per sighting for triangulation
    char lat[16] = {0};
    char lon[16] = {0};
    bool have_gps = line_extract_number(line, "\"lat\":", lat, sizeof(lat)) &&
                    line_extract_number(line, "\"lon\":", lon, sizeof(lon)) && coord_ok(lat, lon);

    bool is_new = false;
    bool fnew = false; // a genuinely-new, established friend was recorded this line
    uint32_t up = 0;
    bool tri = false;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            uint32_t now = model->tick_secs;
            up = now;
            tri = model->triangulate;
            // gps-outlier guard: drop a far-off junk fix (fall back to last good below)
            if(have_gps && gps_outlier(model, parse_deg(lat), parse_deg(lon))) have_gps = false;
            is_new = peers_update(
                &model->peers, name, identity, pwnd_tot, rssi, channel, now);
            bool bonded = peers_any_bonded(&model->peers, now);
            if(!have_gps && model->last_lat[0] && coord_ok(model->last_lat, model->last_lon)) {
                strncpy(lat, model->last_lat, sizeof(lat) - 1);
                strncpy(lon, model->last_lon, sizeof(lon) - 1);
                have_gps = true;
            }
            // established gate: only persist/count a peer heard before, so a one-off bad parse stays out of friends.bin and can't inflate friends_met
            int fi = is_new ? -1 : friend_get(model, identity, &fnew);
            persona_note_peer(model->persona, fnew, bonded);
            if(fi >= 0) {
                FriendRec* fr = &model->friends[fi];
                strncpy(fr->name, name[0] ? name : "???", PEER_NAME_MAX - 1);
                fr->name[PEER_NAME_MAX - 1] = '\0';
                fr->pwnd_tot = pwnd_tot;
                fr->rssi = (int16_t)rssi;
                if((int16_t)rssi > fr->best_rssi) fr->best_rssi = (int16_t)rssi;
                if(fr->times_seen < 0xFFFF) fr->times_seen++;
                if(have_gps) {
                    float la = parse_deg(lat);
                    float lo = parse_deg(lon);
                    // keep the strongest fix as a fallback (triangulation off or <2 samples)
                    if(fr->lat >= 1e8f || (rssi != 0 && (int8_t)rssi > fr->loc_rssi)) {
                        fr->lat = la;
                        fr->lon = lo;
                        fr->loc_rssi = (int8_t)rssi;
                    }
                    // fold one throttled sample per window so a long dwell can't out-vote distinct positions
                    if(tri && (model->friend_track_tick[fi] == 0 ||
                               model->tick_secs - model->friend_track_tick[fi] >= AP_TRACK_MIN_SECS)) {
                        model->friend_track_tick[fi] = model->tick_secs;
                        loc_accumulate(
                            &fr->loc_n, &fr->w_sum, &fr->wlat_sum, &fr->wlon_sum, la, lo, rssi);
                    }
                }
            }
        },
        true);

    if(fnew) app->got_new_friend = true; // chirp only for a genuinely new, established friend

    // one peers.csv row per established-peer sighting; gated like the friend record; lat/lon empty if no fix
    if(tri && !is_new) {
        storage_common_mkdir(app->storage, "/ext/apps_data/pwnfriend");
        File* f = storage_file_alloc(app->storage);
        if(storage_file_open(f, PEERS_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
            if(storage_file_size(f) == 0) {
                const char* h = "uptime_s,identity,name,rssi,channel,lat,lon\n";
                storage_file_write(f, h, strlen(h));
            }
            char qn[40];
            csv_quote(name, qn, sizeof(qn));
            char row[160];
            snprintf(
                row, sizeof(row), "%lu,%s,%s,%d,%d,%s,%s\n", (unsigned long)up, identity, qn,
                rssi, channel, have_gps ? lat : "", have_gps ? lon : "");
            storage_file_write(f, row, strlen(row));
        }
        storage_file_close(f);
        storage_file_free(f);
    }
}

static void pwnfriend_handle_adv_line(PwnfriendApp* app, const char* line) {
    int ch = 0, sent = 0, ver = 0;
    line_extract_int(line, "ch=", &ch);
    line_extract_int(line, "sent=", &sent);
    line_extract_int(line, "ver=", &ver); // firmware protocol version (0 on old builds)
    // fw=<hash> is an unquoted word; copy by hand up to the space (empty on old firmware)
    char fw[16] = {0};
    const char* fp = strstr(line, "fw=");
    if(fp) {
        fp += 3;
        size_t i = 0;
        while(fp[i] && fp[i] != ' ' && fp[i] != '\r' && fp[i] != '\n' && i < sizeof(fw) - 1) {
            fw[i] = fp[i];
            i++;
        }
        fw[i] = '\0';
    }
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            model->adv_channel = (uint8_t)ch;
            model->adv_sent_count = (uint32_t)sent;
            model->fw_proto = ver;
            strncpy(model->fw_commit, fw, sizeof(model->fw_commit) - 1);
            model->fw_commit[sizeof(model->fw_commit) - 1] = '\0';
        },
        true);
}

static int hexval(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// normalise a bssid to a 12-char lowercase-hex key (colons/non-hex dropped)
static void bssid_key(char out[13], const char* in) {
    size_t n = 0;
    for(const char* c = in; *c && n < 12; c++) {
        if(hexval(*c) < 0) continue;
        out[n++] = (*c >= 'A' && *c <= 'F') ? (char)(*c + 32) : *c;
    }
    out[n] = '\0';
}

// insert into the per-session pwnd dedup set; true only on first sight. full -> false (mirrors firmware's markPwnd cap)
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

// get-or-create the AP record for key; -1 if empty/full+new. *is_new set on creation (count fires once per BSSID)
static int ap_get(PwnfriendModel* model, const char* key, bool* is_new) {
    *is_new = false;
    if(!key[0]) return -1;
    int i = ap_find(model, key);
    if(i >= 0) {
        model->ap_seen_tick[i] = model->tick_secs; // refresh last-seen (NOT the order)
        return i;
    }
    if(model->ap_count >= AP_MAX) {
        // full: recycle the least-recently-heard slot but PROTECT captured APs (loot stays; full history is in wardrive.csv/pcaps)
        int victim = -1;
        for(uint16_t k = 0; k < model->ap_count; k++) {
            const ApRec* e = &model->aps[k];
            // keep captures + flagged APs (evicting an ignored one would drop it from -wl)
            if(e->pmkid || e->handshake || e->whitelisted || e->targeted) continue;
            if(victim < 0 || model->ap_seen_tick[k] < model->ap_seen_tick[victim]) victim = (int)k;
        }
        if(victim < 0) { // everything captured (unlikely) -> fall back to overall oldest
            victim = 0;
            for(uint16_t k = 1; k < model->ap_count; k++)
                if(model->ap_seen_tick[k] < model->ap_seen_tick[victim]) victim = (int)k;
        }
        i = victim;
    } else {
        i = (int)model->ap_count++;
    }
    memset(&model->aps[i], 0, sizeof(ApRec));
    strncpy(model->aps[i].bssid, key, 12);
    model->aps[i].bssid[12] = '\0';
    model->aps[i].first_seq = ++model->ap_seq; // set once at discovery -> stable ordering
    model->ap_seen_tick[i] = model->tick_secs;
    model->ap_track_tick[i] = 0; // recycled slot: don't inherit the old AP's track throttle
    model->ap_pcap_flags[i] = 0; // recycled slot: fresh pcap bookkeeping
    model->aps[i].lat = 1e9f; // no location until a geotagged line arrives
    model->aps[i].lon = 1e9f;
    model->aps[i].loc_rssi = -128; // reset for a recycled slot
    *is_new = true;
    return i;
}

// load persisted AP table. targeted is session-only (cleared); whitelist persists and is re-sent on first advertise
static void ap_db_load(Storage* storage, PwnfriendModel* model) {
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, AP_DB_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint32_t hdr[3] = {0};
        if(storage_file_read(f, hdr, sizeof(hdr)) == sizeof(hdr) && hdr[0] == AP_DB_MAGIC &&
           hdr[1] == AP_DB_VERSION) {
            uint32_t n = hdr[2] > AP_MAX ? AP_MAX : hdr[2];
            size_t got = storage_file_read(f, model->aps, n * sizeof(ApRec));
            model->ap_count = (uint16_t)(got / sizeof(ApRec));
            for(uint16_t i = 0; i < model->ap_count; i++) {
                model->aps[i].targeted = false;
                // continue ap_seq above loaded first_seq so new sightings sort as most-recent
                if(model->aps[i].first_seq >= model->ap_seq)
                    model->ap_seq = model->aps[i].first_seq + 1;
            }
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

// upsert a friend by identity; *is_new on discovery. full -> recycle least-recently-heard
static int friend_get(PwnfriendModel* model, const char* identity, bool* is_new) {
    *is_new = false;
    if(!identity || !identity[0]) return -1;
    for(uint16_t i = 0; i < model->friend_count; i++) {
        if(strcmp(model->friends[i].identity, identity) == 0) {
            model->friend_seen_tick[i] = model->tick_secs;
            return (int)i;
        }
    }
    int i;
    if(model->friend_count >= FRIEND_MAX) {
        i = 0;
        for(uint16_t k = 1; k < model->friend_count; k++)
            if(model->friend_seen_tick[k] < model->friend_seen_tick[i]) i = (int)k;
        model->friend_overflow = true;
    } else {
        i = (int)model->friend_count++;
    }
    memset(&model->friends[i], 0, sizeof(FriendRec));
    strncpy(model->friends[i].identity, identity, PEER_ID_MAX - 1);
    model->friends[i].identity[PEER_ID_MAX - 1] = '\0';
    model->friends[i].first_seq = ++model->friend_seq;
    model->friends[i].best_rssi = -128;
    model->friends[i].lat = 1e9f;
    model->friends[i].lon = 1e9f;
    model->friends[i].loc_rssi = -128;
    model->friend_seen_tick[i] = model->tick_secs;
    model->friend_track_tick[i] = 0; // recycled slot: don't inherit the old friend's throttle
    *is_new = true;
    return i;
}

static void friend_db_load(Storage* storage, PwnfriendModel* model) {
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, FRIEND_DB_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint32_t hdr[3] = {0};
        if(storage_file_read(f, hdr, sizeof(hdr)) == sizeof(hdr) && hdr[0] == FRIEND_DB_MAGIC &&
           hdr[1] == FRIEND_DB_VERSION) {
            uint32_t n = hdr[2] > FRIEND_MAX ? FRIEND_MAX : hdr[2];
            size_t got = storage_file_read(f, model->friends, n * sizeof(FriendRec));
            uint16_t loaded = (uint16_t)(got / sizeof(FriendRec));
            // self-heal: drop records whose identity isn't clean 64-hex (legacy garbage), compact in place
            uint16_t w = 0;
            for(uint16_t i = 0; i < loaded; i++) {
                if(!identity_is_64hex(model->friends[i].identity)) continue;
                if(w != i) model->friends[w] = model->friends[i];
                if(model->friends[w].first_seq >= model->friend_seq)
                    model->friend_seq = model->friends[w].first_seq + 1;
                w++;
            }
            model->friend_count = w;
        }
    }
    storage_file_close(f);
    storage_file_free(f);
}

static void friend_db_save(Storage* storage, PwnfriendModel* model) {
    storage_common_mkdir(storage, "/ext/apps_data/pwnfriend");
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, FRIEND_DB_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        uint32_t hdr[3] = {FRIEND_DB_MAGIC, FRIEND_DB_VERSION, model->friend_count};
        storage_file_write(f, hdr, sizeof(hdr));
        storage_file_write(f, model->friends, (size_t)model->friend_count * sizeof(FriendRec));
    }
    storage_file_close(f);
    storage_file_free(f);
}

// prefs file: home point + quiet + triangulate (home.bin)
typedef struct {
    uint32_t magic;
    uint32_t version;
    float lat;
    float lon;
    uint8_t quiet;
    uint8_t home_set; // v3: user set a home (vs default Prague)
    uint8_t triangulate; // v4: on-device triangulation enabled
    uint8_t saver; // v5: battery saver 0/1/2
} HomeDb;

static void home_load(Storage* storage, PwnfriendModel* model) {
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, HOME_DB_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        HomeDb h = {0}; // zero-init: fields absent from an older, shorter record read as 0
        size_t got = storage_file_read(f, &h, sizeof(h));
        // accept magic + at least v3 layout so growing the struct (v4) doesn't wipe saved home/quiet
        if(got >= offsetof(HomeDb, triangulate) && h.magic == HOME_DB_MAGIC) {
            model->home_lat = h.lat;
            model->home_lon = h.lon;
            model->quiet = h.quiet != 0;
            model->home_set = h.home_set != 0;
            // triangulate present only from v4; older records keep the alloc default (on).
            if(got >= offsetof(HomeDb, saver) && h.version >= 4) model->triangulate = h.triangulate != 0;
            // saver present only from v5; older records keep the alloc default (off).
            if(got >= sizeof(HomeDb) && h.version >= 5) model->saver = h.saver;
        }
    }
    storage_file_close(f);
    storage_file_free(f);
}

static void home_save(Storage* storage, PwnfriendModel* model) {
    storage_common_mkdir(storage, "/ext/apps_data/pwnfriend");
    File* f = storage_file_alloc(storage);
    if(storage_file_open(f, HOME_DB_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        HomeDb h = {HOME_DB_MAGIC, 5, model->home_lat, model->home_lon,
                    (uint8_t)(model->quiet ? 1 : 0), (uint8_t)(model->home_set ? 1 : 0),
                    (uint8_t)(model->triangulate ? 1 : 0), model->saver};
        storage_file_write(f, &h, sizeof(h));
    }
    storage_file_close(f);
    storage_file_free(f);
}

// gps-outlier guard: a fix >GPS_OUTLIER_KM from our reference (set home, else last good fix) is junk; no reference yet -> keep
#define GPS_OUTLIER_KM 150.0f
static bool gps_outlier(const PwnfriendModel* m, float la, float lo) {
    float rlat = 1e9f, rlon = 1e9f;
    if(m->home_set) {
        rlat = m->home_lat;
        rlon = m->home_lon;
    } else if(m->last_lat[0]) {
        rlat = parse_deg(m->last_lat);
        rlon = parse_deg(m->last_lon);
    }
    if(rlat >= 1e8f) return false;
    return geo_km(rlat, rlon, la, lo) > GPS_OUTLIER_KM;
}

// compact age string (Ns/Nm/Nh)
static void fmt_age(uint32_t secs, char* out, size_t n) {
    if(secs < 60)
        snprintf(out, n, "%lus", (unsigned long)secs);
    else if(secs < 3600)
        snprintf(out, n, "%lum", (unsigned long)(secs / 60));
    else
        snprintf(out, n, "%luh", (unsigned long)(secs / 3600));
}

// format a coordinate to 6 decimals without %f (newlib-nano has none); for the map QR URL
static void fmt_coord(float v, char* out, size_t n) {
    if(n == 0) return;
    char* p = out;
    size_t rem = n;
    if(v < 0.0f) {
        if(rem > 1) { *p++ = '-'; rem--; }
        v = -v;
    }
    long ip = (long)v;
    float frac = v - (float)ip;
    int w = snprintf(p, rem, "%ld", ip); // integer part (no float)
    if(w > 0 && (size_t)w < rem) {
        p += w;
        rem -= (size_t)w;
    }
    if(rem > 1) { *p++ = '.'; rem--; }
    for(int i = 0; i < 6 && rem > 1; i++) {
        frac *= 10.0f;
        int d = (int)frac;
        if(d < 0) d = 0;
        if(d > 9) d = 9;
        *p++ = (char)('0' + d);
        rem--;
        frac -= (float)d;
    }
    if(rem > 0) *p = '\0';
}

// gps_place = distance + 8-point compass to HOME; single-precision math only (-Werror=double-promotion)
static void pwnfriend_update_place(PwnfriendModel* model) {
    float lat = parse_deg(model->last_lat), lon = parse_deg(model->last_lon);
    if(lat >= 1e8f || lon >= 1e8f) {
        model->gps_place[0] = '\0';
        model->gps_course[0] = '\0';
        return;
    }
    float coslat = cosf(lat * 3.14159265f / 180.0f);
    float north = model->home_lat - lat; // degrees north to home
    float east = (model->home_lon - lon) * coslat; // degrees east to home (longitude-corrected)
    float km = sqrtf(north * north + east * east) * 111.0f; // ~111 km / degree
    static const char* DIRS[8] = {"N", "NE", "E", "SE", "S", "SW", "W", "NW"};
    // atan2f: 0 = due north, +pi/2 = east. Round to eighths; &7 wraps negatives correctly.
    float ang = atan2f(east, north);
    const char* dir = DIRS[((int)roundf(ang / 0.78539816f)) & 7];
    int brg = (int)roundf(ang * 57.29578f); // radians -> degrees, 0 = N, 90 = E
    if(brg < 0) brg += 360;
    // no home set yet -> point at default Prague, call it "Mother"; after "Set home" it's "Home"
    const char* hn = model->home_set ? HOME_NAME : "Mother";
    // distance+direction on gps_place, bearing on gps_course (own row; combined was too wide)
    model->gps_course[0] = '\0';
    if(km < 0.03f) { // only the "we're here" line within ~30m; otherwise keep showing distance
        if(model->home_set)
            snprintf(model->gps_place, sizeof(model->gps_place), "At %s!", hn);
        else
            snprintf(model->gps_place, sizeof(model->gps_place), "look up to Mother");
    } else {
        // row1 name+distance; row2 dir+bearing (° ring drawn at render time; no ° glyph in the font)
        if(km < 1.0f)
            snprintf(model->gps_place, sizeof(model->gps_place), "%s %dm", hn, (int)(km * 1000.0f));
        else
            snprintf(model->gps_place, sizeof(model->gps_place), "%s %dkm", hn, (int)(km + 0.5f));
        snprintf(model->gps_course, sizeof(model->gps_course), "%s %d", dir, brg);
    }
}

static void pwnfriend_handle_pwnd_line(PwnfriendApp* app, const char* line) {
    char bssid[18] = {0};
    char ssid[33] = {0};
    char type[12] = {0};
    char via[10] = {0};
    char lat[16] = {0};
    char lon[16] = {0};
    int channel = 0, rssi = 0;

    line_extract_str(line, "\"bssid\":\"", bssid, sizeof(bssid));
    line_extract_str(line, "\"ssid\":\"", ssid, sizeof(ssid));
    line_extract_str(line, "\"type\":\"", type, sizeof(type));
    line_extract_str(line, "\"via\":\"", via, sizeof(via)); // active|passive (empty on fw<4)
    line_extract_int(line, "\"channel\":", &channel);
    line_extract_int(line, "\"rssi\":", &rssi);
    // lat/lon are present only when the GPS had a fix (contract v2); both or neither.
    bool have_gps = line_extract_number(line, "\"lat\":", lat, sizeof(lat)) &&
                    line_extract_number(line, "\"lon\":", lon, sizeof(lon)) && coord_ok(lat, lon);

    const char* label = ssid[0] ? ssid : bssid;
    char key[13];
    bssid_key(key, bssid);

    bool counted = false;
    uint32_t up = 0;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            up = model->tick_secs;
            // gps-outlier guard before it geotags loot
            if(have_gps && gps_outlier(model, parse_deg(lat), parse_deg(lon))) have_gps = false;
            // gate the count behind consent+capture opt-in; dedup by BSSID so a 15s re-emit counts once
            if(model->capture_mode != CaptureOff && pwnd_seen_insert(model, key)) {
                persona_note_pwnd(model->persona);
                strncpy(model->last_pwnd_ssid, label, sizeof(model->last_pwnd_ssid) - 1);
                model->last_pwnd_ssid[sizeof(model->last_pwnd_ssid) - 1] = '\0';
                // Provenance split: did our attack earn it, or did we sniff it passively?
                if(strcmp(via, "active") == 0) model->pwn_active++;
                else model->pwn_passive++;
                counted = true;
            }
            // record the capture on the AP regardless of the count gate (reflects what landed)
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
                if(have_gps) {
                    float la = parse_deg(lat);
                    float lo = parse_deg(lon);
                    // Stash where it was heard strongest (gains/refines the fallback fix).
                    if(a->lat >= 1e8f || (rssi != 0 && (int8_t)rssi > a->loc_rssi)) {
                        a->lat = la;
                        a->lon = lo;
                        a->loc_rssi = (int8_t)rssi;
                    }
                    // Throttle the centroid fold (a PWND re-emits every ~15s while in range).
                    if(model->triangulate &&
                       (model->ap_track_tick[ai] == 0 ||
                        model->tick_secs - model->ap_track_tick[ai] >= AP_TRACK_MIN_SECS)) {
                        model->ap_track_tick[ai] = model->tick_secs;
                        loc_accumulate(&a->loc_n, &a->w_sum, &a->wlat_sum, &a->wlon_sum, la, lo,
                                       rssi);
                    }
                }
            }
            if(have_gps) {
                model->gps_seen = true;
                strncpy(model->last_lat, lat, sizeof(model->last_lat) - 1);
                model->last_lat[sizeof(model->last_lat) - 1] = '\0';
                strncpy(model->last_lon, lon, sizeof(model->last_lon) - 1);
                model->last_lon[sizeof(model->last_lon) - 1] = '\0';
                pwnfriend_update_place(model); // distance+bearing to home
            }
        },
        true);

    // A captured handshake implies WPA/WPA2-PSK; log it (once) as a geotagged row.
    if(have_gps && counted) {
        wardrive_log(
            app->storage, bssid, ssid, "[WPA2-PSK-CCMP][ESS]", channel, rssi, lat, lon);
    }

    // dev telemetry: one row per capture (provenance + RSSI)
    if(counted) {
        storage_common_mkdir(app->storage, "/ext/apps_data/pwnfriend");
        File* f = storage_file_alloc(app->storage);
        if(storage_file_open(f, CAPTURES_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
            if(storage_file_size(f) == 0) {
                const char* h = "uptime_s,bssid,ssid,type,via,rssi,channel,lat,lon\n";
                storage_file_write(f, h, strlen(h));
            }
            char row[128];
            snprintf(
                row, sizeof(row), "%lu,%s,%s,%s,%s,%d,%d,%s,%s\n", (unsigned long)up, bssid, ssid,
                type, via[0] ? via : "?", rssi, channel, lat, lon);
            storage_file_write(f, row, strlen(row));
        }
        storage_file_close(f);
        storage_file_free(f);
    }

    if(counted) app->got_pwnd = true; // capture blink
}

// build a minimal WPA2 beacon carrying ssid for bssidhex (~100B), to splice the ESSID
// (hashcat's PBKDF2 salt) into a pcap; rescues captures the firmware's own splice missed.
// byte layout mirrors the firmware's streamSyntheticBeacon.
static int build_synth_beacon(uint8_t* b, const char* bssidhex, const char* ssid) {
    if(!ssid || !ssid[0]) return 0;
    uint8_t mac[6];
    for(int i = 0; i < 6; i++) {
        int hi = hexval(bssidhex[i * 2]), lo = hexval(bssidhex[i * 2 + 1]);
        if(hi < 0 || lo < 0) return 0;
        mac[i] = (uint8_t)((hi << 4) | lo);
    }
    int slen = (int)strlen(ssid);
    if(slen > 32) slen = 32;
    int p = 0;
    static const uint8_t head[10] = {0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(b + p, head, 10); p += 10;
    memcpy(b + p, mac, 6); p += 6; // Addr2 = BSSID
    memcpy(b + p, mac, 6); p += 6; // Addr3 = BSSID
    b[p++] = 0x00; b[p++] = 0x00; // seq-ctl
    memset(b + p, 0, 8); p += 8; // timestamp
    b[p++] = 0x64; b[p++] = 0x00; // beacon interval
    b[p++] = 0x11; b[p++] = 0x00; // caps: ESS + Privacy
    b[p++] = 0x00; b[p++] = (uint8_t)slen; // SSID IE
    memcpy(b + p, ssid, slen); p += slen;
    static const uint8_t rates[6] = {0x01, 0x04, 0x82, 0x84, 0x8b, 0x96};
    memcpy(b + p, rates, 6); p += 6;
    static const uint8_t rsn[22] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
                                    0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
                                    0x0c, 0x00};
    memcpy(b + p, rsn, 22); p += 22;
    return p;
}

// "PWNFRIEND_RSSI <mac> <dbm>" — throttled live-signal refresh for a known AP (fw v3)
static void pwnfriend_handle_rssi_line(PwnfriendApp* app, const char* line) {
    char key[13];
    bssid_key(key, line + 15); // hex of the mac, colons skipped, stops at 12
    const char* sp = strchr(line + 15, ' ');
    if(!sp) return;
    int rssi = (int)strtol(sp + 1, NULL, 10);
    with_view_model(
        app->view, PwnfriendModel * model,
        {
            int ai = ap_find(model, key);
            if(ai >= 0) {
                model->aps[ai].rssi = (int16_t)rssi;
                model->ap_seen_tick[ai] = model->tick_secs; // refresh last-seen, keep order
            }
        },
        true);
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
                    line_extract_number(line, "\"lon\":", lon, sizeof(lon)) && coord_ok(lat, lon);

    char key[13];
    bssid_key(key, bssid);

    bool is_new_ap = false;
    bool do_track = false;
    bool inject = false;
    char beac_ssid[33] = {0};
    uint32_t up = 0;
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            up = model->tick_secs;
            // gps-outlier guard before it geotags this AP
            if(have_gps && gps_outlier(model, parse_deg(lat), parse_deg(lon))) have_gps = false;
            // upsert the AP; new BSSID counts once so a resume replay can't inflate it
            int ai = ap_get(model, key, &is_new_ap);
            if(ai >= 0) {
                ApRec* a = &model->aps[ai];
                a->channel = (int16_t)channel;
                a->rssi = (int16_t)rssi;
                if(ssid[0]) {
                    strncpy(a->ssid, ssid, sizeof(a->ssid) - 1);
                    a->ssid[sizeof(a->ssid) - 1] = '\0';
                    a->has_essid = true;
                    // late name for an already-captured AP -> splice its ESSID beacon now (once)
                    if((model->ap_pcap_flags[ai] & APF_HS_SEEN) &&
                       !(model->ap_pcap_flags[ai] & APF_BEACON_DONE)) {
                        model->ap_pcap_flags[ai] |= APF_BEACON_DONE;
                        strncpy(beac_ssid, a->ssid, sizeof(beac_ssid) - 1);
                        inject = true;
                    }
                }
                if(have_gps) {
                    float la = parse_deg(lat);
                    float lo = parse_deg(lon);
                    // keep the strongest fix as a fallback (triangulation off / <2 samples)
                    if(a->lat >= 1e8f || (rssi != 0 && (int8_t)rssi > a->loc_rssi)) {
                        a->lat = la;
                        a->lon = lo;
                        a->loc_rssi = (int8_t)rssi;
                    }
                    // throttle: one triangulation sample per AP per window so a long dwell can't out-vote distinct positions
                    if(model->triangulate &&
                       (model->ap_track_tick[ai] == 0 ||
                        model->tick_secs - model->ap_track_tick[ai] >= AP_TRACK_MIN_SECS)) {
                        model->ap_track_tick[ai] = model->tick_secs;
                        loc_accumulate(&a->loc_n, &a->w_sum, &a->wlat_sum, &a->wlon_sum, la, lo,
                                       rssi);
                        do_track = true;
                    }
                }
            }
            if(is_new_ap) persona_note_ap(model->persona);
            if(have_gps) {
                model->gps_seen = true;
                strncpy(model->last_lat, lat, sizeof(model->last_lat) - 1);
                model->last_lat[sizeof(model->last_lat) - 1] = '\0';
                strncpy(model->last_lon, lon, sizeof(model->last_lon) - 1);
                model->last_lon[sizeof(model->last_lon) - 1] = '\0';
                pwnfriend_update_place(model); // distance+bearing to home
            }
        },
        true);

    // late name for a captured AP: splice the ESSID beacon into its pcap
    if(inject) {
        uint8_t beac[100];
        int bl = build_synth_beacon(beac, key, beac_ssid);
        if(bl > 0) pcap_append_frame(app->storage, key, beac, (uint16_t)bl);
    }

    // one wardrive row per first-seen BSSID (resume replay won't rewrite); encryption unknown from a beacon
    if(have_gps && is_new_ap) {
        wardrive_log(app->storage, bssid, ssid, "[ESS]", channel, rssi, lat, lon);
    }

    // throttled per-sighting track row; many spots per BSSID = a triangulation set
    if(do_track) {
        storage_common_mkdir(app->storage, "/ext/apps_data/pwnfriend");
        File* f = storage_file_alloc(app->storage);
        if(storage_file_open(f, AP_TRACK_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
            if(storage_file_size(f) == 0) {
                const char* h = "uptime_s,bssid,ssid,rssi,channel,lat,lon\n";
                storage_file_write(f, h, strlen(h));
            }
            char qs[70];
            csv_quote(ssid, qs, sizeof(qs));
            char row[160];
            snprintf(
                row, sizeof(row), "%lu,%s,%s,%d,%d,%s,%s\n", (unsigned long)up, bssid, qs, rssi,
                channel, lat, lon);
            storage_file_write(f, row, strlen(row));
        }
        storage_file_close(f);
        storage_file_free(f);
    }
}

static void pwnfriend_handle_hs_line(PwnfriendApp* app, const char* line) {
    // "PWNFRIEND_HS <bssid12hex> <hex-of-full-802.11-frame>"; the bssid names the per-target
    // pcap so beacon + EAPOL share one crackable <bssid>.pcap without needing a preceding PWND.
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

    // record only if capture is opted in; under the lock note the EAPOL file and, if we know the name, queue the ESSID splice (once)
    bool record = false;
    bool inject = false;
    char beac_ssid[33] = {0};
    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            record = (model->capture_mode != CaptureOff);
            if(record) {
                int ai = ap_find(model, bssid); // bssid is the 12-hex key
                if(ai >= 0) {
                    model->ap_pcap_flags[ai] |= APF_HS_SEEN;
                    if(model->aps[ai].has_essid &&
                       !(model->ap_pcap_flags[ai] & APF_BEACON_DONE)) {
                        model->ap_pcap_flags[ai] |= APF_BEACON_DONE;
                        strncpy(beac_ssid, model->aps[ai].ssid, sizeof(beac_ssid) - 1);
                        inject = true;
                    }
                }
            }
        },
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

    // bssid is the (fs-safe) pcap filename; splice the ESSID beacon first (once/session) so a known name reaches the pcap
    if(inject) {
        uint8_t beac[100];
        int bl = build_synth_beacon(beac, bssid, beac_ssid);
        if(bl > 0) pcap_append_frame(app->storage, bssid, beac, (uint16_t)bl);
    }
    pcap_append_frame(app->storage, bssid, frame, (uint16_t)flen);
}

static void pwnfriend_handle_miss_line(PwnfriendApp* app, const char* line) {
    // on_miss: firmware attacked with no capture -> demotivated face + miss tally, mark the AP.
    // gated on capture armed so a stray MISS can't skew the mood.
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

// "PWNFRIEND_EPOCH {...}" — dev telemetry (fw v4): one CSV row per epoch for offline tuning
static void pwnfriend_handle_epoch_line(PwnfriendApp* app, const char* line) {
    int n = 0, recon = 0, att = 0, chans = 0, assoc = 0, deauth = 0, uni = 0, sta = 0, hs = 0,
        pmkid = 0, miss = 0, dpmf = 0, dnocli = 0;
    line_extract_int(line, "\"n\":", &n);
    line_extract_int(line, "\"recon\":", &recon);
    line_extract_int(line, "\"attackable\":", &att);
    line_extract_int(line, "\"chans\":", &chans);
    line_extract_int(line, "\"assoc\":", &assoc);
    line_extract_int(line, "\"deauth\":", &deauth);
    line_extract_int(line, "\"unicast\":", &uni);
    line_extract_int(line, "\"sta\":", &sta);
    line_extract_int(line, "\"hs\":", &hs);
    line_extract_int(line, "\"pmkid\":", &pmkid);
    line_extract_int(line, "\"miss\":", &miss);
    line_extract_int(line, "\"dpmf\":", &dpmf); // deauths skipped: PMF-protected
    line_extract_int(line, "\"dnocli\":", &dnocli); // deauths skipped: no client

    uint32_t up = 0;
    char lat[16], lon[16];
    with_view_model(
        app->view, PwnfriendModel * model,
        {
            up = model->tick_secs;
            strncpy(lat, model->last_lat, sizeof(lat));
            lat[sizeof(lat) - 1] = '\0';
            strncpy(lon, model->last_lon, sizeof(lon));
            lon[sizeof(lon) - 1] = '\0';
        },
        false);

    storage_common_mkdir(app->storage, "/ext/apps_data/pwnfriend");
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, TELEMETRY_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        if(storage_file_size(f) == 0) {
            const char* h =
                "uptime_s,lat,lon,epoch,recon,attackable,chans,assoc,deauth,unicast,sta,hs,pmkid,"
                "miss,dpmf,dnocli\n";
            storage_file_write(f, h, strlen(h));
        }
        char row[200];
        snprintf(
            row, sizeof(row), "%lu,%s,%s,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
            (unsigned long)up, lat, lon, n, recon, att, chans, assoc, deauth, uni, sta, hs, pmkid,
            miss, dpmf, dnocli);
        storage_file_write(f, row, strlen(row));
    }
    storage_file_close(f);
    storage_file_free(f);
}

// "PWNFRIEND_GPS fix=.. sats=.. acc=.. lat=.. lon=.." (fw v5) — periodic fix status, emitted
// even with no fix, so we can watch acquisition on-screen and log TTFF to gps.csv.
static void pwnfriend_handle_gps_line(PwnfriendApp* app, const char* line) {
    int fix = 0, sats = 0, acc = 0;
    char lat[16] = "", lon[16] = "";
    line_extract_int(line, "fix=", &fix);
    line_extract_int(line, "sats=", &sats);
    line_extract_int(line, "acc=", &acc);
    line_extract_number(line, "lat=", lat, sizeof(lat));
    line_extract_number(line, "lon=", lon, sizeof(lon));

    uint32_t up = 0;
    with_view_model(
        app->view, PwnfriendModel * model,
        {
            model->gps_fix = fix != 0;
            model->gps_sats = sats;
            model->gps_acc = acc;
            up = model->tick_secs;
        },
        false);

    storage_common_mkdir(app->storage, "/ext/apps_data/pwnfriend");
    File* f = storage_file_alloc(app->storage);
    if(storage_file_open(f, GPS_PATH, FSAM_WRITE, FSOM_OPEN_APPEND)) {
        if(storage_file_size(f) == 0) {
            const char* h = "uptime_s,fix,sats,acc_m,lat,lon\n";
            storage_file_write(f, h, strlen(h));
        }
        char row[96];
        snprintf(
            row, sizeof(row), "%lu,%d,%d,%d,%s,%s\n", (unsigned long)up, fix, sats, acc, lat, lon);
        storage_file_write(f, row, strlen(row));
    }
    storage_file_close(f);
    storage_file_free(f);
}

static void pwnfriend_process_line(PwnfriendApp* app, const char* line) {
    // PWND and PEER share the PWNFRIEND_P prefix, so compare both fully
    if(strncmp(line, "PWNFRIEND_PEER ", 15) == 0) {
        pwnfriend_handle_peer_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_PWND ", 15) == 0) {
        pwnfriend_handle_pwnd_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_HS ", 13) == 0) {
        pwnfriend_handle_hs_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_AP ", 13) == 0) {
        pwnfriend_handle_ap_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_RSSI ", 15) == 0) {
        pwnfriend_handle_rssi_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_EPOCH ", 16) == 0) {
        pwnfriend_handle_epoch_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_GPS ", 14) == 0) {
        pwnfriend_handle_gps_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_ADV ", 14) == 0) {
        pwnfriend_handle_adv_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_MISS ", 15) == 0) {
        pwnfriend_handle_miss_line(app, line);
    }
    // any PWNFRIEND_* line proves the board is alive; stamp the link watchdog here
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
    // other lines are ordinary Marauder chatter; ignore
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

// map persona + peers onto the flipagotchi Pwnagotchi struct; repopulated each draw
static void pwnfriend_populate(PwnfriendModel* model) {
    Persona* p = model->persona;
    Pwnagotchi* pwn = model->pwn;

    furi_string_set(pwn->hostname, p->s.name);
    pwn->face = (enum PwnagotchiFace)persona_face(p);
    // exit prompt: angry face while asking, happy for a beat if you stay. deadline compare works at tick 0
    bool staying = model->tick_secs < model->stayed_until;
    if(model->confirm_exit)
        pwn->face = (enum PwnagotchiFace)FaceAngry;
    else if(staying)
        pwn->face = (enum PwnagotchiFace)FaceHappy;
    pwn->mode = PwnMode_Ai;

    // CH: the channel the ESP32 is on now (per PWNFRIEND_ADV); '*' until it reports one
    uint8_t cur_ch = model->adv_channel;
    if(cur_ch >= 1 && cur_ch <= 14) {
        furi_string_printf(pwn->channel, "%u", (unsigned)cur_ch);
    } else {
        furi_string_set(pwn->channel, "*");
    }

    // AP: count of recent, not-ignored APs on the current channel (all recent if channel unknown)
    uint16_t apc = 0;
    for(uint16_t i = 0; i < model->ap_count; i++) {
        if(model->aps[i].whitelisted) continue; // ignored APs don't count
        if(cur_ch >= 1 && cur_ch <= 14 && model->aps[i].channel != cur_ch) continue;
        if(!ap_signal_recent(model, i)) continue;
        apc++;
    }
    furi_string_printf(pwn->apStat, "%u", (unsigned)apc);

    // BAT slot: power/saver-aware label + %. on power: "PWR" alone when full, "PWR 85%" while
    // charging; on battery: BAT / BAT L / BAT D per the effective saver level, + %.
    if(model->on_power && model->charge_done) {
        furi_string_set_str(pwn->uptime, "PWR");
    } else {
        uint8_t eff_sv = effective_saver(model);
        const char* slot = model->on_power ? "PWR" :
                           (eff_sv == 2 ? "BAT D" : (eff_sv == 1 ? "BAT L" : "BAT"));
        furi_string_printf(pwn->uptime, "%s %u%%", slot, (unsigned)model->battery_pct);
    }

    // PWND: real handshakes captured, this session (lifetime).
    furi_string_printf(
        pwn->handshakes,
        "%lu (%lu)",
        (unsigned long)p->pwnd_run,
        (unsigned long)p->s.pwnd_tot);

    // message bubble (Mood page only). paused hint + fresh-catch shout take priority; else mood, and now and then a stat brag
    if(model->confirm_exit) {
        furi_string_set(pwn->message, "leaving me? Back=bye");
    } else if(staying) {
        furi_string_set(pwn->message, "yay, staying!");
    } else if(!model->advertising) {
        furi_string_set(pwn->message, "paused - OK for menu");
    } else if((p->mood == MoodHappy || p->mood == MoodCool) && model->last_pwnd_ssid[0]) {
        furi_string_printf(pwn->message, "pwnd %s!", model->last_pwnd_ssid);
    } else {
        uint32_t slot = (model->tick_secs / 5) % 6; // rotate every 5s
        if(slot == 1 && p->pwnd_run)
            furi_string_printf(pwn->message, "%lu shakes!", (unsigned long)p->pwnd_run);
        else if(slot == 3 && p->aps_session)
            furi_string_printf(pwn->message, "%lu APs seen", (unsigned long)p->aps_session);
        else if(slot == 5)
            furi_string_set(pwn->message, "Hack the planet!"); // wraps to 2 lines in the bubble
        else
            furi_string_set(pwn->message, persona_mood_label(p));
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

// one-time authorization acknowledgement, before capture can be armed
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

// encode the setup URL once, on the app thread (not the draw callback); maxVersion capped
// at 4 so the buffers stay ~138B and don't blow the stack.
static void pwnfriend_qr_encode(PwnfriendModel* model) {
    uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
    model->qr_ok = qrcodegen_encodeText(
        PWNFRIEND_SETUP_URL, tmp, model->qr, qrcodegen_Ecc_LOW, 1, 4,
        qrcodegen_Mask_AUTO, true);
}

// "No ESP32" warning: setup QR (left) + what-to-check text (right)
static void draw_str_trunc(Canvas* c, int x, int y, const char* s, int maxw); // defined below

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

// QR of the selected AP's location (a geo: URI); scan with a phone
static void pwnfriend_draw_ap_qr(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    const ApRec* a = &model->aps[model->detail_ap];
    if(model->ap_qr_ok) {
        int size = qrcodegen_getSize(model->ap_qr);
        int scale = (FLIPPER_SCREEN_HEIGHT - 2) / size; // fit the height, keep a quiet zone
        if(scale < 1) scale = 1;
        int px = size * scale;
        int oy = (FLIPPER_SCREEN_HEIGHT - px) / 2;
        for(int y = 0; y < size; y++)
            for(int x = 0; x < size; x++)
                if(qrcodegen_getModule(model->ap_qr, x, y))
                    canvas_draw_box(canvas, 2 + x * scale, oy + y * scale, scale, scale);
        int tx = 2 + px + 5;
        int tw = FLIPPER_SCREEN_WIDTH - tx - 2;
        // AP name as the heading, its estimated coordinates beside the QR.
        canvas_set_font(canvas, FontPrimary);
        draw_str_trunc(canvas, tx, 12, a->ssid[0] ? a->ssid : "(hidden)", tw);
        canvas_set_font(canvas, FontSecondary);
        float elat = a->lat, elon = a->lon;
        loc_estimate(
            model->triangulate, a->loc_n, a->w_sum, a->wlat_sum, a->wlon_sum, a->lat, a->lon,
            &elat, &elon);
        char cbuf[16];
        fmt_coord(elat, cbuf, sizeof(cbuf));
        canvas_draw_str(canvas, tx, 30, cbuf);
        fmt_coord(elon, cbuf, sizeof(cbuf));
        canvas_draw_str(canvas, tx, 42, cbuf);
        canvas_draw_str(canvas, tx, 56, "scan me");
    } else {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 4, 32, "no location for this AP");
    }
}

// bottom-right: the last pwned AP, right-aligned on the PWND baseline, clamped so it never collides with the "PWND N (N)" count
#define PWNFRIEND_STATUS_LEFT_LIMIT 64
#define PWNFRIEND_STATUS_Y PWNAGOTCHI_HANDSHAKES_I // 63, the PWND baseline row

static void pwnfriend_draw_last_pwnd(Canvas* canvas, const PwnfriendModel* model) {
    if(!model->last_pwnd_ssid[0]) return; // nothing captured yet -> leave it blank
    canvas_set_font(canvas, FontSecondary);
    // left limit = measured width of the "PWND N (N)" count + a gap, so a big count can't be overlapped
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

// RSSI -> 0..50 bar units (total=50): -90 dBm (floor) empty .. -40 dBm full.
static int rssi_level(int rssi) {
    int v = rssi + 90;
    if(v < 0) v = 0;
    if(v > 50) v = 50;
    return v;
}

// AP RSSI fresh enough (heard within the TTL) to show a meter; stale/loaded APs hide it
static bool ap_signal_recent(const PwnfriendModel* m, uint16_t i) {
    return m->ap_seen_tick[i] != 0 && (m->tick_secs - m->ap_seen_tick[i]) <= AP_SIGNAL_TTL_SECS;
}

// Compact capture flags for a list row: E(SSID)/P(MKID)/H(andshake), '-' if absent.
static void ap_flags_str(const ApRec* a, char out[4]) {
    out[0] = a->has_essid ? 'E' : '-';
    out[1] = a->pmkid ? 'P' : '-';
    out[2] = a->handshake ? 'H' : '-';
    out[3] = '\0';
}

// draw s at baseline (x,y), clipped to maxw. ASCII renders; every other UTF-8 char draws as
// one centred dot (Flipper font can't). display-only; raw SSID stays in the CSV/pcap.
static void draw_str_trunc(Canvas* c, int x, int y, const char* s, int maxw) {
    const int xend = x + maxw;
    const int dot_cell = 5; // px a substituted glyph occupies
    char run[48]; // buffer consecutive ASCII so a run draws as ONE string (proper kerning)
    size_t rn = 0;
    for(const char* p = s;; p++) {
        unsigned char ch = (unsigned char)*p;
        bool ascii = (ch >= 0x20 && ch < 0x7F);
        if(ascii && rn < sizeof(run) - 1) {
            run[rn++] = *p;
            continue;
        }
        if(rn) { // flush the accumulated ASCII run in one draw call
            run[rn] = '\0';
            int w = (int)canvas_string_width(c, run);
            if(x + w <= xend) {
                canvas_draw_str(c, x, y, run);
                x += w;
                rn = 0;
            } else {
                // Tail doesn't fit: grow char-by-char to the widest prefix that does, draw, stop.
                char tmp[48];
                size_t k = 0;
                for(; k < rn; k++) {
                    tmp[k] = run[k];
                    tmp[k + 1] = '\0';
                    if(x + (int)canvas_string_width(c, tmp) > xend) {
                        tmp[k] = '\0';
                        break;
                    }
                }
                canvas_draw_str(c, x, y, tmp);
                return;
            }
        }
        if(ch == '\0') break;
        if(!ascii) {
            // one dot per non-ASCII char: skip its UTF-8 continuation bytes
            while(((unsigned char)*(p + 1) & 0xC0) == 0x80) p++;
            if(x + dot_cell > xend) return;
            canvas_draw_box(c, x + 1, y - 4, 2, 2); // centred in the ~8px row
            x += dot_cell;
        }
    }
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
    return m == CaptureDeauth ? "DEAUTH" : m == CapturePmkid ? "PMKID" :
           m == CapturePassive ? "CAP" :
                                 "off";
}

// tiny inline d-pad glyphs (no firmware icons); x = left edge, yc = vertical centre
static void icon_left(Canvas* c, int x, int yc) { // solid ◄, 4x7
    for(int i = 0; i < 4; i++) canvas_draw_line(c, x + i, yc - i, x + i, yc + i);
}
static void icon_right(Canvas* c, int x, int yc) { // solid ►, 4x7
    for(int i = 0; i < 4; i++) canvas_draw_line(c, x + 3 - i, yc - i, x + 3 - i, yc + i);
}
// right-aligned "◄ value ►" for an arrow-adjustable row; y = text baseline
static void draw_adjust_value(Canvas* c, int y, const char* value) {
    int yc = y - 3; // glyph centre vs the text baseline
    int vw = (int)canvas_string_width(c, value);
    icon_right(c, FLIPPER_SCREEN_WIDTH - 5, yc); // ► apex at the right edge (col 126)
    int vx = FLIPPER_SCREEN_WIDTH - 5 - 2 - vw; // value sits left of the ►
    canvas_draw_str(c, vx, y, value);
    icon_left(c, vx - 6, yc); // ◄ left of the value
}
// inverted title bar: title left, optional right text
static void draw_titlebar(Canvas* c, const char* title, const char* right) {
    canvas_draw_box(c, 0, 0, FLIPPER_SCREEN_WIDTH, 11);
    canvas_set_color(c, ColorWhite);
    canvas_set_font(c, FontSecondary);
    int rw = right ? (int)canvas_string_width(c, right) : 0;
    // title via the dot renderer (may carry unrenderable unicode), clipped off the right text
    draw_str_trunc(c, 2, 9, title, FLIPPER_SCREEN_WIDTH - 2 - (right ? rw + 4 : 2));
    if(right) canvas_draw_str(c, FLIPPER_SCREEN_WIDTH - 2 - rw, 9, right);
    canvas_set_color(c, ColorBlack);
}

// fill out[] with filtered aps[] indices: live signal first, then strongest RSSI, discovery order as a stable tiebreak. insertion sort, n<=256
static uint16_t ap_filtered(const PwnfriendModel* m, uint16_t* out) {
    uint16_t n = 0;
    for(uint16_t i = 0; i < m->ap_count; i++) {
        if(m->list_filter == FilterPwned && !(m->aps[i].pmkid || m->aps[i].handshake)) continue;
        if(m->list_filter == FilterWhitelist && !m->aps[i].whitelisted) continue;
        out[n++] = i;
    }
    for(uint16_t i = 1; i < n; i++) {
        uint16_t v = out[i];
        bool rv = ap_signal_recent(m, v);
        int16_t rssiv = m->aps[v].rssi;
        uint32_t sv = m->aps[v].first_seq;
        int j = (int)i - 1;
        while(j >= 0) {
            uint16_t u = out[j];
            bool ru = ap_signal_recent(m, u);
            int16_t rssiu = m->aps[u].rssi;
            // v outranks u: live over stale; else stronger RSSI; else earlier-discovered (stable)
            bool v_first = (rv && !ru) ||
                           (rv == ru && (rssiv > rssiu || (rssiv == rssiu && sv > m->aps[u].first_seq)));
            if(!v_first) break;
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = v;
    }
    return n;
}

#define APLIST_ROWS 5

// True if this friend's RSSI is fresh enough to show a live meter (heard within the TTL).
static bool friend_signal_recent(const PwnfriendModel* m, uint16_t i) {
    return m->friend_seen_tick[i] != 0 &&
           (m->tick_secs - m->friend_seen_tick[i]) <= AP_SIGNAL_TTL_SECS;
}

// order friends[]: live first, then strongest RSSI, discovery order as a stable tiebreak. insertion sort, n<=64
static uint16_t friend_order(const PwnfriendModel* m, uint16_t* out) {
    uint16_t n = m->friend_count;
    for(uint16_t i = 0; i < n; i++) out[i] = i;
    for(uint16_t i = 1; i < n; i++) {
        uint16_t v = out[i];
        bool rv = friend_signal_recent(m, v);
        int16_t rssiv = m->friends[v].rssi;
        uint32_t sv = m->friends[v].first_seq;
        int j = (int)i - 1;
        while(j >= 0) {
            uint16_t u = out[j];
            bool ru = friend_signal_recent(m, u);
            int16_t rssiu = m->friends[u].rssi;
            bool v_first = (rv && !ru) ||
                           (rv == ru &&
                            (rssiv > rssiu || (rssiv == rssiu && sv > m->friends[u].first_seq)));
            if(!v_first) break;
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = v;
    }
    return n;
}

static void pwnfriend_draw_menu(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    draw_titlebar(canvas, "pwnfriend menu", NULL);
    canvas_set_font(canvas, FontSecondary);

    uint16_t pwned = 0, wl = 0;
    for(uint16_t i = 0; i < model->ap_count; i++) {
        if(model->aps[i].pmkid || model->aps[i].handshake) pwned++;
        if(model->aps[i].whitelisted) wl++;
    }

    int rows = APLIST_ROWS;
    int top = 0;
    if(model->menu_idx >= rows) top = model->menu_idx - rows + 1;
    for(int r = 0; r < rows && top + r < MenuCount; r++) {
        int it = top + r;
        const char* label = "";
        char value[24];
        value[0] = '\0';
        bool adjustable = false; // draws ◄ value ► instead of a plain right-aligned value
        switch(it) {
        // OK-activated rows: a plain right-aligned value (count / name / hint).
        case MenuPwnedAps: label = "Pwned APs"; snprintf(value, sizeof(value), "%u", pwned); break;
        case MenuAllAps:
            label = "Recent APs";
            snprintf(value, sizeof(value), "%u", model->ap_count);
            break;
        case MenuWhitelist: label = "Ignore"; snprintf(value, sizeof(value), "%u", wl); break;
        case MenuFriends:
            label = "Friends";
            snprintf(
                value, sizeof(value), "%u%s", model->friend_count,
                model->friend_overflow ? "+" : "");
            break;
        case MenuTarget: {
            label = "Target";
            const char* tn = NULL;
            for(uint16_t i = 0; i < model->ap_count; i++)
                if(model->aps[i].targeted) {
                    tn = model->aps[i].ssid[0] ? model->aps[i].ssid : model->aps[i].bssid;
                    break;
                }
            snprintf(value, sizeof(value), "%.14s", tn ? tn : "*"); // clear it with OK
            break;
        }
        case MenuStats: label = "Stats"; break;
        case MenuName:
            label = "Name";
            snprintf(value, sizeof(value), "%s", model->persona->s.name);
            break;
        case MenuSetHome:
            label = "Set home";
            if(!model->gps_seen) snprintf(value, sizeof(value), "no gps");
            break;
        // Arrow-adjustable rows: value flanked by ◄ ► glyphs.
        case MenuAdvertise:
            label = "Advertise";
            adjustable = true;
            snprintf(value, sizeof(value), "%s", model->advertising ? "ON" : "off");
            break;
        case MenuCapture:
            label = "Capture";
            adjustable = true;
            snprintf(value, sizeof(value), "%s", capture_name(model->capture_mode));
            break;
        case MenuMinRssi:
            label = "Min RSSI";
            adjustable = true;
            snprintf(value, sizeof(value), "%d", model->min_rssi);
            break;
        case MenuRecon:
            label = "Recon";
            adjustable = true;
            snprintf(value, sizeof(value), "%us", model->recon_secs);
            break;
        case MenuQuiet:
            label = "Quiet";
            adjustable = true;
            snprintf(value, sizeof(value), "%s", model->quiet ? "on" : "off");
            break;
        case MenuTriangulate:
            label = "Triangulate";
            adjustable = true;
            snprintf(value, sizeof(value), "%s", model->triangulate ? "on" : "off");
            break;
        case MenuBattery:
            label = "Battery saver";
            adjustable = true;
            snprintf(
                value, sizeof(value), "%s",
                model->saver == 3 ? "auto" :
                model->saver == 2 ? "deep" :
                model->saver == 1 ? "light" :
                                    "off");
            break;
        case MenuAbout: label = "About"; break;
        default: break;
        }
        int y = 11 + (r + 1) * 10; // baseline of this row
        bool sel = it == model->menu_idx;
        if(sel) {
            canvas_draw_box(canvas, 0, y - 9, FLIPPER_SCREEN_WIDTH, 10);
            canvas_set_color(canvas, ColorWhite);
        }
        canvas_draw_str(canvas, 3, y, label);
        if(value[0]) {
            if(adjustable) {
                draw_adjust_value(canvas, y, value);
            } else {
                int vw = (int)canvas_string_width(canvas, value);
                canvas_draw_str(canvas, FLIPPER_SCREEN_WIDTH - 3 - vw, y, value);
            }
        }
        if(sel) canvas_set_color(canvas, ColorBlack);
    }
}

static void pwnfriend_draw_aplist(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    char title[24];
    snprintf(
        title, sizeof(title), "%s",
        model->list_filter == FilterPwned    ? "PWNED APS" :
        model->list_filter == FilterWhitelist ? "IGNORED" :
                                                "RECENT APS");
    uint16_t idx[AP_MAX];
    uint16_t n = ap_filtered(model, idx);
    char hint[10];
    snprintf(hint, sizeof(hint), "%u", n);
    draw_titlebar(canvas, title, hint);
    canvas_set_font(canvas, FontSecondary);
    if(n == 0) {
        canvas_draw_str(
            canvas, 2, 36,
            model->list_filter == FilterPwned    ? "no pwned APs yet" :
            model->list_filter == FilterWhitelist ? "no ignored APs" :
                                                    "no APs seen yet");
        return;
    }
    for(uint16_t r = 0; r < APLIST_ROWS && model->list_top + r < n; r++) {
        uint16_t apidx = idx[model->list_top + r];
        const ApRec* a = &model->aps[apidx];
        int y = 11 + (r + 1) * 10;
        bool sel = (model->list_top + r == model->list_idx);
        if(sel) {
            canvas_draw_box(canvas, 0, y - 9, FLIPPER_SCREEN_WIDTH, 10);
            canvas_set_color(canvas, ColorWhite);
        }
        // pwned view: name + [T/I] + capture status; other views also add signal bar + E/P/H flags
        const char* name = a->ssid[0] ? a->ssid : a->bssid;
        bool pwned_view = model->list_filter == FilterPwned;
        char right[8];
        if(pwned_view)
            snprintf(right, sizeof(right), "%s", ap_crackable(a) ? "CRACK" : "cap");
        else
            ap_flags_str(a, right);
        int fw = (int)canvas_string_width(canvas, right);
        int fx = FLIPPER_SCREEN_WIDTH - 2 - fw; // right element hugs the right edge
        int marker_x = pwned_view ? fx - 10 : 0;
        if(!pwned_view) {
            int bar_w = 26;
            int bar_x = fx - 4 - bar_w;
            marker_x = bar_x - 8;
            // Only draw the meter if the signal is fresh; a stale AP shows no bar.
            if(ap_signal_recent(model, apidx))
                draw_progress(canvas, bar_x, y - 7, bar_w, 7, rssi_level(a->rssi), 50);
        }
        draw_str_trunc(canvas, 3, y, name, marker_x - 5);
        if(a->targeted)
            canvas_draw_str(canvas, marker_x, y, "T");
        else if(a->whitelisted)
            canvas_draw_str(canvas, marker_x, y, "I");
        canvas_draw_str(canvas, fx, y, right);
        if(sel) canvas_set_color(canvas, ColorBlack);
    }
}

static void pwnfriend_draw_apdetail(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    const ApRec* a = &model->aps[model->detail_ap];
    // SSID goes in the title bar (clipped at the edge if long) so the body has room.
    draw_titlebar(canvas, a->ssid[0] ? a->ssid : "(hidden)", NULL);
    canvas_set_font(canvas, FontSecondary);
    char l[40];
    char mac[18];
    fmt_bssid_colons(a->bssid, mac);
    snprintf(l, sizeof(l), "%s  ch%d", mac, a->channel);
    canvas_draw_str(canvas, 2, 22, l);
    // distance to the AP's estimated location (triangulated, else strongest fix); needs a current fix
    float clat = parse_deg(model->last_lat), clon = parse_deg(model->last_lon);
    float alat = 1e9f, alon = 1e9f;
    loc_estimate(
        model->triangulate, a->loc_n, a->w_sum, a->wlat_sum, a->wlon_sum, a->lat, a->lon, &alat,
        &alon);
    char dist[14];
    dist[0] = '\0';
    if(model->gps_seen && clat < 1e8f && alat < 1e8f) {
        float km = geo_km(clat, clon, alat, alon);
        if(km < 1.0f)
            snprintf(dist, sizeof(dist), "~%dm", (int)(km * 1000.0f));
        else
            snprintf(dist, sizeof(dist), "~%dkm", (int)(km + 0.5f));
    }
    // Row 2: bar (only if fresh) + RSSI + age, with the DISTANCE right-aligned.
    char age[10];
    uint32_t seen = model->ap_seen_tick[model->detail_ap];
    if(seen)
        fmt_age(model->tick_secs - seen, age, sizeof(age));
    else
        snprintf(age, sizeof(age), "old");
    if(ap_signal_recent(model, model->detail_ap)) {
        draw_progress(canvas, 2, 30, 34, 8, rssi_level(a->rssi), 50);
        snprintf(l, sizeof(l), "%ddBm %s", a->rssi, age);
        canvas_draw_str(canvas, 40, 37, l);
    } else {
        snprintf(l, sizeof(l), "%ddBm %s", a->rssi, age);
        canvas_draw_str(canvas, 2, 37, l);
    }
    if(dist[0])
        canvas_draw_str(
            canvas, FLIPPER_SCREEN_WIDTH - 2 - (int)canvas_string_width(canvas, dist), 37, dist);
    // Crackability as a plain-language formula (what we have -> whether it cracks).
    const char* key = a->pmkid ? "PMKID" : a->handshake ? "HS" : NULL;
    if(a->has_essid && key)
        snprintf(l, sizeof(l), "ESSID + %s = CRACKABLE", key);
    else if(key)
        snprintf(l, sizeof(l), "%s but no ESSID", key);
    else if(a->has_essid)
        snprintf(l, sizeof(l), "ESSID, no key yet");
    else
        snprintf(l, sizeof(l), "nothing caught yet");
    canvas_draw_str(canvas, 2, 53, l);
    // bottom row: target[x] (Left), ignore[x] (Right), and a centred OK-map hint when a location is known
    snprintf(l, sizeof(l), "target[%c]", a->targeted ? 'x' : ' ');
    canvas_draw_str(canvas, 2, 63, l);
    snprintf(l, sizeof(l), "ignore[%c]", a->whitelisted ? 'x' : ' ');
    int rw = (int)canvas_string_width(canvas, l);
    canvas_draw_str(canvas, FLIPPER_SCREEN_WIDTH - 2 - rw, 63, l);
    if(alat < 1e8f) {
        const char* h = "map";
        int gw = 7 + 2 + (int)canvas_string_width(canvas, h);
        int gx = (FLIPPER_SCREEN_WIDTH - gw) / 2;
        canvas_draw_disc(canvas, gx + 3, 60, 3);
        canvas_draw_str(canvas, gx + 9, 63, h);
    }
}

static void pwnfriend_draw_friendlist(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    uint16_t idx[FRIEND_MAX];
    uint16_t n = friend_order(model, idx);
    char hint[10];
    snprintf(hint, sizeof(hint), "%u%s", n, model->friend_overflow ? "+" : "");
    draw_titlebar(canvas, "FRIENDS", hint);
    canvas_set_font(canvas, FontSecondary);
    if(n == 0) {
        canvas_draw_str(canvas, 2, 36, "no friends met yet");
        return;
    }
    for(uint16_t r = 0; r < APLIST_ROWS && model->fl_top + r < n; r++) {
        uint16_t fidx = idx[model->fl_top + r];
        const FriendRec* fr = &model->friends[fidx];
        int y = 11 + (r + 1) * 10;
        bool sel = (model->fl_top + r == model->fl_idx);
        if(sel) {
            canvas_draw_box(canvas, 0, y - 9, FLIPPER_SCREEN_WIDTH, 10);
            canvas_set_color(canvas, ColorWhite);
        }
        const char* name = fr->name[0] ? fr->name : "???";
        // Right: their capture count (a pwnagotchi's headline stat).
        char right[12];
        snprintf(right, sizeof(right), "%ld", (long)fr->pwnd_tot);
        int fw = (int)canvas_string_width(canvas, right);
        int fx = FLIPPER_SCREEN_WIDTH - 2 - fw;
        int bar_w = 26;
        int bar_x = fx - 4 - bar_w;
        if(friend_signal_recent(model, fidx))
            draw_progress(canvas, bar_x, y - 7, bar_w, 7, rssi_level(fr->rssi), 50);
        draw_str_trunc(canvas, 3, y, name, bar_x - 5);
        canvas_draw_str(canvas, fx, y, right);
        if(sel) canvas_set_color(canvas, ColorBlack);
    }
}

static void pwnfriend_draw_frienddetail(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    const FriendRec* fr = &model->friends[model->detail_friend];
    // friend's face (ASCII stand-in; real pwngrid faces are unicode) in the title's right slot, name left
    draw_titlebar(canvas, fr->name[0] ? fr->name : "???", "^_^");
    canvas_set_font(canvas, FontSecondary);
    char l[40];
    // Row 1: a short slice of the 64-hex identity (enough to tell buddies apart).
    char sid[17];
    strncpy(sid, fr->identity, sizeof(sid) - 1);
    sid[sizeof(sid) - 1] = '\0';
    snprintf(l, sizeof(l), "id %s", sid);
    canvas_draw_str(canvas, 2, 22, l);
    // Distance from us to the friend's estimated location (triangulated, else strongest fix).
    float clat = parse_deg(model->last_lat), clon = parse_deg(model->last_lon);
    float alat = 1e9f, alon = 1e9f;
    loc_estimate(
        model->triangulate, fr->loc_n, fr->w_sum, fr->wlat_sum, fr->wlon_sum, fr->lat, fr->lon,
        &alat, &alon);
    char dist[14];
    dist[0] = '\0';
    if(model->gps_seen && clat < 1e8f && alat < 1e8f) {
        float km = geo_km(clat, clon, alat, alon);
        if(km < 1.0f)
            snprintf(dist, sizeof(dist), "~%dm", (int)(km * 1000.0f));
        else
            snprintf(dist, sizeof(dist), "~%dkm", (int)(km + 0.5f));
    }
    // Row 2: signal (live bar + current RSSI, else best-ever) + age, distance right-aligned.
    char age[10];
    uint32_t seen = model->friend_seen_tick[model->detail_friend];
    if(seen)
        fmt_age(model->tick_secs - seen, age, sizeof(age));
    else
        snprintf(age, sizeof(age), "old");
    if(friend_signal_recent(model, model->detail_friend)) {
        draw_progress(canvas, 2, 30, 34, 8, rssi_level(fr->rssi), 50);
        snprintf(l, sizeof(l), "%ddBm %s", fr->rssi, age);
        canvas_draw_str(canvas, 40, 37, l);
    } else {
        snprintf(l, sizeof(l), "best %ddBm %s", fr->best_rssi, age);
        canvas_draw_str(canvas, 2, 37, l);
    }
    if(dist[0])
        canvas_draw_str(
            canvas, FLIPPER_SCREEN_WIDTH - 2 - (int)canvas_string_width(canvas, dist), 37, dist);
    // Row: their capture count + how many times we've heard them (triangulation samples).
    snprintf(l, sizeof(l), "pwned %ld   seen %ux", (long)fr->pwnd_tot, fr->times_seen);
    canvas_draw_str(canvas, 2, 50, l);
    // OK-map hint on the bottom row (a small disc + "map"), centred, when a location is known.
    if(alat < 1e8f) {
        const char* h = "map";
        int gw = 7 + 2 + (int)canvas_string_width(canvas, h);
        int gx = (FLIPPER_SCREEN_WIDTH - gw) / 2;
        canvas_draw_disc(canvas, gx + 3, 60, 3);
        canvas_draw_str(canvas, gx + 9, 63, h);
    }
}

// QR of the friend's last location; reuses the AP-location QR buffer (one QR on screen at a time)
static void pwnfriend_draw_friend_qr(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    const FriendRec* fr = &model->friends[model->detail_friend];
    if(model->ap_qr_ok) {
        int size = qrcodegen_getSize(model->ap_qr);
        int scale = (FLIPPER_SCREEN_HEIGHT - 2) / size;
        if(scale < 1) scale = 1;
        int px = size * scale;
        int oy = (FLIPPER_SCREEN_HEIGHT - px) / 2;
        for(int y = 0; y < size; y++)
            for(int x = 0; x < size; x++)
                if(qrcodegen_getModule(model->ap_qr, x, y))
                    canvas_draw_box(canvas, 2 + x * scale, oy + y * scale, scale, scale);
        int tx = 2 + px + 5;
        int tw = FLIPPER_SCREEN_WIDTH - tx - 2;
        canvas_set_font(canvas, FontPrimary);
        draw_str_trunc(canvas, tx, 12, fr->name[0] ? fr->name : "???", tw);
        canvas_set_font(canvas, FontSecondary);
        float elat = fr->lat, elon = fr->lon;
        loc_estimate(
            model->triangulate, fr->loc_n, fr->w_sum, fr->wlat_sum, fr->wlon_sum, fr->lat, fr->lon,
            &elat, &elon);
        char cbuf[16];
        fmt_coord(elat, cbuf, sizeof(cbuf));
        canvas_draw_str(canvas, tx, 30, cbuf);
        fmt_coord(elon, cbuf, sizeof(cbuf));
        canvas_draw_str(canvas, tx, 42, cbuf);
        canvas_draw_str(canvas, tx, 56, "scan me");
    } else {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 4, 32, "no location for friend");
    }
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
    // tx beacons + capture provenance split (active = our attack, passive = sniffed)
    snprintf(
        l, sizeof(l), "tx %lu  pwn a%lu/p%lu", (unsigned long)model->adv_sent_count,
        (unsigned long)model->pwn_active, (unsigned long)model->pwn_passive);
    canvas_draw_str(canvas, 2, 61, l);
}

// the <mrq> mark as text; draw_mono() renders it at a fixed pitch (stock fonts are proportional)
static const char* MRQ_ART[] = {
    "     _    __/\\_______  _______",
    "    / \\  /  \\_____   \\/  ___  \\",
    "   /   \\/    /  _/  _/     /  /",
    "  /         /   \\   \\     /  /",
    " /   /\\  /\\_\\___/\\   \\____   \\",
    "(___/  \\/  <mrq>  \\___)   \\___)",
};

// draw an ASCII-art line at a fixed cell pitch cw so columns line up
static void draw_mono(Canvas* c, int x, int y, const char* s, int cw) {
    for(const char* p = s; *p; p++, x += cw) {
        if(*p == ' ') continue; // blank cell — just advance
        char ch[2] = {*p, '\0'};
        canvas_draw_str(c, x, y, ch);
    }
}

static void pwnfriend_draw_about(Canvas* canvas, const PwnfriendModel* model) {
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);
    // the mrq banner scrolls (timer advances about_scroll; OK toggles bounce/infinite; Left/Right speed). art on 8px rows, bottom free for two version lines
    const size_t art_n = sizeof(MRQ_ART) / sizeof(MRQ_ART[0]);
    int cw = (int)canvas_string_width(canvas, "_"); // pitch: seamless underscore runs
    if(cw < 1) cw = 5;
    int cols = 0;
    for(size_t i = 0; i < art_n; i++) {
        int len = (int)strlen(MRQ_ART[i]);
        if(len > cols) cols = len;
    }
    int art_w = cols * cw;
    const int GAP = 16; // blank run between the wrapped copies in infinite mode
    int x0; // left x of the first art copy
    if(model->about_infinite) {
        int period = art_w + GAP;
        x0 = -(int)(model->about_scroll % (uint32_t)period);
    } else {
        int span = art_w - FLIPPER_SCREEN_WIDTH; // overflow to reveal on the right
        if(span < 0) span = 0;
        if(span == 0) {
            x0 = 0;
        } else {
            int phase = (int)(model->about_scroll % (uint32_t)(2 * span));
            x0 = -(phase <= span ? phase : 2 * span - phase); // triangle wave = bounce
        }
    }
    for(size_t i = 0; i < art_n; i++) {
        int y = 7 + (int)i * 8;
        draw_mono(canvas, x0, y, MRQ_ART[i], cw);
        if(model->about_infinite) draw_mono(canvas, x0 + art_w + GAP, y, MRQ_ART[i], cw);
    }
    char line[32];
    // App: version + short git hash (baked in at build; "nogit" outside a checkout).
    snprintf(line, sizeof(line), "app %s %s", PWNFRIEND_APP_VERSION, PWNFRIEND_GIT_HASH);
    canvas_draw_str(canvas, 2, 56, line);
    // firmware: prefer the build hash (verifiable reflash; the protocol number can't tell two v4 builds apart), fall back to the protocol
    if(model->fw_proto == 0)
        snprintf(line, sizeof(line), "fw  none (want v%d)", PWNFRIEND_FW_PROTO);
    else if(model->fw_commit[0])
        snprintf(
            line, sizeof(line), "fw  %s %s", model->fw_commit,
            model->fw_proto < PWNFRIEND_FW_PROTO ? "old" : "ok");
    else if(model->fw_proto < PWNFRIEND_FW_PROTO)
        snprintf(line, sizeof(line), "fw  v%d old (want v%d)", model->fw_proto, PWNFRIEND_FW_PROTO);
    else
        snprintf(line, sizeof(line), "fw  v%d ok", model->fw_proto);
    canvas_draw_str(canvas, 2, 64, line);
}

// multi-line stat panel right of the face, shown off the Mood page; auto-reverts after HOME_STATS_TIMEOUT_SECS
static void pwnfriend_draw_home_stats(Canvas* canvas, const PwnfriendModel* model) {
    canvas_set_font(canvas, FontSecondary);
    const Persona* p = model->persona;
    const int x = 61;
    int y = 17;
    char l[40];
#define HS_ROW(...)                              \
    do {                                         \
        snprintf(l, sizeof(l), __VA_ARGS__);     \
        canvas_draw_str(canvas, x, y, l);        \
        y += 9;                                  \
    } while(0)
    switch(model->stat_page) {
    case StatPageCounts: {
        uint16_t crack = 0;
        for(uint16_t i = 0; i < model->ap_count; i++)
            if(model->aps[i].has_essid && (model->aps[i].pmkid || model->aps[i].handshake)) crack++;
        HS_ROW("pwnd %lu/%lu", (unsigned long)p->pwnd_run, (unsigned long)p->s.pwnd_tot);
        HS_ROW("aps %lu", (unsigned long)p->aps_session);
        HS_ROW("crack %u", (unsigned)crack);
        HS_ROW("epoch %lu", (unsigned long)p->epoch);
        break;
    }
    case StatPageSocial: {
        int near = 0;
        for(int i = 0; i < MAX_PEERS; i++)
            if(model->peers.items[i].used) near++;
        HS_ROW("friends %lu", (unsigned long)p->s.friends_met);
        HS_ROW("won a%lu p%lu", (unsigned long)model->pwn_active, (unsigned long)model->pwn_passive);
        HS_ROW("near %d", near);
        break;
    }
    case StatPageGps:
    default:
        // distance/direction on one row, course on its own; raw coords live on Stats
        if(model->gps_seen) {
            HS_ROW("%s", model->gps_place[0] ? model->gps_place : "locating...");
            if(model->gps_course[0]) {
                canvas_draw_str(canvas, x, y, model->gps_course);
                int w = (int)canvas_string_width(canvas, model->gps_course);
                canvas_draw_circle(canvas, x + w + 2, y - 5, 1); // a real superscript ° ring
                y += 9;
            }
        } else {
            // no fix yet: show acquisition so a slow fix is visible (sats climbing = working)
            HS_ROW("%s", model->gps_sats > 0 ? "acquiring" : "no signal");
            HS_ROW("sats %d", model->gps_sats);
        }
        break;
    }
#undef HS_ROW
}

static void pwnfriend_draw_home(Canvas* canvas, PwnfriendModel* model) {
    pwnfriend_populate(model);
    // draw the pwnagotchi screen piecewise, skipping the AI/AUTO/MANU tag (corner shows the last pwned AP)
    Pwnagotchi* pwn = model->pwn;
    pwnagotchi_draw_face(pwn, canvas);
    pwnagotchi_draw_name(pwn, canvas);
    pwnagotchi_draw_channel(pwn, canvas);
    pwnagotchi_draw_aps(pwn, canvas);
    pwnagotchi_draw_uptime(pwn, canvas);
    pwnagotchi_draw_lines(pwn, canvas);
    pwnagotchi_draw_friend(pwn, canvas);
    pwnagotchi_draw_handshakes(pwn, canvas);
    // Mood page (or paused) speaks; other pages show the stat panel; exit/staying always speaks
    bool reacting = model->confirm_exit || model->tick_secs < model->stayed_until;
    if(!reacting && model->advertising && model->stat_page != StatPageMood)
        pwnfriend_draw_home_stats(canvas, model);
    else
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
    // "no ESP32" only takes over the home screen; menu/browser stay usable
    if(model->link_down && model->screen == ScreenHome) {
        pwnfriend_draw_link_down(canvas, model);
        return;
    }
    switch(model->screen) {
    case ScreenMenu: pwnfriend_draw_menu(canvas, model); return;
    case ScreenApList: pwnfriend_draw_aplist(canvas, model); return;
    case ScreenApDetail: pwnfriend_draw_apdetail(canvas, model); return;
    case ScreenApQr: pwnfriend_draw_ap_qr(canvas, model); return;
    case ScreenFriendList: pwnfriend_draw_friendlist(canvas, model); return;
    case ScreenFriendDetail: pwnfriend_draw_frienddetail(canvas, model); return;
    case ScreenFriendQr: pwnfriend_draw_friend_qr(canvas, model); return;
    case ScreenStats: pwnfriend_draw_stats(canvas, model); return;
    case ScreenAbout: pwnfriend_draw_about(canvas, model); return;
    case ScreenHome:
    default: pwnfriend_draw_home(canvas, model); return;
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

// name editor OK: apply + persist the name, back to menu, refresh the beacon
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

    // consent modal: long-OK accepts, Back cancels, everything else swallowed
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
        // exit: first Back prompts, second Back quits; any other key cancels; a dead board just exits
        if(event->key == InputKeyBack) {
            bool quit = false;
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    if(model->link_down || model->confirm_exit) {
                        quit = true;
                    } else {
                        model->confirm_exit = true;
                        model->confirm_secs = model->tick_secs;
                    }
                },
                true);
            return !quit; // false -> ViewDispatcher runs pwnfriend_exit and the app closes
        }
        {
            bool cancelled = false;
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    if(model->confirm_exit) {
                        model->confirm_exit = false;
                        model->stayed_until = model->tick_secs + CONFIRM_STAY_SECS; // happy "phew"
                        cancelled = true;
                    }
                },
                true);
            if(cancelled) return true; // this keypress just dismisses the prompt
        }
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
                    model->stat_touch_secs = model->tick_secs; // arm the auto-revert timer
                },
                true);
            return true;
        }
        // Up/Down unused on home (channel is set by targeting an AP)
        if(event->key == InputKeyUp || event->key == InputKeyDown) return true;
        return true; // Back (exit) is handled above; swallow any other stray key

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
                    // Wrap around both ways: Down off the end -> first, Up off the top -> last.
                    if(event->key == InputKeyDown)
                        model->menu_idx = (uint8_t)((model->menu_idx + 1) % MenuCount);
                    else
                        model->menu_idx = (uint8_t)((model->menu_idx + MenuCount - 1) % MenuCount);
                },
                true);
            return true;
        }
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            int dir = (event->key == InputKeyRight) ? 1 : -1;
            bool toggled_adv = false, now_adv = false, prompted = false;
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    switch(model->menu_idx) {
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
                            int v = ((int)model->capture_mode + dir + CaptureModeCount) %
                                    CaptureModeCount;
                            model->capture_mode = (uint8_t)v;
                            need_advertise = model->advertising;
                        }
                        break;
                    case MenuMinRssi: {
                        int v = model->min_rssi + dir * 2;
                        if(v < -90) v = -90;
                        if(v > -40) v = -40;
                        if(v != model->min_rssi) {
                            model->min_rssi = (int8_t)v;
                            need_advertise = model->advertising;
                        }
                        break;
                    }
                    case MenuRecon: {
                        int v = (int)model->recon_secs + dir * 5;
                        if(v < 10) v = 10;
                        if(v > 120) v = 120;
                        if(v != (int)model->recon_secs) {
                            model->recon_secs = (uint16_t)v;
                            need_advertise = model->advertising;
                        }
                        break;
                    }
                    case MenuQuiet:
                        model->quiet = !model->quiet;
                        home_save(app->storage, model);
                        break;
                    case MenuTriangulate:
                        model->triangulate = !model->triangulate;
                        home_save(app->storage, model);
                        break;
                    case MenuBattery:
                        // cycle off / light / deep / auto
                        model->saver = (uint8_t)(((int)model->saver + dir + 4) % 4);
                        need_advertise = model->advertising; // push effective -saver to the ESP
                        home_save(app->storage, model);
                        break;
                    default: break; // nav rows act on OK
                    }
                },
                true);
            if(toggled_adv) {
                if(now_adv)
                    pwnfriend_send_advertise(app);
                else
                    pwnfriend_send_stop(app);
            } else if(need_advertise && !prompted) {
                pwnfriend_send_advertise(app);
            }
            return true;
        }
        if(event->key == InputKeyOk) {
            bool open_name = false;
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
                        model->list_filter = FilterPwned;
                        model->list_idx = 0;
                        model->list_top = 0;
                        break;
                    case MenuAllAps:
                        model->screen = ScreenApList;
                        model->list_filter = FilterAll;
                        model->list_idx = 0;
                        model->list_top = 0;
                        break;
                    case MenuWhitelist:
                        model->screen = ScreenApList;
                        model->list_filter = FilterWhitelist;
                        model->list_idx = 0;
                        model->list_top = 0;
                        break;
                    case MenuFriends:
                        model->screen = ScreenFriendList;
                        model->fl_idx = 0;
                        model->fl_top = 0;
                        break;
                    case MenuTarget: {
                        // clear the focus target and drop back to the auto (*) sweep
                        bool had = false;
                        for(uint16_t i = 0; i < model->ap_count; i++)
                            if(model->aps[i].targeted) {
                                model->aps[i].targeted = false;
                                had = true;
                            }
                        if(had) {
                            model->tuned_channel = 0; // back to the '*' sweep
                            need_advertise = model->advertising;
                        }
                        break;
                    }
                    case MenuStats: model->screen = ScreenStats; break;
                    case MenuAbout: model->screen = ScreenAbout; break;
                    case MenuSetHome:
                        // Capture the current fix as home (persisted). Needs a fix.
                        if(model->gps_seen) {
                            model->home_lat = parse_deg(model->last_lat);
                            model->home_lon = parse_deg(model->last_lon);
                            model->home_set = true; // now it's "Home", not "Mother"
                            pwnfriend_update_place(model);
                            home_save(app->storage, model);
                        }
                        break;
                    default: break; // Advertise/Capture/Channel/MinRssi/Recon/Quiet use Left/Right
                    }
                },
                true);
            if(open_name) {
                text_input_set_header_text(app->text_input, "Persona name");
                text_input_set_result_callback(
                    app->text_input, pwnfriend_name_result, app, app->name_buf,
                    sizeof(app->name_buf), false);
                view_dispatcher_switch_to_view(app->view_dispatcher, 1);
            }
            if(need_advertise) pwnfriend_send_advertise(app); // e.g. after clearing the target
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
                        // Wrap both ways so you can run off either end to the other.
                        if(event->key == InputKeyDown)
                            model->list_idx = (uint16_t)((model->list_idx + 1) % n);
                        else
                            model->list_idx = (uint16_t)((model->list_idx + n - 1) % n);
                        if(model->list_idx < model->list_top) model->list_top = model->list_idx;
                        if(model->list_idx >= model->list_top + APLIST_ROWS)
                            model->list_top = model->list_idx - APLIST_ROWS + 1;
                    }
                },
                true);
            return true;
        }
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            bool is_left = event->key == InputKeyLeft; // Left = target, Right = ignore
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    uint16_t idx[AP_MAX];
                    uint16_t n = ap_filtered(model, idx);
                    if(n && model->list_idx < n) {
                        ApRec* a = &model->aps[idx[model->list_idx]];
                        if(is_left) { // exclusive: one focus AP, clears ignore
                            bool on = !a->targeted;
                            for(uint16_t i = 0; i < model->ap_count; i++)
                                model->aps[i].targeted = false;
                            a->targeted = on;
                            if(on) {
                                a->whitelisted = false;
                                // pin the hunt to the target's channel so the attack lands there
                                if(a->channel >= 1 && a->channel <= 14)
                                    model->tuned_channel = (int8_t)a->channel;
                            } else {
                                model->tuned_channel = 0; // untarget -> back to auto sweep
                            }
                        } else { // ignore, exclusive with target
                            a->whitelisted = !a->whitelisted;
                            if(a->whitelisted) a->targeted = false;
                        }
                        // Toggling may drop this row from a filtered view — reclamp.
                        uint16_t n2 = ap_filtered(model, idx);
                        if(n2 == 0) {
                            model->list_idx = 0;
                            model->list_top = 0;
                        } else {
                            if(model->list_idx >= n2) model->list_idx = n2 - 1;
                            if(model->list_idx < model->list_top)
                                model->list_top = model->list_idx;
                            if(model->list_idx >= model->list_top + APLIST_ROWS)
                                model->list_top = model->list_idx - APLIST_ROWS + 1;
                        }
                        need_advertise = model->advertising;
                    }
                },
                true);
            if(need_advertise) pwnfriend_send_advertise(app);
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
            // list_idx already tracks the AP we were viewing, so we land back on it.
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenApList; }, true);
            return true;
        }
        if(event->key == InputKeyUp || event->key == InputKeyDown) {
            // Up/Down flip to prev/next AP in detail, keeping list_idx in sync
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    uint16_t idx[AP_MAX];
                    uint16_t n = ap_filtered(model, idx);
                    if(n) {
                        uint16_t pos = 0;
                        for(uint16_t k = 0; k < n; k++)
                            if(idx[k] == model->detail_ap) { pos = k; break; }
                        if(event->key == InputKeyDown)
                            pos = (uint16_t)((pos + 1) % n);
                        else
                            pos = (uint16_t)((pos + n - 1) % n);
                        model->detail_ap = idx[pos];
                        model->list_idx = pos;
                        if(model->list_idx < model->list_top) model->list_top = model->list_idx;
                        if(model->list_idx >= model->list_top + APLIST_ROWS)
                            model->list_top = model->list_idx - APLIST_ROWS + 1;
                    }
                },
                true);
            return true;
        }
        if(event->key == InputKeyOk) {
            // OK: QR of this AP's location (a geo: URI) to scan with a phone, if we have one.
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    const ApRec* a = &model->aps[model->detail_ap];
                    float alat = 1e9f;
                    float alon = 1e9f;
                    if(loc_estimate(
                           model->triangulate, a->loc_n, a->w_sum, a->wlat_sum, a->wlon_sum,
                           a->lat, a->lon, &alat, &alon)) {
                        char lats[16];
                        char lons[16];
                        char url[64];
                        uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
                        fmt_coord(alat, lats, sizeof(lats));
                        fmt_coord(alon, lons, sizeof(lons));
                        // vendor-neutral geo: URI (opens in whatever map app, not forced Google)
                        snprintf(url, sizeof(url), "geo:%s,%s", lats, lons);
                        model->ap_qr_ok = qrcodegen_encodeText(
                            url, tmp, model->ap_qr, qrcodegen_Ecc_LOW, 1, 4, qrcodegen_Mask_AUTO,
                            true);
                        model->screen = ScreenApQr;
                    }
                },
                true);
            return true;
        }
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            bool is_left = event->key == InputKeyLeft; // Left = target, Right = ignore
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    ApRec* a = &model->aps[model->detail_ap];
                    if(is_left) { // exclusive: one focus AP, clears ignore, pins channel
                        bool on = !a->targeted;
                        for(uint16_t i = 0; i < model->ap_count; i++)
                            model->aps[i].targeted = false;
                        a->targeted = on;
                        if(on) {
                            a->whitelisted = false;
                            if(a->channel >= 1 && a->channel <= 14)
                                model->tuned_channel = (int8_t)a->channel;
                        } else {
                            model->tuned_channel = 0;
                        }
                    } else { // ignore, exclusive with target
                        a->whitelisted = !a->whitelisted;
                        if(a->whitelisted) a->targeted = false;
                    }
                    // Stay in detail (Up/Down keeps browsing); no pop back to the list.
                    need_advertise = model->advertising;
                },
                true);
            if(need_advertise) pwnfriend_send_advertise(app);
            return true;
        }
        return true;

    case ScreenApQr:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenApDetail; }, true);
            return true;
        }
        return true; // swallow everything else on the QR screen

    case ScreenFriendList:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenMenu; }, true);
            return true;
        }
        if(event->key == InputKeyUp || event->key == InputKeyDown) {
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    uint16_t n = model->friend_count;
                    if(n) {
                        if(event->key == InputKeyDown)
                            model->fl_idx = (uint16_t)((model->fl_idx + 1) % n);
                        else
                            model->fl_idx = (uint16_t)((model->fl_idx + n - 1) % n);
                        if(model->fl_idx < model->fl_top) model->fl_top = model->fl_idx;
                        if(model->fl_idx >= model->fl_top + APLIST_ROWS)
                            model->fl_top = model->fl_idx - APLIST_ROWS + 1;
                    }
                },
                true);
            return true;
        }
        if(event->key == InputKeyOk) {
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    uint16_t idx[FRIEND_MAX];
                    uint16_t n = friend_order(model, idx);
                    if(n && model->fl_idx < n) {
                        model->detail_friend = idx[model->fl_idx];
                        model->screen = ScreenFriendDetail;
                    }
                },
                true);
            return true;
        }
        return true;

    case ScreenFriendDetail:
        if(event->key == InputKeyBack) {
            // fl_idx already tracks the friend we were viewing, so we land back on it.
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenFriendList; }, true);
            return true;
        }
        if(event->key == InputKeyUp || event->key == InputKeyDown) {
            // Up/Down flip to the prev/next friend, staying in detail; fl_idx stays in sync.
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    uint16_t idx[FRIEND_MAX];
                    uint16_t n = friend_order(model, idx);
                    if(n) {
                        uint16_t pos = 0;
                        for(uint16_t k = 0; k < n; k++)
                            if(idx[k] == model->detail_friend) { pos = k; break; }
                        if(event->key == InputKeyDown)
                            pos = (uint16_t)((pos + 1) % n);
                        else
                            pos = (uint16_t)((pos + n - 1) % n);
                        model->detail_friend = idx[pos];
                        model->fl_idx = pos;
                        if(model->fl_idx < model->fl_top) model->fl_top = model->fl_idx;
                        if(model->fl_idx >= model->fl_top + APLIST_ROWS)
                            model->fl_top = model->fl_idx - APLIST_ROWS + 1;
                    }
                },
                true);
            return true;
        }
        if(event->key == InputKeyOk) {
            // OK: QR of this friend's last location (a geo: URI) to scan with a phone.
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    const FriendRec* fr = &model->friends[model->detail_friend];
                    float alat = 1e9f;
                    float alon = 1e9f;
                    if(loc_estimate(
                           model->triangulate, fr->loc_n, fr->w_sum, fr->wlat_sum, fr->wlon_sum,
                           fr->lat, fr->lon, &alat, &alon)) {
                        char lats[16];
                        char lons[16];
                        char url[64];
                        uint8_t tmp[qrcodegen_BUFFER_LEN_FOR_VERSION(4)];
                        fmt_coord(alat, lats, sizeof(lats));
                        fmt_coord(alon, lons, sizeof(lons));
                        snprintf(url, sizeof(url), "geo:%s,%s", lats, lons);
                        model->ap_qr_ok = qrcodegen_encodeText(
                            url, tmp, model->ap_qr, qrcodegen_Ecc_LOW, 1, 4, qrcodegen_Mask_AUTO,
                            true);
                        model->screen = ScreenFriendQr;
                    }
                },
                true);
            return true;
        }
        return true;

    case ScreenFriendQr:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenFriendDetail; }, true);
            return true;
        }
        return true; // swallow everything else on the QR screen

    case ScreenStats:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenMenu; }, true);
            return true;
        }
        return true;

    case ScreenAbout:
        if(event->key == InputKeyBack) {
            with_view_model(
                app->view, PwnfriendModel * model, { model->screen = ScreenMenu; }, true);
            return true;
        }
        // OK toggles bounce/infinite scroll; Left speeds the banner up, Right slows it.
        if(event->key == InputKeyOk) {
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    model->about_infinite = !model->about_infinite;
                    model->about_scroll = 0; // restart cleanly in the new mode
                },
                true);
            return true;
        }
        if(event->key == InputKeyLeft || event->key == InputKeyRight) {
            int dir = (event->key == InputKeyLeft) ? 1 : -1; // Left = faster
            with_view_model(
                app->view, PwnfriendModel * model,
                {
                    int s = (int)model->about_speed + dir;
                    if(s < 1) s = 1;
                    if(s > ABOUT_SPEED_MAX) s = ABOUT_SPEED_MAX;
                    model->about_speed = (uint8_t)s;
                },
                true);
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
// Timer: fires ANIM_HZ/sec. Every ANIM_HZ-th fire is the 1 Hz heartbeat that ages the
// persona, prunes peers, resends & saves; the in-between fires just scroll About.
// ---------------------------------------------------------------------------

static void pwnfriend_timer_callback(void* ctx) {
    PwnfriendApp* app = ctx;
    bool resend = false;
    bool save = false;

    app->anim_tick++;
    bool second = (app->anim_tick % ANIM_HZ) == 0; // one real second has elapsed

    // sub-second fires only animate About; skip them (and redraw) on other screens
    Screen screen = ScreenHome;
    with_view_model(app->view, PwnfriendModel * model, { screen = model->screen; }, false);
    if(!second && screen != ScreenAbout) return;

    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            if(model->screen == ScreenAbout) model->about_scroll += model->about_speed;
            if(second) {
                model->tick_secs++;
                model->battery_pct = furi_hal_power_get_pct(); // for the home BAT slot
                // VBUS present = on external power (true when charging, full-and-plugged, or
                // even data-only USB) -> saver forced off, slot shows PWR. is_charging() alone
                // misses the full-battery case.
                model->on_power = furi_hal_power_get_usb_voltage() > 4.0f;
                model->charge_done = furi_hal_power_is_charging_done(); // full -> "PWR" (no %)
                // Home stat panel auto-reverts to the persona voice after a quiet spell.
                if(model->stat_page != StatPageMood &&
                   model->tick_secs - model->stat_touch_secs >= HOME_STATS_TIMEOUT_SECS)
                    model->stat_page = StatPageMood;
                // The exit prompt gives up (persona stops asking) if you ignore it.
                if(model->confirm_exit &&
                   model->tick_secs - model->confirm_secs >= CONFIRM_EXIT_TIMEOUT_SECS)
                    model->confirm_exit = false;
                peers_prune(&model->peers, model->tick_secs);
                bool bonded = peers_any_bonded(&model->peers, model->tick_secs);
                model->persona->friend_near = bonded;
                // "engaged" = advertising + capture armed + APs around; keeps it content mid-hunt (each AP reported once)
                model->persona->hunting = model->advertising &&
                                          model->capture_mode != CaptureOff &&
                                          model->ap_count > 0;
                persona_tick(model->persona, 1);

                // link watchdog: warn only while advertising, past boot grace + silence timeout. unsigned sub is safe (stamps <= tick_secs)
                if(model->advertising) {
                    uint32_t since_rx = model->tick_secs - model->last_rx_secs;
                    uint32_t since_adv = model->tick_secs - model->advertising_since;
                    // deep saver dozes the radio ~25s at a time (near-silent) — don't flash the
                    // "no ESP32" screen then; only warn after a much longer real silence.
                    uint32_t link_to = (effective_saver(model) == 2) ? 40 : PWNFRIEND_LINK_TIMEOUT_SECS;
                    model->link_down =
                        (since_rx >= link_to) && (since_adv >= PWNFRIEND_LINK_GRACE_SECS);
                } else {
                    model->link_down = false; // paused never warns
                }

                // push a fresh -saver promptly when the effective level flips (power
                // plugged/unplugged, or AUTO crossing 20%), not just on the 15s cadence.
                if(model->advertising && effective_saver(model) != model->last_saver_eff)
                    resend = true;
                if(model->advertising &&
                   (model->tick_secs - model->last_adv_sent >= PWNFRIEND_ADV_RESEND_SECS)) {
                    resend = true;
                }
                if(model->tick_secs % PWNFRIEND_SAVE_SECS == 0) {
                    save = true;
                }
            }
        },
        true);

    // send_advertise needs ~760B of buffers, too much for the 1KB timer stack; kick the 2KB worker
    if(resend) furi_thread_flags_set(furi_thread_get_id(app->worker_thread), WorkerEventResend);
    if(save) {
        // a save racing a note_peer update at worst records a slightly stale count (harmless)
        with_view_model(
            app->view,
            PwnfriendModel * model,
            {
                persona_save(model->persona);
                ap_db_save(app->storage, model);
                friend_db_save(app->storage, model);
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

            if(app->got_new_friend || app->got_pwnd) {
                bool quiet = false;
                with_view_model(
                    app->view, PwnfriendModel * model, { quiet = model->quiet; }, false);
                if(app->got_new_friend) {
                    app->got_new_friend = false;
                    if(!quiet) notification_message(app->notification, &sequence_new_friend);
                }
                if(app->got_pwnd) {
                    app->got_pwnd = false;
                    if(!quiet) notification_message(app->notification, &sequence_pwnd);
                }
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
            // default full pwnagotchi (capture+deauth), gated by consent: returning user arms Deauth now, else start Off and raise the consent screen
            model->consent_given = consent_is_given();
            model->capture_mode = model->consent_given ? CaptureDeauth : CaptureOff;
            model->showing_consent = !model->consent_given;
            model->last_pwnd_ssid[0] = '\0';
            model->pwnd_seen_count = 0;
            model->ap_count = 0;
            model->ap_seq = 1;
            // init per-AP session arrays for every slot (loaded APs skip ap_get)
            for(uint16_t i = 0; i < AP_MAX; i++) {
                model->ap_seen_tick[i] = 0;
                model->ap_track_tick[i] = 0;
                model->ap_pcap_flags[i] = 0;
                model->aps[i].lat = 1e9f;
                model->aps[i].lon = 1e9f;
                model->aps[i].loc_rssi = -128; // weakest, so the first real fix always wins
            }
            ap_db_load(app->storage, model); // browse APs/pwns from previous sessions
            // friends browser: init per-slot signal, then restore met friends
            model->friend_count = 0;
            model->friend_overflow = false;
            model->friend_seq = 1;
            for(uint16_t i = 0; i < FRIEND_MAX; i++) {
                model->friend_seen_tick[i] = 0;
                model->friend_track_tick[i] = 0;
            }
            model->fl_idx = 0;
            model->fl_top = 0;
            model->detail_friend = 0;
            friend_db_load(app->storage, model);
            model->tuned_channel = 0; // auto (*) — the recon sweep
            model->stat_page = StatPageMood;
            model->min_rssi = -78; // matches the firmware default attack floor
            model->recon_secs = 30; // pwnagotchi recon_time
            model->screen = ScreenHome;
            model->menu_idx = 0;
            model->list_idx = 0;
            model->list_top = 0;
            model->list_filter = FilterAll;
            model->detail_ap = 0;
            model->fw_proto = 0; // unknown until the first PWNFRIEND_ADV with ver=
            model->fw_commit[0] = '\0'; // filled from the first ADV that carries fw=
            model->pwn_active = 0;
            model->pwn_passive = 0;
            model->quiet = false;
            model->triangulate = true; // on by default; home_load may turn it off
            model->saver = 0; // battery saver off by default; home_load may restore it
            model->on_power = false;
            model->last_saver_eff = 0xFF; // sentinel: forces the first -saver push
            model->confirm_exit = false;
            model->confirm_secs = 0;
            model->stayed_until = 0;
            model->about_scroll = 0;
            model->about_speed = ABOUT_SPEED_DEFAULT;
            model->about_infinite = false; // default to bounce
            model->gps_seen = false;
            model->gps_sats = 0;
            model->gps_fix = false;
            model->gps_acc = 0;
            model->last_lat[0] = '\0';
            model->last_lon[0] = '\0';
            model->gps_place[0] = '\0';
            model->gps_course[0] = '\0';
            model->home_lat = HOME_LAT; // default; overridden by home.bin / "Set home"
            model->home_lon = HOME_LON;
            model->home_set = false; // default Prague = the persona's "Mother" until set
            home_load(app->storage, model); // may restore quiet + home_set
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

    // ANIM_HZ heartbeat; per-second work gated inside, extra fires animate About
    app->timer = furi_timer_alloc(pwnfriend_timer_callback, FuriTimerTypePeriodic, app);
    furi_timer_start(app->timer, furi_kernel_get_tick_frequency() / ANIM_HZ);

    // auto-start greeting (advertising is true); the timer re-pushes every PWNFRIEND_ADV_RESEND_SECS
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
            friend_db_save(app->storage, model);
        },
        false);

    // tear down serial (silences RX IRQ) BEFORE freeing the worker, so a late byte can't poke a freed thread
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
