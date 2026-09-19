#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view.h>
#include <gui/view_dispatcher.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <stdlib.h>
#include <string.h>

#include "../include/pwnfriend.h"
#include "../include/persona.h"
#include "../include/peers.h"
#include "../include/face.h"
#include "../include/pwnagotchi.h"
#include "../include/consent.h"
#include "../include/pcap.h"
#include "../include/wardrive.h"

typedef enum {
    WorkerEventStop = (1 << 0),
    WorkerEventRx = (1 << 1),
} WorkerEventFlags;

#define WORKER_EVENTS_MASK (WorkerEventStop | WorkerEventRx)

// Distinct BSSIDs whose capture we've already counted this app session. Caps the
// per-session pwnd dedup table; a re-emitted PWNFRIEND_PWND (the Flipper re-sends
// the whole command every 15s) is then idempotent and can't inflate pwnd_run/tot.
#define PWND_SEEN_MAX 64

// Capture escalation, default off. Cycled with Up; leaving Off the first time
// needs the one-time consent acknowledgement. Passive = record handshakes the
// firmware sniffs; Deauth = also advertise + send active deauth (-deauth 1).
typedef enum {
    CaptureOff = 0,
    CapturePassive,
    CaptureDeauth,
} CaptureMode;

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

    // GPS: set once the firmware reports any lat/lon (geotag seen). last_lat/lon
    // are verbatim decimal-degree strings from the most recent fix, for the badge.
    bool gps_seen;
    char last_lat[16];
    char last_lon[16];
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
    char cmd[200];
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
            snprintf(
                cmd,
                sizeof(cmd),
                "pwnfriend -n %s -id %s -f %d -pr %lu -pt %lu -u %lu -e %lu -cap %d -deauth %d\n",
                safe_name,
                p->s.identity,
                (int)persona_face(p),
                (unsigned long)p->pwnd_run, // REAL handshakes this run
                (unsigned long)p->s.pwnd_tot, // REAL handshakes lifetime
                (unsigned long)p->s.total_uptime,
                (unsigned long)p->epoch,
                cap,
                deauth);
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
            if(have_gps) {
                model->gps_seen = true;
                strncpy(model->last_lat, lat, sizeof(model->last_lat) - 1);
                model->last_lat[sizeof(model->last_lat) - 1] = '\0';
                strncpy(model->last_lon, lon, sizeof(model->last_lon) - 1);
                model->last_lon[sizeof(model->last_lon) - 1] = '\0';
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

    with_view_model(
        app->view,
        PwnfriendModel * model,
        {
            persona_note_ap(model->persona);
            if(have_gps) {
                model->gps_seen = true;
                strncpy(model->last_lat, lat, sizeof(model->last_lat) - 1);
                model->last_lat[sizeof(model->last_lat) - 1] = '\0';
                strncpy(model->last_lon, lon, sizeof(model->last_lon) - 1);
                model->last_lon[sizeof(model->last_lon) - 1] = '\0';
            }
        },
        true);

    // The firmware emits one PWNFRIEND_AP per BSSID per session, so this is one
    // geotagged wardrive row per network. Encryption is unknown from a beacon here.
    if(have_gps) {
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

static void pwnfriend_handle_miss_line(PwnfriendApp* app) {
    // pwnagotchi's on_miss: firmware attacked an AP MISS_ATTEMPTS times with no
    // capture. Flash the demotivated face (only reached in active/Deauth mode).
    with_view_model(
        app->view, PwnfriendModel * model, { persona_note_miss(model->persona); }, true);
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
        pwnfriend_handle_miss_line(app);
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

    // CH: the channel we're broadcasting on (or * when paused).
    if(model->advertising && model->adv_channel) {
        furi_string_printf(pwn->channel, "%u", (unsigned)model->adv_channel);
    } else {
        furi_string_set(pwn->channel, "*");
    }

    // APS: access points seen this session (lifetime).
    furi_string_printf(
        pwn->apStat,
        "%lu (%lu)",
        (unsigned long)p->aps_session,
        (unsigned long)p->s.aps_tot);

    // UP: cumulative uptime as hh:mm:ss.
    uint32_t up = (uint32_t)p->s.total_uptime;
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

    // Message: a paused hint, the fresh catch, or level + mood voice line.
    if(!model->advertising) {
        furi_string_set(pwn->message, "paused - OK to greet");
    } else if((p->mood == MoodHappy || p->mood == MoodCool) && model->last_pwnd_ssid[0]) {
        furi_string_printf(pwn->message, "pwnd %s!", model->last_pwnd_ssid);
    } else {
        furi_string_printf(
            pwn->message,
            "Lv%lu %s",
            (unsigned long)persona_level(p),
            persona_mood_label(p));
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

// A bottom-right badge showing the live capture state (overwrites the AI tag).
static void pwnfriend_draw_capture_badge(Canvas* canvas, CaptureMode mode) {
    if(mode == CaptureOff) return;
    canvas_set_font(canvas, FontSecondary);
    const char* tag = (mode == CaptureDeauth) ? "DEAUTH" : "CAP";
    int w = canvas_string_width(canvas, tag);
    int x = FLIPPER_SCREEN_WIDTH - w - 1;
    if(mode == CaptureDeauth) {
        // Inverse box so active RF transmission is unmistakable.
        canvas_draw_box(canvas, x - 1, 56, w + 2, 8);
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_str(canvas, x, 63, tag);
        canvas_set_color(canvas, ColorBlack);
    } else {
        canvas_set_color(canvas, ColorWhite);
        canvas_draw_box(canvas, x - 1, 56, w + 2, 8);
        canvas_set_color(canvas, ColorBlack);
        canvas_draw_str(canvas, x, 63, tag);
    }
}

// A tiny "gps" tag on the bottom line once any geotag has been seen, sitting left
// of the mode/capture tag so it never collides with the PWND readout or the badge.
static void pwnfriend_draw_gps_tag(Canvas* canvas, const PwnfriendModel* model) {
    if(!model->gps_seen) return;
    canvas_set_font(canvas, FontSecondary);
    const char* tag = "gps";
    int w = canvas_string_width(canvas, tag);
    canvas_draw_str(canvas, FLIPPER_SCREEN_WIDTH - w - 28, 63, tag);
}

static void pwnfriend_draw_callback(Canvas* canvas, void* ctx) {
    PwnfriendModel* model = ctx;
    canvas_clear(canvas);
    if(model->showing_consent) {
        pwnfriend_draw_consent(canvas);
        return;
    }
    pwnfriend_populate(model);
    pwnagotchi_draw_all(model->pwn, canvas);
    pwnfriend_draw_gps_tag(canvas, model);
    pwnfriend_draw_capture_badge(canvas, model->capture_mode);
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

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
                    model->capture_mode = CapturePassive; // enact the pending enable
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

    if(event->type != InputTypeShort) return false;

    if(event->key == InputKeyOk) {
        // OK: start / pause advertising (unchanged).
        bool now_advertising = false;
        with_view_model(
            app->view,
            PwnfriendModel * model,
            {
                model->advertising = !model->advertising;
                now_advertising = model->advertising;
            },
            true);
        if(now_advertising) {
            pwnfriend_send_advertise(app);
        } else {
            pwnfriend_send_stop(app);
        }
        return true;
    }

    if(event->key == InputKeyUp) {
        // Up: cycle the capture gate Off -> Passive -> Deauth -> Off. Leaving Off
        // the first time needs the consent acknowledgement (shown, not cycled).
        bool prompted = false, changed = false, advertising = false;
        with_view_model(
            app->view,
            PwnfriendModel * model,
            {
                if(model->capture_mode == CaptureOff && !model->consent_given) {
                    model->showing_consent = true;
                    prompted = true;
                } else {
                    model->capture_mode = (model->capture_mode + 1) % 3;
                    changed = true;
                }
                advertising = model->advertising;
            },
            true);
        // Push the new deauth state to the firmware right away when live.
        if(changed && !prompted && advertising) pwnfriend_send_advertise(app);
        return true;
    }
    return false;
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
            persona_tick(model->persona, 1);

            if(model->advertising &&
               (model->tick_secs - model->last_adv_sent >= PWNFRIEND_ADV_RESEND_SECS)) {
                resend = true;
            }
            if(model->tick_secs % PWNFRIEND_SAVE_SECS == 0) {
                save = true;
            }
        },
        true);

    if(resend) pwnfriend_send_advertise(app);
    if(save) {
        // persona pointer lives for the app's lifetime; a save racing a note_peer
        // update at worst records a slightly stale count, which is harmless.
        with_view_model(
            app->view, PwnfriendModel * model, { persona_save(model->persona); }, false);
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
            model->advertising = false;
            model->capture_mode = CaptureOff; // default: presence only
            model->consent_given = consent_is_given();
            model->showing_consent = false;
            model->last_pwnd_ssid[0] = '\0';
            model->pwnd_seen_count = 0;
            model->gps_seen = false;
            model->last_lat[0] = '\0';
            model->last_lon[0] = '\0';
        },
        true);

    view_set_previous_callback(app->view, pwnfriend_exit);
    view_dispatcher_add_view(app->view_dispatcher, 0, app->view);
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

    return app;
}

static void pwnfriend_app_free(PwnfriendApp* app) {
    furi_assert(app);

    furi_timer_stop(app->timer);
    furi_timer_free(app->timer);

    // Stop advertising and persist a final time (serial still live).
    pwnfriend_send_stop(app);
    with_view_model(
        app->view, PwnfriendModel * model, { persona_save(model->persona); }, false);

    // Tear down serial (which silences the RX IRQ) BEFORE freeing the worker
    // thread, so a byte arriving mid-teardown can't poke a freed thread.
    furi_hal_serial_deinit(app->serial_handle);
    furi_hal_serial_control_release(app->serial_handle);

    furi_thread_flags_set(furi_thread_get_id(app->worker_thread), WorkerEventStop);
    furi_thread_join(app->worker_thread);
    furi_thread_free(app->worker_thread);

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
