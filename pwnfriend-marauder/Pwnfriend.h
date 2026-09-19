// Pwnfriend — pwngrid advertisement broadcaster for ESP32 Marauder.
//
// Turns the Flipper's Wi-Fi board into a social pwngrid peer: it broadcasts a
// Pwnagotchi-compatible beacon (source MAC de:ad:be:ef:de:ad, JSON persona in
// vendor IE 222) so a nearby Pwnagotchi detects it, greets it, and — thanks to a
// stable identity — counts encounters and befriends it over time.
//
// This is a self-contained module. It only reaches into Marauder for the raw
// 802.11 TX primitive; everything else (frame building, persona, channel hop,
// peer reporting) lives here to keep the fork's merge surface tiny. See
// PATCH.md for the handful of insertion points into WiFiScan.
//
// Wire format reference: ../doc/PwnfriendProtocol.md

#pragma once

#include <Arduino.h>
#include <esp_wifi.h>
#include <LinkedList.h>

// Provided by Marauder (declared in WiFiScan.h). Redeclared here so the module
// compiles even if included before that header.
extern "C" esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void* buffer,
                                       int len, bool en_sys_seq);

class Pwnfriend {
  public:
    Pwnfriend();

    // Parse a `pwnfriend ...` CLI line (already tokenised by Marauder's
    // CommandLine into argv/argc) and load it into the live persona. Missing
    // args keep their previous / default value. Returns false only on a
    // malformed identity.
    bool configureFromArgs(LinkedList<String>* args);

    // Rebuild the beacon frame from the current persona. Call after any persona
    // change. Cheap; also called lazily by broadcast().
    void rebuild();

    // Hop to the next broadcast channel (or the pinned one) and transmit the
    // persona beacon a few times. Call this on a timer from WiFiScan::main().
    void broadcast();

    // Emit one PWNFRIEND_PEER line for a sniffed Pwnagotchi beacon. `payload`
    // is the raw 802.11 frame, `rssi`/`channel` come from the rx metadata.
    void reportPeer(const uint8_t* payload, int length, int rssi, int channel);

    // Capture path (called from the pwnfriend rx callback on DATA frames).
    // Detects a crackable EAPOL M2 handshake or an RSN PMKID (M1) and, once per
    // BSSID this session, emits a PWNFRIEND_PWND line. Streams every EAPOL frame
    // to the Flipper as a self-describing PWNFRIEND_HS <bssid> <hex> line so it
    // is filed under the right per-BSSID pcap. `payload` is the raw 802.11 frame,
    // `length` is rx_ctrl.sig_len. `has_fix`/`lat`/`lon` geotag the PWND line when
    // the GPS has a fix. Returns true if the frame was EAPOL (so the caller should
    // append it to the on-board pcap too).
    bool reportHandshake(const uint8_t* payload, int length, int rssi, int channel,
                         bool has_fix, double lat, double lon);

    // Recon: dedup a non-pwngrid beacon into one PWNFRIEND_AP line per BSSID, and
    // stream that first beacon to the Flipper as a PWNFRIEND_HS line so the pcap
    // carries the ESSID (a mandatory 22000 field). `has_fix`/`lat`/`lon` geotag
    // the AP line when the GPS has a fix. Returns true the first time a BSSID is
    // stored (append the beacon to the on-board pcap then).
    bool reportAP(const uint8_t* payload, int length, int rssi, int channel,
                  bool has_fix, double lat, double lon);

    // True once a persona has been loaded (so broadcast() has something to send).
    bool ready() const { return _ready; }

    // Clear the per-session capture dedup tables. Called at real scan start
    // (RunPwnfriendScan), NOT on a persona refresh — so re-sending the pwnfriend
    // command every 15s doesn't re-count already-pwnd APs and inflate pwnd_tot.
    void beginSession() { _n_recon = 0; _n_pwnd_seen = 0; }

    void reset();

  private:
    void buildJson(char* out, size_t out_len);

    // Persona
    char     _name[33];
    char     _identity[65];   // 64 hex + NUL
    const char* _face;        // UTF-8 glyph
    uint32_t _pwnd_run;
    uint32_t _pwnd_tot;
    uint32_t _uptime;
    uint32_t _epoch;
    bool     _deauth_policy;
    uint8_t  _session_id[6];  // Addr3, stable per persona

    // Channel hopping
    int      _pinned_channel;  // -1 => hop
    uint8_t  _hop_idx;

    // Prebuilt frame
    uint8_t  _frame[300];
    int      _frame_len;
    bool     _ready;

    uint32_t _sent;
    uint32_t _last_active_ms;  // throttle for the assoc+deauth active burst

    // Per-session capture bookkeeping (cleared in beginSession(), at scan start).
    struct ReconAP {
        uint8_t bssid[6];
        char ssid[33];
        uint8_t channel;
        uint8_t attacks; // active-mode assoc/deauth bursts aimed at this AP
        bool missed;     // already emitted a PWNFRIEND_MISS for it
    };
    static const int MAX_RECON = 64;
    static const int MAX_PWND  = 64;
    // Active-mode bursts against an AP with no capture before it counts as a
    // "miss" (pwnagotchi's on_miss). ACTIVE_INTERVAL_MS apart, so ~4 * 2s = 8s.
    static const int MISS_ATTEMPTS = 4;
    ReconAP  _recon[MAX_RECON];
    int      _n_recon;
    uint8_t  _pwnd_seen[MAX_PWND][6];
    int      _n_pwnd_seen;

    int  reconIndex(const uint8_t* bssid) const;   // -1 if unseen
    bool markPwnd(const uint8_t* bssid);           // true if newly counted
    bool isPwnd(const uint8_t* bssid) const;       // already captured this session?
    void emitPwnd(const uint8_t* bssid, const char* ssid,
                  const char* type, int channel, int rssi,
                  bool has_fix, double lat, double lon);
    void deauthAP(const uint8_t* bssid);
    // Send a WPA2 association request to a target AP to solicit its RSN PMKID
    // (EAPOL M1) — pwnagotchi's associate() half, no client needed. Only fired
    // in active mode (the -deauth opt-in), same as deauthAP.
    void assocAP(const uint8_t* bssid, const char* ssid);
    // Emit one self-describing "PWNFRIEND_HS <bssid12hex> <framehex>" line for a
    // raw 802.11 frame. The Flipper files the frame under <bssid>.pcap by parsing
    // this line alone (no dependence on a preceding PWND). Raw binary would trip
    // the CLI's CR/XON handling, so we stream lowercase hex.
    void streamFrameHex(const uint8_t* bssid, const uint8_t* frame, int length);
};

// Map a face index (matching flipagotchi's enum PwnagotchiFace) to a glyph.
const char* pwnfriend_face_glyph(int idx);
