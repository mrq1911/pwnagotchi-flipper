// Pwnfriend — pwngrid advertisement broadcaster for ESP32 Marauder.
//
// Broadcasts a Pwnagotchi-compatible beacon (MAC de:ad:be:ef:de:ad, JSON persona
// in vendor IE 222) so a nearby Pwnagotchi detects, greets, and befriends it.
// Self-contained: only reaches into Marauder for the raw 802.11 TX primitive.
// See PATCH.md for insertion points; wire format: ../doc/PwnfriendProtocol.md

#pragma once

// serial-protocol version, stamped on PWNFRIEND_ADV (ver=N) so the Flipper warns on
// stale firmware. bump on any protocol change. v2=dwell recon+unicast/repeat deauth+
// PMKID auth+ESSID embed+flags; v3=live RSSI (PWNFRIEND_RSSI); v4=epoch telemetry+
// provenance (via=)+floor-free PMKID.
#define PWNFRIEND_PROTO 4

// min interval between PWNFRIEND_RSSI updates per AP, so re-heard beacons don't flood serial.
#define PWNFRIEND_RSSI_EMIT_MS 3000

#include <Arduino.h>
#include <esp_wifi.h>
#include <LinkedList.h>

// provided by Marauder (WiFiScan.h); redeclared so we compile if included first.
extern "C" esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void* buffer,
                                       int len, bool en_sys_seq);

class Pwnfriend {
  public:
    Pwnfriend();

    // parse a tokenised `pwnfriend ...` CLI line into the live persona; missing
    // args keep their value. false only on a malformed identity.
    bool configureFromArgs(LinkedList<String>* args);

    // rebuild the beacon frame from the persona; call after any change (also called by broadcast()).
    void rebuild();

    // hop/pin channel and transmit the persona beacon a few times; call on a timer from WiFiScan::main().
    void broadcast();

    // emit one PWNFRIEND_PEER line for a sniffed Pwnagotchi beacon. has_fix/lat/lon
    // geotag the sighting (RSSI + position -> triangulate offline).
    void reportPeer(const uint8_t* payload, int length, int rssi, int channel,
                    bool has_fix, double lat, double lon);

    // capture path (rx callback, DATA frames). detects EAPOL M2 / RSN PMKID (M1) and
    // emits PWNFRIEND_PWND once per BSSID; streams every EAPOL frame as a self-describing
    // PWNFRIEND_HS line. returns true if EAPOL (caller appends to pcap).
    bool reportHandshake(const uint8_t* payload, int length, int rssi, int channel,
                         bool has_fix, double lat, double lon);

    // recon: dedup a non-pwngrid beacon into one PWNFRIEND_AP line per BSSID.
    // has_fix/lat/lon geotag the AP line. returns true the first time a BSSID is
    // stored (append beacon to pcap then).
    bool reportAP(const uint8_t* payload, int length, int rssi, int channel,
                  bool has_fix, double lat, double lon);

    // recon: harvest a client STA (non-BSSID address of a known AP) for unicast deauth.
    // rx callback, every DATA frame, allocation-free.
    void reportClient(const uint8_t* payload, int length);

    // true once a persona is loaded.
    bool ready() const { return _ready; }

    // clear per-session dedup tables. at scan start only, NOT on the 15s persona
    // refresh (else re-counts pwnd APs, inflates pwnd_tot).
    void beginSession() {
        _n_recon = 0;
        _n_pwnd_seen = 0;
        _n_sta = 0;
        _inactive_epochs = 0;  // a fresh scan starts at full recon speed
        _epoch_pwnd = false;
        _epoch_seq = 0;
        _ep_assoc = _ep_deauth = _ep_unicast = _ep_hs = _ep_pmkid = _ep_miss = 0;
        _ep_dpmf = _ep_dnocli = 0;
        resetPhase();
    }

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
    bool     _assoc_policy;   // associate (solicit PMKID) without deauth — "PMKID-only"
    uint8_t  _session_id[6];  // Addr3, stable per persona

    // Channel hopping
    int      _pinned_channel;  // -1 => hop
    uint8_t  _hop_idx;

    // Prebuilt frame
    uint8_t  _frame[300];
    int      _frame_len;
    bool     _ready;

    uint32_t _sent;
    uint32_t _last_active_ms;  // throttle for the pinned-channel active burst

    // pwnagotchi-faithful recon/attack epoch loop. RECON sweeps all channels gathering
    // APs; ATTACK visits each AP-bearing channel, fires assoc+deauth once, and dwells so
    // the 4-way completes before hopping.
    enum Phase { PHASE_RECON, PHASE_ATTACK };
    Phase    _phase;
    uint32_t _phase_ms;        // millis() when the phase / channel dwell began
    uint8_t  _cur_channel;     // channel we're parked on right now
    uint32_t _last_hop_ms;     // recon-sweep hop cadence timer
    uint32_t _last_sweep_ms;   // all-channel advertise-sweep cadence timer
    uint8_t  _attack_list[14]; // AP-bearing channels to attack this epoch
    int      _n_attack;        // channels in _attack_list
    int      _attack_idx;      // current channel within _attack_list
    bool     _chan_attacked;   // fired assoc+deauth on _attack_list[_attack_idx]?
    bool     _epoch_pwnd;      // captured anything this epoch (activity signal)
    uint8_t  _inactive_epochs; // consecutive fruitless epochs (recon_time doubling)
    uint32_t _last_deauth_ms;  // re-deauth cadence within the current channel dwell
    uint32_t _cur_dwell_ms;    // this channel's dwell, scaled by its target count
    int8_t   _attack_min_rssi; // deauth floor: don't bother deauthing APs weaker than this
    uint32_t _recon_time_ms;   // recon_time override (-recon), default 30s

    // Per-epoch telemetry (emitted as PWNFRIEND_EPOCH at endEpoch, then reset).
    uint32_t _epoch_seq;       // running epoch index since beginSession
    uint16_t _ep_assoc, _ep_deauth, _ep_unicast; // frames fired this epoch
    uint16_t _ep_hs, _ep_pmkid, _ep_miss;        // outcomes this epoch
    uint16_t _ep_dpmf, _ep_dnocli;               // deauths skipped: PMF-protected / no client

    // targeting + whitelist. target set -> only that BSSID attacked; whitelisted BSSIDs
    // never attacked (still recon'd).
    bool     _target_set;
    uint8_t  _target[6];
    static const int MAX_WL = 16;
    uint8_t  _wl[MAX_WL][6];
    int      _n_wl;

    // Per-session capture bookkeeping (cleared in beginSession(), at scan start).
    struct ReconAP {
        uint8_t bssid[6];
        char ssid[33];
        uint8_t channel;
        int8_t  rssi;    // latest beacon RSSI, refreshed as we re-hear it (0 = unknown)
        uint8_t attacks; // active-mode assoc/deauth bursts aimed at this AP
        bool missed;     // already emitted a PWNFRIEND_MISS for it
        bool pmf;        // 802.11w PMF required (RSN MFPR) -> deauth is futile, PMKID only
        uint32_t last_rssi_ms; // millis() of the last PWNFRIEND_RSSI we streamed for it
    };
    // dense areas top 80 APs; 64 dropped ~16. 128 covers a busy neighbourhood.
    static const int MAX_RECON = 128;
    static const int MAX_PWND  = 128;
    static const int MAX_STA   = 128;   // client stations tracked for unicast deauth
    // active-mode bursts with no capture before it's a "miss" (pwnagotchi on_miss).
    static const int MISS_ATTEMPTS = 4;
    ReconAP  _recon[MAX_RECON];
    int      _n_recon;
    uint8_t  _pwnd_seen[MAX_PWND][6];
    int      _n_pwnd_seen;

    // client stations sniffed from DATA frames for unicast deauth (both directions);
    // broadcast deauth is ignored by modern clients.
    struct ClientSta {
        uint8_t mac[6];
        uint8_t ap_idx;      // index into _recon of the AP this client belongs to
        uint32_t last_seen;  // millis(), to age out roamed/departed clients
    };
    ClientSta _sta[MAX_STA];
    int       _n_sta;

    // Recon/attack epoch machine helpers (see broadcast()).
    void resetPhase();                    // back to a fresh RECON sweep
    void endEpoch(uint32_t now);          // roll inactive streak, restart RECON
    void buildAttackList();               // AP-bearing channels, most-populated first
    void attackChannel(uint8_t channel);  // assoc + full deauth pass on entry
    void deauthChannelPass(uint8_t channel); // deauth-only re-kick during the dwell
    uint32_t channelDwellMs(uint8_t channel); // dwell scaled by eligible target count
    bool attackable(const ReconAP& ap) const; // eligible for assoc: not pwned/whitelisted/off-target
    bool deauthable(const ReconAP& ap) const;  // + strong enough to bother deauthing (RSSI floor)
    bool hasClient(int ap_idx) const;           // a fresh associated client -> deauth can work
    bool isWhitelisted(const uint8_t* bssid) const;
    // directed wildcard-SSID probe to make a nameless AP reveal its ESSID.
    void probeAP(const uint8_t* bssid);
    // clients older than this are treated as gone.
    static const uint32_t STA_TTL_MS = 180000;

    int  reconIndex(const uint8_t* bssid) const;   // -1 if unseen
    bool markPwnd(const uint8_t* bssid);           // true if newly counted
    bool isPwnd(const uint8_t* bssid) const;       // already captured this session?
    void emitPwnd(const uint8_t* bssid, const char* ssid,
                  const char* type, int channel, int rssi,
                  bool has_fix, double lat, double lon, bool active);
    void deauthAP(const uint8_t* bssid);
    // unicast deauth of one client, spoofed BOTH directions — the form modern clients honour.
    void deauthClient(const uint8_t* bssid, const uint8_t* client);
    // WPA2 assoc-request to solicit the RSN PMKID (EAPOL M1); no client needed. prefixed
    // by open-system auth so the AP processes it.
    void assocAP(const uint8_t* bssid, const char* ssid);
    // emit one self-describing "PWNFRIEND_HS <bssid> <hex>" line; Flipper files it under
    // <bssid>.pcap from this line alone. hex because raw binary trips the CLI's CR/XON handling.
    void streamFrameHex(const uint8_t* bssid, const uint8_t* frame, int length);
    // on capture, synthesize a minimal ESSID-bearing beacon into the same pcap: hashcat
    // needs the ESSID, and EAPOL-as-DATA caps otherwise lack it. no-op if SSID unknown.
    void streamSyntheticBeacon(const uint8_t* bssid, const char* ssid);
};

// map a face index (flipagotchi's PwnagotchiFace) to a glyph.
const char* pwnfriend_face_glyph(int idx);
