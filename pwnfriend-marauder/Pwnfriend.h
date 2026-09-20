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

// pwnfriend serial-protocol version, stamped on every PWNFRIEND_ADV line (ver=N) so
// the Flipper app can warn when the flashed firmware is older than it needs. Bump on
// any protocol change. v2 = dwell recon + unicast/repeat deauth + PMKID auth + ESSID
// embed + target/whitelist/recon/assoc flags. v3 = live RSSI refresh (PWNFRIEND_RSSI).
// v4 = per-epoch telemetry (PWNFRIEND_EPOCH) + capture provenance (via=) + floor-free
// PMKID solicitation.
#define PWNFRIEND_PROTO 4

// Min interval between PWNFRIEND_RSSI updates for one AP, so re-heard beacons refresh
// the signal without flooding the serial link.
#define PWNFRIEND_RSSI_EMIT_MS 3000

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

    // Recon: harvest a client station from a DATA frame (the non-BSSID address of
    // an AP we already know) into the client table, so active mode can deauth it by
    // UNICAST. Called from the rx callback on every DATA frame; allocation-free.
    void reportClient(const uint8_t* payload, int length);

    // True once a persona has been loaded (so broadcast() has something to send).
    bool ready() const { return _ready; }

    // Clear the per-session capture dedup tables. Called at real scan start
    // (RunPwnfriendScan), NOT on a persona refresh — so re-sending the pwnfriend
    // command every 15s doesn't re-count already-pwnd APs and inflate pwnd_tot.
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

    // --- pwnagotchi-faithful recon/attack dwell (agent.py's epoch loop) ---
    // RECON sweeps every channel for recon_time gathering APs (and being heard on
    // the mesh); ATTACK then visits each AP-bearing channel, fires associate()+
    // deauth() once, and DWELLS hop_recon_time on it so the solicited 4-way
    // handshake actually completes before we hop away. The old blind 500ms hop is
    // exactly why nothing was ever captured.
    enum Phase { PHASE_RECON, PHASE_ATTACK };
    Phase    _phase;
    uint32_t _phase_ms;        // millis() when the phase / channel dwell began
    uint8_t  _cur_channel;     // channel we're parked on right now
    uint32_t _last_hop_ms;     // recon-sweep hop cadence timer
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

    // Targeting + whitelist (set from the Flipper's options menu). When a target is
    // set, only that BSSID is attacked (the attack list collapses to its channel);
    // whitelisted BSSIDs are never attacked (but still recon'd/reported).
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
    // A dense area easily tops 80 APs; 64 silently dropped ~16 of them (never
    // recon'd, never attacked). 128 covers a busy neighbourhood.
    static const int MAX_RECON = 128;
    static const int MAX_PWND  = 128;
    static const int MAX_STA   = 128;   // client stations tracked for unicast deauth
    // Active-mode bursts against an AP with no capture before it counts as a
    // "miss" (pwnagotchi's on_miss).
    static const int MISS_ATTEMPTS = 4;
    ReconAP  _recon[MAX_RECON];
    int      _n_recon;
    uint8_t  _pwnd_seen[MAX_PWND][6];
    int      _n_pwnd_seen;

    // Client stations sniffed from DATA frames, so we can deauth them by UNICAST
    // (spoofing both directions) the way pwnagotchi/bettercap does — broadcast
    // deauth is ignored by modern clients, which is why yield was so low.
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
    // Directed probe request (wildcard SSID) to make a nameless AP reveal its ESSID,
    // so a keymat-only capture can still be cracked (hcxdumptool-style).
    void probeAP(const uint8_t* bssid);
    // Clients older than this (no data frame seen) are treated as gone: don't deauth
    // an AP on their behalf.
    static const uint32_t STA_TTL_MS = 180000;

    int  reconIndex(const uint8_t* bssid) const;   // -1 if unseen
    bool markPwnd(const uint8_t* bssid);           // true if newly counted
    bool isPwnd(const uint8_t* bssid) const;       // already captured this session?
    void emitPwnd(const uint8_t* bssid, const char* ssid,
                  const char* type, int channel, int rssi,
                  bool has_fix, double lat, double lon, bool active);
    void deauthAP(const uint8_t* bssid);
    // Unicast deauth of one client, spoofed in BOTH directions (AP->client and
    // client->AP) — the effective form modern clients honour, mirroring bettercap's
    // wifi.deauth (and Marauder's sendDeauthFrame).
    void deauthClient(const uint8_t* bssid, const uint8_t* client);
    // Send a WPA2 association request to a target AP to solicit its RSN PMKID
    // (EAPOL M1) — pwnagotchi's associate() half, no client needed. Prefixed by an
    // open-system Authentication so the AP actually processes it. Only fired in
    // active mode (the -deauth opt-in), same as deauthAP.
    void assocAP(const uint8_t* bssid, const char* ssid);
    // Emit one self-describing "PWNFRIEND_HS <bssid12hex> <framehex>" line for a
    // raw 802.11 frame. The Flipper files the frame under <bssid>.pcap by parsing
    // this line alone (no dependence on a preceding PWND). Raw binary would trip
    // the CLI's CR/XON handling, so we stream lowercase hex.
    void streamFrameHex(const uint8_t* bssid, const uint8_t* frame, int length);
    // On capture, synthesize a minimal beacon carrying the AP's ESSID and stream it
    // into the same per-BSSID pcap. hcxpcapngtool/hashcat need the ESSID in the file;
    // when we caught the EAPOL as DATA frames but never sniffed/kept the real beacon
    // (e.g. table was full, or a cross-session file), the capture was uncrackable
    // without this. No-op if the SSID is unknown/hidden.
    void streamSyntheticBeacon(const uint8_t* bssid, const char* ssid);
};

// Map a face index (matching flipagotchi's enum PwnagotchiFace) to a glyph.
const char* pwnfriend_face_glyph(int idx);
