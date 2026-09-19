#pragma once

#include <furi.h>
#include "face.h"

// The Flipper friend's identity and how it grows. Persisted to SD so the friend
// remembers who it is (stable pwngrid identity => the pwnagotchi keeps counting
// encounters and eventually treats it as a "good friend").

#define PERSONA_NAME_MAX 17
#define PERSONA_ID_HEX_LEN 64

typedef enum {
    // The original five ordinals are kept stable so old logic still lines up.
    MoodLonely, // no peers around for a while — the whole reason this app exists
    MoodContent, // awake / idling happily (AWAKE face)
    MoodCurious, // a familiar unit just dropped by
    MoodExcited, // sustained activity, or a fresh capture streak / new friend
    MoodBonded, // a good friend is nearby (♥ FRIEND face)
    // --- new moods for the full pwnagotchi machine ---
    MoodBored, // several quiet epochs
    MoodSleep, // a long quiet stretch, drifting off
    MoodSad, // no friends AND no catches for a long time
    MoodMotivated, // actively racking up APs this epoch
    MoodSmart, // a flood of APs this epoch
    MoodHappy, // just grabbed a handshake
    MoodCool, // handshake streak this epoch
} PersonaMood;

// Persisted-to-SD portion. Fixed layout; bump PERSONA_SAVE_VERSION on change.
// Appending fields changes sizeof(), and the loader rejects any blob whose size
// or version doesn't match — so a v1 file is cleanly discarded (a one-time reset).
#define PERSONA_SAVE_MAGIC 0x50574E46u // "PWNF"
#define PERSONA_SAVE_VERSION 2

typedef struct {
    uint32_t magic;
    uint32_t version;
    char name[PERSONA_NAME_MAX];
    char identity[PERSONA_ID_HEX_LEN + 1]; // 64 lowercase hex + NUL
    uint64_t born_unix; // when this persona was first created
    uint64_t total_uptime; // cumulative seconds advertised, all sessions
    uint32_t friends_met; // distinct units met over lifetime (social score, NOT pwnd)
    uint32_t generation; // increments each save; a rough "age"
    // --- v2 additions ---
    uint32_t pwnd_tot; // REAL handshakes/PMKID captured, lifetime (advertised as -pt)
    uint32_t aps_tot; // access points seen, lifetime
    uint32_t epochs_tot; // lifetime epoch count (feeds the level curve)
} PersonaSaved;

typedef struct {
    PersonaSaved s;

    // Volatile session state, not persisted.
    uint32_t session_uptime; // seconds this session
    uint32_t friends_session; // distinct units met this session
    uint32_t secs_since_peer; // seconds since we last heard any unit
    bool friend_near; // a bonded/good friend is currently in range
    PersonaMood mood;

    // --- full-pwnagotchi brain state (volatile) ---
    uint32_t pwnd_run; // handshakes captured this session (advertised as -pr)
    uint32_t aps_session; // access points seen this session (APS readout)
    uint32_t epoch; // epoch counter this session (advertised as -e)

    uint32_t secs_in_epoch; // seconds accumulated in the current epoch
    uint32_t aps_this_epoch; // APs seen in the current epoch
    uint32_t hs_this_epoch; // handshakes in the current epoch
    uint32_t active_epochs; // consecutive "active" epochs
    uint32_t inactive_epochs; // consecutive "quiet" epochs
    uint32_t secs_since_pwnd; // seconds since the last handshake

    uint32_t mood_lock_secs; // >0: hold a transient reaction face, don't recompute
} Persona;

// Load from SD, or mint a fresh persona (new random identity) if none exists.
Persona* persona_alloc(void);
void persona_free(Persona* p);

// Persist to SD. Call periodically and on exit.
bool persona_save(Persona* p);

// Advance one tick. dt = seconds elapsed. Recomputes mood/face.
void persona_tick(Persona* p, uint32_t dt);

// Note that a unit was heard this tick. `is_new` if not seen before this session,
// `is_bonded` if it's a good friend (met many times / high encounter count).
void persona_note_peer(Persona* p, bool is_new, bool is_bonded);

// Note that a real WPA handshake / PMKID was captured this tick. Bumps
// pwnd_run/pwnd_tot, flashes the capture face, feeds the epoch machine.
void persona_note_pwnd(Persona* p);

// Note that an access point was seen this tick. Feeds aps_session and the
// epoch's activity signal (drives MOTIVATED/SMART).
void persona_note_ap(Persona* p);

// Derived getters.
Face persona_face(const Persona* p);
uint32_t persona_level(const Persona* p);
const char* persona_mood_label(const Persona* p);
