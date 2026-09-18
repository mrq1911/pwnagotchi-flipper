#pragma once

#include <furi.h>
#include "face.h"

// The Flipper friend's identity and how it grows. Persisted to SD so the friend
// remembers who it is (stable pwngrid identity => the pwnagotchi keeps counting
// encounters and eventually treats it as a "good friend").

#define PERSONA_NAME_MAX 17
#define PERSONA_ID_HEX_LEN 64

typedef enum {
    MoodLonely, // no one around for a while — the whole reason this app exists
    MoodContent, // idling happily
    MoodCurious, // someone was just here
    MoodExcited, // just met a new unit
    MoodBonded, // a good friend is nearby
} PersonaMood;

// Persisted-to-SD portion. Fixed layout; bump PERSONA_SAVE_VERSION on change.
#define PERSONA_SAVE_MAGIC 0x50574E46u // "PWNF"
#define PERSONA_SAVE_VERSION 1

typedef struct {
    uint32_t magic;
    uint32_t version;
    char name[PERSONA_NAME_MAX];
    char identity[PERSONA_ID_HEX_LEN + 1]; // 64 lowercase hex + NUL
    uint64_t born_unix; // when this persona was first created
    uint64_t total_uptime; // cumulative seconds advertised, all sessions
    uint32_t friends_met; // distinct units met over lifetime (advertised as pwnd_tot)
    uint32_t generation; // increments each save; a rough "age"
} PersonaSaved;

typedef struct {
    PersonaSaved s;

    // Volatile session state, not persisted.
    uint32_t session_uptime; // seconds this session
    uint32_t friends_session; // distinct units met this session (advertised as pwnd_run)
    uint32_t secs_since_peer; // seconds since we last heard any unit
    bool friend_near; // a bonded/good friend is currently in range
    PersonaMood mood;
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

// Derived getters.
Face persona_face(const Persona* p);
uint32_t persona_level(const Persona* p);
const char* persona_mood_label(const Persona* p);
