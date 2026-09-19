#include "../include/persona.h"

#include <stdlib.h>
#include <string.h>
#include <furi_hal_random.h>
#include <storage/storage.h>
#include <datetime/datetime.h>
#include <furi_hal_rtc.h>

#define PERSONA_DIR "/ext/apps_data/pwnfriend"
#define PERSONA_PATH PERSONA_DIR "/persona.bin"

// Seconds of silence before the friend gets lonely — the sad face this whole
// app exists to prevent on the pwnagotchi is one we let our own friend show too.
#define LONELY_AFTER_SECS 45

// One "epoch" ~ a recon window. The mood machine evaluates activity per epoch.
// pwnagotchi counts epochs in recon sweeps; here an epoch is a fixed 30 s window,
// so its bored/sad/excited "num_epochs" thresholds scale down proportionately.
#define PERSONA_EPOCH_SECS 30

// Per-epoch activity thresholds (APs seen inside one epoch).
#define PERSONA_EPOCH_ACTIVE_APS 4 // >= this -> the epoch counts as "active"
#define PERSONA_SMART_APS 8 // a flood this epoch -> SMART face

// Consecutive-epoch thresholds (mirrors pwnagotchi bored/sad/excited_num_epochs).
#define PERSONA_EXCITED_EPOCHS 3 // consecutive active epochs -> EXCITED
#define PERSONA_BORED_EPOCHS 4 // consecutive quiet epochs   -> BORED  (~2 min)
#define PERSONA_SLEEP_EPOCHS 8 // ... even longer            -> SLEEP  (~4 min)
#define PERSONA_SAD_EPOCHS 6 // quiet AND catch-less       -> SAD

// Handshake streak inside one epoch that earns the COOL face.
#define PERSONA_COOL_STREAK 4

// Time-based feels (seconds).
#define PERSONA_CURIOUS_SECS 15 // a peer this recently -> curious
#define PERSONA_SAD_SECS 180 // no catch this long feeds the gloom
#define PERSONA_PWND_REACT_SECS 8 // hold the capture (happy/cool/excited) face
#define PERSONA_PEER_REACT_SECS 6 // hold the "new friend!" excited face

static uint64_t persona_now_unix(void) {
    DateTime dt;
    furi_hal_rtc_get_datetime(&dt);
    return (uint64_t)datetime_datetime_to_timestamp(&dt);
}

static void persona_gen_identity(char* out /* PERSONA_ID_HEX_LEN+1 */) {
    static const char hex[] = "0123456789abcdef";
    uint8_t raw[32];
    furi_hal_random_fill_buf(raw, sizeof(raw));
    for(size_t i = 0; i < sizeof(raw); i++) {
        out[i * 2] = hex[(raw[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[raw[i] & 0xF];
    }
    out[PERSONA_ID_HEX_LEN] = '\0';
}

static void persona_mint(Persona* p) {
    memset(p, 0, sizeof(Persona));
    p->s.magic = PERSONA_SAVE_MAGIC;
    p->s.version = PERSONA_SAVE_VERSION;
    strncpy(p->s.name, "flippy", PERSONA_NAME_MAX - 1);
    persona_gen_identity(p->s.identity);
    p->s.born_unix = persona_now_unix();
    p->s.total_uptime = 0;
    p->s.friends_met = 0;
    p->s.generation = 0;
    // memset above already zeroed the v2 counters and every volatile epoch field.
    p->mood = MoodContent; // AWAKE on start, like a real pwnagotchi
    p->secs_since_peer = 0; // a grace window before it gets lonely
}

Persona* persona_alloc(void) {
    Persona* p = malloc(sizeof(Persona));

    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool loaded = false;

    if(storage_file_open(file, PERSONA_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        PersonaSaved saved;
        uint16_t read = storage_file_read(file, &saved, sizeof(saved));
        if(read == sizeof(saved) && saved.magic == PERSONA_SAVE_MAGIC &&
           saved.version == PERSONA_SAVE_VERSION) {
            memset(p, 0, sizeof(Persona));
            p->s = saved;
            // Guard against a corrupt name/identity from a truncated write.
            p->s.name[PERSONA_NAME_MAX - 1] = '\0';
            p->s.identity[PERSONA_ID_HEX_LEN] = '\0';
            // The memset above zeroed every volatile epoch counter before p->s = saved.
            p->mood = MoodContent;
            p->secs_since_peer = 0;
            loaded = true;
        }
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);

    if(!loaded) persona_mint(p);
    return p;
}

void persona_free(Persona* p) {
    free(p);
}

bool persona_save(Persona* p) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    storage_common_mkdir(storage, PERSONA_DIR);

    File* file = storage_file_alloc(storage);
    bool ok = false;
    if(storage_file_open(file, PERSONA_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        p->s.generation++;
        uint16_t written = storage_file_write(file, &p->s, sizeof(p->s));
        ok = (written == sizeof(p->s));
    }
    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

// Close out the current epoch: classify it, roll the active/inactive streaks,
// and reset the per-epoch tallies. Mirrors pwnagotchi's epoch bookkeeping.
static void persona_end_epoch(Persona* p) {
    p->epoch++;
    p->s.epochs_tot++;

    bool got_hs = (p->hs_this_epoch > 0);
    bool active = got_hs || (p->aps_this_epoch >= PERSONA_EPOCH_ACTIVE_APS);

    if(active) {
        p->active_epochs++;
        p->inactive_epochs = 0;
    } else {
        p->active_epochs = 0;
        p->inactive_epochs++;
    }

    p->aps_this_epoch = 0;
    p->hs_this_epoch = 0;
}

// The steady-state mood when no transient reaction is being held. Priority order
// is chosen so a real signal (friend, live activity) always beats a slow decay.
static PersonaMood persona_baseline_mood(const Persona* p) {
    // A good friend in range always wins.
    if(p->friend_near) return MoodBonded;

    bool no_peers = (p->secs_since_peer >= LONELY_AFTER_SECS);

    // Live activity this very epoch reacts fastest.
    if(p->aps_this_epoch >= PERSONA_SMART_APS) return MoodSmart;
    if(p->active_epochs >= PERSONA_EXCITED_EPOCHS) return MoodExcited;
    if(p->aps_this_epoch >= PERSONA_EPOCH_ACTIVE_APS) return MoodMotivated;

    // A unit just visited -> curious (still social; beats the gloom onset).
    if(p->secs_since_peer < PERSONA_CURIOUS_SECS) return MoodCurious;

    // Long drought of BOTH friends and catches -> sad; friends-only drought -> lonely.
    if(no_peers && p->secs_since_pwnd >= PERSONA_SAD_SECS &&
       p->inactive_epochs >= PERSONA_SAD_EPOCHS)
        return MoodSad;
    if(no_peers) return MoodLonely;

    // Quiet but not lonely -> bored, then drifting to sleep.
    if(p->inactive_epochs >= PERSONA_SLEEP_EPOCHS) return MoodSleep;
    if(p->inactive_epochs >= PERSONA_BORED_EPOCHS) return MoodBored;

    return MoodContent; // awake / idle
}

void persona_tick(Persona* p, uint32_t dt) {
    p->session_uptime += dt;
    p->s.total_uptime += dt;
    p->secs_since_peer += dt;
    p->secs_since_pwnd += dt;
    p->secs_in_epoch += dt;

    // Epoch boundary: score the window and roll the streak counters.
    if(p->secs_in_epoch >= PERSONA_EPOCH_SECS) {
        p->secs_in_epoch = 0;
        persona_end_epoch(p);
    }

    // Decay a held transient reaction (capture / new-friend flash).
    if(p->mood_lock_secs > dt)
        p->mood_lock_secs -= dt;
    else
        p->mood_lock_secs = 0;

    // While a reaction is held, keep it — otherwise settle to the baseline.
    if(p->mood_lock_secs == 0) p->mood = persona_baseline_mood(p);
}

void persona_note_peer(Persona* p, bool is_new, bool is_bonded) {
    p->secs_since_peer = 0;
    if(is_new) {
        p->friends_session++;
        p->s.friends_met++;
    }
    if(is_bonded) {
        p->friend_near = true;
        p->mood = MoodBonded; // no lock; friend_near keeps the baseline here
    } else if(is_new) {
        p->mood = MoodExcited;
        p->mood_lock_secs = PERSONA_PEER_REACT_SECS; // flash "new friend!"
    } else {
        p->mood = MoodCurious; // a familiar face dropped by
    }
}

void persona_note_pwnd(Persona* p) {
    p->pwnd_run++;
    p->s.pwnd_tot++;
    p->hs_this_epoch++;
    p->secs_since_pwnd = 0;

    // Fresh-capture reaction: 1 -> happy, 2..3 -> excited, streak -> cool.
    if(p->hs_this_epoch >= PERSONA_COOL_STREAK)
        p->mood = MoodCool;
    else if(p->hs_this_epoch >= 2)
        p->mood = MoodExcited;
    else
        p->mood = MoodHappy;

    p->mood_lock_secs = PERSONA_PWND_REACT_SECS; // hold the reaction face
}

void persona_note_ap(Persona* p) {
    p->aps_session++;
    p->s.aps_tot++;
    p->aps_this_epoch++;
    // No direct mood poke: persona_baseline_mood() reads aps_this_epoch each tick,
    // so MOTIVATED/SMART surface within a second without flicker.
}

Face persona_face(const Persona* p) {
    switch(p->mood) {
    case MoodLonely:
        return FaceLonely;
    case MoodContent:
        return FaceAwake;
    case MoodCurious:
        return FaceLookRHappy;
    case MoodExcited:
        return FaceExcited;
    case MoodBonded:
        return FaceFriend;
    case MoodBored:
        return FaceBored;
    case MoodSleep:
        return FaceSleep;
    case MoodSad:
        return FaceSad;
    case MoodMotivated:
        return FaceMotivated;
    case MoodSmart:
        return FaceSmart;
    case MoodHappy:
        return FaceHappy;
    case MoodCool:
        return FaceCool;
    default:
        return FaceAwake;
    }
}

uint32_t persona_level(const Persona* p) {
    // Grows with time alive, handshakes captured, and friends met. Real pwnd count
    // the most; then a gentle triangular curve so it slows as it climbs.
    uint32_t hours = (uint32_t)(p->s.total_uptime / 3600);
    uint32_t score = hours + p->s.pwnd_tot * 3 + p->s.friends_met;
    uint32_t level = 1;
    uint32_t step = 3;
    uint32_t need = step;
    while(score >= need) {
        level++;
        step++;
        need += step;
    }
    return level;
}

const char* persona_mood_label(const Persona* p) {
    switch(p->mood) {
    case MoodLonely:
        return "lonely...";
    case MoodContent:
        return "hack the planet";
    case MoodCurious:
        return "curious";
    case MoodExcited:
        return "living the life!";
    case MoodBonded:
        return "<3 buddy";
    case MoodBored:
        return "bored...";
    case MoodSleep:
        return "zzz...";
    case MoodSad:
        return "so alone :(";
    case MoodMotivated:
        return "on the hunt!";
    case MoodSmart:
        return "so many APs!";
    case MoodHappy:
        return "got a handshake!";
    case MoodCool:
        return "on a streak!";
    default:
        return "";
    }
}
