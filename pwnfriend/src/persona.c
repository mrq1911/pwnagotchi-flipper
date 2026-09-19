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

// One "epoch" == one recon window. Upstream personality.recon_time = 30 s, so we
// use the same wall-time per epoch: "num_epochs" here means the same as upstream.
#define PERSONA_EPOCH_SECS 30 // personality.recon_time

// max_inactive_scale / recon_inactive_multiplier: agent.recon() doubles recon_time
// once inactive_for >= max_inactive_scale, so the friend slows its scanning when
// nothing is happening. We mirror that by stretching the epoch window the same way,
// which scales the wall-time onset of boredom/sadness exactly like upstream.
#define PERSONA_MAX_INACTIVE_SCALE 2 // personality.max_inactive_scale
#define PERSONA_RECON_INACTIVE_MULT 2 // personality.recon_inactive_multiplier

// Per-epoch activity thresholds (APs seen inside one epoch). Upstream's activity is
// "did we deauth/assoc/handshake this epoch"; we proxy it with per-epoch AP volume
// (min_rssi filtering stays in firmware, out of the brain).
#define PERSONA_EPOCH_ACTIVE_APS 4 // >= this -> the epoch counts as "active"
#define PERSONA_SMART_APS 8 // a flood this epoch -> SMART face

// Consecutive-epoch thresholds (real pwnagotchi defaults.toml values).
#define PERSONA_EXCITED_EPOCHS 10 // active_for >= excited_num_epochs -> EXCITED
#define PERSONA_BORED_EPOCHS 15 // inactive_for >= bored_num_epochs -> BORED
#define PERSONA_SAD_EPOCHS 25 // inactive_for >= sad_num_epochs   -> SAD
#define PERSONA_SLEEP_EPOCHS (PERSONA_SAD_EPOCHS * 2) // 2x sad (automata's escalation) -> SLEEP

// Handshake streak inside one epoch that earns the COOL face.
#define PERSONA_COOL_STREAK 4

// Time-based feels (seconds).
#define PERSONA_CURIOUS_SECS 15 // a peer this recently -> curious
#define PERSONA_PWND_REACT_SECS 8 // hold the capture (happy/cool/excited) face
#define PERSONA_PEER_REACT_SECS 6 // hold the "new friend!" excited face
#define PERSONA_MISS_REACT_SECS 4 // hold the "missed!" demotivated face

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

// Current epoch length in seconds. Upstream agent.recon() doubles recon_time once
// inactive_for >= max_inactive_scale; we stretch the epoch window identically so
// the wall-time onset of boredom/sadness scales the same way it does upstream.
static uint32_t persona_epoch_len(const Persona* p) {
    if(p->inactive_epochs >= PERSONA_MAX_INACTIVE_SCALE)
        return PERSONA_EPOCH_SECS * PERSONA_RECON_INACTIVE_MULT;
    return PERSONA_EPOCH_SECS;
}

// Close out the current epoch: classify it, roll the active/inactive streaks,
// and reset the per-epoch tallies. Mirrors pwnagotchi Epoch.next(): an epoch is
// "active" iff there was any activity OR a handshake, and inactive/active_for are
// the consecutive streaks the mood machine reads.
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

// The steady-state mood when no transient reaction is being held. Mirrors the
// dispatch in Automata.next_epoch(): the activity streak (active/inactive_for)
// drives excited/bored/sad, and a good friend around turns any down epoch grateful
// (upstream set_bored/set_sad/set_lonely all defer to set_grateful when the support
// network is strong enough).
static PersonaMood persona_baseline_mood(const Persona* p) {
    // The automata activity/social droughts. sad supersedes bored, both pure
    // inactivity (Epoch.next); sleep is our friendlier stand-in for automata's
    // set_angry escalation at inactive_for >= 2*sad_num_epochs.
    bool sleepy = (p->inactive_epochs >= PERSONA_SLEEP_EPOCHS);
    bool sad = (p->inactive_epochs >= PERSONA_SAD_EPOCHS);
    bool bored = (p->inactive_epochs >= PERSONA_BORED_EPOCHS);
    bool lonely = (p->secs_since_peer >= LONELY_AFTER_SECS);
    bool down = sleepy || sad || bored || lonely;

    // A good friend in range always wins: grateful on a bad day (the support-network
    // override), bonded otherwise (on_new_peer picks the FRIEND face for a bond).
    if(p->friend_near) return down ? MoodGrateful : MoodBonded;

    // Live activity this very epoch reacts fastest (per-epoch AP volume + the
    // sustained excited from active_for >= excited_num_epochs).
    if(p->aps_this_epoch >= PERSONA_SMART_APS) return MoodSmart;
    if(p->active_epochs >= PERSONA_EXCITED_EPOCHS) return MoodExcited;
    if(p->aps_this_epoch >= PERSONA_EPOCH_ACTIVE_APS) return MoodMotivated;

    // A unit just dropped by -> curious (on_new_peer for a returning unit).
    if(p->secs_since_peer < PERSONA_CURIOUS_SECS) return MoodCurious;

    // The slow decay: sleep (deep) > sad > bored are pure inactivity; then our
    // social 'lonely' drought (no peers heard for a while).
    if(sleepy) return MoodSleep;
    if(sad) return MoodSad;
    if(bored) return MoodBored;
    if(lonely) return MoodLonely;

    return MoodContent; // awake / normal (on_normal)
}

void persona_tick(Persona* p, uint32_t dt) {
    p->session_uptime += dt;
    p->s.total_uptime += dt;
    p->secs_since_peer += dt;
    p->secs_since_pwnd += dt;
    p->secs_in_epoch += dt;

    // Epoch boundary: score the window and roll the streak counters. The window
    // stretches while inactive (persona_epoch_len), mirroring agent.recon()'s
    // recon_time doubling.
    if(p->secs_in_epoch >= persona_epoch_len(p)) {
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

void persona_note_miss(Persona* p) {
    // Automata._on_miss -> view.on_miss: an interaction that hit nothing. Upstream
    // flashes a face + "Missed!"; we hold a short DEMOTIVATED nudge, then settle back.
    // (We don't model max_misses_for_recon -> stale -> lonely/angry; kept simple.)
    p->mood = MoodDemotivated;
    p->mood_lock_secs = PERSONA_MISS_REACT_SECS;
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
    case MoodGrateful:
        return FaceGrateful;
    case MoodDemotivated:
        return FaceDemotivated;
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

// One representative line per mood, taken from pwnagotchi's voice.py (upstream
// random-picks from a list; we keep the shortest faithful pick for the Flipper's
// message area). The mapping follows view.py's face<->voice pairing.
const char* persona_mood_label(const Persona* p) {
    switch(p->mood) {
    case MoodLonely:
        return "I feel so alone ..."; // voice.on_lonely
    case MoodContent:
        return "Hack the Planet!"; // voice.on_starting (on_normal is just "...")
    case MoodCurious:
        return "Unit is nearby!"; // voice.on_new_peer (returning unit)
    case MoodExcited:
        return "I'm living the life!"; // voice.on_excited
    case MoodBonded:
        return "I love my friends!"; // voice.on_grateful (a bond in range)
    case MoodBored:
        return "I'm bored ..."; // voice.on_bored
    case MoodSleep:
        return "Zzzzz"; // voice.on_napping
    case MoodSad:
        return "I'm very sad ..."; // voice.on_sad
    case MoodMotivated:
        return "Best day of my life!"; // voice.on_motivated
    case MoodSmart:
        return "So many networks!!!"; // voice.on_excited
    case MoodHappy:
        return "Cool, got a handshake!"; // voice.on_handshakes
    case MoodCool:
        return "I pwn therefore I am."; // voice.on_excited (streak swagger)
    case MoodGrateful:
        return "Good friends are a blessing!"; // voice.on_grateful
    case MoodDemotivated:
        return "Shitty day :/"; // voice.on_demotivated (a miss)
    default:
        return "";
    }
}
