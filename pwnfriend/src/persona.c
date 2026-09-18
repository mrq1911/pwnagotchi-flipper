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
    p->mood = MoodLonely;
    p->secs_since_peer = LONELY_AFTER_SECS;
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
            p->mood = MoodLonely;
            p->secs_since_peer = LONELY_AFTER_SECS;
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

void persona_tick(Persona* p, uint32_t dt) {
    p->session_uptime += dt;
    p->s.total_uptime += dt;
    p->secs_since_peer += dt;

    // Mood decays toward lonely when no one is around.
    if(p->secs_since_peer >= LONELY_AFTER_SECS) {
        p->mood = MoodLonely;
        p->friend_near = false;
    } else if(p->friend_near) {
        p->mood = MoodBonded;
    } else if(p->mood == MoodExcited && p->secs_since_peer > 6) {
        // Excitement settles into contentment after a few seconds.
        p->mood = MoodContent;
    } else if(p->mood != MoodExcited) {
        p->mood = (p->secs_since_peer < 15) ? MoodCurious : MoodContent;
    }
}

void persona_note_peer(Persona* p, bool is_new, bool is_bonded) {
    p->secs_since_peer = 0;
    if(is_bonded) {
        p->friend_near = true;
        p->mood = MoodBonded;
    }
    if(is_new) {
        p->friends_session++;
        p->s.friends_met++;
        if(!is_bonded) p->mood = MoodExcited;
    } else if(!is_bonded && p->mood == MoodLonely) {
        p->mood = MoodCurious;
    }
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
    default:
        return FaceAwake;
    }
}

uint32_t persona_level(const Persona* p) {
    // Grows with time spent alive and friends met. Cheap, monotonic, and it feels
    // rewarding to watch tick up. hours + 2*friends, then a gentle sqrt-ish curve.
    uint32_t hours = (uint32_t)(p->s.total_uptime / 3600);
    uint32_t score = hours + p->s.friends_met * 2;
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
        return "content";
    case MoodCurious:
        return "curious";
    case MoodExcited:
        return "new friend!";
    case MoodBonded:
        return "<3 buddy";
    default:
        return "";
    }
}
