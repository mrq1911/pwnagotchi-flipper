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

typedef enum {
    WorkerEventStop = (1 << 0),
    WorkerEventRx = (1 << 1),
} WorkerEventFlags;

#define WORKER_EVENTS_MASK (WorkerEventStop | WorkerEventRx)

typedef struct {
    Persona* persona;
    PeerList peers;
    uint32_t tick_secs;
    bool advertising;
    uint32_t last_adv_sent;
    uint32_t adv_sent_count; // last "sent=" from the ESP32
    uint8_t adv_channel; // last channel it reported broadcasting on
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

    // Line assembly — touched only by the worker thread.
    char line[288];
    size_t line_len;
    bool got_new_friend; // set by worker, consumed for a notification blink
} PwnfriendApp;

static const NotificationSequence sequence_new_friend = {
    &message_display_backlight_on,
    &message_green_255,
    &message_vibro_on,
    &message_delay_50,
    &message_vibro_off,
    NULL,
};

// ---------------------------------------------------------------------------
// Serial: build + send the advertise command, and stop.
// ---------------------------------------------------------------------------

static void pwnfriend_send_advertise(PwnfriendApp* app) {
    char cmd[188];
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
            snprintf(
                cmd,
                sizeof(cmd),
                "pwnfriend -n %s -id %s -f %d -pr %lu -pt %lu -u %lu\n",
                safe_name,
                p->s.identity,
                (int)persona_face(p),
                (unsigned long)p->friends_session,
                (unsigned long)p->s.friends_met,
                (unsigned long)p->s.total_uptime);
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

static void pwnfriend_process_line(PwnfriendApp* app, const char* line) {
    if(strncmp(line, "PWNFRIEND_PEER ", 15) == 0) {
        pwnfriend_handle_peer_line(app, line);
    } else if(strncmp(line, "PWNFRIEND_ADV ", 14) == 0) {
        pwnfriend_handle_adv_line(app, line);
    }
    // Any other line is ordinary Marauder chatter; ignore it.
}

// ---------------------------------------------------------------------------
// Drawing
// ---------------------------------------------------------------------------

static void pwnfriend_draw_callback(Canvas* canvas, void* ctx) {
    PwnfriendModel* model = ctx;
    Persona* p = model->persona;

    canvas_clear(canvas);

    // Face on the left.
    face_draw(canvas, persona_face(p), 0, 2);

    // Name + level, top right of the face.
    canvas_set_font(canvas, FontPrimary);
    char header[28];
    snprintf(header, sizeof(header), "%s", p->s.name);
    canvas_draw_str(canvas, 40, 11, header);

    canvas_set_font(canvas, FontSecondary);
    char lvl[16];
    snprintf(lvl, sizeof(lvl), "Lv %lu", (unsigned long)persona_level(p));
    canvas_draw_str_aligned(canvas, 127, 4, AlignRight, AlignTop, lvl);

    // Mood + friends met.
    canvas_draw_str(canvas, 40, 22, persona_mood_label(p));
    char met[24];
    snprintf(
        met,
        sizeof(met),
        "met %lu (+%lu)",
        (unsigned long)p->s.friends_met,
        (unsigned long)p->friends_session);
    canvas_draw_str(canvas, 40, 32, met);

    // Status line under the head area.
    canvas_draw_line(canvas, 0, 35, 127, 35);
    char status[40];
    if(model->advertising) {
        snprintf(
            status, sizeof(status), "saying hi... ch%u", (unsigned)model->adv_channel);
    } else {
        snprintf(status, sizeof(status), "paused - press OK to greet");
    }
    canvas_draw_str(canvas, 0, 45, status);

    // Detected pwnagotchis.
    int y = 55;
    int shown = 0;
    for(int i = 0; i < MAX_PEERS && shown < 2; i++) {
        if(!model->peers.items[i].used) continue;
        Peer* pe = &model->peers.items[i];
        int bars = peers_rssi_bars(pe->rssi);
        char row[40];
        snprintf(
            row,
            sizeof(row),
            "%.*s%.*s %s %d",
            bars,
            "||||",
            4 - bars,
            "....",
            pe->name,
            pe->pwnd_tot);
        canvas_draw_str(canvas, 0, y, row);
        y += 9;
        shown++;
    }
    if(shown == 0) {
        canvas_draw_str(canvas, 0, 55, "no units heard yet");
    }
}

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

static bool pwnfriend_input_callback(InputEvent* event, void* ctx) {
    PwnfriendApp* app = ctx;
    if(event->type != InputTypeShort) return false;

    if(event->key == InputKeyOk) {
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

    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_enable_queue(app->view_dispatcher);
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
            peers_init(&model->peers);
            model->tick_secs = 0;
            model->advertising = false;
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
        app->view, PwnfriendModel * model, { persona_free(model->persona); }, false);
    view_free(app->view);
    view_dispatcher_free(app->view_dispatcher);

    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);
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
