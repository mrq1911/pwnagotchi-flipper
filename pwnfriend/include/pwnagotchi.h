#pragma once

#include <furi.h>
#include <gui/canvas.h>
#include <stdbool.h>
#include <string.h>

#include "pwn_constants.h"

#define PWNAGOTCHI_HEIGHT FLIPPER_SCREEN_HEIGHT
#define PWNAGOTCHI_WIDTH FLIPPER_SCREEN_WIDTH
#define PWNAGOTCHI_FACE_I 25
#define PWNAGOTCHI_FACE_J 0
#define PWNAGOTCHI_NAME_I 17
#define PWNAGOTCHI_NAME_J 0
#define PWNAGOTCHI_CHANNEL_I 7
#define PWNAGOTCHI_CHANNEL_J 0
#define PWNAGOTCHI_APS_I 7
#define PWNAGOTCHI_APS_J 30
#define PWNAGOTCHI_UPTIME_I 7
// UPTIME is drawn right-aligned to the screen edge (see pwnagotchi_draw_uptime), so
// no fixed J is needed; a full hh:mm:ss can't overrun the edge or hit the AP count.
#define PWNAGOTCHI_LINE1_START_I 8
#define PWNAGOTCHI_LINE1_START_J 0
#define PWNAGOTCHI_LINE1_END_I 8
#define PWNAGOTCHI_LINE1_END_J 127
#define PWNAGOTCHI_LINE2_START_I 54
#define PWNAGOTCHI_LINE2_START_J 0
#define PWNAGOTCHI_LINE2_END_I 54
#define PWNAGOTCHI_LINE2_END_J 127
#define PWNAGOTCHI_HANDSHAKES_I 63
#define PWNAGOTCHI_HANDSHAKES_J 0
#define PWNAGOTCHI_FRIEND_FACE_I 52
#define PWNAGOTCHI_FRIEND_FACE_J 3
#define PWNAGOTCHI_FRIEND_STAT_I 52
#define PWNAGOTCHI_FRIEND_STAT_J 24
#define PWNAGOTCHI_MODE_AI_I 63
#define PWNAGOTCHI_MODE_AI_J 121
#define PWNAGOTCHI_MODE_AUTO_I 63
#define PWNAGOTCHI_MODE_AUTO_J 105
#define PWNAGOTCHI_MODE_MANU_I 63
#define PWNAGOTCHI_MODE_MANU_J 103
#define PWNAGOTCHI_MESSAGE_I 17
#define PWNAGOTCHI_MESSAGE_J 60

#define PWNAGOTCHI_FONT FontSecondary

/**
 * Enum to represent possible faces to save them locally rather than transmit every time
 */
enum PwnagotchiFace {
    NoFace = 0,
    DefaultFace,
    Look_r,
    Look_l,
    Look_r_happy,
    Look_l_happy,
    Sleep,
    Sleep2,
    Awake,
    Bored,
    Intense,
    Cool,
    Happy,
    Grateful,
    Excited,
    Motivated,
    Demotivated,
    Smart,
    Lonely,
    Sad,
    Angry,
    Friend,
    Broken,
    Debug,
    Upload,
    Upload1,
    Upload2
};


/**
 * Enum for current mode of the pwnagotchi
 */
enum PwnagotchiMode { PwnMode_Auto, PwnMode_Ai, PwnMode_Manual };

typedef struct {
    /// Current face
    enum PwnagotchiFace face;
    /// CH channel display at top left
    FuriString* channel;
    /// AP text shown at the top
    FuriString* apStat;
    /// Uptime as text
    FuriString* uptime;
    /// Hostname of the unit
    FuriString* hostname;
    /// Message that is displayed
    FuriString* message;
    /// LAST SSID and other handshake information for the bottom
    FuriString* handshakes;
    /// Current mode the pwnagotchi is in
    enum PwnagotchiMode mode;
    /// Name and aps of friend
    FuriString* friendStat;

} Pwnagotchi;

/**
 * @brief Allocates and constructs a pwnagotchi struct
 * 
 * @return Pwnagotchi* Constructed pwnagotchi pointer
 */
Pwnagotchi* pwnagotchi_alloc();

/**
 * @brief Destruct and free pwnagotchi
 * 
 * @param pwn Pwnagotchi to destruct
 */
void pwnagotchi_free(Pwnagotchi* pwn);

/**
 * Draw the default display with no additional information provided
 * 
 * @param pwn Pwnagotchi device to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_blank(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw the stored pwnagotchi's face on the device
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_face(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw the name of the pwnagotchi
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_name(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw channel on pwnagotchi
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_channel(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw aps on pwnagotchi
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_aps(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw uptime on pwnagotchi
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_uptime(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw lines on pwnagotchi
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_lines(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw friend of pwnagotchi on screen
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_friend(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw current mode of pwnagotchi
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_mode(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw the number of handshakes in the PWND portion as well as the last handshake
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_handshakes(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Draw the message that the pwnagotchi is showing on the screen
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_message(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Runs all drawing functions to update the screen completely
 * 
 * @param pwn Pwnagotchi to draw
 * @param canvas Canvas to draw on
 */
void pwnagotchi_draw_all(Pwnagotchi* pwn, Canvas* canvas);

/**
 * Clears the screen buffer of the pwnagotchi
 * 
 * @param pwn Pwn to clear
 */
void pwnagotchi_screen_clear(Pwnagotchi* pwn);
