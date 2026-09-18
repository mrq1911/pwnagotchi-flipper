#include "../include/face.h"

// Face bitmaps, compiled from assets/faces/*.png into this generated header by fbt.
#include "pwnfriend_icons.h"

void face_draw(Canvas* canvas, Face face, int x, int y) {
    const Icon* icon = NULL;

    switch(face) {
    case FaceDefault:
    case FaceAwake:
        icon = &I_awake_flipagotchi;
        break;
    case FaceLookR:
        icon = &I_look_r_flipagotchi;
        break;
    case FaceLookL:
        icon = &I_look_l_flipagotchi;
        break;
    case FaceLookRHappy:
        icon = &I_look_r_happy_flipagotchi;
        break;
    case FaceLookLHappy:
        icon = &I_look_l_happy_flipagotchi;
        break;
    case FaceSleep:
        icon = &I_sleep_flipagotchi;
        break;
    case FaceSleep2:
        icon = &I_sleep2_flipagotchi;
        break;
    case FaceBored:
        icon = &I_bored_flipagotchi;
        break;
    case FaceIntense:
        icon = &I_intense_flipagotchi;
        break;
    case FaceCool:
        icon = &I_cool_flipagotchi;
        break;
    case FaceHappy:
        icon = &I_happy_flipagotchi;
        break;
    case FaceGrateful:
        icon = &I_grateful_flipagotchi;
        break;
    case FaceExcited:
        icon = &I_excited_flipagotchi;
        break;
    case FaceMotivated:
        icon = &I_motivated_flipagotchi;
        break;
    case FaceDemotivated:
        icon = &I_demotivated_flipagotchi;
        break;
    case FaceSmart:
        icon = &I_smart_flipagotchi;
        break;
    case FaceLonely:
        icon = &I_lonely_flipagotchi;
        break;
    case FaceSad:
        icon = &I_sad_flipagotchi;
        break;
    case FaceAngry:
        icon = &I_angry_flipagotchi;
        break;
    case FaceFriend:
        icon = &I_friend_flipagotchi;
        break;
    case FaceBroken:
        icon = &I_broken_flipagotchi;
        break;
    case FaceDebug:
        icon = &I_debug_flipagotchi;
        break;
    case FaceUpload:
        icon = &I_upload_flipagotchi;
        break;
    case FaceUpload1:
        icon = &I_upload1_flipagotchi;
        break;
    case FaceUpload2:
        icon = &I_upload2_flipagotchi;
        break;
    case FaceNone:
    default:
        return;
    }

    canvas_draw_icon(canvas, x, y, icon);
}
