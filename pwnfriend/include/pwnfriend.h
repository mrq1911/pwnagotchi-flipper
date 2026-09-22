#pragma once

#include <furi_hal.h>

// serial link to the ESP32 board; same USART/baud as Marauder's CLI, no rewiring
#define PWNFRIEND_UART_CHANNEL FuriHalSerialIdUsart
#define PWNFRIEND_UART_BAUD 115200

// secs between persona re-pushes to the ESP32 so its beacon reflects growing counts
#define PWNFRIEND_ADV_RESEND_SECS 15

// secs between persona saves to SD
#define PWNFRIEND_SAVE_SECS 30

// ESP32-absence: board sends PWNFRIEND_ADV ~2x/sec; silence for LINK_TIMEOUT after
// LINK_GRACE (covers boot + StartScan) warns the user
#define PWNFRIEND_LINK_TIMEOUT_SECS 5
#define PWNFRIEND_LINK_GRACE_SECS 10

// setup link QR'd on the "no ESP32" screen; <=53 bytes so the QR stays version-3 (29x29) at 2px/module
#define PWNFRIEND_SETUP_URL "https://github.com/mrq1911/pwnagotchi-flipper"

// serial-proto version this app expects (mirrors firmware PWNFRIEND_PROTO). firmware stamps
// ver=N on each PWNFRIEND_ADV; non-zero but below this -> board too old, warn the user
#define PWNFRIEND_FW_PROTO 5

// FLIPPER_SCREEN_WIDTH / _HEIGHT come from pwn_constants.h (via pwnagotchi.h).
