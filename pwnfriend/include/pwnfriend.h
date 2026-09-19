#pragma once

#include <furi_hal.h>

// Serial link to the ESP32 board (official Wi-Fi Dev Board or Feberis Pro). Same
// USART/baud Marauder's CLI uses, so no rewiring is needed.
#define PWNFRIEND_UART_CHANNEL FuriHalSerialIdUsart
#define PWNFRIEND_UART_BAUD 115200

// How often (seconds) we re-push the persona to the ESP32 while advertising, so
// its beacon reflects our growing uptime / friend counts.
#define PWNFRIEND_ADV_RESEND_SECS 15

// How often (seconds) we persist the persona to SD.
#define PWNFRIEND_SAVE_SECS 30

// ESP32-absence detection. The board answers with PWNFRIEND_ADV ~2x/sec while
// advertising; if we hear nothing for LINK_TIMEOUT after having advertised at
// least LINK_GRACE (covers the board's boot + StartScan), we warn the user.
#define PWNFRIEND_LINK_TIMEOUT_SECS 5
#define PWNFRIEND_LINK_GRACE_SECS 10

// The setup link shown as a QR on the "no ESP32" screen: which boards work + how
// to flash. Kept <=53 bytes so the QR stays version-3 (29x29) at 2px/module.
#define PWNFRIEND_SETUP_URL "https://github.com/mrq1911/pwnagotchi-flipper"

// FLIPPER_SCREEN_WIDTH / _HEIGHT come from pwn_constants.h (via pwnagotchi.h).
