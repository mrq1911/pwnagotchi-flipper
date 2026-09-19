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

// FLIPPER_SCREEN_WIDTH / _HEIGHT come from pwn_constants.h (via pwnagotchi.h).
