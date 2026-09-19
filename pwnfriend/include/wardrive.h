#pragma once

#include <storage/storage.h>
#include <stdint.h>
#include <stdbool.h>

// WiGLE-importable wardrive log. One CSV, appended a row per geotagged AP/PWND.
// Lives beside the persona so everything the app writes is under one data dir.
#define PWNFRIEND_WARDRIVE_DIR "/ext/apps_data/pwnfriend"
#define PWNFRIEND_WARDRIVE_PATH PWNFRIEND_WARDRIVE_DIR "/wardrive.csv"

// Append one WiGLE-1.4 row. `lat`/`lon` are the verbatim decimal-degree strings
// straight out of the firmware JSON (we never parse them to float — the Flipper
// printf has float disabled), so they must be non-empty. On a brand-new/empty
// file the pre-header + column header are written first. Returns false on error.
bool wardrive_log(
    Storage* storage,
    const char* mac, // "aa:bb:cc:dd:ee:ff"
    const char* ssid, // may be empty
    const char* auth, // AuthMode capabilities string
    int channel,
    int rssi,
    const char* lat,
    const char* lon);
