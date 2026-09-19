#pragma once

#include <storage/storage.h>
#include <stdint.h>
#include <stdbool.h>

// Where captured handshake pcaps land, one file per target (<ssid_or_bssid>.pcap).
#define PWNFRIEND_HS_DIR "/ext/apps_data/pwnfriend/handshakes"

// LINKTYPE_IEEE802_11: bare 802.11 frames, no radiotap. Matches Marauder's own
// pcap byte-for-byte, so aircrack-ng / hcxpcapngtool / tshark all read it.
#define PCAP_LINKTYPE_IEEE802_11 105
#define PCAP_SNAPLEN 4096

// Append one raw 802.11 frame to <dir>/<name>.pcap, writing the 24-byte classic
// pcap global header first if the file is new/empty. Open-append-close per frame
// so a yank mid-capture leaves a valid, growing pcap. Returns false on error.
bool pcap_append_frame(Storage* storage, const char* name, const uint8_t* frame, uint16_t len);
