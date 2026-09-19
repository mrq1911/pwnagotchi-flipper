# Adding `pwnfriend` to ESP32 Marauder

`Pwnfriend.{h,cpp}` are self-contained. To wire them into a Marauder build you drop
both files into `esp32_marauder/` and make six small edits to existing files. Line
numbers below are approximate (they drift between Marauder releases) — search for the
quoted anchor text instead.

Tested against the `esp32_marauder` layout as of ESP32Marauder 2025. The additions do
not touch any existing behaviour; `sniffpwn` etc. keep working unchanged.

---

## 0. Copy the module

```
cp pwnfriend-marauder/Pwnfriend.h   <marauder>/esp32_marauder/
cp pwnfriend-marauder/Pwnfriend.cpp <marauder>/esp32_marauder/
```

Marauder already vendors `ArduinoJson` and `LinkedList`, which the module uses.

---

## 1. `esp32_marauder.ino` — instantiate the broadcaster

Near the other global objects (e.g. `WiFiScan wifi_scan_obj;`), add:

```cpp
#include "Pwnfriend.h"
Pwnfriend pwnfriend_obj;
```

and add `extern Pwnfriend pwnfriend_obj;` wherever the other `extern ... _obj;`
declarations live (typically `configs.h` or the top of `WiFiScan.cpp`).

---

## 2. `WiFiScan.h` — new scan mode

Alongside `#define WIFI_SCAN_PWN 3` add an unused id, e.g.:

```cpp
#define WIFI_SCAN_PWNFRIEND 111
```

and declare the runner next to `RunPwnScan`:

```cpp
void RunPwnfriendScan(uint8_t scan_mode, uint16_t color);
```

---

## 3. `WiFiScan.cpp` — the runner (copy of RunPwnScan)

Right after `WiFiScan::RunPwnScan`, add:

```cpp
void WiFiScan::RunPwnfriendScan(uint8_t scan_mode, uint16_t color) {
  (void)scan_mode; (void)color;
  startPcap("pwnfriend");
  esp_wifi_init(&cfg2);
  #ifdef HAS_IDF_3
    esp_wifi_set_country(&country);
    esp_event_loop_create_default();
  #endif
  // AP mode + promiscuous: AP is the interface Marauder's own beacon TX uses
  // (esp_wifi_80211_tx on WIFI_IF_AP actually radiates; STA-mode TX silently
  // dropped frames), and promiscuous rx still fires for sniffing peers.
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_start();
  this->setMac();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&beaconSnifferCallback);
  this->changeChannel(this->set_channel);
  this->wifi_initialized = true;
  initTime = millis();
}
```

(Names like `filt`, `cfg2`, `setMac`, `beaconSnifferCallback` come straight from the
fork's own `RunPwnScan`, so they resolve wherever that does.)

---

## 4. `WiFiScan.cpp` — dispatch in `StartScan`

Next to `else if (scan_mode == WIFI_SCAN_PWN) RunPwnScan(scan_mode, color);` add:

```cpp
else if (scan_mode == WIFI_SCAN_PWNFRIEND)
  RunPwnfriendScan(scan_mode, color);
```

---

## 5. `WiFiScan.cpp` — sniff + broadcast in `main()`

Add `WIFI_SCAN_PWNFRIEND` to the mode list at the top of `WiFiScan::main` that does the
channel-hop block (the `if ((currentScanMode == WIFI_SCAN_PROBE) || ... )`), then hang
the broadcast off the same tick:

```cpp
else if (currentScanMode == WIFI_SCAN_PWNFRIEND) {
  if (millis() - initTime >= 500) {   // ~pwngrid signaling cadence
    initTime = millis();
    pwnfriend_obj.broadcast();        // hops channel + sends the friend beacon
  }
}
```

Broadcasting itself steps the channel, so no separate `channelHop()` is needed here.

Also add `WIFI_SCAN_PWNFRIEND` to the big `currentScanMode == ...` guard around line
2990 (the one that gates the promiscuous beacon path) and to any `scanning`/`sniffing`
predicate you want it treated as an active scan by (so `stopscan` and the status UI see
it). Search for `WIFI_SCAN_PWN` and mirror each occurrence.

---

## 6. `WiFiScan.cpp` — report sniffed peers

In `beaconSnifferCallback`, where a matched pwngrid MAC currently calls
`processPwnagotchiBeacon`, branch for our mode so we emit the structured
`PWNFRIEND_PEER` line (which carries rssi + channel that `processPwnagotchiBeacon`
doesn't have):

```cpp
if (mac_match) {
  if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND)
    pwnfriend_obj.reportPeer(snifferPacket->payload, len,
                             snifferPacket->rx_ctrl.rssi,
                             snifferPacket->rx_ctrl.channel);
  else
    wifi_scan_obj.processPwnagotchiBeacon(snifferPacket->payload, len);
  return;
}
```

Make sure the outer `if ((currentScanMode == WIFI_SCAN_PROBE) || ... )` that wraps the
mgmt-frame branch also includes `WIFI_SCAN_PWNFRIEND`, otherwise the callback returns
before reaching this code.

---

## 6b. `WiFiScan.cpp` — capture EAPOL/PMKID (DATA frames)

The promiscuous filter already passes DATA (`WiFiScan.h`: `filt = MGMT | DATA`), but
`beaconSnifferCallback` only ever acts on `WIFI_PKT_MGMT`. To capture handshakes we
add a DATA-frame branch **before** the mgmt-only dispatch `if`, i.e. immediately
before the line

```cpp
if ((wifi_scan_obj.currentScanMode == WIFI_SCAN_PROBE) ||
```

insert:

```cpp
if ((wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND) &&
    (type == WIFI_PKT_DATA)) {
  if (pwnfriend_obj.reportHandshake(snifferPacket->payload, len,
                                    snifferPacket->rx_ctrl.rssi,
                                    snifferPacket->rx_ctrl.channel))
    buffer_obj.append(snifferPacket, len);
  return;
}
```

`len` here is still `rx_ctrl.sig_len` (the mgmt path decrements it by 4 only inside the
`WIFI_PKT_MGMT` block), so DATA frames get their full length. `reportHandshake` detects
an EAPOL M2 (→ `type:"handshake"`) or an RSN PMKID KDE in M1 (→ `type:"pmkid"`), dedups
per BSSID for the session, and emits `PWNFRIEND_PWND`. It also streams the full frame to
the Flipper as `PWNFRIEND_HS <lowercase-hex>` (the Flipper reassembles those into a pcap;
raw binary would trip the serial CLI's CR/XON handling), and returns true for **any**
EAPOL frame so the caller also appends it to the on-board pcap if the ESP32 has an SD.

## 6c. `WiFiScan.cpp` — recon non-pwngrid beacons

Inside the beacon branch (`payload[0] == 0x80`, after the pwngrid `mac_match` return),
immediately **before**

```cpp
if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWN) {
```

insert:

```cpp
if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND) {
  if (pwnfriend_obj.reportAP(snifferPacket->payload, len,
                             snifferPacket->rx_ctrl.rssi,
                             snifferPacket->rx_ctrl.channel))
    buffer_obj.append(snifferPacket, len);
  return;
}
```

`len` here is already FCS-stripped (`-4`), fine for SSID parsing. `reportAP` dedups each
non-pwngrid AP into one `PWNFRIEND_AP` line per BSSID and stores it (BSSID + ESSID +
channel) so the deauth tick and the `PWNFRIEND_PWND` SSID lookup have it. The stored
channel is also what the `-deauth` opt-in uses: `broadcast()` only deauths recon'd APs
on the channel it is currently parked on, and only when the persona's `-deauth` flag is
set (default off). No filter change is needed — `filt` already passes DATA.

---

## 7. `CommandLine.cpp` / `CommandLine.h` — the command

In `CommandLine.h`, next to `SNIFF_PWN_CMD`:

```cpp
const char PROGMEM PWNFRIEND_CMD[] = "pwnfriend";
```

In `CommandLine.cpp`'s command dispatch (next to the `SNIFF_PWN_CMD` handler):

```cpp
else if (cmd_args.get(0) == PWNFRIEND_CMD) {
  if (!pwnfriend_obj.configureFromArgs(&cmd_args)) {
    Serial.println(F("PWNFRIEND_ERR bad -id (need 64 hex)"));
  } else {
    Serial.print(F("Starting pwnfriend. Stop with "));
    Serial.println(STOPSCAN_CMD);
    wifi_scan_obj.StartScan(WIFI_SCAN_PWNFRIEND, TFT_MAGENTA);
  }
}
```

Add `#include "Pwnfriend.h"` and `extern Pwnfriend pwnfriend_obj;` at the top of
`CommandLine.cpp` if not already visible.

---

## Using it directly (without the Flipper app)

Over the board's serial CLI at 115200:

```
pwnfriend -n lonelybot -id 3b1e9f...<64 hex>...2a -f 21 -pr 0 -pt 7 -u 3600
```

Your Pwnagotchi should, within a hop cycle or two, flip to a friendly face and announce
"Hello lonelybot! Nice to meet you." Stop with `stopscan`.

The Flipper `pwnfriend` app drives exactly this command for you and manages the persona,
so you normally never type it by hand.
