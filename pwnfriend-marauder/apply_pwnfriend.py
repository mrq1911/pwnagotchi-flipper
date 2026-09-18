#!/usr/bin/env python3
"""Add the `pwnfriend` command to an ESP32 Marauder checkout.

Anchored, idempotent source surgery — the automated form of PATCH.md. It finds
quoted anchor strings (which survive line-number drift between Marauder releases
and forks) and inserts our hooks. If an anchor is missing it aborts loudly, so a
CI build fails clearly instead of producing a broken firmware.

Usage:
    python3 apply_pwnfriend.py /path/to/marauder            # dir with esp32_marauder/
    python3 apply_pwnfriend.py /path/to/marauder/esp32_marauder

Verified against justcallmekoko/ESP32Marauder and bpmcircuits/ESP32Marauder_FEBERIS.
"""

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


class AnchorError(SystemExit):
    pass


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="surrogateescape")


def _write(p: Path, s: str) -> None:
    p.write_text(s, encoding="utf-8", errors="surrogateescape")


def insert_after(text, anchor, addition, tag):
    """Insert `addition` immediately after the line that ends the `anchor` match.

    The anchor may span multiple lines; we anchor to the end of the whole match,
    not its first newline, so a `sig\\n{` anchor inserts after the `{`.
    """
    if tag in text:
        return text, False  # already applied
    idx = text.find(anchor)
    if idx == -1:
        raise AnchorError(f"anchor not found: {anchor!r}")
    anchor_end = idx + len(anchor)
    line_end = text.find("\n", anchor_end)
    if line_end == -1:
        line_end = len(text)
    return text[: line_end + 1] + addition + text[line_end + 1 :], True


def insert_before(text, anchor, addition, tag):
    """Insert `addition` immediately before the line containing `anchor`."""
    if tag in text:
        return text, False
    idx = text.find(anchor)
    if idx == -1:
        raise AnchorError(f"anchor not found: {anchor!r}")
    line_start = text.rfind("\n", 0, idx) + 1
    return text[:line_start] + addition + text[line_start:], True


def replace_once(text, old, new, tag):
    if tag in text:
        return text, False
    if old not in text:
        raise AnchorError(f"replace target not found: {old!r}")
    return text.replace(old, new, 1), True


def find_src(root: Path) -> Path:
    if (root / "esp32_marauder.ino").exists():
        return root
    sub = root / "esp32_marauder"
    if (sub / "esp32_marauder.ino").exists():
        return sub
    raise SystemExit(f"could not find esp32_marauder.ino under {root}")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    src = find_src(Path(sys.argv[1]).resolve())
    print(f"patching Marauder at {src}")

    # 0. Copy the module in.
    for name in ("Pwnfriend.h", "Pwnfriend.cpp"):
        shutil.copy2(HERE / name, src / name)
        print(f"  copied {name}")

    steps = 0

    # 1. esp32_marauder.ino — declare the global object.
    p = src / "esp32_marauder.ino"
    t = _read(p)
    t, done = insert_after(
        t,
        "WiFiScan wifi_scan_obj;",
        '#include "Pwnfriend.h"\nPwnfriend pwnfriend_obj;\n',
        tag="Pwnfriend pwnfriend_obj;",
    )
    _write(p, t); steps += done

    # 2. WiFiScan.h — scan-mode id + runner declaration.
    p = src / "WiFiScan.h"
    t = _read(p)
    t, d1 = insert_after(
        t, "#define WIFI_SCAN_PWN ", "#define WIFI_SCAN_PWNFRIEND 111\n",
        tag="WIFI_SCAN_PWNFRIEND")
    t, d2 = insert_after(
        t, "void RunPwnScan(uint8_t scan_mode, uint16_t color);",
        "    void RunPwnfriendScan(uint8_t scan_mode, uint16_t color);\n",
        tag="RunPwnfriendScan")
    _write(p, t); steps += d1 + d2

    # 3. WiFiScan.cpp — include, runner, dispatch, sniff-report, main() tick,
    #    and the outer sniffer guard.
    p = src / "WiFiScan.cpp"
    t = _read(p)

    t, d = insert_after(
        t, '#include "WiFiScan.h"',
        '#include "Pwnfriend.h"\nextern Pwnfriend pwnfriend_obj;\n',
        tag="extern Pwnfriend pwnfriend_obj;")
    steps += d

    runner = '''void WiFiScan::RunPwnfriendScan(uint8_t scan_mode, uint16_t color) {
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

'''
    t, d = insert_before(
        t, "void WiFiScan::RunPwnScan(uint8_t scan_mode, uint16_t color)",
        runner, tag="RunPwnfriendScan(uint8_t")
    steps += d

    t, d = insert_after(
        t,
        "    RunPwnScan(scan_mode, color);",
        "  else if (scan_mode == WIFI_SCAN_PWNFRIEND)\n"
        "    RunPwnfriendScan(scan_mode, color);\n",
        tag="RunPwnfriendScan(scan_mode, color);")
    steps += d

    # Broadcast on every main() tick while in pwnfriend mode (and skip the rest,
    # since broadcast() hops channels itself and the rx callback reports peers).
    t, d = insert_after(
        t,
        "void WiFiScan::main(uint32_t currentTime)\n{",
        "  if (currentScanMode == WIFI_SCAN_PWNFRIEND) {\n"
        "    if (currentTime - initTime >= 500) {\n"
        "      initTime = millis();\n"
        "      pwnfriend_obj.broadcast();\n"
        "    }\n"
        "    return;\n"
        "  }\n",
        tag="pwnfriend_obj.broadcast();")
    steps += d

    # Let the sniffer callback process our mode, and branch to reportPeer.
    t, d = replace_once(
        t,
        "      (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWN)) {",
        "      (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWN) ||\n"
        "      (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND)) {",
        tag="WIFI_SCAN_PWNFRIEND)) {")
    steps += d

    t, d = replace_once(
        t,
        "          wifi_scan_obj.processPwnagotchiBeacon(snifferPacket->payload, len);",
        "          if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND)\n"
        "            pwnfriend_obj.reportPeer(snifferPacket->payload, len, "
        "snifferPacket->rx_ctrl.rssi, snifferPacket->rx_ctrl.channel);\n"
        "          else\n"
        "            wifi_scan_obj.processPwnagotchiBeacon(snifferPacket->payload, len);",
        tag="pwnfriend_obj.reportPeer(")
    steps += d
    _write(p, t)

    # 4. CommandLine.h — the command string.
    p = src / "CommandLine.h"
    t = _read(p)
    t, d = insert_after(
        t, 'const char PROGMEM SNIFF_PWN_CMD[] = "sniffpwn";',
        'const char PROGMEM PWNFRIEND_CMD[] = "pwnfriend";\n',
        tag="PWNFRIEND_CMD")
    _write(p, t); steps += d

    # 5. CommandLine.cpp — include + command handler.
    p = src / "CommandLine.cpp"
    t = _read(p)
    t, d1 = insert_after(
        t, '#include "CommandLine.h"',
        '#include "Pwnfriend.h"\nextern Pwnfriend pwnfriend_obj;\n',
        tag="extern Pwnfriend pwnfriend_obj;")
    handler = '''    else if (cmd_args.get(0) == PWNFRIEND_CMD) {
      if (!pwnfriend_obj.configureFromArgs(&cmd_args)) {
        Serial.println(F("PWNFRIEND_ERR bad -id (need 64 hex)"));
      } else {
        Serial.print(F("Starting pwnfriend. Stop with "));
        Serial.println(STOPSCAN_CMD);
        wifi_scan_obj.StartScan(WIFI_SCAN_PWNFRIEND, TFT_MAGENTA);
      }
    }
'''
    t, d2 = insert_before(
        t, "    else if (cmd_args.get(0) == SNIFF_PWN_CMD) {",
        handler, tag="cmd_args.get(0) == PWNFRIEND_CMD")
    _write(p, t); steps += d1 + d2

    print(f"done ({steps} insertion(s) applied; already-applied steps skipped)")


if __name__ == "__main__":
    main()
