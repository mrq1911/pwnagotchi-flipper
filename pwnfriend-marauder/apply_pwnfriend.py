#!/usr/bin/env python3
"""Add the `pwnfriend` command to an ESP32 Marauder checkout.

Anchored, idempotent source surgery (automated PATCH.md): finds quoted anchor
strings and inserts our hooks, aborting loudly if an anchor is missing.

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

    # 0. copy the module in; bake our short commit into pwnfriend_commit.h (fw=<hash> on PWNFRIEND_ADV).
    import subprocess
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(HERE), "rev-parse", "--short=7", "HEAD"], text=True).strip()
    except Exception:
        commit = "nogit"
    (HERE / "pwnfriend_commit.h").write_text(
        '#pragma once\n#define PWNFRIEND_FW_COMMIT "%s"\n' % commit)
    print(f"  fw commit: {commit}")

    for name in ("Pwnfriend.h", "Pwnfriend.cpp", "pwnfriend_frames.h", "pwnfriend_commit.h"):
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

    # 3. WiFiScan.cpp — include, runner, dispatch, sniff-report, main() tick, sniffer guard.
    p = src / "WiFiScan.cpp"
    t = _read(p)

    t, d = insert_after(
        t, '#include "WiFiScan.h"',
        '#include "Pwnfriend.h"\nextern Pwnfriend pwnfriend_obj;\n',
        tag="extern Pwnfriend pwnfriend_obj;")
    steps += d

    runner = '''void WiFiScan::RunPwnfriendScan(uint8_t scan_mode, uint16_t color) {
  (void)scan_mode; (void)color;
  // Real scan start: clear the per-session capture dedup tables here (NOT in
  // configureFromArgs, which the Flipper re-runs every ~15s to refresh the
  // persona) so a persona refresh doesn't re-count pwnd APs / inflate pwnd_tot.
  pwnfriend_obj.beginSession();
  startPcap("pwnfriend");
  // Mirror Marauder's beacon-attack TX init EXACTLY. The AP config
  // (esp_wifi_set_config) is REQUIRED: without it the AP iface never fully
  // comes up and esp_wifi_80211_tx(WIFI_IF_AP) silently radiates nothing
  // (verified on-air: 0 frames). Promiscuous rx is layered on so the friend
  // still sniffs peers while broadcasting.
  ap_config.ap.ssid_hidden = 1;
  ap_config.ap.beacon_interval = 10000;
  ap_config.ap.ssid_len = 0;
  packets_sent = 0;
  esp_wifi_init(&cfg);
  #ifdef HAS_IDF_3
    esp_wifi_set_country(&country);
  #endif
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_set_config(WIFI_IF_AP, &ap_config);
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

    # broadcast on every main() tick in pwnfriend mode, skip the rest. also feed the GPS
    # fix status through so the friend can emit PWNFRIEND_GPS (throttled inside reportGps).
    t, d = insert_after(
        t,
        "void WiFiScan::main(uint32_t currentTime)\n{",
        "  if (currentScanMode == WIFI_SCAN_PWNFRIEND) {\n"
        "    #ifdef HAS_GPS\n"
        "      static bool pf_gps_probed = false;\n"
        "      if (!pf_gps_probed) {\n"
        "        pf_gps_probed = true;  // one read-only capability probe per boot\n"
        "        pwnfriend_obj.reportGpsCaps(gps_obj.probeReport().c_str());\n"
        "      }\n"
        "    #endif\n"
        "    if (currentTime - initTime >= 500) {\n"
        "      initTime = millis();\n"
        "      pwnfriend_obj.broadcast();\n"
        "      #ifdef HAS_GPS\n"
        "        pwnfriend_obj.reportGps(gps_obj.getFixStatus(), gps_obj.getNumSats(),\n"
        "                                gps_obj.getAccuracy(), gps_obj.getLat().c_str(),\n"
        "                                gps_obj.getLon().c_str());\n"
        "      #endif\n"
        "    }\n"
        "    return;\n"
        "  }\n",
        tag="pwnfriend_obj.broadcast();")
    steps += d

    # let the sniffer callback process our mode and branch to reportPeer.
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
        "          if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND) {\n"
        "            #ifdef HAS_GPS\n"
        "              bool pf_fix = gps_obj.getFixStatus() && gps_obj.getNumSats() >= 4;\n"
        "              double pf_lat = pf_fix ? atof(gps_obj.getLat().c_str()) : 0.0;\n"
        "              double pf_lon = pf_fix ? atof(gps_obj.getLon().c_str()) : 0.0;\n"
        "            #else\n"
        "              bool pf_fix = false; double pf_lat = 0.0; double pf_lon = 0.0;\n"
        "            #endif\n"
        "            pwnfriend_obj.reportPeer(snifferPacket->payload, len, "
        "snifferPacket->rx_ctrl.rssi, snifferPacket->rx_ctrl.channel, pf_fix, pf_lat, pf_lon);\n"
        "          } else\n"
        "            wifi_scan_obj.processPwnagotchiBeacon(snifferPacket->payload, len);",
        tag="pwnfriend_obj.reportPeer(")
    steps += d

    # 3b. capture path: EAPOL/PMKID come as DATA frames; beaconSnifferCallback only handles
    # MGMT, so handle pwnfriend DATA first and append EAPOL to the pcap. len here is still
    # rx_ctrl.sig_len (correct for DATA).
    t, d = insert_before(
        t,
        "  if ((wifi_scan_obj.currentScanMode == WIFI_SCAN_PROBE) ||",
        "  if ((wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND) &&\n"
        "      (type == WIFI_PKT_DATA)) {\n"
        "    #ifdef HAS_GPS\n"
        "      bool pf_fix = gps_obj.getFixStatus() && gps_obj.getNumSats() >= 4;\n"
        "      double pf_lat = pf_fix ? atof(gps_obj.getLat().c_str()) : 0.0;\n"
        "      double pf_lon = pf_fix ? atof(gps_obj.getLon().c_str()) : 0.0;\n"
        "    #else\n"
        "      bool pf_fix = false; double pf_lat = 0.0; double pf_lon = 0.0;\n"
        "    #endif\n"
        "    // Harvest the client station from every DATA frame so active mode can\n"
        "    // UNICAST-deauth it (broadcast deauth is ignored by modern clients).\n"
        "    pwnfriend_obj.reportClient(snifferPacket->payload, len);\n"
        "    if (pwnfriend_obj.reportHandshake(snifferPacket->payload, len,\n"
        "                                      snifferPacket->rx_ctrl.rssi,\n"
        "                                      snifferPacket->rx_ctrl.channel,\n"
        "                                      pf_fix, pf_lat, pf_lon))\n"
        "      buffer_obj.append(snifferPacket, len);\n"
        "    return;\n"
        "  }\n",
        tag="pwnfriend_obj.reportHandshake(")
    steps += d

    # 3c. recon: dedup non-pwngrid beacons into PWNFRIEND_AP lines. sits inside
    # if(type==MGMT)->if(payload[0]==0x80) after the pwngrid mac_match return, so peers
    # never reach it. len here is FCS-stripped (-4).
    t, d = insert_before(
        t,
        "        if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWN) {",
        "        if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND) {\n"
        "          #ifdef HAS_GPS\n"
        "            bool pf_fix = gps_obj.getFixStatus() && gps_obj.getNumSats() >= 4;\n"
        "            double pf_lat = pf_fix ? atof(gps_obj.getLat().c_str()) : 0.0;\n"
        "            double pf_lon = pf_fix ? atof(gps_obj.getLon().c_str()) : 0.0;\n"
        "          #else\n"
        "            bool pf_fix = false; double pf_lat = 0.0; double pf_lon = 0.0;\n"
        "          #endif\n"
        "          if (pwnfriend_obj.reportAP(snifferPacket->payload, len,\n"
        "                                     snifferPacket->rx_ctrl.rssi,\n"
        "                                     snifferPacket->rx_ctrl.channel,\n"
        "                                     pf_fix, pf_lat, pf_lon))\n"
        "            buffer_obj.append(snifferPacket, len);\n"
        "          return;\n"
        "        }\n",
        tag="pwnfriend_obj.reportAP(")
    steps += d
    _write(p, t)

    # 3d. GPS: drop the per-boot $PSTMSRR reset in GpsInterface::begin(). resetting the
    # Teseo GNSS engine on every power-up throws away a backup-powered hot start and slows
    # TTFF; the constellation mask still persists via SAVEPAR, so the reset is redundant.
    # tolerant: some Marauder bases don't send PSTM commands at all.
    p = src / "GpsInterface.cpp"
    if p.exists():
        t = _read(p)
        try:
            t, d = replace_once(
                t,
                '  MicroNMEA::sendSentence(Serial2, "$PSTMSRR");',
                "  // pwnfriend: no per-boot $PSTMSRR reset -- restarting the GNSS engine every\n"
                "  // boot discards a backup-powered hot start and slows TTFF. the mask set above\n"
                "  // persists in NVM via SAVEPAR; a reset is only needed to *change* it.",
                tag="pwnfriend: no per-boot $PSTMSRR")
            _write(p, t); steps += d
        except AnchorError:
            print("  note: $PSTMSRR absent in GpsInterface.cpp; skipped GPS-reset patch")

    # 3e. GPS: read-only capability probe. sends $PSTMGETSWVER/$PSTMGETPAR (queries, never a
    # write) and collects the module's $PSTM replies for ~1.4s so we can see which Teseo
    # firmware / STAGPS support / constellation mask it has. tolerant of Marauder bases.
    ph = src / "GpsInterface.h"
    if p.exists() and ph.exists():
        th = _read(ph)
        th, dh = insert_after(
            th, "String getNmeaNotparsed();",
            "    String probeReport();  // pwnfriend: read-only $PSTM capability query\n",
            tag="String probeReport();")
        _write(ph, th); steps += dh

        t = _read(p)
        probe = '''
// pwnfriend: read-only GPS capability probe. sends version/param QUERIES only (no SETPAR/
// SAVEPAR, so nothing is written to the module) and gathers the $PSTM replies for a short
// window. returns them '|'-joined, or a marker when the module is silent/absent.
String GpsInterface::probeReport() {
  if (!this->gps_enabled) return String("no-gps-module");
  uint32_t t0 = millis();
  while (Serial2.available() && millis() - t0 < 200) Serial2.read();  // drop backlog
  const char* queries[] = { "$PSTMGETSWVER,255", "$PSTMGETPAR,1201" };
  String out, cur;
  for (unsigned q = 0; q < 2; q++) {
    MicroNMEA::sendSentence(Serial2, queries[q]);
    uint32_t start = millis();
    while (millis() - start < 700) {
      while (Serial2.available()) {
        char c = (char)Serial2.read();
        if (c == '\\r' || c == '\\n') {
          if (cur.startsWith("$PSTM")) { if (out.length()) out += '|'; out += cur; }
          cur = "";
        } else if (cur.length() < 140) cur += c;
      }
    }
  }
  return out.length() ? out : String("no-pstm-reply");
}
'''
        t, dc = insert_after(
            t,
            "String GpsInterface::getNmeaNotparsed() {\n"
            "  return this->notparsed_nmea_sentence;\n"
            "}",
            probe, tag="String GpsInterface::probeReport()")
        _write(p, t); steps += dc

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
      } else if (wifi_scan_obj.currentScanMode == WIFI_SCAN_PWNFRIEND) {
        // Already running: configureFromArgs() already refreshed + rebuilt the
        // persona. Do NOT StartScan again -- that would tear down/re-init WiFi,
        // wipe recon, and reset the channel hop. The ~15s command re-send is
        // only a live persona update.
        Serial.println(F("pwnfriend persona updated"));
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
