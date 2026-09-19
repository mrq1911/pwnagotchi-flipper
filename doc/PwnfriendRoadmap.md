# Pwnfriend roadmap

The friend is being built in phases, cheapest-and-most-compatible first, so a lonely
pwnagotchi gets greeted today and the friend grows into a real unit over time.

## Phase 1 — Say hi, on hardware you already have (done)

Goal: your pwnagotchi detects a peer and greets it, with zero new hardware and minimal
new firmware.

- **`pwnfriend-marauder/`** — a `pwnfriend` command added to ESP32 Marauder (which ships
  on both the official Wi-Fi Dev Board and the Feberis Pro). Broadcasts a pwngrid
  advertisement beacon and reports sniffed pwnagotchis back over UART. Chosen because
  Marauder is already flashed on the user's boards — maximum compatibility.
- **`pwnfriend/`** — our own Flipper app. Owns the persona (name, stable identity, face,
  uptime, friends met), persists it to SD, drives the ESP32, and shows the friend + the
  units in range. The friend "levels up" from uptime and encounters.

At this phase `pwnd_tot` is a *social* score (distinct units met) — honest, but a
costume rather than earned handshakes.

## Phase 2 — Earn it for real (capture landed)

Goal: the friend's advertised stats are earned like a real pwnagotchi. Capture is now
**implemented** on top of the Phase 1 Marauder fork.

- **Passive capability (done)**: real AP scanning + channel hopping alongside the pwngrid
  mesh. Every AP seen is reported (`PWNFRIEND_AP`), driving the on-screen APS count.
- **Handshake / PMKID capture (done)**: the friend passively records WPA handshakes and
  RSN PMKIDs from networks in range and reports each as an earned `PWNFRIEND_PWND`, so
  `pwnd_run`/`pwnd_tot` are now **real captured-handshake counts**, not a social score.
  Frames are streamed as hex (`PWNFRIEND_HS`) and written to a crackable linktype-105
  pcap on the Flipper SD (`/ext/apps_data/pwnfriend/handshakes/`).
- **Opt-in deauth (done)**: an optional active deauth to speed a capture. **Off by
  default**, gated behind an explicit per-session opt-in; the `-deauth` flag is only sent
  when the user turns it on, and the friend then advertises `policy.deauth: true`.

  > ⚠️ Capture and deauth are only for networks you own or are explicitly authorized to
  > test. Both are off by default and gated behind an explicit opt-in. The rest of the
  > friend (presence, mesh, passive scan) needs none of it. Educational use only.

### Still remaining

- **Extract** the beacon/persona/capture logic out of the Marauder fork into a dedicated
  ESP32 firmware the project fully owns (no wrestling Marauder's scan-mode state machine,
  no rebase-on-every-release tax). The Marauder `pwnfriend` command stays as the
  lightweight "just say hi" option for people who only want that.
- **GPS-tagged captures** *(Feberis Pro has a GPS)*: log *where* the friend met each unit
  and caught each handshake, wardriving-style. Marauder already does this
  (`WIFI_SCAN_WAR_DRIVE`, `GpsInterface`, geofences), so the friend can record a little
  map of its social life and its catches. Same authorization caveat applies to captures;
  presence/meeting locations are benign.
- **AI brain**: a real mood/behaviour model driving channel choice and target selection
  from what it's seeing, instead of the current meeting-count heuristic — the piece that
  makes it feel like a pwnagotchi rather than a beacon with a face.
- The Flipper `pwnfriend` app remains the companion brain/display: it keeps owning the
  persona and rendering it, and gains richer views for captured handshakes and GPS trails.

## Build & test tooling (in-repo)

- **`tools/validate_beacon.py`** — runs the exact advertisement frame we build against
  every invariant pwngrid / Marauder / the Pwnagotchi enforce (identity regex, single-IE
  fit, MAC/offsets, required keys). We can't emulate the WiFi radio, but this proves the
  *frame* is correct without hardware. Run it before shipping any change to the beacon.
- **`pwnfriend-marauder/apply_pwnfriend.py`** — anchored, idempotent script that adds the
  `pwnfriend` command to a Marauder checkout (the automated form of `PATCH.md`).
- **`.github/workflows/build-pwnfriend.yml`** — CI that clones a Marauder fork, runs the
  patcher, and builds a flashable `.bin`, so "flash once, use both apps" needs no local
  Arduino toolchain. First run needs the Feberis chip/target confirmed.

## Phase 3 — Nice-to-haves

- Multiple personas / "reincarnation" on the same Flipper.
- Bond memory: remember specific units across sessions (persist met peers by identity)
  so reunions are recognized ("welcome back, kitty!").
- Face/animation parity with the flipagotchi renderer for a fuller on-screen life.
