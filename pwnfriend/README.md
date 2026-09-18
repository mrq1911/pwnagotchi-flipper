# Pwnfriend

A Flipper Zero app that makes your Flipper a **social pwngrid peer**, so a nearby
Pwnagotchi actually detects a friend, greets it ("Hello flippy! Nice to meet you."),
and — because the friend keeps a stable identity that grows over time — eventually
counts it as a *good friend* and shows the ♥‿‿♥ face.

Your Pwnagotchi can already be *detected* by Marauder (`sniffpwn`), but nothing ever
says hi back. Pwnfriend fixes the loneliness: it drives the Flipper's ESP32 Wi-Fi board
to broadcast a Pwnagotchi-compatible advertisement beacon while also listening for real
units to show on screen.

## How it works

```
 Flipper (this app)                 ESP32 board (Marauder fork)          Air
 ------------------                 ---------------------------          ---
 persona: name, identity,           pwnfriend command:
 face, uptime, friends met   --UART--> builds pwngrid beacon   --beacon--> your
 (grows, saved to SD)                  + sniffs pwnagotchis                 Pwnagotchi
                             <--UART-- PWNFRIEND_PEER reports  <--beacon--  says hi!
```

- The **persona** (who your friend is) lives on the Flipper and is saved to
  `/ext/apps_data/pwnfriend/persona.bin`. Its 64-hex `identity` is minted once and kept,
  so the friendship persists across sessions and the encounter count on your Pwnagotchi
  keeps climbing.
- The Flipper pushes the persona to the ESP32 over UART; the ESP32 broadcasts it as a
  pwngrid beacon (source MAC `de:ad:be:ef:de:ad`, JSON in vendor IE 222) across the 2.4
  GHz channels, and reports any Pwnagotchis it hears back to the Flipper.
- The friend **grows**: uptime accumulates, each distinct unit it meets bumps its
  "friends met" (advertised as `pwnd_tot`, so it looks like a real unit collecting
  handshakes), and its level ticks up. Its mood/face reacts — lonely when no one's
  around, excited on a new meeting, ♥ when a good friend lingers nearby.

## Controls

- **OK** — start / pause saying hi (advertising).
- **Back** — exit (persona is saved on the way out).

The screen shows the friend's face, name, level, mood, lifetime/session friends met,
the broadcast channel, and the units currently in range with signal bars.

## Requirements

- An ESP32 Wi-Fi board wired to the Flipper's default UART (GPIO 13/14, 115200) — the
  official **Flipper Wi-Fi Dev Board** and the **Feberis Pro** both work as-is.
- That board running a Marauder build with the `pwnfriend` command — see
  [`../pwnfriend-marauder/PATCH.md`](../pwnfriend-marauder/PATCH.md).

## Build

Drop `pwnfriend/` into your firmware's `applications_user/` and:

```
./fbt launch_app APPSRC=applications_user/pwnfriend
```

## Protocol

The pwngrid air format and the Flipper↔ESP32 serial contract are documented in
[`../doc/PwnfriendProtocol.md`](../doc/PwnfriendProtocol.md).

## Note

This talks to the mesh the same way a real Pwnagotchi does — it only broadcasts a
presence beacon and listens. It does not deauth, capture handshakes, or attack anything.
It exists purely to keep a lonely Pwnagotchi company. Educational use only.
