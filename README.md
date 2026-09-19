# Pwnagotchi-Flipper interface
This program will interface the pwnagotchi with the flipper. This will be accomplished using custom code on the pwnagotchi's end to give the flipper simple rendering instructions over UART.

<img src='doc/attachments/PwnZeroBaseWFace.png' alt='Flipper screen showing base Pwnagotchi display' height="128" width="256"/>
<img src="doc/attachments/PwnInAction.gif" width="256" height="160"/>

## Layout
```
pwnagotchi-flipper
 |--> flipagotchi/         Flipper-side app: renders a wired pwnagotchi's screen
 |--> pwnzero/             pwnagotchi-side plugin that feeds flipagotchi over UART
 |--> pwnfriend/           Flipper-side app: a social pwngrid peer (see below)
 |--> pwnfriend-marauder/  ESP32 Marauder fork bits that broadcast the friend beacon
```
- flipagotchi is the Flipper-side application
- pwnzero is the pwnagotchi-side application

## Pwnfriend: give your lonely pwnagotchi a friend

```
         _    __/\_______  _______
        / \  /  \_____   \/  ___  \
       /   \/    /  _/  _/     /  /
=-=-=-/         /   \   \     /  /=-=-=-
-=-=-/   /\  /\_\___/\   \____   \-=-=-=
    (___/  \/  <mrq>  \___)   \___)
```

A pwnagotchi gets sad when no other units are around. Marauder can already detect a
pwnagotchi's beacons, but it never answers — so your unit stays lonely. `pwnfriend` makes
the Flipper's ESP32 board broadcast a pwngrid-compatible advertisement so your pwnagotchi
detects a peer, says "Hello!", and (thanks to a stable, growing identity) befriends it
over time. The Flipper keeps a little persona that levels up the longer it runs and the
more units it meets.

> **✅ Fully Marauder-compatible.** pwnfriend ships as a small patch on top of ESP32
> Marauder, so the firmware you flash is a *complete Marauder build with the extra
> `pwnfriend` command added*. Flash the ESP32 **once** and you get **both**: the normal
> Marauder GUI / companion app **and** pwnfriend — nothing about stock Marauder is removed
> or broken. Your Flipper drives the pwnfriend brain over the same UART Marauder already uses.

See [`pwnfriend/README.md`](pwnfriend/README.md), which boards work + how to flash in
[`COMPATIBLE_HARDWARE.md`](COMPATIBLE_HARDWARE.md), the Marauder patch in
[`pwnfriend-marauder/PATCH.md`](pwnfriend-marauder/PATCH.md), and the wire format in
[`doc/PwnfriendProtocol.md`](doc/PwnfriendProtocol.md).

### Full pwnagotchi mode

Beyond just saying hi, the friend can now behave like a real pwnagotchi:

- **scans** APs and passively **captures** WPA handshakes / PMKIDs → earns **real** pwnd,
  and reacts with pwnagotchi moods and faces.
- **saves a crackable `.pcap` per network** on the Flipper SD
  (`/ext/apps_data/pwnfriend/handshakes/<bssid>.pcap`, linktype 105). Each file now carries
  the network's ESSID beacon plus its EAPOL/PMKID frames → feed it straight to hcxtools /
  hashcat (mode 22000) / aircrack-ng, no manual ESSID needed.
- **geotags** every sighting when a GPS is present (Feberis Pro) and writes a
  **WiGLE-importable** wardrive log (`/ext/apps_data/pwnfriend/wardrive.csv`).
- optional active **deauth** to speed a capture along.

> **⚠️ Authorized use only.** Handshake/PMKID capture and deauth are only legal on Wi-Fi
> networks you **own or are explicitly authorized to test**. They run a full pwnagotchi by
> default, but stay **gated behind a one-time authorization screen** shown on first launch
> (accept to arm capture + deauth; decline to stay presence-only). You can drop back to
> off/passive any time from the menu, and target/whitelist specific APs. Unauthorized use
> may be a crime where you live — you alone are responsible for how you use this.
> Educational purposes only.

## Setup
### Flipagotchi Setup (Flipper side)
<b>The flipagotchi app can be downloaded from the flipper app store.</b> If you would like to do things manually then follow these instructions.
1. Connect your Flipper to your computer
2. Clone the Flipper Zero firmware onto your machine
3. Place the ```flipagotchi/``` directory into the ```applications_user/```
4. Open a terminal and navigate to the root of the firmware
5. Execute the following command to compile the app and launch it on the Flipper:<br>
    ```./fbt launch_app APPSRC=applications_user/flipagotchi```
6. This will now compile and load the app onto your Flipper

### PwnZero Setup (Pwnagotchi side)
This procedure will explain how to configure the Pwnagotchi to use the PwnZero plugin to communicate with the Flipper. Note: You may need to change the pyserial file name based on whichever version pip downloaded for you.
1. On your host machine run `pip3 download pyserial`, this should download a `.whl` file.
2. Take note of the filename of the `.whl` and insert that instead of mine
3. Also on the host, run `scp pyserial-3.5-py2.py3-none-any.whl pi@10.0.0.2:/home/pi` to transfer the `.whl` file to the pwnagotchi
4. Now on the pwnagotchi install the module as root with `sudo pip3 install /home/pi/pyserial-3.5-py2.py3-none-any.whl`
5. Disable Bluetooth on the Pi by adding ```dtoverlay=disable-bt``` at the bottom of the ```/boot/config.txt``` file
    1. This needs to be disabled so that the full UART is directed to ```/dev/serial0```
6. Enter the raspberry pi configuration settings with `sudo raspi-config`
    1. Select `Interface Options`
    2. Select `Serial Port`
    3. Select `No` for shell over serial
    4. Select `Yes` for serial enabled
6. Place the PwnZero.py file somewhere on the Pi in either its own folder or a folder with other plugins
7. Edit ```/etc/pwnagotchi/config.toml``` file and set ```main.custom_plugins = "/path/to/plugin/folder"```
8. Follow hardware setup shown in `doc/HardwareSetup.md` to connect the devices
9. Restart the Pwnagotchi and open the Flipagotchi app on the Flipper Zero

### Setup note
[Chrismettal](https://github.com/Chrismettal) has designed a "backpack" for the Flipper Zero which is a board that allows you to cleanly attach various devices to the Flipper. They have created one for the Raspberry Pi Zero W which would be a great way to keep your Flipagotchi tidy! Here is a link to their [project](https://github.com/Chrismettal/flipper-zero-backpacks#raspberry-pi-zero-w).

## Development stages
### Stage 1: Simple display rendering
- Stage 1 will focus on getting the Pwnagotchi display to render on the Flipper's display

### Stage 2: App interaction
- Stage 2 will allow the user to interact and control the pwnagotchi using the Flipper's interface

## Contributing
If you would like to contribute, you may make a pull request. It will be helpful if you first open an issue describing the change that you are interested in contributing.

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Disclaimer
<b>This program is meant for educational purposes ONLY. I disclaim any and all responsibility for the usage of this program by external parties (not me).</b>
