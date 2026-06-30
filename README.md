[![Ko-Fi](https://img.shields.io/badge/Ko--Fi-Support%20Me-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/stoke)
[![Website](https://img.shields.io/badge/Website-stokemctoke.com-FAA307)](https://stokemctoke.com)
[![Shop](https://img.shields.io/badge/Shop-gallusgadgets.com-E8900A)](https://gallusgadgets.com)
[![Platform: ESP32-C5](https://img.shields.io/badge/Platform-ESP32--C5-blue)](https://www.espressif.com/en/products/socs/esp32-c5)

# WiFuxx: ESP32-C5 Autonomous Dual-Band Deauth

![image](WiFuxx_DualBand-Deauth-Firmware.jpg)


**WiFuxx** is a compact, autonomous deauthentication tool designed for the XIAO ESP32-C5. It scans for nearby Wi-Fi networks, filters by signal strength, and launches targeted deauth attacks indefinitely — all displayed on a tiny OLED screen. It runs hands-free by default, with an **optional phone-friendly web control panel** for hand-picking targets and tuning settings.

> 🔌 **Running on a bare ESP32-C5-DevKitC-1 (no OLED)?** The same binary works there too — see the **[Dev-Kit User Manual](USER-MANUAL-DEVKIT.md)** for flashing and the onboard RGB-LED status guide.

---

## ⚠️ Legal Disclaimer

> **IMPORTANT:** Laws regarding Wi-Fi deauthentication vary significantly by country. In many jurisdictions, using a deauther against networks you do not own or have explicit permission to test is **illegal** and may result in criminal charges, fines, or imprisonment.
> 
> **This tool is intended for:**
> 
> - ✅ Testing your own network security
> - ✅ Educational purposes in controlled environments
> - ✅ Authorised penetration testing
> 
> **DO NOT USE on public, neighbour, or any networks without written permission.**
> 
> **By using this software, you accept full responsibility for your actions.**

---

## 📡 Features

- **⚡ Autonomous by Default** — Power on and it scans, then attacks indefinitely. No app, no setup, no internet.
- **📱 Optional Web Control Panel** — Hold **BOOT** for 2 s to reboot into a phone-friendly WebUI: scan and hand-pick a single AP, a network's 2.4 + 5 GHz pair, or everything. Reachable at `http://192.168.42.42` **or `http://wifuxx.local`** (mDNS). The radio is time-separated from the attack by a reboot, sidestepping the ESP32-C5's single-radio AP-vs-attack conflict.
- **💾 Persistent Settings (NVS)** — Edit the AP name/channel, per-band RSSI thresholds, per-band burst sizes, an optional WebUI login, and the boot splash right from the panel — all saved across reboots. Forgot the login? Hold **BOOT for 10 s** in the panel to factory-reset.
- **📊 Smart Targeting** — Separate signal thresholds per band: > -75 dBm (2.4GHz) and > -70 dBm (5GHz) by default.
- **🖥️ OLED Display** — Real-time status on a 128×64 screen:
  - Per-band AP counts (2.4GHz / 5GHz)
  - Current status (IDLE / SCAN / ATTACK + elapsed time)
  - Scrolling list of target SSIDs
  - Live battery icon (top-right, XIAO builds with battery pads)
- **🔋 Battery Monitoring** — On-board LiPo sense via the XIAO battery pads (GPIO6/26), with a low-power **Charge Mode** reachable from the WebUI.
- **🔫 Dual-Band Support** — Attacks both 2.4 GHz and 5 GHz networks simultaneously.
- **🚀 High Performance** — Optimised channel-hopping with batch I2C display updates (~100x fewer I2C transactions vs naive approach).
- **📝 Serial Logging** — Detailed logs via USB serial for debugging.

---

## 🛠️ Hardware Required

| Component                 | Quantity | Notes                  |
| ------------------------- | -------- | ---------------------- |
| XIAO ESP32-C5             | 1        | Main controller        |
| 0.96" OLED Display (I2C)  | 1        | 128×64, SSD1306 driver |
| Breadboard & Jumper Wires | —        | For prototyping        |
| USB-C Cable               | 1        | Power and programming  |

---

## 🔌 Wiring Diagram

Connect the OLED display to the XIAO ESP32-C5 as follows:

```
XIAO ESP32-C5          OLED Display
┌─────────────┐        ┌──────────┐
│             │        │          │
│     3V3     ├───────►│   VCC    │
│             │        │          │
│     GND     ├───────►│   GND    │
│             │        │          │
│  D4 (SDA)   ├───────►│   SDA    │  (GPIO23)
│             │        │          │
│  D5 (SCL)   ├───────►│   SCL    │  (GPIO24)
│             │        │          │
└─────────────┘        └──────────┘
```

**Pin Mapping Reference:**

| XIAO Pin | GPIO   | OLED Connection |
| -------- | ------ | --------------- |
| D4 (SDA) | GPIO23 | SDA (Data)      |
| D5 (SCL) | GPIO24 | SCL (Clock)     |
| 3V3      | —      | VCC (Power)     |
| GND      | —      | Ground          |

> **Note:** Both the XIAO ESP32-C5 and most 0.96" SSD1306 OLED modules include onboard LDO (Low Drop-Out) voltage regulators, so either 3.3V or 5V can be used to power the OLED. This project runs the OLED at 5V without issue. On standard modules, the I2C signal lines (SDA/SCL) are pulled up to the regulated 3.3V rail internally, keeping them safe for the ESP32-C5's 3.3V GPIO regardless of supply voltage. Verify this is the case for your specific module before powering at 5V.

---

## ⚡ Flashing the Pre-built Binary

If you don't want to build from source, you can flash the pre-built merged binary directly from your browser — no toolchain required.

### Recommended Tool: ESPConnect

**[https://thelastoutpostworkshop.github.io/ESPConnect/](https://thelastoutpostworkshop.github.io/ESPConnect/)**

This is the recommended flashing tool for the ESP32-C5. Many popular online flash tools do not yet support the C5, but ESPConnect does. It also displays useful chip information (flash size, MAC address, chip revision, etc.) directly in the browser.

### Steps

1. Download `WiFuxx_v2.3.0_merged.bin` from the [Releases](https://github.com/stokemctoke/WiFuxx_ESP32-C5-Auto-Dualband-Deauth/releases) page
2. Open **ESPConnect** in a Chromium-based browser (Chrome, Edge — Firefox is not supported for WebSerial)
3. Connect your XIAO ESP32-C5 via USB-C
4. Click **Connect** and select your device from the port list
5. Choose **Custom Flash** and select `WiFuxx_v2.3.0_merged.bin`
6. Set the flash address to `0x0`
7. Click **Flash** and wait for it to complete
8. Press the reset button on the XIAO — WiFuxx will boot immediately

> The merged binary includes the bootloader, partition table, and application in a single file, so flashing at `0x0` is all that's needed.

---

## 📥 Installation

### Prerequisites

- XIAO ESP32-C5 board support
- USB-C cable

> **Directory structure:** Keep ESP-IDF (the toolchain) and WiFuxx (the project) in separate locations. The instructions below use `~/Github-Repos/` — that's just where I keep my repos. Clone them wherever makes sense for your setup, and adjust the paths accordingly.
> 
> ```
> ~/Github-Repos/
>   esp-idf/                        ← toolchain
>   WiFuxx_ESP32-C5-Auto-Dualband-Deauth/ ← this project
> ```

### Step 1: Install ESP-IDF v5.5.1

> ⚠️ **WiFuxx requires ESP-IDF v5.5.1 specifically.** Other versions are not guaranteed to work.

```bash
mkdir -p ~/Github-Repos && cd ~/Github-Repos
git clone --recursive --branch v5.5.1 --depth 1 https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh esp32c5
. ./export.sh
```

> The `. ./export.sh` (note the leading dot and space) sets up the required environment variables for the current shell session. You will need to re-run this each time you open a new terminal.

### Step 2: Clone WiFuxx

```bash
cd ~/Github-Repos
git clone https://github.com/stokemctoke/WiFuxx_ESP32-C5-Auto-Dualband-Deauth.git
```

### Step 3: Patch the WiFi Library

A patched version of the ESP32-C5 WiFi library is required for deauth functionality. The patch file is included in the `patched_libnet` folder of this repository.

Navigate to the ESP32-C5 WiFi library directory inside your ESP-IDF installation:

```bash
cd ~/Github-Repos/esp-idf/components/esp_wifi/lib/esp32c5
```

Remove the existing library file and replace it with the patched version:

```bash
rm libnet80211.a
cp ~/Github-Repos/WiFuxx_ESP32-C5-Auto-Dualband-Deauth/patched_libnet/libnet80211.a .
```

### Step 4: Build and Flash

```bash
cd ~/Github-Repos/WiFuxx_ESP32-C5-Auto-Dualband-Deauth
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

> Replace `/dev/ttyUSB0` with your actual serial port. Also may be shown as `/dev/ttyACM0`

---

## 🎮 Operation

### Automatic Mode

WiFuxx runs autonomously from the moment it powers on:

```
SCAN (5–10s) → ATTACK (infinite) 
```

If no targets above the signal threshold are found on boot, the device waits 25 seconds and rescans until it finds targets. Once targets are found, it attacks indefinitely without stopping.

**Display status during each phase:**

| Phase  | Display                                                      |
| ------ | ------------------------------------------------------------ |
| IDLE   | Waiting to rescan (only if no targets found)                 |
| SCAN   | Scanning for networks, counting strong APs per band          |
| ATTACK | Actively deauthenticating targets (shows elapsed time in seconds) |

### Control Mode (Web Panel)

Hold **BOOT** for ~2 s while running and WiFuxx reboots into Control Mode: it brings up an open SoftAP (`WiFuxx-Control`) hosting a web panel — no attack runs in this mode.

1. Join the Wi-Fi network `WiFuxx-Control` (no password).
2. Browse to **`http://192.168.42.42`** or **`http://wifuxx.local`**.
3. **SCAN**, then choose **DEAUTH** (one AP), **DUAL-BAND SAME AP**, or **DEAUTH ALL** — the device reboots into Attack Mode targeting your choice.
4. The **Settings** card edits the AP name/channel, thresholds, burst sizes, an optional login, and the boot splash (saved to NVS), with a **Reset to defaults** button.

> Set a WebUI login and forgot it? Hold **BOOT for 10 s** while in Control Mode to wipe settings back to defaults. Power-cycling always returns to automatic Attack Mode.

### OLED Display Layout

```
┌────────────────────────────────┐
│ >> PRO DEAUTHER                │  ← Title
│ 2.4G:4 5G:3                    │  ← Per-band AP counts
│ ATK 42s                        │  ← Status + elapsed time
│ NETGEAR_123                    │  ← Target 1 (scrolls if >5)
│ BT-Hub_456                     │  ← Target 2
│ Starlink_789                   │  ← Target 3
│ TP-Link_XXX                    │  ← Target 4
│ Xfinity_YYY                    │  ← Target 5
└────────────────────────────────┘
```

### Configuration Parameters

The most-used settings — AP name/channel, per-band RSSI thresholds, per-band burst sizes, an optional WebUI login, and skip-splash — are editable **live from the WebUI Settings panel** and persist in NVS. Their factory defaults live in `main/settings.h`:

```c
#define WF_DEF_THR_24      (-75)  // Attack 2.4GHz APs stronger than this (dBm)
#define WF_DEF_THR_5       (-70)  // Attack 5GHz APs stronger than this (dBm)
#define WF_DEF_BURST_24    30     // Deauth frames per burst on 2.4GHz
#define WF_DEF_BURST_5     50     // Deauth frames per burst on 5GHz
#define WF_DEF_AP_SSID     "WiFuxx-Control"  // Control-mode SoftAP name
#define WF_DEF_AP_CHANNEL  1
```

Remaining compile-time constants (`MAX_TARGETS`, `AUTO_SCAN_INTERVAL_SEC`, GPIO/LED pins) stay at the top of `main.c`.

---

## 📊 Serial Monitor Output

Connect via serial monitor to see detailed logs:

```bash
idf.py monitor
```

Example output:

```
I (1234) WiFuxx: Scanning for networks...
I (5678) WiFuxx: Found 15 total networks
I (5679) WiFuxx:   [0] NETGEAR_123 (CH 6, 2.4GHz, RSSI -45, MAC aa:bb:cc:dd:ee:ff)
I (5680) WiFuxx:   [1] BT-Hub_456  (CH 1, 2.4GHz, RSSI -52, MAC 11:22:33:44:55:66)
I (5681) WiFuxx: Starting infinite attack on 7 targets
I (5682) WiFuxx: DUAL-BAND ATTACK STARTED!
I (7683) WiFuxx: [2 s] Total:   4900 pkt | PPS: 2450 | Cycles: 12
I (7684) WiFuxx:   2.4GHz:   2800 pkt (1400 pps) - 4 targets
I (7685) WiFuxx:   5GHz:     2100 pkt (1050 pps) - 3 targets
```

---

## 🔧 Troubleshooting

| Problem             | Solution                                                                                     |
| ------------------- | -------------------------------------------------------------------------------------------- |
| OLED display blank  | Check wiring, especially SDA/SCL. Run an I2C scanner sketch to verify address.               |
| No deauth effect    | Verify promiscuous mode is enabled — check serial for `"Failed to enable promiscuous mode"`. |
| Device not scanning | Ensure Wi-Fi is initialised correctly — serial logs will show errors.                        |
| Compilation errors  | Run `idf.py fullclean` and rebuild. Ensure ESP-IDF is v5.5.1.                                |

---

## 📈 Performance

| Metric              | Value                                                |
| ------------------- | ---------------------------------------------------- |
| Packet rate         | ~2,500 packets/second (aggregate across all targets) |
| Channel switch delay| 12 ms                                                |
| Display update rate | 1 Hz (batch I2C flush, negligible CPU impact)        |
| Memory usage        | ~50 KB heap, ~500 KB flash                           |

---

## 🔮 Future Ideas

- Battery level monitoring (XIAO battery pads)
- Battery icon on OLED
- External antenna mod
- 3D printed enclosure

---

## 🙏 Credits

- Patched Libnet - [AnvilBrain](https://github.com/AnvilBrain)
- ESP-IDF framework - [Espressif](https://www.espressif.com/)
- SSD1306 Driver - Adapted from Public Domain Sources

---

## 📜 Licence

MIT Licence — see the [LICENSE](LICENSE) file for details.

---

## ⚡ Quick Start

1. Wire OLED: `VCC→3V3`, `GND→GND`, `SDA→D4`, `SCL→D5`
2. Flash with `idf.py flash monitor`
3. Watch the OLED show the intro screen, then AP counts and attack status
4. Device scans immediately on boot and attacks all targets above threshold indefinitely

> **Remember:** Only use on your own networks! 🛡️

---

>> ***WiFuxx:** Because sometimes you just need to fuxx about (with your own network)* 😉
