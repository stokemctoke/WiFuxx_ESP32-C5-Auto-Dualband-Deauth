[![Ko-Fi](https://img.shields.io/badge/Ko--Fi-Support%20Me-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/stoke)
[![Website](https://img.shields.io/badge/Website-stokemctoke.com-FAA307)](https://stokemctoke.com)
[![Shop](https://img.shields.io/badge/Shop-gallusgadgets.com-E8900A)](https://gallusgadgets.com)
[![Platform: ESP32-C5](https://img.shields.io/badge/Platform-ESP32--C5-blue)](https://www.espressif.com/en/products/socs/esp32-c5)

# WiFuxx — Dev-Kit User Manual

**by Gallus Gadgets** · *autonomous dual-band Wi-Fi deauther*

WiFuxx running on a **bare Espressif ESP32-C5-DevKitC-1** — no screen required. The
DevKit's **onboard RGB LED** is your status display, and the optional **web control
panel** gives you full control from a phone. It's the **same firmware** as the XIAO
build: one binary, `WiFuxx_v2.1.1_merged.bin`, runs on both boards.

> 👉 Using the XIAO custom board with an OLED instead? See the main **[README](README.md)**.

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

## 🛠️ What You Need

| Component                     | Notes                                          |
| ----------------------------- | ---------------------------------------------- |
| ESP32-C5-DevKitC-1 (v1.2)     | Bare DevKit — onboard WS2812 RGB LED on GPIO27 |
| USB-C Cable                   | Power and flashing (native USB serial)         |

No OLED, no wiring, no extra parts — flash it and go. (An OLED is optional: wire an
SSD1306 to **SDA = GPIO23 / SCL = GPIO24** and the firmware will use it automatically.)

> ⚠️ **The BOOT and RST button labels are swapped on the ESP32-C5-DevKitC-1.** Every
> "hold" action in this guide (Control Mode, factory reset) is triggered by the button
> physically printed **RST** — *not* the one printed BOOT. This guide calls that
> RST-labeled button **RESET**: wherever you read "hold RESET", press the **RST** button.

---

## ⚡ Flashing the Pre-built Binary

The DevKit uses the **identical** `WiFuxx_v2.1.1_merged.bin` as the XIAO build — the
merged binary bundles the bootloader, partition table, and app, so flashing at `0x0`
is all that's needed.

### Recommended Tool: ESPConnect

**[https://thelastoutpostworkshop.github.io/ESPConnect/](https://thelastoutpostworkshop.github.io/ESPConnect/)**

This is the recommended flashing tool for the ESP32-C5. Many popular online flash tools do not yet support the C5, but ESPConnect does, and it shows useful chip info (flash size, MAC, revision) in the browser.

### Steps

1. Download `WiFuxx_v2.1.1_merged.bin` from the [Releases](https://github.com/stokemctoke/WiFuxx_ESP32-C5-Auto-Dualband-Deauth/releases) page.
2. Open **ESPConnect** in a Chromium-based browser (Chrome or Edge — Firefox is not supported for WebSerial).
3. Plug the DevKit into USB-C and connect to its serial port.
4. Choose **Custom Flash** and select `WiFuxx_v2.1.1_merged.bin`.
5. Set the flash address to `0x0`.
6. Click **Flash** and wait for it to complete.

**Prefer the command line?**

```bash
esptool.py -p /dev/ttyACM0 write_flash 0x0 WiFuxx_v2.1.1_merged.bin
# or, from a built tree:  idf.py -p /dev/ttyACM0 flash
```

> If flashing won't start, hold the **RST**-labeled button while tapping the **BOOT**-labeled button to force download mode, then release. (Yes — labels are swapped on this board; see the note above.)

---

## 🌈 RGB LED Status Guide

With no screen, the **onboard RGB LED (GPIO27)** is how you read what WiFuxx is doing.
It's driven at ~25% brightness so it's comfortable to watch.

| State           | Colour     | Pattern       | Meaning                                           |
| --------------- | ---------- | ------------- | ------------------------------------------------- |
| Boot            | 🔵 Blue    | Solid         | Chip powering up, before Wi-Fi init               |
| Wi-Fi Init      | 🟣 Magenta | Solid         | Wi-Fi stack coming online                         |
| Scanning        | 🩵 Cyan    | Fast pulse    | Actively scanning for nearby networks             |
| No Targets      | 🟡 Yellow  | Slow blink    | Scan finished, nothing above threshold — retrying |
| Targets Found   | 🟢 Green   | Solid (~½ s)  | Targets locked, attack about to start             |
| Attacking       | 🔴 Red     | Breathing     | Deauth burst loop running                         |
| WebUI / Control | 🌈 Rainbow | Slow breath   | Control Mode AP is up, waiting for your browser   |

---

## 🎮 Using It Without a Screen

### Automatic mode (default)
Power on → after a moment WiFuxx scans, then **attacks the strong Wi-Fi networks near
you indefinitely**. Watch the LED: 🔵 → 🩵 → 🟢 → 🔴. That's it — fully hands-free.
(In Control Mode the LED instead does a slow **🌈 rainbow breath**.)

### Control Mode (web panel)
To hand-pick targets or change settings, open the web panel:

1. While it's running, **hold the RESET button (the one printed RST) for ~2 s** — it reboots into Control Mode
   (LED starts a **🌈 slow rainbow breath**).
2. On your phone, join the Wi-Fi network **`WiFuxx-Control`** *(no password by default)*.
3. In a browser, open **`http://192.168.42.42`** or **`http://wifuxx.local`**.
4. Tap **SCAN**, then choose **DEAUTH** (one network), **DUAL-BAND SAME AP**, or **DEAUTH
   ALL**. The **Settings** panel lets you tune thresholds, burst sizes, the AP name, an
   optional login, and more — all saved across reboots (NVS).

WiFuxx reboots and attacks your choice. Hold **RESET** again to reopen the panel.

### Factory reset / lockout escape
Set a WebUI login and forgot it? In Control Mode, **hold RESET (the RST-labeled button) for ~10 s** — WiFuxx wipes
all settings back to defaults and reboots. (Default AP SSID `WiFuxx-Control`, IP
`192.168.42.42`.)

### Power off
Unplug USB. Power-on always restarts in automatic mode.

---

## 📝 Notes & Caveats

- **No on-screen hints.** On a screenless DevKit the LED and this guide are your only
  cues — there's no OLED prompting you to "connect to WiFuxx-Control". Bookmark
  `http://wifuxx.local`.
- **Charge Mode is XIAO-only.** The web panel's **CHARGE MODE** button is for the
  battery-powered XIAO build. The bare DevKit has no battery or charger, so it just
  shows "Charging…" and you'd have to power-cycle to leave — ignore it on a DevKit.
- **Don't hold the RESET (RST-labeled) button while powering on / resetting** unless you
  *want* firmware-update (download) mode — the app won't run. Just power-cycle without
  touching it.
- **FYI (hardware):** on the ESP32-C5, the strapping combo GPIO27 = low **and** GPIO28 =
  low at reset is invalid. This only matters at the instant of reset (before the app
  runs), so normal operation is unaffected — just don't externally force the LED line low
  while pressing the RESET (RST-labeled) button.

---

## 🔫 Same Firmware, Two Boards

| | XIAO custom board | Bare DevKitC-1 |
| --- | --- | --- |
| Binary | `WiFuxx_v2.1.1_merged.bin` | **same** `WiFuxx_v2.1.1_merged.bin` |
| Status display | OLED (SSD1306) | Onboard RGB LED (GPIO27) |
| Hold button (Control Mode / reset) | GPIO28 (printed BOOT) | GPIO28 — press the **RST**-labeled button (labels swapped) |
| WebUI | ✅ `wifuxx.local` | ✅ `wifuxx.local` |
| Factory reset (10 s hold) | ✅ | ✅ |

---

```
>_ Gallus Gadgets // build. break. learn.
```
