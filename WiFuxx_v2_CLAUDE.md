# WiFuxx v2 — Claude Code Handover

## Project Context

WiFuxx is an ESP-IDF (v5.5.1) project targeting the XIAO ESP32-C5.
It is an autonomous dual-band (2.4GHz + 5GHz) Wi-Fi deauthentication tool.
The existing codebase lives in `main/main.c`.

v2 adds a **WebUI mode** accessible via a hardware button, without any PCB changes.

---

## Hardware

- MCU: XIAO ESP32-C5
- OLED: 0.96" SSD1306 128x64 I2C (SDA=GPIO23, SCL=GPIO24)
- Status LED: WS2812B on GPIO27
- Button: BOOT button = GPIO9 (active LOW, internal pull-up)

---

## v2 Feature: Button-Triggered WebUI Mode

### Behaviour

The firmware operates in one of two states at any time:

| State | Description |
|---|---|
| `STATE_ATTACK` | Default on boot. Scans then deauths indefinitely. |
| `STATE_WEBUI` | Triggered by button hold. SoftAP + HTTP server active. |

**Transitions:**
- `STATE_ATTACK` → `STATE_WEBUI`: Hold BOOT button (GPIO9) for 2 seconds during attack
- `STATE_WEBUI` → `STATE_ATTACK`: User presses "Start Attack" in the WebUI. Always performs a fresh scan before attacking.

There is no auto-timeout. The device stays in whichever state it is in until explicitly switched.

### Button Detection

- Poll GPIO9 in the main loop (or a dedicated task)
- Detect a clean 2-second hold (debounce: 50ms)
- On hold confirmed: set state to `STATE_WEBUI`
- GPIO9 is already pulled high by the internal pull-up; button press = LOW

### SoftAP Configuration

```c
// SSID
#define WEBUI_AP_SSID     "WiFuxx-Control"
#define WEBUI_AP_PASS     ""          // Open network
#define WEBUI_AP_CHANNEL  1
#define WEBUI_AP_MAX_CONN 1

// Static IP
#define WEBUI_AP_IP       "192.168.42.42"
#define WEBUI_AP_GW       "192.168.42.42"
#define WEBUI_AP_NETMASK  "255.255.255.0"
```

Set the static IP using `esp_netif_set_ip_info()` on the AP netif before calling `esp_wifi_start()`.

### OLED Display in WebUI Mode

When in `STATE_WEBUI`, the OLED must show:

```
┌────────────────────────────────┐
│ >> WiFuxx WebUI                │
│                                │
│ Connect to:                    │
│ WiFuxx-Control                 │
│                                │
│ http://192.168.42.42           │
│                                │
│                                │
└────────────────────────────────┘
```

### Status LED in WebUI Mode

Use a static **orange** colour (not currently used by any state).
RGB value: `(255, 80, 0)` at 25% brightness = `(64, 20, 0)`.

---

## WebUI HTTP Server

Use `esp_http_server` (already available in ESP-IDF, no extra components needed).

### Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/` | Serve the HTML UI page |
| GET | `/scan` | Trigger a fresh Wi-Fi scan, return JSON array of APs |
| POST | `/attack` | Accept JSON body specifying attack mode, transition to `STATE_ATTACK` |

### `/scan` Response Format

```json
[
  { "ssid": "NETGEAR_123", "rssi": -45, "band": "2.4", "mac": "aa:bb:cc:dd:ee:ff", "channel": 6 },
  { "ssid": "BT-Hub_456",  "rssi": -52, "band": "5",   "mac": "11:22:33:44:55:66", "channel": 36 }
]
```

### `/attack` Request Body

```json
{ "mode": "all" }
{ "mode": "single", "mac": "aa:bb:cc:dd:ee:ff" }
{ "mode": "dualband", "ssid": "NETGEAR_123" }
```

On receiving a valid `/attack` POST:
1. Stop the HTTP server
2. Tear down SoftAP
3. Perform a fresh scan
4. Apply targeting based on mode
5. Transition to `STATE_ATTACK`

### WebUI HTML Page

Serve as a `const char*` string in C (no SPIFFS needed for a single page).
The page should be functional on a mobile browser and accessible at `http://192.168.42.42`.

Required UI elements:
- "Scan Networks" button — calls `/scan`, renders results as a list
- Each scan result shows: SSID, RSSI, band, MAC
- Per-AP "Deauth" button (single target mode)
- "Deauth All" button
- "Dual-Band Same AP" button (targets both bands of the same SSID if both are present)
- Status area showing current action / result

Keep the HTML minimal and self-contained (inline CSS, no external resources).
Dark theme to match the device aesthetic.

---

## State Transition: WebUI to Attack

Critical: promiscuous mode and SoftAP **cannot run simultaneously**.

Teardown sequence when leaving `STATE_WEBUI`:
1. `httpd_stop()`
2. `esp_wifi_stop()`
3. `esp_wifi_set_mode(WIFI_MODE_NULL)` (or reconfigure for STA+promiscuous)
4. Re-initialise Wi-Fi for promiscuous mode (existing v1 init sequence)
5. Fresh scan
6. Begin attack loop

---

## Existing Codebase Notes

- All configuration `#define`s are at the top of `main/main.c`
- Attack loop runs in a FreeRTOS task
- OLED updates are batched (1Hz flush) to minimise I2C overhead
- WS2812B LED driven via RMT peripheral on GPIO27
- Existing states: IDLE, SCAN, ATTACK — v2 adds WEBUI to this set
- `BAD_SIGNAL_THRESHOLD_24` / `BAD_SIGNAL_THRESHOLD_5` thresholds still apply in WebUI-triggered attacks

---

## Implementation Order

1. Add `STATE_WEBUI` to the state enum
2. Implement GPIO9 button hold detection (2s, debounced)
3. Implement SoftAP init with static IP `192.168.42.1`
4. Implement HTTP server with `/`, `/scan`, `/attack` endpoints
5. Implement OLED WebUI screen
6. Implement orange LED state for WebUI
7. Implement clean teardown/reinit sequence on attack trigger
8. End-to-end test: boot → attack → hold button → WebUI on phone → scan → deauth all → attack resumes

---

## Out of Scope for v2

- Authentication on the WebUI (open AP is intentional for ease of use)
- Persistent settings / NVS
- OTA update endpoint
- SPIFFS / file system
