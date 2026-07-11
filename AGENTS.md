# AGENTS.md — WiFuxx (ESP32-C5 Dual-Band Deauther)

Canonical guidance for any AI agent or new contributor working on this repo.
This is the single source of truth; tool-specific entrypoints (`CLAUDE.md`,
`.cursor/rules/`) are thin pointers to this file.

## What this is
**WiFuxx** — an autonomous dual-band (2.4 GHz + 5 GHz) Wi-Fi deauthentication
tool for the **ESP32-C5**, by **Gallus Gadgets**. Firmware is C on ESP-IDF; the
bulk of it lives in `main/main.c`. One firmware ships on two hardware variants
(see below).

## Build — read this first (the critical gotcha)
This firmware **only actually deauthenticates when built against a patched Wi-Fi
library**. Stock ESP-IDF compiles cleanly but the radio stack silently refuses to
send raw deauth frames — you get a build that looks fine and does nothing.

Requires **ESP-IDF v5.5.1** (patched). From the project root:

1. `source <your-esp-idf-5.5.1>/export.sh`
2. Copy the patched library into the toolchain (needed on every clean build):
   `cp patched_libnet/libnet80211.a "$IDF_PATH/components/esp_wifi/lib/esp32c5/libnet80211.a"`
3. `idf.py set-target esp32c5` (first time only), then `idf.py build`

Do **not** raise the flash size to 8 MB — the 4 MB image runs on 4 MB and 8 MB
boards alike.

## Versioning is driven by `version.txt`
`CMakeLists.txt` reads `version.txt` into `PROJECT_VER`. The firmware reports it
via `esp_app_get_description()->version`, and the OTA "is there a newer release?"
check compares GitHub's latest tag against it. To change the version, edit
`version.txt` — nothing else.

## Partitions / OTA
`partitions.csv` is a 4 MB **dual-OTA** layout (`ota_0` / `ota_1`) so an update
flashes the inactive slot and rolls back on failure. A board coming from the old
2 MB single-app layout needs a one-time `idf.py erase-flash` before its first
flash (stale `otadata` otherwise). OTA pulls the plain app image
`WiFuxx_Dualband_Deauther.bin` from the latest GitHub release.

**OTA gotcha:** GitHub 302-redirects the asset download to a storage host with a
~1 KB AWS-signed URL. The HTTP client's TX buffer must be big enough to hold that
request line — set `buffer_size` / `buffer_size_tx` to 2048 in the OTA download
config, or `esp_https_ota` fails with `Out of buffer`.

## Hardware variants (firmware auto-detects at boot)
- **XIAO custom board** — OLED screen + LiPo battery (Charge Mode, always-on
  battery gauge); **no** status LED.
- **Bare ESP32-C5-DevKitC-1** — no screen; status shown on the **onboard WS2812B
  RGB LED**.

Battery/charge features hide themselves on boards without battery sensing. Note:
the DevKit has its **BOOT/RST silkscreen swapped** — the RST-labelled button is
the one that triggers the button-hold actions (the XIAO is unaffected).

## Release flow (strict semver: feature=minor, fix=patch, breaking=major)
1. Commit on a work branch and push.
2. `git merge --no-ff` into `master`.
3. Annotated tag `vX.Y.Z`.
4. `gh release create vX.Y.Z` with **both** assets:
   - `WiFuxx_v<ver>_merged.bin` — full flash image for USB-flashing new units.
   - `WiFuxx_Dualband_Deauther.bin` — plain app image (the exact name OTA fetches).

Regenerate the merged bin from a fresh build:
`(cd build && esptool.py --chip esp32c5 merge_bin -o ../WiFuxx_v<ver>_merged.bin @flash_args)`

`master` is the only long-lived branch — delete work branches after they merge.

## Customer-facing docs
`README.md`, `USER-MANUAL-XIAO.md`, `USER-MANUAL-DEVKIT.md`, `QUICK-START-XIAO.md`.
Each carries a `*Firmware vX.Y.Z · Last updated YYYY-MM-DD*` stamp under its H1 —
**bump both the version and the date on any doc edit or release** (the PCB has a
QR code pointing to these pages, so they must match the shipped firmware).

## Responsible use
WiFuxx is for testing your **own** networks, controlled education you own, and
**authorised** penetration testing only. Keep that framing prominent in any
user-facing output.
