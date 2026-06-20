// settings.h - WiFuxx persistent user settings (NVS-backed)
//
// Small key/value config lives in the NVS namespace "wifuxx" as a single
// versioned blob. Defaults below mirror the original compile-time CONFIGURATION
// block in main.c, so a fresh device behaves exactly like stock firmware until
// the user edits anything from the WebUI.
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

// Bump when the struct layout changes — a mismatch on load falls back to defaults.
#define SETTINGS_VERSION   1

// Compile-time defaults (single source of truth for "factory" values).
#define WF_DEF_AP_SSID      "WiFuxx-Control"
#define WF_DEF_AP_CHANNEL   1
#define WF_DEF_THR_24       (-75)   // 2.4GHz RSSI attack threshold (dBm)
#define WF_DEF_THR_5        (-70)   // 5GHz   RSSI attack threshold (dBm)
#define WF_DEF_BURST_24     30      // 2.4GHz deauth burst size
#define WF_DEF_BURST_5      50      // 5GHz   deauth burst size
#define WF_DEF_SKIP_SPLASH  false   // skip the boot branding splashes

typedef struct {
    uint8_t version;        // == SETTINGS_VERSION; guards against stale layouts
    char    ap_ssid[33];    // SoftAP / WebUI SSID
    uint8_t ap_channel;     // SoftAP channel (1..13)
    int8_t  thr_24;         // 2.4GHz RSSI attack threshold (dBm)
    int8_t  thr_5;          // 5GHz   RSSI attack threshold (dBm)
    uint8_t burst_24;       // 2.4GHz deauth burst size
    uint8_t burst_5;        // 5GHz   deauth burst size
    char    ui_user[17];    // WebUI Basic-auth username ("" disables auth)
    char    ui_pass[33];    // WebUI Basic-auth password
    bool    skip_splash;    // skip the boot branding splashes
} wifuxx_settings_t;

// The live settings, populated by settings_load(). Read freely after that.
extern wifuxx_settings_t g_settings;

// Load settings from NVS into g_settings. Any missing/invalid/old blob is
// replaced with compile-time defaults, which are then persisted. Call once at
// boot, after nvs_flash_init().
void settings_load(void);

// Persist the current g_settings to NVS and recompute the cached auth header.
esp_err_t settings_save(void);

// Erase the namespace, reload compile-time defaults, and persist them.
void settings_reset(void);

// Expected "Authorization" header value for the WebUI ("Basic <b64>"), or NULL
// when no username is configured (auth disabled). Recomputed on load/save.
const char *settings_expected_auth(void);
