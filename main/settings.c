// settings.c - NVS-backed persistent user settings for WiFuxx.
#include "settings.h"

#include <string.h>
#include <stdio.h>
#include "nvs.h"
#include "esp_log.h"

static const char *TAG = "settings";

#define SETTINGS_NS   "wifuxx"
#define SETTINGS_KEY  "cfg"

wifuxx_settings_t g_settings;

// Cached "Basic <b64(user:pass)>" header; empty string == auth disabled.
static char s_auth_header[96];

// Minimal base64 encoder (no padding bugs, no external deps).
static void b64_encode(const unsigned char *in, size_t len, char *out) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0, o = 0;
    while (i < len) {
        uint32_t a = i < len ? in[i++] : 0;
        uint32_t b = i < len ? in[i++] : 0;
        uint32_t c = i < len ? in[i++] : 0;
        uint32_t trip = (a << 16) | (b << 8) | c;
        out[o++] = tbl[(trip >> 18) & 0x3F];
        out[o++] = tbl[(trip >> 12) & 0x3F];
        out[o++] = tbl[(trip >> 6)  & 0x3F];
        out[o++] = tbl[ trip        & 0x3F];
    }
    size_t mod = len % 3;
    if (mod) {                       // fix up padding for the final group
        out[o - 1] = '=';
        if (mod == 1) out[o - 2] = '=';
    }
    out[o] = '\0';
}

static void settings_recompute_auth(void) {
    if (g_settings.ui_user[0] == '\0') {  // no username -> auth disabled
        s_auth_header[0] = '\0';
        return;
    }
    char creds[sizeof(g_settings.ui_user) + sizeof(g_settings.ui_pass)];
    snprintf(creds, sizeof(creds), "%s:%s", g_settings.ui_user, g_settings.ui_pass);
    char b64[80];
    b64_encode((const unsigned char *)creds, strlen(creds), b64);
    snprintf(s_auth_header, sizeof(s_auth_header), "Basic %s", b64);
}

static void settings_set_defaults(void) {
    memset(&g_settings, 0, sizeof(g_settings));
    g_settings.version = SETTINGS_VERSION;
    strncpy(g_settings.ap_ssid, WF_DEF_AP_SSID, sizeof(g_settings.ap_ssid) - 1);
    g_settings.ap_channel  = WF_DEF_AP_CHANNEL;
    g_settings.thr_24      = WF_DEF_THR_24;
    g_settings.thr_5       = WF_DEF_THR_5;
    g_settings.burst_24    = WF_DEF_BURST_24;
    g_settings.burst_5     = WF_DEF_BURST_5;
    g_settings.skip_splash = WF_DEF_SKIP_SPLASH;
    // ui_user / ui_pass left empty (auth disabled) by the memset above.
}

void settings_load(void) {
    settings_set_defaults();

    nvs_handle_t h;
    esp_err_t err = nvs_open(SETTINGS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open failed (%s); using defaults (not persisted)",
                 esp_err_to_name(err));
        settings_recompute_auth();
        return;
    }

    wifuxx_settings_t tmp;
    size_t sz = sizeof(tmp);
    err = nvs_get_blob(h, SETTINGS_KEY, &tmp, &sz);
    if (err == ESP_OK && sz == sizeof(tmp) && tmp.version == SETTINGS_VERSION) {
        g_settings = tmp;
        ESP_LOGI(TAG, "loaded settings from NVS");
    } else {
        ESP_LOGW(TAG, "no/invalid stored settings — writing defaults");
        nvs_set_blob(h, SETTINGS_KEY, &g_settings, sizeof(g_settings));
        nvs_commit(h);
    }
    nvs_close(h);
    settings_recompute_auth();
}

esp_err_t settings_save(void) {
    g_settings.version = SETTINGS_VERSION;

    nvs_handle_t h;
    esp_err_t err = nvs_open(SETTINGS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;

    err = nvs_set_blob(h, SETTINGS_KEY, &g_settings, sizeof(g_settings));
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);

    settings_recompute_auth();
    if (err == ESP_OK) ESP_LOGI(TAG, "settings saved");
    else ESP_LOGE(TAG, "settings save failed: %s", esp_err_to_name(err));
    return err;
}

void settings_reset(void) {
    nvs_handle_t h;
    if (nvs_open(SETTINGS_NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    }
    settings_set_defaults();
    settings_save();   // re-persist defaults and refresh auth cache
    ESP_LOGW(TAG, "settings reset to defaults");
}

const char *settings_expected_auth(void) {
    return s_auth_header[0] ? s_auth_header : NULL;
}
