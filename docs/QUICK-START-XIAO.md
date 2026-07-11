# WiFuxx — Quick Start

*Firmware v2.4.1 · Last updated 2026-07-11*

**by Gallus Gadgets** · *autonomous dual-band Wi-Fi deauther*

> ⚠️ **Your own networks only.** Using this against networks you don't own — or
> don't have written permission to test — is illegal in most countries.

---

### ① Turn it on
Slide the **power switch** (bottom-centre) to **ON**. After a short logo
sequence, WiFuxx scans and **automatically attacks the strong Wi-Fi networks
near you**. The **screen** shows what it's doing.

### ② Pick specific targets *(optional)*
To choose exactly what to test, open the web panel:

1. While it's running, **hold the BOOT button (~2 sec)** — it restarts into
   Control Mode.
2. On your phone, join the Wi-Fi network **`WiFuxx-Control`** *(no password)*.
3. In a browser, open **`http://192.168.42.42`** (or **`http://wifuxx.local`**).
4. Tap **SCAN**, then choose **DEAUTH** (one network), **DUAL-BAND SAME AP**, or
   **DEAUTH ALL**. Use **AUTO MODE** (Power card) to return to hands-free scanning
   without attacking. The **Settings** panel lets you tune and save options.

It restarts and attacks your choice. Hold **BOOT** again to reopen the panel, or use
**AUTO MODE** from the web panel to go back to autonomous operation.

### ③ Turn it off
Slide the **power switch** to **OFF**.
*(Off → On always restarts in automatic mode.)*

---

> ⚠️ **Don't hold BOOT while switching on** — that starts firmware-update mode and
> the screen stays blank. Just switch off and on again without touching BOOT.

*Recharge via the XIAO's USB-C port. Full instructions & troubleshooting are in the
**[XIAO User Manual](USER-MANUAL-XIAO.md)**.*

```
>_ Gallus Gadgets // build. break. learn.
```
