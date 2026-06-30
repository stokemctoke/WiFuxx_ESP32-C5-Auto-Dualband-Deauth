# WiFuxx — User Manual

### Compact Edition · Autonomous Dual-Band Wi-Fi Deauthentication Tool
**by Gallus Gadgets**

WiFuxx is a pocket-sized, battery-powered tool that tests how resilient your
Wi-Fi networks are to "deauthentication" — the technique that knocks devices off
a Wi-Fi access point. Switch it on and it works on its own; or hold the button to
open a phone-friendly control panel and pick exactly what to test.

---

## ⚠️ Read This First — Legal & Responsible Use

> **Using a deauther against networks or devices you do not own — or do not have
> written permission to test — is illegal in most countries** and can lead to
> fines or prosecution.
>
> WiFuxx is intended **only** for:
> - ✅ Testing **your own** network and devices
> - ✅ Education in a controlled environment you own
> - ✅ Authorised penetration testing (with written permission)
>
> **Never** point it at neighbours, public, workplace, or any other network you
> don't own. **You are fully responsible for how you use this device.**

---

## 1. What WiFuxx Does

- Listens for nearby Wi-Fi networks on **both 2.4 GHz and 5 GHz** bands.
- Automatically targets the **strong, nearby** networks (it ignores weak/distant
  ones so it stays focused on networks that are actually near you — i.e. yours).
- Continuously sends deauth frames to disconnect devices from those networks,
  showing live status on its screen.
- Optionally, lets you open a **web control panel** from your phone to scan and
  hand-pick a single network, a network's 2.4 + 5 GHz pair, or everything.

It runs entirely on the device — no app to install, no internet needed.

---

## 2. Your Device

WiFuxx is a small board (about **55 × 35 mm**) with everything built in:

```
   Front of the unit  (approx. 55 × 35 mm)
   ┌──────────────────────────────────────┐
   │  ┌───────────┐     ┌───────────────┐  │
   │  │   XIAO    │     │     OLED      │  │
   │  │  ESP32-C5 │     │    screen     │  │
   │  └───────────┘     └───────────────┘  │
   │             ┌──────────┐              │
   │             │  ON / OFF │             │
   │             └──────────┘              │
   └──────────────────────────────────────┘
     • USB-C (charging): on the XIAO module
     • Power switch:     bottom edge, centre
     • Battery:          connector on the rear
```

| Part | Where | What it's for |
|------|-------|----------------|
| **OLED screen** | Right | Shows everything the device is doing. |
| **XIAO module** | Left | The brain. Its **USB-C port is used to charge** the unit. |
| **Power switch** | Bottom, centre | Turns the unit on and off. |
| **Battery** | Rear connector | Rechargeable battery — makes WiFuxx fully portable. |

> Everything WiFuxx is doing is shown on the **screen** — this model has no status
> light.

> **Early units ship as a bare assembled board** (no enclosure yet — a case is on
> the way). Handle it gently by the edges, keep it away from liquids and metal
> surfaces, and try not to touch the components or antenna area. The power switch,
> BOOT button (on the XIAO), and USB-C port are all directly accessible on the
> board.

---

## 3. Power & Charging

- **On / Off:** use the **power switch** on the bottom edge (centre).
- **Battery:** WiFuxx runs from an internal rechargeable battery, so once charged
  you can use it anywhere. When the battery is empty it simply switches off.
- **Charging:** plug a USB-C cable into the **XIAO's USB-C port** (left side). The
  small **red "C" LED on the XIAO** is your charge indicator:
  - **Blinking** — charging in progress
  - **Out** — fully charged (it may glow steadily for a few seconds first)

  You can charge with the unit on or off, and it's safe to leave it plugged in —
  it stops on its own when full and tops up again if needed.

### Charge Mode (faster, cooler charging)

For the quickest charge, use **Charge Mode**. It turns Wi-Fi off and drops the
unit into a low-power state so almost all the power goes into the battery instead
of running the radio. The screen shows a single dim line with the battery voltage
and percentage.

- **Turn it on:** open the web panel (Control Mode — see §8) and tap **CHARGE
  MODE** under *Power*.
- **Know when it's done:** watch the XIAO's red **C LED** — when it goes out, the
  battery is full. Then unplug.
- **Go back to normal:** flip the **power switch off and on** — WiFuxx restarts in
  automatic Attack Mode.

---

## 4. Switching On — What to Expect

Slide the power switch to **ON**. WiFuxx plays a short animated startup sequence
on the screen:

1. The **Gallus Gadgets** logo fades in, then the wordmark flashes
2. The **WiFuxx logo**
3. A reminder screen:
   ```
   >> WiFuxx
   Dual-Band Deauth

   Hold BOOT btn
   2s for WebUI

   Use your own
   nets only :P
   ```
4. It then **scans** for networks and begins **attacking** automatically.

The whole intro takes under ten seconds, then it gets to work on its own.

---

## 5. The Modes

WiFuxx runs in one of these modes:

| Mode | How you get there | What it does |
|------|-------------------|--------------|
| **Attack Mode** *(default)* | Automatic when switched on | Scans, then deauthenticates all strong nearby networks, forever. |
| **Control Mode (WebUI)** | Hold **BOOT** for 2 s while running | Creates its own Wi-Fi hotspot + web page so you can scan and pick specific targets. |
| **Charge Mode** | Tap **CHARGE MODE** in the web panel *(XIAO only)* | Wi-Fi off, low-power charging. OLED shows **CHARGE MODE** plus a battery readout. Leave it until the XIAO's C LED goes out (see §3). |

To leave Control Mode **without** starting an attack, tap **AUTO MODE** in the web
panel (or power-cycle the unit).

Switching modes restarts the device (this is normal — it takes a couple of
seconds). **Switching the power off and on always returns it to automatic Attack
Mode.**

---

## 6. Reading the Screen

WiFuxx has **one** OLED display — it simply shows a different layout depending on
the mode (it is not two physical screens):

**Attack Mode layout:**
```
>> DEAUTHER    [==] <- title + battery level (top-right)
2.4G:4 5G:3         <- how many networks found per band
ATK 42s             <- currently attacking, 42 seconds in
NETGEAR_123         <- list of networks being targeted
BT-Hub_456              (scrolls if there are more than 5)
Starlink_789
...
```

The small **battery icon** at the top-right shows your charge level and fills as
the battery charges. (It appears only on the battery-powered XIAO build.)

**Control Mode layout:**
```
>> WiFuxx WebUI
Connect to:
WiFuxx-Control      <- the Wi-Fi name to join
http://192.168.42.42  <- the address to open in your browser
or wifuxx.local       <- or this friendly name
```

---

## 7. Using Attack Mode (Automatic)

This is the default — just switch it on.

- It scans, then attacks all strong nearby networks indefinitely.
- The screen shows how many networks it found on each band and a scrolling list
  of their names.
- **If nothing strong is found**, the screen keeps showing low/zero counts and
  WiFuxx simply waits about 25 seconds and scans again — move closer to your
  target network if this persists.
- To stop, **switch it off**.

---

## 8. Using Control Mode (Web Panel) — Hand-Picking Targets

Use this when you want to test one specific network instead of everything nearby.

**Step 1 — Open Control Mode**
While the device is running, **press and hold the BOOT button** (on the XIAO
module, left side) **for about 2 seconds**, then release. It restarts and the
screen shows the connection details.

**Step 2 — Join its Wi-Fi**
On your phone, tablet, or laptop, open Wi-Fi settings and connect to:
- **Network name:** `WiFuxx-Control`
- **Password:** none (it's an open network)

> Your phone may warn that this network "has no internet." That's expected — stay
> connected anyway.

**Step 3 — Open the control page**
In a web browser, go to **either** of these:
```
http://192.168.42.42      (always works)
http://wifuxx.local       (friendlier; iPhone/Mac and most computers)
```
(Type it exactly, including `http://`.) If `wifuxx.local` doesn't resolve on your
device — some Android phones don't support it — just use the numeric address.

**Step 4 — Scan**
Tap **SCAN**. A list of nearby networks appears, each showing its name, signal
strength, band (2.4G/5G), and hardware address (MAC).

**Step 5 — Choose what to test**
- **DEAUTH** next to a single network — test just that one access point.
- **DUAL-BAND SAME AP** — appears when a network broadcasts on both 2.4 GHz and
  5 GHz; tests both halves of that same network together.
- **DEAUTH ALL** — test every network in the list.

**Step 6 — It attacks your choice**
After you choose, the device **leaves Control Mode and restarts into Attack Mode**
targeting your selection. (Your browser will show a "command sent" message; the
hotspot disappears because the device is now attacking.)

**To go back to the control panel:** hold **BOOT** for 2 seconds again.
**To return to fully automatic mode without choosing a target:** switch the power
off and back on — it always starts in Attack Mode.

> 🔋 **Charging instead?** The **Power** card has a **CHARGE MODE** button. It puts
> WiFuxx into low-power charging (Wi-Fi off) with a battery readout on screen — see
> §3. To leave Charge Mode, switch the power off and on.

---

## 9. Settings — Personalise WiFuxx

Scroll down the control page to the **Settings** card. Changes are **saved on the
device** and survive being switched off:

| Setting | What it does |
|---------|--------------|
| **AP SSID / channel** | Rename the `WiFuxx-Control` hotspot and pick its Wi-Fi channel. |
| **2.4G / 5G threshold** | How strong a network must be (dBm) before Attack Mode targets it. |
| **2.4G / 5G burst** | How many deauth frames are sent per burst on each band. |
| **WebUI user / pass** | Optional login for the control page. Leave the username blank for no login. |
| **Skip boot splash** | Skips the startup logo animation for a faster boot. |

Tap **SAVE SETTINGS** to store them. The hotspot name/channel and any login take
effect the **next** time you open Control Mode. **RESET TO DEFAULTS** restores
everything to factory settings.

> 🔑 **Locked yourself out?** If you set a login and forget it, you can't reach the
> page to fix it — so there's a hardware escape: in Control Mode, **hold BOOT for
> 10 seconds**. WiFuxx wipes all settings (including the login) back to defaults
> and restarts into an open control panel.

---

## 10. Buttons & Switch — Quick Reference

| Action | Result |
|--------|--------|
| Hold **BOOT** (on the XIAO) ~2 s *while running* | Opens Control Mode (web panel) |
| Hold **BOOT** ~10 s *while in Control Mode* | Factory-reset (wipes settings + login) |
| Web panel → **Power → AUTO MODE** | Returns to automatic Attack Mode (no attack command) |
| Web panel → **Power → CHARGE MODE** | Low-power charging; unplug when the XIAO C LED goes out |
| **Power switch** off → on | Restarts in automatic Attack Mode (also exits Charge Mode) |

> **Important:** Do **not** hold the BOOT button *while switching the unit on*. On
> this hardware that makes it start in firmware-update ("flashing") mode and the
> screen will stay blank. If that happens, switch off, wait a moment, and switch
> on again **without** touching BOOT.

---

## 11. Troubleshooting & Error States

| Symptom | What it means / what to do |
|---------|----------------------------|
| **Screen stays blank when switched on** | Battery may be flat — charge via the XIAO's USB-C and try again. If you switched on while holding BOOT, it has started in flashing mode — switch off and on again without touching BOOT. |
| **Won't switch on at all** | Charge it (USB-C on the XIAO) for a while, then try the power switch again. |
| **Holding BOOT does nothing** | Make sure the unit has finished starting and is already running before you hold. Hold for a **full 2 seconds**. BOOT only opens Control Mode *from* Attack Mode. |
| **Screen shows it found no networks** | Nothing nearby was strong enough to target. Move closer to the network you're testing; it keeps rescanning automatically. |
| **Can't find the "WiFuxx-Control" Wi-Fi** | Confirm you're in Control Mode (the screen shows the connect info). Refresh your phone's Wi-Fi list. |
| **Joined WiFuxx-Control but the page won't load** | Type the full address `http://192.168.42.42` (not `https`). On Android, turn off mobile data and "auto-switch to mobile network" so the phone stays on the device's hotspot. |
| **`wifuxx.local` doesn't open** | Some Android phones don't support `.local` names — just use `http://192.168.42.42` instead. iPhones, Macs and most computers handle `wifuxx.local` fine. |
| **Set a WebUI password and forgot it** | In Control Mode, hold **BOOT for 10 seconds** — WiFuxx factory-resets (wiping the login) and restarts into an open control panel. |
| **Phone keeps dropping the WiFuxx-Control connection** | It's an internet-less network; tell your phone to stay connected to it. |
| **Scan shows few or no networks** | Move closer to your target and tap **SCAN** again. Hidden or very weak networks may not appear. |
| **A device won't disconnect during a test** | Some modern routers and phones resist deauthentication (a protection called PMF/802.11w). 5 GHz also has shorter range — move closer. This is a property of the target, not a fault in WiFuxx. |
| **Screen shows "CHARGE MODE" / one dim line** | It's in Charge Mode — low-power charging started from the web panel. Unplug when the XIAO C LED goes out, then switch off and on to use it normally. |
| **How do I stop everything?** | Switch it off. |
| **How do I reset to normal?** | Switch off and on — it always starts in automatic Attack Mode. |

---

## 12. Safety Reminder

WiFuxx temporarily disrupts Wi-Fi connections. Never use it where doing so could
cause harm or affect networks and people you don't have permission to test —
including shared buildings, workplaces, and public spaces. **Your own networks
only.**

---

```
>_ Gallus Gadgets  //  build. break. learn.
```

*WiFuxx — because sometimes you just need to fuxx about (with your own network).* 😉
