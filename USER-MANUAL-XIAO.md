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
- **Charging:** recharge through the **USB-C port on the XIAO** (left side).

> 📝 **Draft note — remove before printing:** the production board's charging isn't
> finalised yet (the current test unit uses a separate charge module that is *not*
> on the production PCB). Confirm the charging method and any charge indicator once
> test boards arrive, then finalise this section. *(A dedicated Gallus Gadgets
> charge module is planned for an upcoming project.)*

---

## 4. Switching On — What to Expect

Slide the power switch to **ON**. WiFuxx plays a short startup sequence on the
screen:

1. **WiFuxx logo**
2. **Gallus Gadgets logo**
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

## 5. The Two Modes

WiFuxx is always in one of two modes:

| Mode | How you get there | What it does |
|------|-------------------|--------------|
| **Attack Mode** *(default)* | Automatic when switched on | Scans, then deauthenticates all strong nearby networks, forever. |
| **Control Mode (WebUI)** | Hold **BOOT** for 2 s while running | Creates its own Wi-Fi hotspot + web page so you can scan and pick specific targets. |

Switching modes restarts the device (this is normal — it takes a couple of
seconds). **Switching the power off and on always returns it to automatic Attack
Mode.**

---

## 6. Reading the Screen

WiFuxx has **one** OLED display — it simply shows a different layout depending on
the mode (it is not two physical screens):

**Attack Mode layout:**
```
>> PRO DEAUTHER     <- title
2.4G:4 5G:3         <- how many networks found per band
ATK 42s             <- currently attacking, 42 seconds in
NETGEAR_123         <- list of networks being targeted
BT-Hub_456              (scrolls if there are more than 5)
Starlink_789
...
```

**Control Mode layout:**
```
>> WiFuxx WebUI
Connect to:
WiFuxx-Control      <- the Wi-Fi name to join
http://192.168.42.42  <- the address to open in your browser
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
In a web browser, go to:
```
http://192.168.42.42
```
(Type it exactly, including `http://`.)

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

---

## 9. Buttons & Switch — Quick Reference

| Action | Result |
|--------|--------|
| Hold **BOOT** (on the XIAO) ~2 s *while running* | Opens Control Mode (web panel) |
| **Power switch** off → on | Restarts in automatic Attack Mode |

> **Important:** Do **not** hold the BOOT button *while switching the unit on*. On
> this hardware that makes it start in firmware-update ("flashing") mode and the
> screen will stay blank. If that happens, switch off, wait a moment, and switch
> on again **without** touching BOOT.

---

## 10. Troubleshooting & Error States

| Symptom | What it means / what to do |
|---------|----------------------------|
| **Screen stays blank when switched on** | Battery may be flat — charge via the XIAO's USB-C and try again. If you switched on while holding BOOT, it has started in flashing mode — switch off and on again without touching BOOT. |
| **Won't switch on at all** | Charge it (USB-C on the XIAO) for a while, then try the power switch again. |
| **Holding BOOT does nothing** | Make sure the unit has finished starting and is already running before you hold. Hold for a **full 2 seconds**. BOOT only opens Control Mode *from* Attack Mode. |
| **Screen shows it found no networks** | Nothing nearby was strong enough to target. Move closer to the network you're testing; it keeps rescanning automatically. |
| **Can't find the "WiFuxx-Control" Wi-Fi** | Confirm you're in Control Mode (the screen shows the connect info). Refresh your phone's Wi-Fi list. |
| **Joined WiFuxx-Control but the page won't load** | Type the full address `http://192.168.42.42` (not `https`). On Android, turn off mobile data and "auto-switch to mobile network" so the phone stays on the device's hotspot. |
| **Phone keeps dropping the WiFuxx-Control connection** | It's an internet-less network; tell your phone to stay connected to it. |
| **Scan shows few or no networks** | Move closer to your target and tap **SCAN** again. Hidden or very weak networks may not appear. |
| **A device won't disconnect during a test** | Some modern routers and phones resist deauthentication (a protection called PMF/802.11w). 5 GHz also has shorter range — move closer. This is a property of the target, not a fault in WiFuxx. |
| **How do I stop everything?** | Switch it off. |
| **How do I reset to normal?** | Switch off and on — it always starts in automatic Attack Mode. |

---

## 11. Safety Reminder

WiFuxx temporarily disrupts Wi-Fi connections. Never use it where doing so could
cause harm or affect networks and people you don't have permission to test —
including shared buildings, workplaces, and public spaces. **Your own networks
only.**

---

```
>_ Gallus Gadgets  //  build. break. learn.
```

*WiFuxx — because sometimes you just need to fuxx about (with your own network).* 😉
