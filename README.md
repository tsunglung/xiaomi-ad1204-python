# CUKTECH 10 Ultra (AD1204/C2C615U) Charger Tools

Watch your CUKTECH 10 GaN Charger Ultra's live power stats and change its
settings — from your laptop, over Bluetooth, without the Mi Home app.

This works because the charger talks Bluetooth Low Energy directly. These
scripts speak that same language. You don't need the Mi Home app open (in
fact, it has to be closed — see [Troubleshooting](#troubleshooting)).

## What you get

- **`dashboard.py`** — a live terminal dashboard showing voltage, current,
  wattage, and charging protocol (PD/QC/etc.) for every port, updating in
  real time as you plug/unplug devices. Press `s` to open a settings menu.
- **`ad1204_ble.py`** — the underlying command-line tool, for one-off reads,
  watching raw traffic, or scripting.
- **`fetch_tokens.py`** — logs into your Xiaomi account and dumps the
  Bluetooth address + login token for every device on it, including the
  charger's — which the two tools above need.

## One-time setup

You need Python 3. The `.venv/` folder these instructions assume isn't
checked into git (it's a local Python install, not source code), so create
it yourself the first time:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

That installs everything these scripts need into `.venv/` without touching
your system Python. Every command below runs through `.venv/bin/python` for
the same reason — no need to activate the virtual environment first.

If you ever delete `.venv/` and want it back, just re-run those two
commands.

## Step 1: Get your charger's address and token

The charger's Bluetooth connection is locked with a login token that's
unique to your device. Xiaomi stores it in your Mi Cloud account, so you
log in once to fetch it:

```bash
.venv/bin/python fetch_tokens.py
```

- It will ask for your Xiaomi account email/phone and password.
- If Xiaomi shows a CAPTCHA, this script opens a tiny local page at
  `http://127.0.0.1:31415` — open that in your browser, read the code, and
  type it back into the terminal.
- If your account has two-factor authentication, check your email for a
  code and enter it when prompted.
- It then checks all 8 of Xiaomi's regional servers (your account's data
  doesn't have to live on the one matching your account's country) and
  prints every device it finds, one home at a time, marking the charger
  specifically:

  ```
  server 'cn', home <home id> ('<your userId>'): 2 device(s)
  [+] ijai.vacuum.v13  'Living room vacuum'
      did:     1025488531
      address: 58:B6:23:22:B7:11
      token:   <32 hex chars>
  [+] njcuk.fitting.ad1204  'CUKTECH 10 GaN Charger Ultra'  <== CUKTECH/AD1204 charger
      did:     blt.3.xxxxxxxxxxxx
      address: AA:BB:CC:DD:EE:FF
      token:   <24 hex chars>
      --> .venv/bin/python dashboard.py --token <24 hex chars> --address AA:BB:CC:DD:EE:FF
  [-] no homes found on server 'de'
  ...
  ```

  Copy the `-->` line under the charger entry — that's your ready-to-run
  command for the next step. (Every other device's token is printed too, in
  case you need it for something else — but treat every token on that list
  as a password, not just the charger's.)

  If you already know which region your account is on, `--region cn` (or
  `de`/`us`/`ru`/`tw`/`sg`/`in`/`i2`) skips checking the other seven.

Your login session is cached (`xiaomi.token`) so you generally only need to
do this once. **Treat that token, and the charger's token above, as
passwords** — don't share them or commit them anywhere public. If you ever
re-pair the charger in the Mi Home app, its token changes and you'll need to
run this step again.

On a Mac, Bluetooth addresses aren't exposed the normal way — you can leave
out `--address` and the tools will scan for the charger automatically
instead (see below).

## Step 2: Watch the dashboard

```bash
.venv/bin/python dashboard.py --token <your token> [--address <your address>]
```

On macOS, `--address` is optional — if the charger is awake, it'll be found
automatically by scanning. On first run, macOS will ask permission for
Bluetooth access; allow it.

You'll see a live table like:

AD1204
```
┌─────────┬─────────┬─────────┬────────┬──────────┬────────────────┐
│ Port    │ Voltage │ Current │ Power  │ Protocol │ Load           │
├─────────┼─────────┼─────────┼────────┼──────────┼────────────────┤
│ USB-C1  │  20.0 V │   3.0 A │ 60.0 W │ PD/100W  │ ████████░░░░░░ │
│ USB-C2  │   —     │   —     │  —     │ —        │ ░░░░░░░░░░░░░░ │
│ USB-C3  │   —     │   —     │  —     │ —        │ ░░░░░░░░░░░░░░ │
│ USB-A   │   —     │   —     │  —     │ —        │ ░░░░░░░░░░░░░░ │
├─────────┼─────────┼─────────┼────────┼──────────┼────────────────┤
│ TOTAL   │         │         │ 60.0 W │          │ ████████░░░░░░ │
└─────────┴─────────┴─────────┴────────┴──────────┴────────────────┘
```

C2C615U
```
┌─────────┬─────────┬─────────┬────────┬──────────┬────────────────┬──────────────────────┐
│ Port    │ Voltage │ Current │ Power  │ Protocol │ Load           │ Name                 │
├─────────┼─────────┼─────────┼────────┼──────────┼────────────────┼──────────────────────┤
│ USB-C1  │   5.1 V │   1.7 A │  8.4 W │ 5V       │ ██░░░░░░░░░░░░ │ unknow unknow        │
│ USB-C2  │   5.1 V │   2.3 A │ 11.6 W │ 5V       │ ██░░░░░░░░░░░░ │ Nintendo Switch 2    │
│ Input   │  11.8 V │   1.8 A │ 21.3 W │ PD       │ ████░░░░░░░░░░ │ Cuktech Adapter Type │
├─────────┼─────────┼─────────┼────────┼──────────┼────────────────┼──────────────────────┤
│ TOTAL   │         │         │ 19.8 W │          │ ████████░░░░░░ │                      │
└─────────┴─────────┴─────────┴────────┴──────────┴────────────────┴──────────────────────┘
```

A port only shows numbers once something is actually plugged in and drawing
power — the charger only reports changes, so idle ports just show `—`.

Add `--csv mylog.csv` to also log every reading to a CSV file you can open
in Excel/Numbers/Sheets later:

```bash
.venv/bin/python dashboard.py --token <your token> --csv mylog.csv
```

Press **Ctrl+C** to quit.

### Changing settings from the dashboard

While the dashboard is running, press **`s`** to open a settings menu. You
can change:

- **Scene mode** (AI / Apple / Single / Balance — how the charger splits
  power across ports)
- **Screen-off timeout** (how long before the charger's display sleeps)
- **Language** (charger's on-device display language)
- **Brightness** (1–5)

Pick a setting with its number key, pick a value with its number key, then
confirm with **`y`** (or cancel with **`n`**/`x`). Nothing is sent to the
charger until you confirm — this changes the physical device's behavior, so
only confirm changes you actually intend.

## Alternative: one-off commands with ad1204_ble.py

If you don't want the live dashboard — e.g. you just want to check current
values once, or change one setting from a script — use `ad1204_ble.py`
directly:

```bash
# Read everything once and exit
.venv/bin/python ad1204_ble.py --token <your token>

# Read once, then also print live updates for 30 seconds
.venv/bin/python ad1204_ble.py --token <your token> --watch 30

# Change a setting (siid-piid=value)
.venv/bin/python ad1204_ble.py --token <your token> --set 2-5=1   # scene mode = AI
```

## Troubleshooting

**"device not found" / it can't connect**
- Close the Mi Home app first — the charger only accepts one Bluetooth
  connection at a time, and if the app is connected, these tools can't get
  in (and vice versa).
- Make sure the charger is awake: its display goes to sleep and it stops
  broadcasting over Bluetooth when idle. Wake the display or plug something
  in, then try again.
- Bluetooth scanning is a bit flaky by nature — if it doesn't find the
  charger on the first try, just run the command again.

**Login/auth fails with a key mismatch**
- If you recently re-paired the charger in the Mi Home app, its token
  rotated. Re-run `fetch_tokens.py` to get the new one.

**macOS asks for Bluetooth permission**
- Approve it — it only needs to ask once per Python installation. Don't run
  the scan repeatedly in a tight loop while waiting; give each attempt a
  few seconds.

**Xiaomi only lets me request a couple of 2FA codes per day**
- That's a Xiaomi account rate limit, not something these tools control.
  Once logged in, your session is cached so you shouldn't need to log in
  again for a while.

## A note on safety

Changing a setting (scene mode, screen-off timer, port state, etc.) changes
your physical device's actual behavior right now — it's not a simulation.
The dashboard's settings menu always asks for a `y`/`n` confirmation before
sending anything, precisely so you don't do this by accident.
