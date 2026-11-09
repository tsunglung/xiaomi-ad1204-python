#!/usr/bin/env python3
"""
dashboard.py — live terminal dashboard for the CUKTECH 10 / AD1204 charger.

Renders one row per port (USB-C1/C2/C3/A) as a live rich table with voltage /
current / computed watts / negotiated protocol / load bar, plus total output.
Data comes from the charger's change-driven telemetry pushes (siid 2, piid 1-4)
— see ad1204-protocol.md. Press 's' while running to open a settings menu
(scene mode, screen-off timeout, language, brightness) — every change is
confirmed (y/n) before it's sent to the device.

Usage:
  python3 dashboard.py --token <12-byte hex> [--address <mac|uuid>] [--csv out.csv]

macOS note: BLE MACs are not exposed; run without --address and pick the device
(we scan for the 0xFE95 service and prefer names containing 'cuk'/'ad1204').
"""

import argparse
import asyncio
import csv
import json
import os
import struct
import sys
import time

try:
    import termios
    import tty
    HAVE_TTY = True
except ImportError:
    HAVE_TTY = False

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

sys.argv = sys.argv or ["dashboard.py"]
import importlib.util

_spec = importlib.util.spec_from_file_location(
    "ble", os.path.join(os.path.dirname(os.path.abspath(__file__)), "ad1204_ble.py"))
ble = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ble)

from bleak import BleakScanner  # noqa: E402
from usbids_helper import usb_list_find

PORTS = {
    1: "USB-C1",
    2: "USB-C2",
    3: "USB-C3",
    4: "USB-A",
}


def bar(frac, width=14):
    frac = max(0.0, min(1.0, frac))
    n = int(frac * width)
    return "█" * n + "░" * (width - n)


class KeyReader:
    """Single-keypress reader (no Enter needed), POSIX cbreak mode.

    No-ops if stdin isn't a TTY (e.g. piped/non-interactive) so the dashboard
    still runs — the settings menu is just unreachable in that case.
    """

    def __init__(self):
        self.queue = asyncio.Queue()
        self.enabled = HAVE_TTY and sys.stdin.isatty()
        self.fd = sys.stdin.fileno() if self.enabled else None
        self._old = None

    def __enter__(self):
        if self.enabled:
            self._old = termios.tcgetattr(self.fd)
            tty.setcbreak(self.fd)
            asyncio.get_event_loop().add_reader(self.fd, self._on_readable)
        return self

    def _on_readable(self):
        ch = os.read(self.fd, 1).decode(errors="ignore")
        if ch:
            self.queue.put_nowait(ch)

    def __exit__(self, exc_type, exc, tb):
        if self.enabled:
            asyncio.get_event_loop().remove_reader(self.fd)
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self._old)
        return False


SETTINGS = [
    {"key": "1", "siid": 2, "piid": 5, "name": "Scene mode", "values": ble.ENUMS[(2, 5)]},
    {"key": "2", "siid": 2, "piid": 6, "name": "Screen-off timeout", "values": ble.ENUMS[(2, 6)]},
    {"key": "3", "siid": 2, "piid": 13, "name": "Language", "values": ble.ENUMS[(2, 13)]},
    {"key": "4", "siid": 2, "piid": 14, "name": "Brightness", "values": {i: str(i) for i in range(1, 6)}},
]

SETTINGS_C2C615U = [
    {"key": "1", "siid": 2, "piid": 1, "name": "Screen on/off", "values": {0: "Off", 1: "On"}},
    {"key": "2", "siid": 2, "piid": 2, "name": "Screen Brightness", "values": {i: str(i * 10) for i in range(0, 10)}},
    {"key": "3", "siid": 2, "piid": 3, "name": "Screen rotation interval", "values": {0: "Off", 2: "2 s", 5: "5 s", 8: "8 s", 10: "10 s"}},
]


class Dashboard:
    PROTO_MIJIA = {0: "idle", 1: "5V", 2: "5V", 3: "QC", 4: "AFC", 5: "FCP",
                   6: "SCP", 7: "PD", 8: "PPS", 9: "PPS", 10: "UFCS"}
    PROTO_HW = {0x30: "PD", 0x60: "USB-A", 0x70: "QC", 0x80: "PD"}

    def __init__(self, token, address, csv_path=None, model="ad1204"):
        self.ch = ble.Charger(token, verbose=False, address=address)
        self.model = model.lower()
        if self.model == "c2c615u":
            PORTS.pop(3, None)
            PORTS.pop(4, None)
            PORTS[3] = "Input"
        self.state = {p: None for p in PORTS}          # piid -> (V, I, X, Y, ts)
        self.proto = {p: (None, None) for p in PORTS}  # piid -> (proto_name, cap_w)
        self.device = {p: ("", "") for p in PORTS}  # piid -> (vid, pid)
        self._csv_file = open(csv_path, "a", newline="") if csv_path else None
        self.csv = csv.writer(self._csv_file) if csv_path else None
        if self.csv:
            self.csv.writerow(["ts", "piid", "port", "volts", "amps", "watts", "proto", "cap_w", "alloc_xy"])
        self.mode = "normal"  # normal | select_setting | select_value | confirm | result
        self.pending_setting = None
        self.pending_value = None
        self.result_ok = None
        self.result_msg = None
        self.result_shown_at = 0.0

    def update_protocol(self, piid, value):
        """piid 17 = C1/C2, piid 18 = C3/A: u32 = [hi_proto][hi_capW][lo_proto][lo_capW]."""
        pairs = ((1, 2), (3, 4))[piid - 17]
        for port, half in zip(pairs, ((value >> 16) & 0xFFFF, value & 0xFFFF)):
            code, cap = (half >> 8) & 0xFF, half & 0xFF
            name = self.PROTO_MIJIA.get(code) or self.PROTO_HW.get(code)
            self.proto[port] = (name or (f"0x{code:02X}" if code else None), cap or None)

    def update(self, pkt):
        for o in pkt.get("objects", []):
            v = o.get("value")
            if o.get("siid") == 2 and o.get("piid") in (17, 18) and isinstance(v, int):
                self.update_protocol(o["piid"], v)
                continue
            if o.get("siid") == 2 and o.get("piid") in PORTS and isinstance(v, int):
                b = v.to_bytes(4, "little")[::-1]       # sent order V I X Y
                volts, amps = b[0] / 10.0, b[1] / 10.0
                self.state[o["piid"]] = (volts, amps, b[2], b[3], time.time())
                if self.csv:
                    pname, cap = self.proto.get(o["piid"], (None, None))
                    self.csv.writerow([f"{time.time():.0f}", o["piid"], PORTS[o["piid"]],
                                       f"{volts:.1f}", f"{amps:.1f}", f"{volts * amps:.2f}",
                                       pname or "", cap if cap is not None else "",
                                       f"{b[2]:02X}{b[3]:02X}"])
                    self._csv_file.flush()
            if o.get("siid") == 2 and o.get("piid") in [5, 9, 12] and isinstance(v, str):
                val = bytearray.fromhex(v)
                if len(val) == 11 and o.get("piid") == 12:
                    cal_checksum = (val[0] + val[1] + val[2] + val[3] + val[4] + val[5] + val[6] + val[7] + val[8] + val[9]) & 0xFF
                    if val[0] == int("0xAA", 16) and cal_checksum == val[10]:
                        volts, amps = (val[1] * 256 + val[2]) / 1000.0, (val[3] * 256 + val[4]) / 1000.0
                        proto = 7 if volts > 1.0 else 0
                        proto = 1 if volts > 4.5 and volts < 5.4 else proto
                        self.state[1] = (volts, amps, proto, 0, time.time())
                        if self.csv:
                            pname, cap = self.proto.get(1, (None, None))
                            self.csv.writerow([f"{time.time():.0f}", 1, PORTS[1],
                                            f"{volts:.1f}", f"{amps:.1f}", f"{volts * amps:.2f}",
                                            pname or "", cap if cap is not None else "",
                                            f"{b[2]:02X}{b[3]:02X}"])
                            self._csv_file.flush()
                        volts, amps = (val[5] * 256 + val[6]) / 1000.0, (val[7] * 256 + val[8]) / 1000.0
                        proto = 7 if volts > 1.0 else 0
                        proto = 1 if volts > 4.5 and volts < 5.4 else proto
                        self.state[2] = (volts, amps, proto, 0, time.time())
                        if self.csv:
                            pname, cap = self.proto.get(2, (None, None))
                            self.csv.writerow([f"{time.time():.0f}", 2, PORTS[2],
                                            f"{volts:.1f}", f"{amps:.1f}", f"{volts * amps:.2f}",
                                            pname or "", cap if cap is not None else "",
                                            f"{b[2]:02X}{b[3]:02X}"])
                            self._csv_file.flush()
                if len(val) == 14 and o.get("piid") == 9:
                    cal_checksum = (val[0] + val[1] + val[2] + val[3] + val[4] + val[5] + val[6] + val[7] + val[8] + val[9] + val[10] + val[11] + val[12]) & 0xFF
                    if val[0] == int("0x77", 16) and cal_checksum == val[13]:
                        self.device[1] = (f"0x{val[1]:02x}{val[2]:02x}", f"0x{val[3]:02x}{val[4]:02x}")
                        self.device[2] = (f"0x{val[7]:02x}{val[8]:02x}", f"0x{val[9]:02x}{val[10]:02x}")
                if len(val) == 11 and o.get("piid") == 5:
                    cal_checksum = (val[0] + val[1] + val[2] + val[3] + val[4] + val[5] + val[6] + val[7] + val[8] + val[9]) & 0xFF
                    if val[0] == int("0x55", 16) and cal_checksum == val[10]:
                        volts, amps = (val[5] * 256 + val[6]) / 1000.0, (val[7] * 256 + val[8]) / 1000.0
                        self.state[3] = (volts, amps, 7, 0, time.time())
                        self.proto[3] = ("PD", None) if volts > 5.3 else ("5V", None)
                        self.device[3] = ("0x2e87", f"0x{((val[1] >> 6) & 0x1):04x}")
                        if self.csv:
                            pname, cap = self.proto.get(3, (None, None))
                            self.csv.writerow([f"{time.time():.0f}", 2, PORTS[3],
                                            f"{volts:.1f}", f"{amps:.1f}", f"{volts * amps:.2f}",
                                            pname or "", cap if cap is not None else "",
                                            f"{b[2]:02X}{b[3]:02X}"])
                            self._csv_file.flush()

    def port_cells(self, p, now):
        """(voltage, current, watts, protocol, load_bar) for one port; None = no data."""
        st = self.state[p]
        if st and now - st[4] < 60:
            volts, amps, x, y, _ = st
            watts = volts * amps
            pname, cap = self.proto.get(p, (None, None))
            if not pname:
                table = self.PROTO_MIJIA if p in (1, 2) else self.PROTO_HW
                pname = table.get(x)
            proto = (pname or "?") + (f"/{cap}W" if cap else "")
            return (f"{volts:.1f} V", f"{amps:.1f} A", watts,
                    proto, bar(watts / 100.0))
        return ("—", "—", None, "—", bar(0.0))

    def build_table(self):
        now = time.time()
        t = Table(box=box.ROUNDED, header_style="bold",
                  title=f"CUKTECH 10 (AD1204/C2C615U)  {time.strftime('%H:%M:%S')}")
        for name, justify in (("Port", "left"), ("Voltage", "right"), ("Current", "right"),
                              ("Power", "right"), ("Protocol", "left"), ("Load", "left")):
            t.add_column(name, justify=justify)

        if self.model == "c2c615u":
            t.add_column("Name", "left")

        total_w = 0.0
        for p in sorted(PORTS):
            volts, amps, watts, proto, load = self.port_cells(p, now)
            if PORTS[p] != "Input":
                total_w += watts or 0.0
            active = watts is not None and watts > 0.25
            if self.model == "c2c615u":
                vendor, name = usb_list_find(self.device[p][0], self.device[p][1])
                t.add_row(PORTS[p], volts, amps,
                        "—" if watts is None else f"{watts:.1f} W",
                        proto, load, f"{vendor} {name}", style="green" if active else "dim")
            else:
                t.add_row(PORTS[p], volts, amps,
                        "—" if watts is None else f"{watts:.1f} W",
                        proto, load, style="green" if active else "dim")


        t.add_section()
        t.add_row("TOTAL", "", "", f"{total_w:.1f} W", "", bar(min(1.0, total_w / 110.0)),
                  style="bold")
        alloc = "  ".join(
            f"{PORTS[p]}:{self.state[p][2]:02X}{self.state[p][3]:02X}"
            for p in sorted(PORTS) if self.state[p]) or "—"
        t.caption = f"alloc (X/Y): {alloc}"
        return t

    def build_menu_region(self):
        if self.mode == "normal":
            return Panel("[dim][s] settings   [Ctrl+C] quit[/dim]", box=box.MINIMAL)
        if self.mode == "select_setting":
            if self.model == "c2c615u":
                ss = SETTINGS_C2C615U
            else:
                ss = SETTINGS
            lines = [f"{s['key']}) {s['name']}" for s in ss] + ["x) cancel"]
            return Panel("\n".join(lines), title="Select setting", border_style="yellow")
        if self.mode == "select_value":
            s = self.pending_setting
            lines = [f"{k}) {v}" for k, v in s["values"].items()] + ["x) cancel"]
            return Panel("\n".join(lines), title=f"Select value — {s['name']}", border_style="yellow")
        if self.mode == "confirm":
            s, v = self.pending_setting, self.pending_value
            return Panel(f"Send {s['name']} = {s['values'][v]} to the device?\n (y) yes   (n) no",
                         title="Confirm", border_style="red")
        if self.mode == "result":
            return Panel(self.result_msg, border_style="green" if self.result_ok else "red")
        return Panel("")

    def render(self):
        return Group(self.build_table(), self.build_menu_region())

    def handle_key(self, ch):
        if self.mode == "normal":
            if ch == "s":
                self.mode = "select_setting"
            return
        if self.mode == "select_setting":
            if ch in ("x", "\x1b"):
                self.mode = "normal"
                return
            if self.model == "c2c615u":
                ss = SETTINGS_C2C615U
            else:
                ss = SETTINGS
            for s in ss:
                if s["key"] == ch:
                    self.pending_setting = s
                    self.mode = "select_value"
                    return
            return
        if self.mode == "select_value":
            if ch in ("x", "\x1b"):
                self.mode = "normal"
                self.pending_setting = None
                return
            for val in self.pending_setting["values"]:
                if str(val) == ch:
                    self.pending_value = val
                    self.mode = "confirm"
                    return
            return
        if self.mode == "confirm":
            if ch == "y":
                return "send"
            if ch in ("n", "x", "\x1b"):
                self.mode = "normal"
                self.pending_setting = None
                self.pending_value = None
            return
        if self.mode == "result":
            # any key dismisses early
            self.mode = "normal"
            return

    async def send_pending_setting(self):
        s, v = self.pending_setting, self.pending_value
        if s['name'] == 'Screen Brightness':
            v = v * 10
        try:
            raw = struct.pack("<B", v)
            pkt = await self.ch.set_prop(s["siid"], s["piid"], 1, raw, timeout=6.0)
            objs = pkt.get("objects") if pkt else None
            ok = bool(objs) and all(o.get("status") == 0 for o in objs)
            self.result_ok = ok
            self.result_msg = (f"✓ {s['name']} = {s['values'][v]}" if ok
                                else f"✗ set failed: {objs if objs is not None else 'no response (timeout)'}")
        except Exception as e:
            self.result_ok = False
            self.result_msg = f"✗ error: {e}"
        self.mode = "result"
        self.result_shown_at = time.time()
        self.pending_setting = None
        self.pending_value = None

    async def run(self):
        await self.ch.connect()
        await self.ch.login()
        live = Live(self.render(), refresh_per_second=4)
        live.console.print("[green][+] connected[/green] — Ctrl+C to quit, 's' for settings")
        with live, KeyReader() as keys:
            while True:
                try:
                    pkt = await asyncio.wait_for(self.ch.spec_q.get(), timeout=0.2)
                    self.update(pkt)
                except asyncio.TimeoutError:
                    pass

                while True:
                    try:
                        k = keys.queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    if self.handle_key(k) == "send":
                        await self.send_pending_setting()

                if self.mode == "result" and time.time() - self.result_shown_at > 2.5:
                    self.mode = "normal"

                live.update(self.render())


async def find_address(name_filter):
    for _ in range(5):
        devs = await BleakScanner.discover(service_uuids=[ble.SVC], timeout=8.0)
        if not devs:
            continue
        if name_filter:
            hits = [d for d in devs if d.name and name_filter.lower() in d.name.lower()]
            if hits:
                return hits[0].address
        return devs[0].address
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="ad1204", help="Cuktech BLE Model (ad1204 or c2c615u, default: ad1204)")
    ap.add_argument("--token", required=True, help="12-byte login token hex (from fetch_tokens.py)")
    ap.add_argument("--address", default=None, help="MAC (Linux/Win) or peripheral UUID (macOS); omit to auto-scan")
    ap.add_argument("--name", default=None, help="scan name filter")
    ap.add_argument("--csv", help="append telemetry to CSV file")
    args = ap.parse_args()

    token = bytes.fromhex(args.token.replace(" ", ""))
    if len(token) != 12:
        sys.exit("token must be 12 bytes")

    async def go():
        addr = args.address or await find_address(args.name)
        if not addr:
            sys.exit("[-] charger not advertising (awake? app disconnected?)")
        print(f"[*] connecting to device...")
        d = Dashboard(token, addr, args.csv, model=args.model)
        try:
            await d.run()
        except asyncio.CancelledError:
            pass
        finally:
            await d.ch.client.disconnect()

    try:
        asyncio.run(go())
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
