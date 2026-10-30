#!/usr/bin/env python3
"""
ad1204_ble.py — talk to the CUKTECH 10 / AD1204 GaN charger over BLE.

Implements the Mi Home "standard auth" (mible v2) LOGIN followed by the
spec-v2 ("object protocol") channel, as reverse-engineered from the Mi Home
APK (see ad1204-protocol.md) and cross-checked against nokistin/xiaomi-s400-live.

You need (from fetch_tokens.py, or Xiaomi-cloud-tokens-extractor):
    MAC   <your charger's MAC, e.g. AA:BB:CC:DD:EE:FF>
    TOKEN <your 12-byte mible login token (HKDF input), 24 hex chars>

Usage (macOS: BLE addresses are opaque, so we scan for the 0xFE95 service and
match by name; on Linux/Windows you can pass --address with the real MAC):

    pip install bleak
    python3 ad1204_ble.py --token <token>                               # login + dump all props
    python3 ad1204_ble.py --token ... --watch                          # + live property pushes
    python3 ad1204_ble.py --token ... --set 2-5=1                      # scene-mode = AI
    python3 ad1204_ble.py --token ... --name CUKTECH                   # name filter for scan

Flow:
  1. connect, subscribe 0x0010 (UPNP ctrl) + 0x0019 (AVDTP auth data)
  2. LOGIN: 0x24 -> key exchange -> HKDF-SHA256(token, salt=app_rand||dev_rand,
     info="mible-login-info", 64) -> HMAC-SHA256 mutual auth -> 0x15 on 0x0010
  3. spec-v2 frames: AES-CCM-128(tag4), nonce = iv4||0000||ctr2||flag2,
     get=0x02/set=0x00/action=0x05 written to 0x001A (no rsp),
     responses pushed on 0x001B (opcodes 1,3,4,6,7,0xF0)
"""

import argparse
import asyncio
import json
import os
import struct
import sys
import time

try:
    from bleak import BleakClient, BleakScanner
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from bleak.exc import BleakDeviceNotFoundError
except ImportError:
    sys.exit("pip install bleak cryptography")

from usbids_helper import usb_list_find


# ---------------------------------------------------------------- constants
UUID = lambda n: f"0000{n:04x}-0000-1000-8000-00805f9b34fb"
SVC = UUID(0xFE95)
UPNP = UUID(0x0010)   # control opcodes (plaintext 4B LE commands)
AVDTP = UUID(0x0019)  # auth data (multiframe)
SPEC_TX = UUID(0x001A)  # spec-v2 app->device (encrypted)
SPEC_RX = UUID(0x001B)  # spec-v2 device->app notify (encrypted)

CMD_LOGIN = bytes.fromhex("24000000")
CMD_LOGIN_OK = bytes.fromhex("21000000")   # 0x21 (APK: Framer.ENTER_FRAME_PREFIX, = S400 CFM_LOGIN_OK)
CMD_LOGIN_FAIL = bytes.fromhex("22000000")
CMD_LOGIN_ERR2 = bytes.fromhex("23000000")
CMD_ERR_E0 = bytes.fromhex("e0000000")
CMD_ERR_E2 = bytes.fromhex("e2000000")

RCV_RDY = bytes.fromhex("00000101")
RCV_OK = bytes.fromhex("00000100")
SEND_KEY = bytes.fromhex("0000000b0100")
SEND_INFO = bytes.fromhex("0000000a0200")

SPEC_FLAG = 0x2000
OP_SET, OP_GET, OP_ACTION = 0x00, 0x02, 0x05
OP_SET_RESP, OP_GET_RESP, OP_CHANGED, OP_ACTION_RESP, OP_EVENT, OP_STATUS = 1, 3, 4, 6, 7, 0xF0

# from miot-spec.org, njcuk.fitting.1204e / njcuk.fitting.ad1204
LABELS = {
    1: {1: "manufacturer", 2: "model", 3: "device-id", 4: "fw-version", 5: "serial-number"},
    2: {
        1: "stat-u32-1 (per-port energy?)", 2: "stat-u32-2", 3: "stat-u32-3", 4: "stat-u32-4",
        5: "scene-mode {1:AI,2:Apple,3:Single,4:Balance}", 6: "screen-off {0:5m,1:10m,2:30m,3:off,4:1m}",
        7: "port-state-u8-1", 8: "port-state-u8-2",
        9: "port-u16-1 (watts?)", 10: "port-u16-2", 11: "port-u16-3", 12: "port-u16-4",
        13: "language {0:EN,1:CN}", 14: "brightness [1..5]",
        15: "bool-1", 16: "misc-u8", 17: "stat-u32-5", 18: "stat-u32-6",
        19: "bool-2", 20: "bool-3", 21: "stat-u32-7",
    },
}
LABELS_C2C615 = {
    1: {1: "manufacturer", 2: "model", 3: "device-id", 4: "fw-version", 5: "serial-number"},
    2: {
        1: "screen-onoff",
        2: "screen-interval {0:off,2:2s,5:5s,8:8s,10:10s}",
        3: "brightness [0..100]"
    }
}
ENUMS = {  # (siid, piid) -> {value: label}
    (2, 5): {1: "AI", 2: "Apple", 3: "Single", 4: "Balance"},
    (2, 6): {0: "5min", 1: "10min", 2: "30min", 3: "off", 4: "1min"},
    (2, 13): {0: "English", 1: "Chinese"},
}
TYPES = ["bool", "uint8", "int8", "uint16", "int16", "uint32", "int32", "uint64", "int64", "float", "string"]


class AuthError(RuntimeError):
    pass


# ---------------------------------------------------------------- crypto
def hkdf_login(token: bytes, app_rand: bytes, dev_rand: bytes) -> bytes:
    """HKDF-SHA256(ikm=token, salt=app_rand||dev_rand, info='mible-login-info', 64)."""
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        return HKDF(algorithm=hashes.SHA256(), length=64, salt=app_rand + dev_rand,
                    info=b"mible-login-info").derive(token)
    except Exception:
        # minimal standalone HKDF-SHA256
        import hmac as _hmac
        from hashlib import sha256 as _sha
        prk = _hmac.new(app_rand + dev_rand, token, _sha).digest()  # HMAC(key=salt, data=ikm)
        okm, t, i = b"", b"", 1
        while len(okm) < 64:
            t = _hmac.new(prk, t + b"mible-login-info" + bytes([i]), _sha).digest()
            okm += t
            i += 1
        return okm[:64]


def hmac256(key: bytes, data: bytes) -> bytes:
    import hmac
    from hashlib import sha256
    return hmac.new(key, data, sha256).digest()


class Session:
    """tr0-equivalent session crypto (APK: _m_j/tr0.java + sr0.java)."""

    def __init__(self, material: bytes):
        # HKDF output: [0:16]=dev->app key, [16:32]=app->dev key, [32:36]=rx iv, [36:40]=tx iv
        self.rx_key, self.tx_key = material[0:16], material[16:32]
        self.rx_iv, self.tx_iv = material[32:36], material[36:40]
        self.tx_ctr = 0          # u16, bit15 = direction flag
        self.tx_flag = 0
        self.rx_last_hdr = 0
        self.rx_flag_cnt = 0

    def _ccm(self, key, nonce, data, tag=4):
        return AESCCM(key, tag_length=tag)

    def encrypt(self, plain: bytes) -> bytes:
        nonce = self.tx_iv + bytes(4) + struct.pack("<HH", self.tx_ctr, self.tx_flag)
        ct = self._ccm(self.tx_key, nonce, plain).encrypt(nonce, plain, None)
        frame = struct.pack("<H", self.tx_ctr) + ct
        # sr0.OooO00o(): counter++, flag++ on bit15 flip
        prev_flag = (self.tx_ctr & 0x8000) >> 15
        self.tx_ctr = (self.tx_ctr + 1) & 0xFFFF
        if prev_flag != ((self.tx_ctr & 0x8000) >> 15):
            self.tx_flag = (self.tx_flag + 1) & 0xFFFF
        return frame

    def decrypt(self, frame: bytes) -> bytes:
        if len(frame) < 6:
            raise ValueError("frame too short")
        hdr = struct.unpack("<H", frame[:2])[0]
        nonce = self.rx_iv + bytes(4) + struct.pack("<HH", hdr, self.rx_flag_cnt)
        prev_flag = (self.rx_last_hdr & 0x8000) >> 15
        self.rx_last_hdr = hdr
        if prev_flag != ((hdr & 0x8000) >> 15):
            self.rx_flag_cnt = (self.rx_flag_cnt + 1) & 0xFFFF
        plain = self._ccm(self.rx_key, nonce, frame).decrypt(nonce, frame[2:], None)
        return plain


# ---------------------------------------------------------------- spec v2 codec
def build_get(tid: int, props) -> bytes:
    """props: list of (siid, piid). Frame: len|0x2000, tid, op=2, count, [siid u8, piid u16]*"""
    body = b"".join(bytes([siid]) + struct.pack("<H", piid) for siid, piid in props)
    total = 6 + len(body)
    return struct.pack("<HHBB", total | SPEC_FLAG, tid, OP_GET, len(props)) + body


def build_set(tid: int, siid: int, piid: int, type_idx: int, value: bytes) -> bytes:
    hdr = 6 + 5 + len(value)
    return (struct.pack("<HHB", hdr | SPEC_FLAG, tid, OP_SET)
            + bytes([1])                                   # count
            + bytes([siid]) + struct.pack("<HH", piid, (type_idx << 12) | len(value))
            + value)


def decode_value(tcode: int, raw: bytes):
    t = TYPES[tcode] if 0 <= tcode < len(TYPES) else f"t{tcode}"
    try:
        if t == "bool":
            return bool(raw[0])
        if t == "uint8":
            return raw[0]
        if t == "int8":
            return struct.unpack("<b", raw)[0]
        if t in ("uint16", "int16", "uint32", "int32", "uint64", "int64"):
            return struct.unpack("<" + {"uint16": "H", "int16": "h", "uint32": "I",
                                        "int32": "i", "uint64": "Q", "int64": "q"}[t], raw)[0]
        if t == "float":
            return struct.unpack("<f", raw)[0]
        if t == "string":
            return raw.decode("utf-8", "replace")
    except Exception:
        pass
    return raw.hex()


def parse_packet(buf: bytes):
    """Parse a spec-v2 packet (header + objects) into a dict."""
    if len(buf) < 6:
        return None
    hdr, tid = struct.unpack("<HH", buf[:4])
    version, length = hdr >> 12, hdr & 0x1FFF
    opcode = buf[4]
    off = 5

    def u8():
        nonlocal off
        v = buf[off]
        off += 1
        return v

    def u16():
        nonlocal off
        v = struct.unpack("<H", buf[off:off + 2])[0]
        off += 2
        return v

    def obj_val():
        nonlocal off
        tl = u16()
        tcode, ln = tl >> 12, tl & 0xFFF
        raw = buf[off:off + ln]
        off += ln
        return tcode, raw

    out = {"version": version, "len": length, "tid": tid, "opcode": opcode}
    try:
        if opcode == OP_GET_RESP:
            n = u8()
            out["objects"] = []
            for _ in range(n):
                siid, piid, status = u8(), u16(), u16()
                o = {"siid": siid, "piid": piid, "status": status}
                if status == 0 and off + 2 <= len(buf):
                    tcode, raw = obj_val()
                    o["type"], o["value"] = TYPES[tcode] if tcode < 11 else tcode, decode_value(tcode, raw)
                out["objects"].append(o)
        elif opcode == OP_SET_RESP:
            n = u8()
            out["objects"] = [{"siid": u8(), "piid": u16(), "status": u16()} for _ in range(n)]
        elif opcode in (OP_CHANGED,):
            n = u8()
            out["objects"] = []
            for _ in range(n):
                siid, piid = u8(), u16()
                tcode, raw = obj_val()
                out["objects"].append({"siid": siid, "piid": piid,
                                       "type": TYPES[tcode] if tcode < 11 else tcode,
                                       "value": decode_value(tcode, raw)})
        elif opcode == OP_EVENT:
            siid, eiid = u8(), u16()
            n = u8()
            out.update({"siid": siid, "eiid": eiid, "objects": []})
            for _ in range(n):
                piid = u16()
                tcode, raw = obj_val()
                out["objects"].append({"piid": piid, "value": decode_value(tcode, raw)})
        elif opcode == OP_ACTION_RESP:
            out["resp_code"] = u16()
            if off < len(buf):
                n = u8()
                out["objects"] = []
                for _ in range(n):
                    piid = u16()
                    tcode, raw = obj_val()
                    out["objects"].append({"piid": piid, "value": decode_value(tcode, raw)})
        elif opcode == OP_STATUS:
            pass
    except (IndexError, struct.error):
        out["parse_error"] = True
    return out


# ---------------------------------------------------------------- BLE glue
class Charger:
    def __init__(self, token: bytes, name_filter=None, address=None, model="ad1204", verbose=True):
        self.token = token
        self.model = model.lower()
        self.name_filter = name_filter
        self.address = address
        self.verbose = verbose
        self.session = None
        self.upnp_q = asyncio.Queue()
        self.avdtp_q = asyncio.Queue()
        self.spec_q = asyncio.Queue()       # decrypted spec-v2 packets
        self.raw_rx_q = asyncio.Queue()     # (char, raw notify bytes) from 0x001A/0x001B
        self.tid = 1
        self.client = None
        self._pump_task = None

    def log(self, *a):
        if self.verbose:
            print(*a)

    async def find_device(self):
        if self.address:
            return self.address
        self.log("[*] scanning for 0xFE95 devices...")
        devs = await BleakScanner.discover(service_uuids=[SVC], timeout=8.0)
        cands = [d for d in devs if self.name_filter is None
                 or (d.name and self.name_filter.lower() in d.name.lower())]
        if not cands:
            self.log("[!] none found. all 0xFE95 devices:")
            for d in devs:
                self.log(f"    {d.address}  {d.name!r}")
            raise AuthError("device not found — is it plugged in / awake? try --name or --address")
        if len(cands) > 1:
            for d in cands:
                self.log(f"    candidate: {d.address}  {d.name!r}")
        d = cands[0]
        self.log(f"[+] using {d.address} ({d.name!r})")
        return d.address

    async def connect(self):
        addr = await self.find_device()
        self.client = BleakClient(addr)
        await self.client.connect()
        self.log(f"[+] connected, mtu={self.client.mtu_size}")
        await self.client.start_notify(UPNP, self._mk_cb(self.upnp_q))
        await self.client.start_notify(AVDTP, self._mk_cb(self.avdtp_q))
        svc = self.client.services.get_service(SVC)
        if svc is None:
            raise AuthError("service 0xFE95 not present")
        got_rx = False
        for ch in (SPEC_RX, SPEC_TX):
            c = svc.get_characteristic(ch)
            if c is not None and "notify" in (c.properties or []):
                await self.client.start_notify(ch, lambda _h, d, _c=ch: self.raw_rx_q.put_nowait((_c, bytes(d))))
                self.log(f"[+] subscribed notify {ch[:8]}")
                got_rx = got_rx or ch == SPEC_RX
        if not got_rx:
            raise AuthError("no notify characteristic on 0x001B/0x001A")
        if svc.get_characteristic(SPEC_TX) is None:
            raise AuthError("no 0x001A write char — device may not support spec-v2")
        self._pump_task = asyncio.create_task(self._spec_rx_pump())

    def _mk_cb(self, q):
        def cb(_h, data):
            q.put_nowait(bytes(data))
        return cb

    async def _spec_rx_pump(self):
        """Reassemble CMTP multiframe messages on 0x001B/0x001A (APK: SpecWriteChannelManager
        + S400 scale.py _cmtp_pump), tr0-decrypt, push plaintext packets to spec_q."""
        expected, buf, ack_char = 0, b"", None
        while True:
            try:
                char, data = await self.raw_rx_q.get()
            except asyncio.CancelledError:
                return
            self.log(f"  <- {char[4:8]} {data.hex(' ')}")
            if expected == 0 and len(data) >= 6 and data[:3] == b"\x00\x00\x00" and data[5] == 0:
                expected = data[4]
                buf = b""
                ack_char = char
                await self._write(ack_char, RCV_RDY)
                continue
            if expected > 0 and len(data) >= 2:
                buf += data[2:]
                if data[0] >= expected:
                    expected = 0
                    await self._write(ack_char, RCV_OK)
                    try:
                        plain = self.session.decrypt(buf)
                    except Exception as e:
                        self.log(f"  !! decrypt failed: {e} raw={buf.hex(' ')}")
                        continue
                    pkt = parse_packet(plain)
                    if pkt:
                        self.spec_q.put_nowait(pkt)
                continue
            # stray frame without pending reassembly — ignore
        return

    async def _q(self, q, timeout=6.0):
        return await asyncio.wait_for(q.get(), timeout)

    async def _write(self, uuid, data, response=False):
        self.log(f"  -> {uuid[4:8]} {data.hex(' ')}")
        await self.client.write_gatt_char(uuid, data, response=response)

    # ---- AVDTP multiframe (pre-auth, plaintext) ----
    async def _send_parcel(self, payload: bytes, chunk=18, delay=0.05):
        frames = [payload[i:i + chunk] for i in range(0, len(payload), chunk)]
        for n, chunk_data in enumerate(frames, 1):
            await self._write(AVDTP, bytes([n & 0xFF, n >> 8]) + chunk_data)
            await asyncio.sleep(delay)

    async def _recv_parcel(self, timeout=6.0):
        first = await self._q(self.avdtp_q, timeout)
        if first[:3] != b"\x00\x00\x00":
            raise AuthError(f"unexpected AVDTP frame: {first.hex()}")
        count = first[4] | (first[5] << 8)
        await self._write(AVDTP, RCV_RDY)
        buf = b""
        for _ in range(count):
            f = await self._q(self.avdtp_q, timeout)
            buf += f[2:]
        await self._write(AVDTP, RCV_OK)
        return buf

    # ---- login (identical to S400/miauth v2, confirmed in APK login connector) ----
    async def login(self):
        app_rand = os.urandom(16)
        await self._write(UPNP, CMD_LOGIN)
        await self._write(AVDTP, SEND_KEY)
        rdy = await self._q(self.avdtp_q)
        if rdy != RCV_RDY:
            raise AuthError(f"expected RCV_RDY after SEND_KEY, got {rdy.hex()}")
        await self._send_parcel(app_rand)
        ok = await self._q(self.avdtp_q)
        if ok != RCV_OK:
            raise AuthError(f"expected RCV_OK after key, got {ok.hex()}")

        dev_rand = await self._recv_parcel()
        if len(dev_rand) != 16:
            raise AuthError(f"bad dev_rand len {len(dev_rand)}: {dev_rand.hex()}")
        remote_info = await self._recv_parcel()

        material = hkdf_login(self.token, app_rand, dev_rand)
        if remote_info != hmac256(material[0:16], dev_rand + app_rand):
            raise AuthError("HMAC mismatch — wrong/rotated 12-byte token; re-run token extractor")

        our_info = hmac256(material[16:32], app_rand + dev_rand)
        await self._write(AVDTP, SEND_INFO)
        rdy = await self._q(self.avdtp_q)
        if rdy != RCV_RDY:
            raise AuthError(f"expected RCV_RDY after SEND_INFO, got {rdy.hex()}")
        await self._send_parcel(our_info)
        ok = await self._q(self.avdtp_q)
        if ok != RCV_OK:
            raise AuthError(f"expected RCV_OK after info, got {ok.hex()}")

        result = await self._q(self.upnp_q)
        if result != CMD_LOGIN_OK:
            raise AuthError(f"login rejected: {result.hex()}")
        self.session = Session(material)
        self.log("[+] LOGIN OK — encrypted spec channel ready")

    # ---- spec v2 ----
    def _next_tid(self):
        t = self.tid
        self.tid = (self.tid + 1) & 0xFFFF or 1
        return t

    async def get_props(self, props, timeout=6.0):
        frame = build_get(self._next_tid(), props)
        max_plain = self.client.mtu_size - 3 - 2 - 4
        if len(frame) - 4 > max_plain:
            raise AuthError("get batch too large for MTU")
        await self._write(SPEC_TX, self.session.encrypt(frame))
        # spec_q is fed by the pump; wait for a get response
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                pkt = await self._q(self.spec_q, deadline - time.time())
            except asyncio.TimeoutError:
                return None
            if pkt["opcode"] == OP_GET_RESP:
                return pkt
            # unsolicited push while waiting — stash nothing, just surface it
            self.log("[push while waiting]", json.dumps(pkt, ensure_ascii=False))
        return None

    async def set_prop(self, siid, piid, type_idx, value: bytes, timeout=6.0):
        frame = build_set(self._next_tid(), siid, piid, type_idx, value)
        await self._write(SPEC_TX, self.session.encrypt(frame))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                pkt = await self._q(self.spec_q, deadline - time.time())
            except asyncio.TimeoutError:
                return None
            if pkt["opcode"] == OP_SET_RESP:
                return pkt
            if pkt["opcode"] == OP_CHANGED and pkt["objects"][0]["siid"] == siid and pkt["objects"][0]["piid"] == piid:
                return pkt

    async def watch(self, seconds):
        self.log(f"[*] watching spec pushes for {seconds}s ...")
        end = time.time() + seconds
        while time.time() < end:
            try:
                pkt = await self._q(self.spec_q, max(0.1, end - time.time()))
            except asyncio.TimeoutError:
                break
            self.log("[push]", json.dumps(pkt, ensure_ascii=False))

    def pretty(self, pkt):
        if pkt is None:
            return
        for o in pkt.get("objects", []):
            siid, piid = o.get("siid"), o.get("piid")
            if self.model == "c2c615":
                label = LABELS_C2C615.get(siid, {}).get(piid, f"siid{siid}.piid{piid}")
            else:
                label = LABELS.get(siid, {}).get(piid, f"siid{siid}.piid{piid}")
            val = o.get("value", o.get("status"))
            if (siid, piid) in ENUMS and isinstance(val, int):
                val = f"{val} ({ENUMS[(siid, piid)].get(val, '?')})"
            print(f"  siid {siid:>2} piid {piid:>2}  {label:<42} = {val}")

    async def run(self, watch_s=0, sets=None):
        try:
            await self.connect()
        except BleakDeviceNotFoundError:
            print("Charger not found")
            return
        try:
            await self.login()
            if sets:
                for spec, val in sets:
                    siid, piid = map(int, spec.split("-"))
                    # type inference from spec ranges (all SIID2 numerics are uint)
                    for tidx, fmt in ((0, "?"), (1, "B"), (3, "H"), (5, "I")):
                        try:
                            raw = struct.pack("<" + fmt, int(val))
                            break
                        except struct.error:
                            continue
                    print(f"[*] set {siid}-{piid} = {val}")
                    pkt = await self.set_prop(siid, piid, tidx, raw)
                    self.pretty(pkt)
            # dump everything readable
            print("[*] reading all properties ...")
            if self.model == "c2c615":
                all_props = [(s, p) for s, pis in LABELS_C2C615.items() for p in pis]
            else:
                all_props = [(s, p) for s, pis in LABELS.items() for p in pis]
            mtu_batch = max(1, (self.client.mtu_size - 9 - 2) // 3)
            for i in range(0, len(all_props), mtu_batch):
                try:
                    pkt = await self.get_props(all_props[i:i + mtu_batch])
                    self.pretty(pkt)
                except asyncio.TimeoutError:
                    print("  (timeout on batch, skipping)")
            if watch_s:
                await self.watch(watch_s)
        finally:
            await self.client.disconnect()


def main():
    ap = argparse.ArgumentParser(description="CUKTECH/AD1204/C2C615 charger BLE client (mible v2 + spec-v2)")
    ap.add_argument("--token", required=True, help="12-byte login token hex (from token extractor)")
    ap.add_argument("--address", help="MAC (Linux/Win) or peripheral UUID (macOS)")
    ap.add_argument("--name", default=None, help="scan name filter (default: any 0xFE95 device)")
    ap.add_argument("--model", default="ad1204", help="Cuktech BLE Model (default: ad1204)")
    ap.add_argument("--watch", type=int, default=0, metavar="SEC", help="listen for pushes N seconds")
    ap.add_argument("--set", action="append", metavar="SIID-PIID=VALUE", help="set property (e.g. 2-5=1)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    token = bytes.fromhex(args.token.replace(" ", ""))
    if len(token) != 12:
        sys.exit("token must be 12 bytes (24 hex chars)")

    sets = []
    for s in args.set or []:
        spec, val = s.split("=", 1)
        sets.append((spec, val))

    ch = Charger(token, name_filter=args.name, address=args.address, model=args.model, verbose=not args.quiet)
    try:
        asyncio.run(ch.run(watch_s=args.watch, sets=sets))
    except AuthError as e:
        sys.exit(f"[-] {e}")


if __name__ == "__main__":
    main()
