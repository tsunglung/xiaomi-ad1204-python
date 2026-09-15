#!/usr/bin/env python3
"""
fetch_tokens.py — log in to Mi Cloud (captcha/2FA-capable, Xiaomi-cloud-tokens-extractor
style) and dump every device's did/mac/token on the account.
"""

import random
import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
import re

try:
    import requests
except ImportError:
    sys.exit("pip install requests first")

ACCOUNT = "https://account.xiaomi.com"
CAPTCHA_PORT = 31415
OUTDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugin_out")
TOKEN_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xiaomi.token")

# Login is account-wide; home/device data lives on one specific regional
# server that doesn't have to match the device's model region. When --region
# isn't given, we check all of these (matches Xiaomi-cloud-tokens-extractor).
SERVERS = ["cn", "de", "us", "ru", "tw", "sg", "in", "i2"]


# ----------------------------------------------------------------- rc4 helpers
def rc4(key_bytes: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for _ in range(1024):                            # drop 1024
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def rc4_enc(key_b64: str, text: str) -> str:
    return base64.b64encode(rc4(base64.b64decode(key_b64), text.encode())).decode()


def rc4_dec(key_b64: str, payload: str) -> bytes:
    return rc4(base64.b64decode(key_b64), base64.b64decode(payload))


# ----------------------------------------------------------------- captcha server
def serve_captcha(image: bytes, stop: threading.Event):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(image)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", CAPTCHA_PORT), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    path = os.path.join(OUTDIR, "captcha.png")
    os.makedirs(OUTDIR, exist_ok=True)
    with open(path, "wb") as f:
        f.write(image)
    print(f"[!] CAPTCHA required. Open http://127.0.0.1:{CAPTCHA_PORT} in a browser "
          f"(image also saved to {path}), solve it, then enter the code.")
    code = input("captcha code (case-sensitive): ").strip()
    stop.set()
    srv.shutdown()
    return code


# ----------------------------------------------------------------- connector
class MiCloud:
    def __init__(self):
        self.agent = ("".join(chr(random.randint(97, 122)) for _ in range(18))
                      + "-" + "".join(chr(random.randint(65, 69)) for _ in range(13))
                      + " APP/com.xiaomi.mihome APPV/10.5.201")
        self.device_id = "".join(chr(random.randint(97, 122)) for _ in range(6))
        self.s = requests.Session()
        self.s.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="mi.com")
        self.s.cookies.set("sdkVersion", "accountsdk-18.8.15", domain="xiaomi.com")
        self.s.cookies.set("deviceId", self.device_id, domain="mi.com")
        self.s.cookies.set("deviceId", self.device_id, domain="xiaomi.com")
        self.username = self.password = None
        self.ssecurity = None
        self.userId = None
        self.serviceToken = None

    @staticmethod
    def api_url(region):
        return "https://" + ("" if region == "cn" else region + ".") + "api.io.mi.com/app"

    # ---- login (region-independent — account.xiaomi.com, not api.io.mi.com) ----
    def login(self, username, password):
        self.username, self.password = username, password
        print(f"[*] logging in to Xiaomi account {username}")
        if not self._login_step_1():
            sys.exit("[-] invalid username (step 1)")
        if not self._login_step_2():
            sys.exit("[-] invalid login/password (step 2)")
        if getattr(self, "location", None) and not self.serviceToken and not self._login_step_3():
            sys.exit("[-] could not get service token (step 3)")
        print(f"[+] logged in, userId={self.userId}")
        with open(TOKEN_FILE, "w") as f:
            json.dump({"userId": self.userId, "ssecurity": self.ssecurity,
                       "serviceToken": self.serviceToken}, f)
        print(f"[+] credentials cached in {TOKEN_FILE}")

    def load_token(self):
        if os.path.isfile(TOKEN_FILE):
            try:
                t = json.load(open(TOKEN_FILE))
                if t.get("ssecurity") and t.get("serviceToken") and t.get("userId"):
                    self.ssecurity = t["ssecurity"]
                    self.userId = t["userId"]
                    self.serviceToken = t["serviceToken"]
                    print(f"[+] using cached credentials from {TOKEN_FILE}")
                    return True
            except Exception:
                pass
        return False

    def _login_step_1(self):
        r = self.s.get(f"{ACCOUNT}/pass/serviceLogin?sid=xiaomiio&_json=true",
                       headers={"User-Agent": self.agent,
                                "Content-Type": "application/x-www-form-urlencoded"},
                       cookies={"userId": self.username})
        js = json.loads(r.text.replace("&&&START&&&", ""))
        if "_sign" in js:
            self.sign = js["_sign"]
            return True
        if "ssecurity" in js:      # already logged in via cookies
            self.ssecurity, self.userId = js["ssecurity"], js["userId"]
            self.pass_token, self.location = js.get("passToken"), js.get("location")
            return True
        return False

    def _login_step_2(self):
        fields = {"sid": "xiaomiio",
                  "hash": hashlib.md5(self.password.encode()).hexdigest().upper(),
                  "callback": "https://sts.api.io.mi.com/sts",
                  "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
                  "user": self.username, "_sign": self.sign, "_json": "true"}
        r = self.s.post(f"{ACCOUNT}/pass/serviceLoginAuth2", params=fields,
                        headers={"User-Agent": self.agent,
                                 "Content-Type": "application/x-www-form-urlencoded"},
                        allow_redirects=False)
        js = json.loads(r.text.replace("&&&START&&&", ""))

        if js.get("captchaUrl"):
            url = js["captchaUrl"]
            if url.startswith("/"):
                url = "https://account.xiaomi.com" + url
            img = self.s.get(url).content
            code = serve_captcha(img, threading.Event())
            fields["captCode"] = code
            r = self.s.post(f"{ACCOUNT}/pass/serviceLoginAuth2", params=fields,
                            headers={"User-Agent": self.agent,
                                     "Content-Type": "application/x-www-form-urlencoded"},
                            allow_redirects=False)
            js = json.loads(r.text.replace("&&&START&&&", ""))
            if js.get("code") == 87001:
                sys.exit("[-] invalid captcha")

        if "ssecurity" in js and len(str(js["ssecurity"])) > 4:
            self.ssecurity, self.userId = js["ssecurity"], js.get("userId")
            self.pass_token, self.location = js.get("passToken"), js.get("location")
            return True
        if js.get("notificationUrl"):
            return self._2fa_email(js["notificationUrl"])
        print(f"[-] login_step_2 returned: {js}")
        return False

    def _login_step_3(self):
        r = self.s.get(self.location, headers={"User-Agent": self.agent})
        self.serviceToken = r.cookies.get("serviceToken")
        return r.status_code == 200 and self.serviceToken

    def _2fa_email(self, notification_url):
        h = {"User-Agent": self.agent, "Content-Type": "application/x-www-form-urlencoded"}
        print("[!] two-factor authentication required")
        self.s.get(notification_url, headers=h)
        context = parse_qs(urlparse(notification_url).query)["context"][0]
        list_params = {"sid": "xiaomiio", "context": context, "_locale": "en_US"}
        self.s.get(f"{ACCOUNT}/identity/list", params=list_params, headers=h)
        send_params = {"_dc": str(int(time.time() * 1000)), "sid": "xiaomiio",
                       "context": context, "mask": "0", "_locale": "en_US"}
        send_data = {"retry": "0", "icode": "", "_json": "true",
                     "ick": self.s.cookies.get("ick", "")}
        self.s.post(f"{ACCOUNT}/identity/auth/sendEmailTicket",
                    params=send_params, data=send_data, headers=h)
        code = input("2FA code (check your email): ").strip()
        verify_params = {"_flag": "8", "_json": "true", "sid": "xiaomiio",
                         "context": context, "mask": "0", "_locale": "en_US"}
        verify_data = {"_flag": "8", "ticket": code, "trust": "false", "_json": "true",
                       "ick": self.s.cookies.get("ick", "")}
        r = self.s.post(f"{ACCOUNT}/identity/auth/verifyEmail",
                        params=verify_params, data=verify_data, headers=h)
        finish_loc = None
        try:
            finish_loc = r.json().get("location")
        except Exception:
            finish_loc = r.headers.get("Location")
            m = re.search(r'https://account\.xiaomi\.com/identity/result/check\?[^"\']+', r.text)
            if not finish_loc and m:
                finish_loc = m.group(0)
        if not finish_loc:
            r0 = self.s.get(f"{ACCOUNT}/identity/result/check",
                            params={"sid": "xiaomiio", "context": context, "_locale": "en_US"},
                            headers=h, allow_redirects=False)
            finish_loc = r0.url if "serviceLoginAuth2/end" in r0.url else r0.headers.get("Location")
        if not finish_loc:
            return False
        if "identity/result/check" in finish_loc:
            r = self.s.get(finish_loc, headers=h, allow_redirects=False)
            end_url = r.headers.get("Location")
        else:
            end_url = finish_loc
        if not end_url:
            return False
        r = self.s.get(end_url, headers=h, allow_redirects=False)
        if r.status_code == 200 and "Xiaomi Account - Tips" in r.text:
            r = self.s.get(end_url, headers=h, allow_redirects=False)
        ext = r.headers.get("extension-pragma")
        if ext:
            try:
                self.ssecurity = json.loads(ext).get("ssecurity")
            except Exception:
                pass
        if not self.ssecurity:
            print("[-] extension-pragma missing ssecurity")
            return False
        sts = r.headers.get("Location")
        if not sts and r.text:
            i = r.text.find("https://sts.api.io.mi.com/sts")
            if i != -1:
                j = r.text.find('"', i)
                sts = r.text[i:(j if j != -1 else i + 300)]
        if not sts:
            print("[-] no STS redirect after 2FA")
            return False
        r = self.s.get(sts, headers=h, allow_redirects=True)
        self.serviceToken = self.s.cookies.get("serviceToken", domain=".sts.api.io.mi.com") \
            or self.s.cookies.get("serviceToken")
        self.userId = self.userId or self.s.cookies.get("userId", domain=".xiaomi.com") \
            or self.s.cookies.get("userId", domain=".sts.api.io.mi.com")
        return bool(self.serviceToken)

    # ---- encrypted API ----
    def api(self, country, path, data_obj):
        url = self.api_url(country) + path
        data = json.dumps(data_obj) if not isinstance(data_obj, str) else data_obj
        millis = round(time.time() * 1000)
        nonce = base64.b64encode(os.urandom(8) + int(millis / 60000).to_bytes(4, "big")).decode()
        snonce = base64.b64encode(hashlib.sha256(
            base64.b64decode(self.ssecurity) + base64.b64decode(nonce)).digest()).decode()

        def enc_sig(params):
            parts = ["POST", url.split("com")[1].replace("/app/", "/")]
            parts += [f"{k}={v}" for k, v in params.items()]
            parts.append(snonce)
            return base64.b64encode(hashlib.sha1("&".join(parts).encode()).digest()).decode()

        params = {"data": data}
        params["rc4_hash__"] = enc_sig(params)
        for k in list(params):
            params[k] = rc4_enc(snonce, params[k])
        params["signature"] = enc_sig(params)
        params["ssecurity"] = self.ssecurity
        params["_nonce"] = nonce

        cookies = {"userId": str(self.userId),
                   "yetAnotherServiceToken": self.serviceToken,
                   "serviceToken": self.serviceToken,
                   "locale": "en_GB", "timezone": "GMT+02:00", "is_daylight": "1",
                   "dst_offset": "3600000", "channel": "MI_APP_STORE"}
        r = self.s.post(url, headers={"Accept-Encoding": "identity", "User-Agent": self.agent,
                                      "Content-Type": "application/x-www-form-urlencoded",
                                      "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
                                      "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4"},
                        cookies=cookies, params=params)
        if r.status_code != 200:
            raise RuntimeError(f"{path} -> HTTP {r.status_code}: {r.text[:200]}")
        return json.loads(rc4_dec(snonce, r.text))

    # ---- high level ----
    def homes(self, country):
        return self.api(country, "/v2/homeroom/gethome",
                        {"fg": True, "fetch_share": True, "fetch_share_dev": True,
                         "limit": 300, "app_ver": 7})

    def dev_cnt(self, country):
        """Shared/family homes — devices someone else's account shared with you.
        Not returned by homes(); own_homes()'s homelist only covers your own."""
        return self.api(country, "/v2/user/get_device_cnt",
                        {"fetch_own": True, "fetch_share": True})

    def devices(self, country, home_id, owner_id):
        return self.api(country, "/v2/home/home_device_list",
                        {"home_owner": owner_id, "home_id": home_id,
                         "limit": 200, "get_split_device": True, "support_smart_home": True})


def main():
    ap = argparse.ArgumentParser(
        description="Log in to Mi Cloud and dump did/mac/token for every device on the account")
    ap.add_argument("--user")
    ap.add_argument("--pass", dest="password")
    ap.add_argument("--region", choices=SERVERS,
                    help="check only this server (cn|de|us|ru|tw|sg|in|i2); "
                         "default: check all of them, since your account's home data "
                         "doesn't have to live on the server matching a device's model")
    args = ap.parse_args()

    mc = MiCloud()
    if not mc.load_token():
        user = args.user or os.environ.get("MI_USER") or input("Mi account (email/phone/ID): ")
        password = args.password or os.environ.get("MI_PASS") or getpass.getpass("Mi password: ")
        mc.login(user, password)

    servers = [args.region] if args.region else SERVERS
    total = 0
    for country in servers:
        homes = []
        own = mc.homes(country)
        if own and own.get("result"):
            for h in own["result"].get("homelist", []) or []:
                homes.append({"id": h.get("id"), "name": h.get("name"), "owner": mc.userId})
        shared = mc.dev_cnt(country)
        if shared and shared.get("result"):
            for h in shared["result"].get("share", {}).get("share_family", []) or []:
                homes.append({"id": h.get("home_id"), "name": h.get("home_id"), "owner": h.get("home_owner")})

        if not homes:
            print(f"[-] no homes found on server {country!r}")
            continue

        for home in homes:
            resp = mc.devices(country, home["id"], home["owner"])
            devs = (resp.get("result") or {}).get("device_info") or [] if resp else []
            print(f"\nserver {country!r}, home {home['id']} ({home['name']!r}): {len(devs)} device(s)")
            for d in devs:
                total += 1
                model = d.get("model") or "?"
                mac = d.get("mac") or d.get("bssid") or d.get("localip") or "?"
                token = d.get("token") or "?"
                is_charger = model.startswith("njcuk")
                print(f"[+] {model}  {d.get('name')!r}{'  <== CUKTECH/AD1204 charger' if is_charger else ''}")
                print(f"    did:     {d.get('did')}")
                print(f"    address: {mac}")
                print(f"    token:   {token}")
                if is_charger:
                    print(f"    --> .venv/bin/python dashboard.py --token {token} --address {mac}")

    if total == 0:
        sys.exit("[-] no devices found on this account (checked: " + ", ".join(servers) + ")")


if __name__ == "__main__":
    main()
