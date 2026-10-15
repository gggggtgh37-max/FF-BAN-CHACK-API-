import asyncio
import json
import os
import re
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Unity-Version": "2018.4.11f1",
    "ReleaseVersion": "OB55",
}
BAN_KEYWORDS = ["banned", "ban", "suspended", "frozen", "blacklist",
                "restricted", "violation", "cheat", "permanent", "locked"]

def encode_varint(value):
    out = bytearray()
    while True:
        b = value & 0x7f
        value >>= 7
        if value:
            b |= 0x80
        out.append(b)
        if not value:
            break
    return bytes(out)

def encrypt_uid(uid):
    payload = bytes([0x08]) + encode_varint(int(uid)) + bytes.fromhex("10071801")
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(payload, AES.block_size))

async def check_uid(uid):
    timeout = httpx.Timeout(12.0, connect=6.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        response = await client.post(
            "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
            headers=HEADERS, content=encrypt_uid(uid)
        )
    if response.status_code not in (200, 201):
        return {"uid": uid, "status": "UNKNOWN",
                "error": "Upstream service returned HTTP " + str(response.status_code)}
    raw = response.content
    if len(raw) % 16:
        raw += b"\x00" * (16 - len(raw) % 16)
    try:
        decrypted = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).decrypt(raw)
    except Exception:
        decrypted = response.content
    text = decrypted.decode("utf-8", errors="ignore").lower()
    # This is a heuristic, not an authoritative ban determination.
    hits = [word for word in BAN_KEYWORDS if word in text]
    if hits:
        return {"uid": uid, "status": "BANNED", "indicators": hits,
                "note": "Heuristic indicators found; verify in the official game."}
    return {"uid": uid, "status": "UNKNOWN", "indicators": [],
            "note": "No reliable ban signal could be confirmed from this response."}

class handler(BaseHTTPRequestHandler):
    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_json(200, {"ok": True})

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/api", "/api/"):
            self.send_json(200, {
                "ok": True,
                "service": "FF Ban Check API",
                "usage": "/bancheck?uid=PLAYER_UID",
                "warning": "Results are heuristic and may be UNKNOWN; verify through the official game."
            })
            return

        if parsed.path not in ("/bancheck", "/api/bancheck"):
            self.send_json(404, {"ok": False, "error": "Route not found",
                                 "routes": ["/", "/bancheck?uid=PLAYER_UID"]})
            return

        query = parse_qs(parsed.query)
        uid = (query.get("uid") or [""])[0].strip()
        if not re.fullmatch(r"\d{5,15}", uid):
            self.send_json(400, {"ok": False, "error": "Provide a numeric uid (5–15 digits)."})
            return
        try:
            result = asyncio.run(check_uid(uid))
            self.send_json(200, {"ok": True, "result": result})
        except httpx.TimeoutException:
            self.send_json(504, {"ok": False, "error": "Upstream request timed out; try again later."})
        except httpx.HTTPError:
            self.send_json(502, {"ok": False, "error": "Could not reach upstream service."})
        except Exception:
            self.send_json(500, {"ok": False, "error": "Internal server error."})
      
