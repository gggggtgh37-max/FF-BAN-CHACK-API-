# ═══════════════════════════════════════════════════════════════════════
#  FF BULK BAN CHECKER — Parallel + Original Format Preserved
#  Owner: AGS COMMUNITY
# ═══════════════════════════════════════════════════════════════════════
import os
import sys
import json
import time
import asyncio
import re
from datetime import datetime
from pathlib import Path

import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════════
DEFAULT_WORKERS = 100
MAX_WORKERS     = 300
TIMEOUT         = 15
BANN_FILE       = "bann.json"
UNBAN_FILE      = "unban.json"
DATA_FILE       = "accounts.json"

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

HEADERS = {
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; ASUS_Z01QD Build/PI)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/x-www-form-urlencoded",
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.11f1",
    "X-GA": "v1 1",
    "ReleaseVersion": "OB55",
}

GRN = "\033[92m"; RED = "\033[91m"; YEL = "\033[93m"
CYN = "\033[96m"; DIM = "\033[2m"; RST = "\033[0m"


# ═══════════════════════════════════════════════════════════════════════
#  CRYPTO
# ═══════════════════════════════════════════════════════════════════════
def encrypt_aes(hex_payload: str) -> str:
    c = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    data = bytes.fromhex(hex_payload)
    return c.encrypt(pad(data, AES.block_size)).hex()


def encode_varint(value: int) -> bytes:
    if value < 0:
        value = (1 << 64) + value
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            b |= 0x80
        out.append(b)
        if not value:
            break
    return bytes(out)


def encode_uid_field(uid: int) -> str:
    return (bytes([0x08]) + encode_varint(int(uid))).hex()


# ═══════════════════════════════════════════════════════════════════════
#  UID EXTRACTION (কোন ফিল্ড ব্যবহার করব)
# ═══════════════════════════════════════════════════════════════════════
# priority: account_id > uid > game_uid > ...
UID_KEYS_PRIORITY = [
    "account_id", "accountId",
    "uid", "UID",
    "game_uid", "gameUid",
    "user_id", "userId", "userid",
    "guestUid", "guest_uid",
    "id",
]


def get_uid_from_record(record):
    """
    Returns the best available UID from a record.
    Prefers account_id (which is the FF game uid), then uid, etc.
    Also returns which key was used.
    """
    if not isinstance(record, dict):
        return None, None
    for k in UID_KEYS_PRIORITY:
        if k in record:
            v = record[k]
            if v in (None, "", 0, "0"):
                continue
            try:
                sv = str(v).strip()
                if sv.isdigit():
                    return sv, k
            except Exception:
                pass
    return None, None


# ═══════════════════════════════════════════════════════════════════════
#  ACCOUNT FILE PARSER
# ═══════════════════════════════════════════════════════════════════════
def parse_accounts_from_json(content: str):
    """
    Returns list of raw records (dicts) from various JSON formats.
    Preserves original record exactly.
    """
    content = re.sub(r',\s*}', '}', content)
    content = re.sub(r',\s*]', ']', content)
    try:
        data = json.loads(content)
    except Exception:
        return []

    out = []

    def handle_item(item):
        if isinstance(item, dict):
            uid, key = get_uid_from_record(item)
            if uid:
                out.append({"uid": uid, "src_key": key, "raw": item})
        elif isinstance(item, (int, str)):
            sv = str(item).strip()
            if sv.isdigit():
                out.append({"uid": sv, "src_key": "flat", "raw": sv})

    if isinstance(data, list):
        for item in data:
            handle_item(item)
    elif isinstance(data, dict):
        # wrapper keys
        for key in ("accounts", "users", "data", "list", "uids"):
            if key in data and isinstance(data[key], list):
                for item in data[key]:
                    handle_item(item)
                if out:
                    return out
        # single record
        handle_item(data)
    return out


def parse_accounts_from_text(content: str):
    out = []
    seen = set()
    for tok in re.findall(r'\b\d{8,12}\b', content):
        if tok in seen:
            continue
        seen.add(tok)
        out.append({"uid": tok, "src_key": "regex", "raw": tok})
    return out


def load_accounts(filepath: str):
    p = Path(filepath).expanduser()
    if not p.exists():
        print(f"{RED}❌ File not found: {p}{RST}")
        return []
    content = p.read_text(encoding="utf-8", errors="ignore")
    accounts = parse_accounts_from_json(content)
    if not accounts:
        accounts = parse_accounts_from_text(content)

    # dedupe by uid
    seen = set()
    unique = []
    for acc in accounts:
        if acc["uid"] in seen:
            continue
        seen.add(acc["uid"])
        unique.append(acc)
    return unique


# ═══════════════════════════════════════════════════════════════════════
#  BAN CHECK
# ═══════════════════════════════════════════════════════════════════════
BAN_KEYWORDS = [
    "banned", "ban", "suspended", "frozen",
    "blacklist", "restricted", "violation", "cheat",
    "permanent", "locked",
]

# extra byte hints (FF response may include these in hex)
BAN_BLOCK_HINTS = [
    "0a020801",   # field1=varint1
    "120401000000",
]


def _scan_for_ban(dec: bytes):
    txt = dec.decode("utf-8", errors="ignore").lower()
    hex_str = dec.hex().lower()
    matched = [k for k in BAN_KEYWORDS if k in txt]
    for hint in BAN_BLOCK_HINTS:
        if hint in hex_str:
            matched.append(f"hex:{hint}")
    return matched


async def check_ban_async(client: httpx.AsyncClient, uid: str, retries: int = 2):
    body_hex = encode_uid_field(int(uid)) + "10071801"
    enc_hex = encrypt_aes(body_hex)
    body = bytes.fromhex(enc_hex)
    url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"

    last_err = None
    for attempt in range(retries):
        try:
            r = await client.post(url, headers=HEADERS, data=body, timeout=TIMEOUT)
            if r.status_code not in (200, 201):
                last_err = f"HTTP {r.status_code}"
                await asyncio.sleep(0.3)
                continue

            raw = r.content

            # decrypt
            try:
                if len(raw) % 16 != 0:
                    padded = raw + b"\x00" * (16 - (len(raw) % 16))
                else:
                    padded = raw
                cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
                dec = cipher.decrypt(padded)
            except Exception:
                dec = raw

            matched = _scan_for_ban(dec)
            if matched:
                return {"status": "BANNED", "keywords": matched,
                        "note": "ban indicators found"}
            return {"status": "UNBANNED", "keywords": [],
                    "note": "no ban indicators"}
        except Exception as e:
            last_err = str(e)
            await asyncio.sleep(0.3)

    return {"status": "UNKNOWN", "keywords": [],
            "note": f"check failed: {last_err}"}


# ═══════════════════════════════════════════════════════════════════════
#  BULK RUN
# ═══════════════════════════════════════════════════════════════════════
async def run_bulk(accounts, workers=100):
    results = []
    total = len(accounts)
    done = 0
    lock = asyncio.Lock()
    start_ts = time.time()

    limits = httpx.Limits(
        max_connections=workers * 2,
        max_keepalive_connections=workers,
    )
    timeout = httpx.Timeout(TIMEOUT, connect=8)

    async with httpx.AsyncClient(verify=False, timeout=timeout,
                                 limits=limits) as client:
        sem = asyncio.Semaphore(workers)

        async def worker(acc):
            nonlocal done
            async with sem:
                r = await check_ban_async(client, acc["uid"])
                r["uid"] = acc["uid"]
                r["raw"] = acc["raw"]
                r["src_key"] = acc.get("src_key", "?")
                async with lock:
                    results.append(r)
                    done += 1
                    if done % 10 == 0 or done == total:
                        el = time.time() - start_ts
                        rate = done / el if el > 0 else 0
                        eta = (total - done) / rate if rate > 0 else 0
                        sys.stdout.write(
                            f"\r  {CYN}[{done}/{total}]{RST} "
                            f"{DIM}rate={rate:.1f}/s eta={eta:.0f}s{RST}   "
                        )
                        sys.stdout.flush()

        await asyncio.gather(*(worker(a) for a in accounts))

    sys.stdout.write("\r" + " " * 90 + "\r")
    sys.stdout.flush()
    return results


# ═══════════════════════════════════════════════════════════════════════
#  SAVE — preserve original record format
# ═══════════════════════════════════════════════════════════════════════
def save_split(banned, unbanned, unknown):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # BANNED
    banned_records = [r["raw"] for r in banned]
    with open(BANN_FILE, "w", encoding="utf-8") as f:
        json.dump(banned_records, f, indent=4, ensure_ascii=False)

    # UNBANNED
    unbanned_records = [r["raw"] for r in unbanned]
    with open(UNBAN_FILE, "w", encoding="utf-8") as f:
        json.dump(unbanned_records, f, indent=4, ensure_ascii=False)

    # UNKNOWN (optional)
    if unknown:
        unknown_records = [r["raw"] for r in unknown]
        with open("unknown.json", "w", encoding="utf-8") as f:
            json.dump(unknown_records, f, indent=4, ensure_ascii=False)

    # Also write a small meta file
    meta = {
        "generated_at": ts,
        "banned_count": len(banned_records),
        "unbanned_count": len(unbanned_records),
        "unknown_count": len(unknown),
        "source_records_banned_sample": banned_records[:1],
        "source_records_unbanned_sample": unbanned_records[:1],
    }
    with open("ban_check_meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=4, ensure_ascii=False)


# ═══════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════
def main():
    print("=" * 62)
    print(f"   FF BULK BAN CHECKER — AGS COMMUNITY")
    print("=" * 62)
    print()

    # input file
    print(f"  {CYN}📂 Input file path (default: {DATA_FILE}):{RST}")
    path_input = input("     ❯ ").strip().replace('"', '').replace("'", "")
    filepath = path_input or DATA_FILE

    accounts = load_accounts(filepath)
    if not accounts:
        print(f"  {RED}❌ No UIDs found in {filepath}{RST}")
        return

    print(f"  {GRN}✅ Loaded {len(accounts)} accounts{RST}")
    print()

    # workers
    print(f"  {CYN}⚡ Workers (default: {DEFAULT_WORKERS}, max: {MAX_WORKERS}):{RST}")
    w_input = input("     ❯ ").strip()
    try:
        workers = int(w_input) if w_input else DEFAULT_WORKERS
    except Exception:
        workers = DEFAULT_WORKERS
    workers = max(1, min(workers, MAX_WORKERS))

    print()
    print(f"  {YEL}⏳ Starting with {workers} parallel workers...{RST}")
    print()

    start = time.time()
    results = asyncio.run(run_bulk(accounts, workers=workers))
    elapsed = time.time() - start

    banned, unbanned, unknown = [], [], []
    for r in results:
        if r["status"] == "BANNED":
            banned.append(r)
        elif r["status"] == "UNBANNED":
            unbanned.append(r)
        else:
            unknown.append(r)

    save_split(banned, unbanned, unknown)

    print()
    print("=" * 62)
    print(f"  ✅ DONE in {elapsed:.1f}s")
    print("=" * 62)
    print(f"  {RED}🚫 BANNED   : {len(banned)}{RST}   → {BANN_FILE}")
    print(f"  {GRN}✅ UNBANNED : {len(unbanned)}{RST}   → {UNBAN_FILE}")
    if unknown:
        print(f"  {YEL}⚠️  UNKNOWN  : {len(unknown)}{RST}   → unknown.json")
    print("=" * 62)
    print()
    print(f"  {DIM}Files saved in: {Path.cwd()}{RST}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {RED}[!] Cancelled by user{RST}")