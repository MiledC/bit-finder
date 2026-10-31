#!/usr/bin/env python3
"""Independently verify vanity output with libsecp256k1 (via coincurve).

Shares no code with the CUDA program. For every match it checks that:
  1. the WIF has a valid checksum, is mainnet (0x80), uncompressed, and holds the hex key
  2. the key is in [1, n)
  3. libsecp256k1 derives exactly the printed public key from it
  4. hash160 of that public key, Base58Check-encoded, is exactly the printed address
  5. the address starts with every prefix the match claims
  6. a signature made with the private key verifies against the printed public key

Usage: verify.py FILE [FILE...]   (files written by vanity -o, or "-" for stdin)
       verify.py --expect 1Ab,1Cat FILE   also require each listed prefix to be found
Exits non-zero if any record fails or nothing was checked.
"""
import hashlib
import os
import sys

try:
    import coincurve
except ImportError:
    sys.exit("verify.py needs coincurve: pip install coincurve")

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data):
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check_decode(s):
    raw = b58decode(s)
    payload, checksum = raw[:-4], raw[-4:]
    if dsha(payload)[:4] != checksum:
        raise ValueError("bad checksum")
    return payload


def parse(text):
    records, cur = [], {}
    for line in text.splitlines():
        if not line.strip():
            if cur:
                records.append(cur)
                cur = {}
            continue
        key, _, value = line.partition(":")
        cur[key.strip()] = value.strip()
    if cur:
        records.append(cur)
    return records


def check(rec):
    """Returns a list of failure strings (empty means the record is good)."""
    errs = []
    need = ["Prefix", "Address", "Private key", "WIF", "Public key"]
    missing = [k for k in need if k not in rec]
    if missing:
        return ["missing fields: " + ", ".join(missing)]

    priv = bytes.fromhex(rec["Private key"])
    k = int.from_bytes(priv, "big")
    if len(priv) != 32 or not 1 <= k < N:
        return ["private key out of range"]

    try:
        payload = b58check_decode(rec["WIF"])
        if payload[0] != 0x80:
            errs.append("WIF is not mainnet")
        if len(payload) != 33:
            errs.append("WIF is not an uncompressed key")
        elif payload[1:] != priv:
            errs.append("WIF holds a different key than the hex")
    except (ValueError, IndexError) as e:
        errs.append("WIF: %s" % e)

    sk = coincurve.PrivateKey(priv)
    pub = sk.public_key.format(compressed=False)
    if pub.hex() != rec["Public key"].lower():
        errs.append("public key does not match the private key")

    h160 = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
    addr = b58encode(b"\0" + h160 + dsha(b"\0" + h160)[:4])
    if addr != rec["Address"]:
        errs.append("address does not match the key (derived %s)" % addr)

    for p in rec["Prefix"].split(","):
        if not addr.startswith(p.strip()):
            errs.append("address does not start with %s" % p.strip())

    msg = os.urandom(32)
    sig = sk.sign(msg)
    try:
        if not coincurve.PublicKey(bytes.fromhex(rec["Public key"])).verify(sig, msg):
            errs.append("signature does not verify against the public key")
    except ValueError:
        errs.append("printed public key is not a valid curve point")
    return errs


def main(argv):
    expect = []
    if len(argv) > 2 and argv[1] == "--expect":
        expect = [p for p in argv[2].split(",") if p]
        argv = argv[:1] + argv[3:]
    if len(argv) < 2:
        sys.exit(__doc__)
    records = []
    for path in argv[1:]:
        records += parse(sys.stdin.read() if path == "-" else open(path).read())

    bad = 0
    found = set()
    for rec in records:
        errs = check(rec)
        if errs:
            bad += 1
            print("FAIL %s" % rec.get("Address", "?"))
            for e in errs:
                print("     " + e)
        else:
            found.update(p.strip() for p in rec["Prefix"].split(","))
            print("ok   %-36s %s" % (rec["Address"], rec["Prefix"]))
    missing = [p for p in expect if p not in found]
    for p in missing:
        print("MISSING prefix %s" % p)

    print("%d checked, %d failed, %d expected prefixes missing" % (len(records), bad, len(missing)))
    sys.exit(1 if bad or missing or not records else 0)


if __name__ == "__main__":
    main(sys.argv)
