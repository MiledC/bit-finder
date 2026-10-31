#!/usr/bin/env python3
"""Independent reference: checks test_cpu's dump/hash/field output with plain Python ints and hashlib.

Usage: ref.py BINARY
"""
import hashlib
import subprocess
import sys

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (lam * lam - p[0] - q[0]) % P
    return (x, (lam * (p[0] - x) - p[1]) % P)


def mul(k):
    r, a = None, G
    while k:
        if k & 1:
            r = add(r, a)
        a = add(a, a)
        k >>= 1
    return r


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


def main():
    binary = sys.argv[1]
    bad = 0

    def run(mode, n):
        return subprocess.run([binary, mode, str(n)], capture_output=True, text=True, check=True).stdout.split("\n")

    for line in filter(None, run("field", 2000)):
        a, b, s, d, m, i = (int(x, 16) for x in line.split())
        want = ((a + b) % P, (a - b) % P, a * b % P, pow(a, -1, P) if a else 0)
        if (s, d, m, i) != want:
            bad += 1
            print("field mismatch:", line)

    for line in filter(None, run("hash", 500)):
        msg, s, r = line.split()
        m = b"" if msg == "-" else bytes.fromhex(msg)
        if s != hashlib.sha256(m).hexdigest() or r != hashlib.new("ripemd160", m).hexdigest():
            bad += 1
            print("hash mismatch:", line)

    for line in filter(None, run("dump", 300)):
        priv, wif, pub, addr = line.split()
        k = int(priv, 16)
        x, y = mul(k)
        want_pub = "04" + x.to_bytes(32, "big").hex() + y.to_bytes(32, "big").hex()
        h160 = hashlib.new("ripemd160", hashlib.sha256(bytes.fromhex(want_pub)).digest()).digest()
        want_addr = b58check(b"\0" + h160)
        want_wif = b58check(b"\x80" + k.to_bytes(32, "big"))
        if (pub, addr, wif) != (want_pub, want_addr, want_wif):
            bad += 1
            print("key mismatch:", line)

    print("python reference: %s" % ("all matched" if not bad else "%d mismatches" % bad))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
