#pragma once
// Host-only helpers: encoding, prefix -> hash160 range conversion, verification.
#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <string>
#include <vector>

#include "hash.h"
#include "secp256k1.h"
#include "walk.h"

static const char* B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

inline std::string base58(const uint8_t* in, size_t len) {
    size_t zeros = 0;
    while (zeros < len && in[zeros] == 0) zeros++;
    std::vector<uint8_t> digits;  // base-58, little-endian
    for (size_t i = zeros; i < len; i++) {
        uint32_t carry = in[i];
        for (auto& d : digits) {
            carry += (uint32_t)d << 8;
            d = carry % 58;
            carry /= 58;
        }
        while (carry) {
            digits.push_back(carry % 58);
            carry /= 58;
        }
    }
    std::string s(zeros, '1');
    for (auto it = digits.rbegin(); it != digits.rend(); ++it) s += B58[*it];
    return s;
}

inline std::string base58check(const std::vector<uint8_t>& payload) {
    uint8_t h1[32], h2[32];
    sha256(payload.data(), (uint32_t)payload.size(), h1);
    sha256(h1, 32, h2);
    std::vector<uint8_t> full(payload);
    full.insert(full.end(), h2, h2 + 4);
    return base58(full.data(), full.size());
}

inline std::string to_hex(const uint8_t* b, size_t n) {
    static const char* hx = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) {
        s += hx[b[i] >> 4];
        s += hx[b[i] & 15];
    }
    return s;
}

inline void key_to_be(uint8_t out[32], const uint32_t k[8]) {
    for (int i = 0; i < 8; i++) {
        uint8_t* q = out + 28 - 4 * i;
        q[0] = (uint8_t)(k[i] >> 24);
        q[1] = (uint8_t)(k[i] >> 16);
        q[2] = (uint8_t)(k[i] >> 8);
        q[3] = (uint8_t)k[i];
    }
}

struct KeyInfo {
    std::string priv_hex, wif, pub_hex, address;
};

// Recompute everything for a private key from scratch, independent of the GPU.
inline KeyInfo describe_key(const uint32_t k[8], const ge* pow2) {
    KeyInfo ki;
    uint8_t kb[32];
    key_to_be(kb, k);
    ki.priv_hex = to_hex(kb, 32);

    std::vector<uint8_t> wif(1, 0x80);
    wif.insert(wif.end(), kb, kb + 32);
    ki.wif = base58check(wif);  // uncompressed WIF: no 0x01 suffix

    ge p;
    scalar_mul_g(&p, k, pow2);
    uint8_t pub[65];
    pub[0] = 0x04;
    fe_to_be(pub + 1, &p.x);
    fe_to_be(pub + 33, &p.y);
    ki.pub_hex = to_hex(pub, 65);

    uint8_t sh[32], h160[20];
    sha256(pub, 65, sh);
    ripemd160(sh, 32, h160);
    std::vector<uint8_t> payload(1, 0x00);
    payload.insert(payload.end(), h160, h160 + 20);
    ki.address = base58check(payload);
    return ki;
}

// pow2[i] = 2^i G
inline std::vector<ge> make_pow2_table() {
    std::vector<ge> t(256);
    get_generator(&t[0]);
    for (int i = 1; i < 256; i++) ge_double(&t[i], &t[i - 1]);
    return t;
}

// jg[i] = (i+1) G for i in [0, GROUP)
inline std::vector<ge> make_jg_table() {
    std::vector<ge> t(GROUP);
    get_generator(&t[0]);
    if (GROUP > 1) ge_double(&t[1], &t[0]);
    for (int i = 2; i < GROUP; i++) ge_add(&t[i], &t[i - 1], &t[0]);
    return t;
}

// ---- prefix -> ranges --------------------------------------------------------
//
// A P2PKH address is base58 of the 25-byte number N = 0x00 || hash160 || checksum.
// Leading zero bytes become leading '1's. A prefix therefore pins N to a union of
// intervals, and the top 64 bits of hash160 are exactly bits 128..191 of N, so each
// interval maps to an inclusive [lo, hi] over top64. That bound is conservative
// (it can admit a few neighbours at the edges), so every GPU hit is re-checked here.

struct Big {  // 320-bit unsigned, little-endian limbs
    uint32_t w[10];
    Big() { memset(w, 0, sizeof w); }
    explicit Big(uint32_t v) : Big() { w[0] = v; }
};

inline int big_cmp(const Big& a, const Big& b) {
    for (int i = 9; i >= 0; i--)
        if (a.w[i] != b.w[i]) return a.w[i] < b.w[i] ? -1 : 1;
    return 0;
}

inline Big big_mul_add(const Big& a, uint32_t m, uint32_t add) {
    Big r;
    uint64_t c = add;
    for (int i = 0; i < 10; i++) {
        c += (uint64_t)a.w[i] * m;
        r.w[i] = (uint32_t)c;
        c >>= 32;
    }
    return r;
}

inline Big big_mul(const Big& a, const Big& b) {  // truncated to 320 bits
    Big r;
    for (int i = 0; i < 10; i++) {
        uint64_t c = 0;
        for (int j = 0; i + j < 10; j++) {
            c += (uint64_t)a.w[i] * b.w[j] + r.w[i + j];
            r.w[i + j] = (uint32_t)c;
            c >>= 32;
        }
    }
    return r;
}

inline Big big_pow(uint32_t base, int e) {
    Big r(1);
    for (int i = 0; i < e; i++) r = big_mul_add(r, base, 0);
    return r;
}

inline Big big_sub1(Big a) {
    for (int i = 0; i < 10; i++)
        if (a.w[i]-- != 0) break;
    return a;
}

inline uint64_t big_top64(const Big& a) {  // bits 128..191
    return ((uint64_t)a.w[5] << 32) | a.w[4];
}

inline double big_to_double(const Big& a) {
    double d = 0;
    for (int i = 9; i >= 0; i--) d = d * 4294967296.0 + a.w[i];
    return d;
}

struct Prefix {
    std::string text;
    std::vector<std::pair<uint64_t, uint64_t>> ranges;  // inclusive, over top64
    double probability = 0;  // chance a random key matches
};

// Returns false and sets err if the prefix can never match.
inline bool build_prefix(const std::string& text, Prefix& out, std::string& err) {
    out = Prefix();
    out.text = text;
    if (text.empty() || text[0] != '1') {
        err = "uncompressed P2PKH addresses always start with '1'";
        return false;
    }
    for (char ch : text) {
        if (!strchr(B58, ch) || ch == 0) {
            err = std::string("'") + ch + "' is not a base58 character (0, O, I and l are excluded)";
            return false;
        }
    }
    size_t z = 0;
    while (z < text.size() && text[z] == '1') z++;
    if (z > 21) {  // version byte + 20 hash bytes is the most zeros possible
        err = "too many leading '1's";
        return false;
    }
    std::string rest = text.substr(z);
    const Big full = big_pow(256, 25);

    // [lo, hi) intervals over N
    std::vector<std::pair<Big, Big>> spans;
    if (rest.empty()) {
        spans.push_back({Big(0), big_pow(256, 25 - (int)z)});
    } else {
        Big zlo = big_pow(256, 24 - (int)z), zhi = big_pow(256, 25 - (int)z);
        Big R;
        for (char ch : rest) R = big_mul_add(R, 58, (uint32_t)(strchr(B58, ch) - B58));
        Big R1 = big_mul_add(R, 1, 1);
        for (int L = (int)rest.size(); L <= 40; L++) {
            Big scale = big_pow(58, L - (int)rest.size());
            Big lo = big_mul(R, scale), hi = big_mul(R1, scale);
            if (big_cmp(lo, full) >= 0) break;
            Big s = big_cmp(lo, zlo) > 0 ? lo : zlo;
            Big e = big_cmp(hi, zhi) < 0 ? hi : zhi;
            if (big_cmp(s, e) < 0) spans.push_back({s, e});
        }
    }
    double total = big_to_double(big_pow(256, 24));
    for (auto& sp : spans) {
        out.ranges.push_back({big_top64(sp.first), big_top64(big_sub1(sp.second))});
        Big w;
        int64_t c = 0;
        for (int i = 0; i < 10; i++) {
            c += (int64_t)sp.second.w[i] - sp.first.w[i];
            w.w[i] = (uint32_t)c;
            c >>= 32;
        }
        out.probability += big_to_double(w) / total;
    }
    if (out.ranges.empty()) {
        err = "no address can start with this prefix";
        return false;
    }
    return true;
}

// Sort and merge every prefix's ranges into the flat lo,hi,lo,hi... table the GPU reads.
inline std::vector<uint64_t> merge_ranges(const std::vector<Prefix>& prefixes) {
    std::vector<std::pair<uint64_t, uint64_t>> all;
    for (auto& p : prefixes) all.insert(all.end(), p.ranges.begin(), p.ranges.end());
    std::sort(all.begin(), all.end());
    std::vector<uint64_t> flat;
    for (auto& r : all) {
        size_t n = flat.size();
        if (n && (r.first <= flat[n - 1] || r.first - 1 == flat[n - 1])) {
            if (r.second > flat[n - 1]) flat[n - 1] = r.second;
        } else {
            flat.push_back(r.first);
            flat.push_back(r.second);
        }
    }
    return flat;
}

// Merged ranges plus the bucket bitmap the GPU checks first (Filter in walk.h).
struct RangeSet {
    std::vector<uint64_t> ranges;
    std::vector<uint32_t> bits;
    uint32_t shift;
};

inline RangeSet make_range_set(std::vector<uint64_t> flat) {
    RangeSet rs;
    rs.ranges = std::move(flat);
    size_t n = rs.ranges.size() / 2;
    // About 64 buckets per range, so only a few percent of keys reach the binary
    // search. 2^16 to 2^24 buckets: 8 KB to 2 MB, small enough to stay in L2.
    int log2b = 16;
    while (log2b < 24 && ((uint64_t)1 << log2b) < 64 * (uint64_t)n) log2b++;
    rs.shift = 64 - log2b;
    rs.bits.assign(((size_t)1 << log2b) / 32, 0);
    for (size_t i = 0; i < n; i++) {
        uint64_t a = rs.ranges[2 * i] >> rs.shift, b = rs.ranges[2 * i + 1] >> rs.shift;
        for (uint64_t x = a; x <= b; x++) rs.bits[x >> 5] |= 1u << (x & 31);
    }
    return rs;
}

inline RangeSet build_range_set(const std::vector<Prefix>& prefixes) {
    return make_range_set(merge_ranges(prefixes));
}

inline Filter host_filter(const RangeSet& rs) {
    return {rs.bits.data(), rs.shift, rs.ranges.data(), (int)rs.ranges.size() / 2};
}
