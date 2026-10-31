#pragma once
#include "common.h"

HD uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
HD uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
HD uint32_t bswap32(uint32_t x) {
    return (x >> 24) | ((x >> 8) & 0xFF00u) | ((x << 8) & 0xFF0000u) | (x << 24);
}

// ---- SHA-256 ---------------------------------------------------------------

HD void sha256_init(uint32_t s[8]) {
    s[0] = 0x6a09e667u; s[1] = 0xbb67ae85u; s[2] = 0x3c6ef372u; s[3] = 0xa54ff53au;
    s[4] = 0x510e527fu; s[5] = 0x9b05688cu; s[6] = 0x1f83d9abu; s[7] = 0x5be0cd19u;
}

// One compression over 16 big-endian message words.
HD void sha256_compress(uint32_t s[8], const uint32_t m[16]) {
    const uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
    uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = m[i];
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
#ifdef __CUDA_ARCH__
#pragma unroll
#endif
    for (int i = 0; i < 64; i++) {
        uint32_t wi;
        if (i < 16) {
            wi = w[i];
        } else {
            uint32_t w15 = w[(i + 1) & 15], w2 = w[(i + 14) & 15];
            uint32_t s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >> 3);
            uint32_t s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >> 10);
            wi = w[i & 15] + s0 + w[(i + 9) & 15] + s1;
            w[i & 15] = wi;
        }
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + S1 + ch + K[i] + wi;
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
    s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

// General SHA-256 over a byte string (host side and seed derivation).
HD void sha256(const uint8_t* in, uint32_t len, uint8_t out[32]) {
    uint32_t s[8];
    sha256_init(s);
    uint32_t m[16];
    uint64_t bits = (uint64_t)len * 8;
    uint32_t total = ((len + 9 + 63) / 64) * 64;
    for (uint32_t blk = 0; blk < total; blk += 64) {
        for (int i = 0; i < 16; i++) {
            uint32_t w = 0;
            for (int j = 0; j < 4; j++) {
                uint32_t pos = blk + 4 * i + j;
                uint8_t byte;
                if (pos < len) byte = in[pos];
                else if (pos == len) byte = 0x80;
                else if (pos >= total - 8) byte = (uint8_t)(bits >> (8 * (total - 1 - pos)));
                else byte = 0;
                w = (w << 8) | byte;
            }
            m[i] = w;
        }
        sha256_compress(s, m);
    }
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(s[i] >> 24);
        out[4 * i + 1] = (uint8_t)(s[i] >> 16);
        out[4 * i + 2] = (uint8_t)(s[i] >> 8);
        out[4 * i + 3] = (uint8_t)s[i];
    }
}

// ---- RIPEMD-160 ------------------------------------------------------------

HD void ripemd160_init(uint32_t h[5]) {
    h[0] = 0x67452301u; h[1] = 0xEFCDAB89u; h[2] = 0x98BADCFEu; h[3] = 0x10325476u; h[4] = 0xC3D2E1F0u;
}

HD uint32_t rmd_f(int j, uint32_t x, uint32_t y, uint32_t z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

// One compression over 16 little-endian message words.
HD void ripemd160_compress(uint32_t h[5], const uint32_t X[16]) {
    const uint8_t R[80] = {0, 1, 2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                           7, 4, 13, 1,  10, 6,  15, 3,  12, 0,  9,  5,  2,  14, 11, 8,
                           3, 10, 14, 4, 9,  15, 8,  1,  2,  7,  0,  6,  13, 11, 5,  12,
                           1, 9, 11, 10, 0,  8,  12, 4,  13, 3,  7,  15, 14, 5,  6,  2,
                           4, 0, 5,  9,  7,  12, 2,  10, 14, 1,  3,  8,  11, 6,  15, 13};
    const uint8_t RP[80] = {5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
                            6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
                            15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
                            8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
                            12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};
    const uint8_t S[80] = {11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
                           7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
                           11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
                           11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
                           9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
    const uint8_t SP[80] = {8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
                            9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
                            9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
                            15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
                            8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};
    const uint32_t K[5] = {0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu};
    const uint32_t KP[5] = {0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u};

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    uint32_t ap = a, bp = b, cp = c, dp = d, ep = e;
#ifdef __CUDA_ARCH__
#pragma unroll
#endif
    for (int j = 0; j < 80; j++) {
        uint32_t t = rotl32(a + rmd_f(j, b, c, d) + X[R[j]] + K[j >> 4], S[j]) + e;
        a = e; e = d; d = rotl32(c, 10); c = b; b = t;
        t = rotl32(ap + rmd_f(79 - j, bp, cp, dp) + X[RP[j]] + KP[j >> 4], SP[j]) + ep;
        ap = ep; ep = dp; dp = rotl32(cp, 10); cp = bp; bp = t;
    }
    uint32_t t = h[1] + c + dp;
    h[1] = h[2] + d + ep;
    h[2] = h[3] + e + ap;
    h[3] = h[4] + a + bp;
    h[4] = h[0] + b + cp;
    h[0] = t;
}

// General RIPEMD-160 over a byte string (used by the tests).
HD void ripemd160(const uint8_t* in, uint32_t len, uint8_t out[20]) {
    uint32_t h[5];
    ripemd160_init(h);
    uint64_t bits = (uint64_t)len * 8;
    uint32_t total = ((len + 9 + 63) / 64) * 64;
    for (uint32_t blk = 0; blk < total; blk += 64) {
        uint32_t X[16];
        for (int i = 0; i < 16; i++) {
            uint32_t w = 0;
            for (int j = 3; j >= 0; j--) {
                uint32_t pos = blk + 4 * i + j;
                uint8_t byte;
                if (pos < len) byte = in[pos];
                else if (pos == len) byte = 0x80;
                else if (pos >= total - 8) byte = (uint8_t)(bits >> (8 * (pos - (total - 8))));
                else byte = 0;
                w = (w << 8) | byte;
            }
            X[i] = w;
        }
        ripemd160_compress(h, X);
    }
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (uint8_t)h[i];
        out[4 * i + 1] = (uint8_t)(h[i] >> 8);
        out[4 * i + 2] = (uint8_t)(h[i] >> 16);
        out[4 * i + 3] = (uint8_t)(h[i] >> 24);
    }
}
