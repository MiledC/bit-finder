#pragma once
#include "common.h"
#include "hash.h"
#include "secp256k1.h"

// Keys checked per modular inversion (Montgomery batch trick). Each thread
// keeps GROUP field elements in local memory.
#ifndef GROUP
#define GROUP 256
#endif

// hash160 of the uncompressed pubkey 04||X||Y, as 5 little-endian RIPEMD words.
HD void hash160_uncompressed(uint32_t out[5], const ge* p) {
    // D = big-endian words of X||Y; message word m = byte-shifted by one for the 0x04.
    uint32_t D[16];
    for (int i = 0; i < 8; i++) {
        D[i] = p->x.v[7 - i];
        D[8 + i] = p->y.v[7 - i];
    }
    uint32_t m[16];
    m[0] = (0x04u << 24) | (D[0] >> 8);
    for (int i = 1; i < 16; i++) m[i] = (D[i - 1] << 24) | (D[i] >> 8);
    uint32_t s[8];
    sha256_init(s);
    sha256_compress(s, m);
    m[0] = (D[15] << 24) | 0x00800000u;
    for (int i = 1; i < 15; i++) m[i] = 0;
    m[15] = 65 * 8;
    sha256_compress(s, m);

    uint32_t X[16];
    for (int i = 0; i < 8; i++) X[i] = bswap32(s[i]);
    X[8] = 0x80u;
    for (int i = 9; i < 16; i++) X[i] = 0;
    X[14] = 32 * 8;
    ripemd160_init(out);
    ripemd160_compress(out, X);
}

// First 8 bytes of hash160 as a big-endian integer.
HD uint64_t hash160_top64(const uint32_t h[5]) {
    return ((uint64_t)bswap32(h[0]) << 32) | bswap32(h[1]);
}

// ranges: sorted, non-overlapping [lo, hi] pairs, interleaved lo0,hi0,lo1,hi1...
HD bool in_ranges(uint64_t v, const uint64_t* ranges, int n) {
    int lo = 0, hi = n - 1, found = -1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (ranges[2 * mid] <= v) {
            found = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    return found >= 0 && v <= ranges[2 * found + 1];
}

// Private key for thread `tid`: SHA-256(seed || tid || attempt) mod n, nonzero.
// The seed comes from the OS CSPRNG on the host and never leaves the process.
HD void derive_key(uint32_t k[8], const uint8_t seed[32], uint32_t tid) {
    uint8_t buf[40], h[32];
    for (int i = 0; i < 32; i++) buf[i] = seed[i];
    for (int i = 0; i < 4; i++) buf[32 + i] = (uint8_t)(tid >> (8 * i));
    for (uint32_t attempt = 0;; attempt++) {
        for (int i = 0; i < 4; i++) buf[36 + i] = (uint8_t)(attempt >> (8 * i));
        sha256(buf, 40, h);
        for (int i = 0; i < 8; i++) {
            const uint8_t* q = h + 28 - 4 * i;
            k[i] = ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16) | ((uint32_t)q[2] << 8) | q[3];
        }
        if (!sc_is_zero(k) && !sc_geq_n(k)) return;
    }
}

HD uint32_t bump_counter(uint32_t* c) {
#ifdef __CUDA_ARCH__
    return atomicAdd(c, 1u);
#else
    return (*c)++;
#endif
}

// Check the GROUP keys k+1 .. k+GROUP, whose points are P + jG[i] (jG[i] = (i+1)G),
// using one field inversion. Advances P and k by GROUP.
HD void walk_group(ge* P, uint32_t k[8], const ge* jG, const uint64_t* ranges, int nranges,
                   Match* out, uint32_t* count, uint32_t cap) {
    fe pre[GROUP];
    fe acc, dx;
    fe_set_u32(&acc, 1);
    for (int i = 0; i < GROUP; i++) {
        pre[i] = acc;
        fe_sub(&dx, &jG[i].x, &P->x);
        fe_mul(&acc, &acc, &dx);
    }
    fe inv;
    fe_inv(&inv, &acc);  // inv = 1 / prod(dx_0..dx_{G-1})

    ge next;
    for (int i = GROUP - 1; i >= 0; i--) {
        fe dxi, dinv, l, t;
        fe_sub(&dxi, &jG[i].x, &P->x);
        fe_mul(&dinv, &inv, &pre[i]);  // 1 / dx_i
        fe_mul(&inv, &inv, &dxi);      // drop dx_i from the running inverse

        ge q;
        fe_sub(&t, &jG[i].y, &P->y);
        fe_mul(&l, &t, &dinv);
        fe_sqr(&q.x, &l);
        fe_sub(&q.x, &q.x, &P->x);
        fe_sub(&q.x, &q.x, &jG[i].x);
        fe_sub(&t, &P->x, &q.x);
        fe_mul(&t, &l, &t);
        fe_sub(&q.y, &t, &P->y);
        if (i == GROUP - 1) next = q;

        uint32_t h[5];
        hash160_uncompressed(h, &q);
        if (in_ranges(hash160_top64(h), ranges, nranges)) {
            uint32_t slot = bump_counter(count);
            if (slot < cap) sc_add_u32(out[slot].key, k, (uint32_t)(i + 1));
        }
    }
    *P = next;
    sc_add_u32(k, k, GROUP);
}
