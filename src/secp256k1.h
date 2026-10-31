#pragma once
#include "common.h"

// Field elements mod p = 2^256 - 2^32 - 977, as 8 little-endian 32-bit limbs.
struct fe {
    uint32_t v[8];
};

// Affine point. The point at infinity is never stored in one of these.
struct ge {
    fe x, y;
};

// p as limbs, and 2^256 - p = 2^32 + 977 = 0x1000003D1.
#define P0 0xFFFFFC2Fu
#define P1 0xFFFFFFFEu

HD void fe_set_u32(fe* r, uint32_t a) {
    r->v[0] = a;
    for (int i = 1; i < 8; i++) r->v[i] = 0;
}

HD void fe_from_be(fe* r, const uint8_t b[32]) {
    for (int i = 0; i < 8; i++) {
        const uint8_t* q = b + 28 - 4 * i;
        r->v[i] = ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16) | ((uint32_t)q[2] << 8) | q[3];
    }
}

HD void fe_to_be(uint8_t b[32], const fe* a) {
    for (int i = 0; i < 8; i++) {
        uint8_t* q = b + 28 - 4 * i;
        q[0] = (uint8_t)(a->v[i] >> 24);
        q[1] = (uint8_t)(a->v[i] >> 16);
        q[2] = (uint8_t)(a->v[i] >> 8);
        q[3] = (uint8_t)a->v[i];
    }
}

HD bool fe_is_zero(const fe* a) {
    uint32_t t = 0;
    for (int i = 0; i < 8; i++) t |= a->v[i];
    return t == 0;
}

HD bool fe_eq(const fe* a, const fe* b) {
    uint32_t t = 0;
    for (int i = 0; i < 8; i++) t |= a->v[i] ^ b->v[i];
    return t == 0;
}

HD bool fe_geq_p(const fe* a) {
    for (int i = 7; i >= 2; i--)
        if (a->v[i] != 0xFFFFFFFFu) return false;
    if (a->v[1] != P1) return a->v[1] > P1;
    return a->v[0] >= P0;
}

// r += 2^256 - p (mod 2^256); used to subtract p after an overflow.
HD void fe_add_c(fe* r) {
    uint64_t c = (uint64_t)r->v[0] + 0x3D1u;
    r->v[0] = (uint32_t)c;
    c = (c >> 32) + (uint64_t)r->v[1] + 1u;
    r->v[1] = (uint32_t)c;
    c >>= 32;
    for (int i = 2; i < 8; i++) {
        c += r->v[i];
        r->v[i] = (uint32_t)c;
        c >>= 32;
    }
}

HD void fe_reduce_once(fe* r) {
    if (fe_geq_p(r)) fe_add_c(r);
}

HD void fe_add(fe* r, const fe* a, const fe* b) {
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        c += (uint64_t)a->v[i] + b->v[i];
        r->v[i] = (uint32_t)c;
        c >>= 32;
    }
    if (c || fe_geq_p(r)) fe_add_c(r);
}

HD void fe_sub(fe* r, const fe* a, const fe* b) {
    int64_t c = 0;
    for (int i = 0; i < 8; i++) {
        c += (int64_t)a->v[i] - b->v[i];
        r->v[i] = (uint32_t)c;
        c >>= 32;
    }
    if (c) {
        // Went negative: add p back, i.e. subtract 2^256 - p modulo 2^256.
        int64_t d = (int64_t)r->v[0] - 0x3D1;
        r->v[0] = (uint32_t)d;
        d = (d >> 32) + (int64_t)r->v[1] - 1;
        r->v[1] = (uint32_t)d;
        d >>= 32;
        for (int i = 2; i < 8; i++) {
            d += r->v[i];
            r->v[i] = (uint32_t)d;
            d >>= 32;
        }
    }
}

HD void fe_mul(fe* r, const fe* a, const fe* b) {
    uint32_t w[16];
    for (int i = 0; i < 16; i++) w[i] = 0;
    for (int i = 0; i < 8; i++) {
        uint64_t c = 0;
        for (int j = 0; j < 8; j++) {
            c += (uint64_t)a->v[i] * b->v[j] + w[i + j];
            w[i + j] = (uint32_t)c;
            c >>= 32;
        }
        w[i + 8] = (uint32_t)c;
    }
    // hi * 2^256 == hi * (2^32 + 977)
    uint32_t s[8];
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        c += (uint64_t)w[i] + (uint64_t)w[8 + i] * 977u;
        if (i > 0) c += w[7 + i];
        s[i] = (uint32_t)c;
        c >>= 32;
    }
    c += w[15];
    uint64_t top = c;  // < 2^11
    c = (uint64_t)s[0] + top * 977u;
    r->v[0] = (uint32_t)c;
    c = (c >> 32) + (uint64_t)s[1] + top;
    r->v[1] = (uint32_t)c;
    c >>= 32;
    for (int i = 2; i < 8; i++) {
        c += s[i];
        r->v[i] = (uint32_t)c;
        c >>= 32;
    }
    if (c) fe_add_c(r);
    fe_reduce_once(r);
}

HD void fe_sqr(fe* r, const fe* a) { fe_mul(r, a, a); }

// a^(p-2) by square-and-multiply. p-2 = FF..FF FFFFFFFE FFFFFC2D.
HD void fe_inv(fe* r, const fe* a) {
    const uint32_t e[8] = {0xFFFFFC2Du, 0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu,
                           0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
    fe x;
    fe_set_u32(&x, 1);
    for (int i = 7; i >= 0; i--) {
        for (int bit = 31; bit >= 0; bit--) {
            fe_sqr(&x, &x);
            if ((e[i] >> bit) & 1) fe_mul(&x, &x, a);
        }
    }
    *r = x;
}

// r = p + q for p != +-q (holds with overwhelming probability for random keys).
HD void ge_add(ge* r, const ge* p, const ge* q) {
    fe dx, dy, l, l2, t;
    fe_sub(&dx, &q->x, &p->x);
    fe_sub(&dy, &q->y, &p->y);
    fe_inv(&dx, &dx);
    fe_mul(&l, &dy, &dx);
    fe_sqr(&l2, &l);
    fe_sub(&l2, &l2, &p->x);
    fe_sub(&l2, &l2, &q->x);  // x3
    fe_sub(&t, &p->x, &l2);
    fe_mul(&t, &l, &t);
    fe_sub(&r->y, &t, &p->y);
    r->x = l2;
}

HD void ge_double(ge* r, const ge* p) {
    fe n, d, l, l2, t;
    fe_sqr(&n, &p->x);
    fe_add(&t, &n, &n);
    fe_add(&n, &t, &n);  // 3x^2
    fe_add(&d, &p->y, &p->y);
    fe_inv(&d, &d);
    fe_mul(&l, &n, &d);
    fe_sqr(&l2, &l);
    fe_sub(&l2, &l2, &p->x);
    fe_sub(&l2, &l2, &p->x);
    fe_sub(&t, &p->x, &l2);
    fe_mul(&t, &l, &t);
    fe_sub(&r->y, &t, &p->y);
    r->x = l2;
}

// ---- scalars mod n -------------------------------------------------------

HD bool sc_geq_n(const uint32_t k[8]) {
    const uint32_t n[8] = {0xD0364141u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
                           0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
    for (int i = 7; i >= 0; i--)
        if (k[i] != n[i]) return k[i] > n[i];
    return true;
}

// k -= n (mod 2^256), equivalently k += 2^256 - n.
HD void sc_sub_n(uint32_t k[8]) {
    const uint32_t c_[8] = {0x2FC9BEBFu, 0x402DA173u, 0x50B75FC4u, 0x45512319u, 1u, 0, 0, 0};
    uint64_t c = 0;
    for (int i = 0; i < 8; i++) {
        c += (uint64_t)k[i] + c_[i];
        k[i] = (uint32_t)c;
        c >>= 32;
    }
}

HD void sc_add_u32(uint32_t r[8], const uint32_t k[8], uint32_t a) {
    uint64_t c = a;
    for (int i = 0; i < 8; i++) {
        c += k[i];
        r[i] = (uint32_t)c;
        c >>= 32;
    }
    if (c || sc_geq_n(r)) sc_sub_n(r);
}

HD bool sc_is_zero(const uint32_t k[8]) {
    uint32_t t = 0;
    for (int i = 0; i < 8; i++) t |= k[i];
    return t == 0;
}

// r = k*G using a table pow2[i] = 2^i * G. k must be in [1, n).
// Partial sums can never equal +-2^i G for k < n, so ge_add is always valid.
HD void scalar_mul_g(ge* r, const uint32_t k[8], const ge* pow2) {
    bool inf = true;
    for (int i = 0; i < 256; i++) {
        if ((k[i >> 5] >> (i & 31)) & 1) {
            if (inf) {
                *r = pow2[i];
                inf = false;
            } else {
                ge_add(r, r, &pow2[i]);
            }
        }
    }
}

HD void get_generator(ge* g) {
    const uint8_t gx[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62,
                            0x95, 0xCE, 0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE,
                            0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
    const uint8_t gy[32] = {0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB,
                            0xFC, 0x0E, 0x11, 0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85,
                            0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8};
    fe_from_be(&g->x, gx);
    fe_from_be(&g->y, gy);
}
