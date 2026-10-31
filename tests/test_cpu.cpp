// CPU tests for the shared GPU code. Build: make test
//   test_cpu           run self-checks
//   test_cpu dump N    print N random "privhex wif pubhex address" lines for ref.py
//   test_cpu hash N    print N random "msghex sha256 ripemd160" lines for ref.py
//   test_cpu field N   print N random "a b a+b a-b a*b 1/a" lines for ref.py
#include <stdio.h>
#include <math.h>
#include <stdlib.h>

#include <random>

#include "../src/host.h"

static std::mt19937_64 rng(12345);
static int failures = 0;

#define CHECK(cond, ...)                          \
    do {                                          \
        if (!(cond)) {                            \
            failures++;                           \
            printf("FAIL %s:%d: ", __FILE__, __LINE__); \
            printf(__VA_ARGS__);                  \
            printf("\n");                         \
        }                                         \
    } while (0)

static void rand_key(uint32_t k[8]) {
    do {
        for (int i = 0; i < 8; i++) k[i] = (uint32_t)rng();
    } while (sc_is_zero(k) || sc_geq_n(k));
}

static void rand_fe(fe* a) {
    do {
        for (int i = 0; i < 8; i++) a->v[i] = (uint32_t)rng();
        if (rng() % 4 == 0) for (int i = 2; i < 8; i++) a->v[i] = 0xFFFFFFFFu;  // near p
    } while (fe_geq_p(a));
}

static std::string fe_hex(const fe* a) {
    uint8_t b[32];
    fe_to_be(b, a);
    return to_hex(b, 32);
}

static void test_known_vectors(const std::vector<ge>& pow2) {
    uint32_t k[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    KeyInfo ki = describe_key(k, pow2.data());
    CHECK(ki.address == "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", "k=1 address %s", ki.address.c_str());
    CHECK(ki.wif == "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", "k=1 wif %s", ki.wif.c_str());

    uint32_t k2[8] = {2, 0, 0, 0, 0, 0, 0, 0};
    ki = describe_key(k2, pow2.data());
    CHECK(ki.address == "1LagHJk2FyCV2VzrNHVqg3gYG4TSYwDV4m", "k=2 address %s", ki.address.c_str());

    // n-1 is -G: same x as G
    uint32_t km[8] = {0xD0364140u, 0xBFD25E8Cu, 0xAF48A03Bu, 0xBAAEDCE6u,
                      0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu};
    ge p, g;
    scalar_mul_g(&p, km, pow2.data());
    get_generator(&g);
    fe ny;
    fe zero;
    fe_set_u32(&zero, 0);
    fe_sub(&ny, &zero, &g.y);
    CHECK(fe_eq(&p.x, &g.x) && fe_eq(&p.y, &ny), "(n-1)G != -G");
}

static void test_fast_hash160(const std::vector<ge>& pow2) {
    for (int t = 0; t < 200; t++) {
        uint32_t k[8];
        rand_key(k);
        ge p;
        scalar_mul_g(&p, k, pow2.data());
        uint8_t pub[65], sh[32], h[20];
        pub[0] = 4;
        fe_to_be(pub + 1, &p.x);
        fe_to_be(pub + 33, &p.y);
        sha256(pub, 65, sh);
        ripemd160(sh, 32, h);
        uint32_t fast[5];
        hash160_uncompressed(fast, &p);
        uint8_t fb[20];
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 4; j++) fb[4 * i + j] = (uint8_t)(fast[i] >> (8 * j));
        CHECK(memcmp(fb, h, 20) == 0, "fast hash160 mismatch");
        uint64_t top = 0;
        for (int i = 0; i < 8; i++) top = (top << 8) | h[i];
        CHECK(hash160_top64(fast) == top, "top64 mismatch");
    }
}

// The batched walk must produce exactly the points (k+1)G .. (k+GROUP)G.
static void test_walk(const std::vector<ge>& pow2, const std::vector<ge>& jg) {
    std::vector<uint64_t> everything = {0, ~0ull};
    std::vector<Match> out(GROUP);
    for (int t = 0; t < 3; t++) {
        uint32_t k[8], k0[8];
        rand_key(k);
        memcpy(k0, k, sizeof k);
        ge P;
        scalar_mul_g(&P, k, pow2.data());
        for (int round = 0; round < 2; round++) {
            uint32_t count = 0;
            uint32_t base[8];
            memcpy(base, k, sizeof k);
            walk_group(&P, k, jg.data(), everything.data(), 1, out.data(), &count, GROUP);
            CHECK(count == GROUP, "walk reported %u keys", count);
            // Results come out in reverse; check the set is base+1..base+GROUP.
            for (uint32_t i = 0; i < count; i++) {
                uint32_t want[8];
                sc_add_u32(want, base, GROUP - i);
                CHECK(memcmp(want, out[i].key, 32) == 0, "walk key %u wrong", i);
            }
            ge Q;
            scalar_mul_g(&Q, k, pow2.data());
            CHECK(fe_eq(&Q.x, &P.x) && fe_eq(&Q.y, &P.y), "walk end point != kG");
        }
        // A real prefix: plant the target at offset 37 and make sure the walk finds it.
        uint32_t target[8];
        sc_add_u32(target, k, 37);
        std::string addr = describe_key(target, pow2.data()).address;
        Prefix pre;
        std::string err;
        CHECK(build_prefix(addr.substr(0, 7), pre, err), "build_prefix: %s", err.c_str());
        std::vector<uint64_t> rs = merge_ranges({pre});
        uint32_t count = 0;
        walk_group(&P, k, jg.data(), rs.data(), (int)rs.size() / 2, out.data(), &count, GROUP);
        bool found = false;
        for (uint32_t i = 0; i < count && i < GROUP; i++) found |= memcmp(out[i].key, target, 32) == 0;
        CHECK(found, "walk missed planted prefix %s", addr.substr(0, 7).c_str());
    }
}

// No false negatives, few false positives, and probability estimate is right.
static void test_prefix_ranges(const std::vector<ge>& pow2) {
    std::vector<std::string> addrs;
    std::vector<uint64_t> tops;
    for (int t = 0; t < 3000; t++) {
        uint32_t k[8];
        rand_key(k);
        ge p;
        scalar_mul_g(&p, k, pow2.data());
        uint32_t h[5];
        hash160_uncompressed(h, &p);
        tops.push_back(hash160_top64(h));
        addrs.push_back(describe_key(k, pow2.data()).address);
    }
    // Prefixes drawn from real addresses at several lengths, plus hand-picked ones.
    std::vector<std::string> prefixes = {"1", "11", "111", "1A", "1z", "12", "1Q", "1R", "1Love", "1Bit", "1zz"};
    for (int i = 0; i < 40; i++) {
        const std::string& a = addrs[rng() % addrs.size()];
        prefixes.push_back(a.substr(0, 2 + rng() % 6));
    }
    for (auto& text : prefixes) {
        Prefix pre;
        std::string err;
        if (!build_prefix(text, pre, err)) {
            CHECK(false, "build_prefix(%s): %s", text.c_str(), err.c_str());
            continue;
        }
        std::vector<uint64_t> rs = merge_ranges({pre});
        int real = 0, flagged = 0, missed = 0;
        for (size_t i = 0; i < addrs.size(); i++) {
            bool starts = addrs[i].compare(0, text.size(), text) == 0;
            bool in = in_ranges(tops[i], rs.data(), (int)rs.size() / 2);
            real += starts;
            flagged += in;
            missed += starts && !in;
        }
        CHECK(missed == 0, "prefix %s: %d false negatives", text.c_str(), missed);
        CHECK(flagged - real <= 2, "prefix %s: %d false positives", text.c_str(), flagged - real);
        double expect = pre.probability * addrs.size();
        if (expect > 100) {
            CHECK(fabs(real - expect) < 5 * sqrt(expect) + 1, "prefix %s: saw %d expected %.0f",
                  text.c_str(), real, expect);
        }
    }
    Prefix pre;
    std::string err;
    CHECK(!build_prefix("1O", pre, err), "1O should be rejected");
    CHECK(!build_prefix("3abc", pre, err), "3abc should be rejected");
    CHECK(build_prefix("1", pre, err) && fabs(pre.probability - 1.0) < 1e-9, "prob(1) = %f", pre.probability);
    CHECK(build_prefix("11", pre, err) && fabs(pre.probability - 1.0 / 256) < 1e-9, "prob(11) = %f", pre.probability);
}

static void test_derive_key() {
    uint8_t seed[32] = {0};
    uint32_t a[8], b[8], c[8];
    derive_key(a, seed, 0);
    derive_key(b, seed, 1);
    derive_key(c, seed, 0);
    CHECK(memcmp(a, b, 32) != 0, "derive_key: distinct tids gave same key");
    CHECK(memcmp(a, c, 32) == 0, "derive_key: not deterministic");
    CHECK(!sc_geq_n(a) && !sc_is_zero(a), "derive_key out of range");
}

int main(int argc, char** argv) {
    std::vector<ge> pow2 = make_pow2_table(), jg = make_jg_table();
    if (argc == 3) {
        int n = atoi(argv[2]);
        std::string mode = argv[1];
        for (int t = 0; t < n; t++) {
            if (mode == "dump") {
                uint32_t k[8];
                rand_key(k);
                KeyInfo ki = describe_key(k, pow2.data());
                printf("%s %s %s %s\n", ki.priv_hex.c_str(), ki.wif.c_str(), ki.pub_hex.c_str(),
                       ki.address.c_str());
            } else if (mode == "hash") {
                std::vector<uint8_t> m(rng() % 200);
                for (auto& x : m) x = (uint8_t)rng();
                uint8_t s[32], r[20];
                sha256(m.data(), (uint32_t)m.size(), s);
                ripemd160(m.data(), (uint32_t)m.size(), r);
                printf("%s %s %s\n", m.empty() ? "-" : to_hex(m.data(), m.size()).c_str(),
                       to_hex(s, 32).c_str(), to_hex(r, 20).c_str());
            } else if (mode == "field") {
                fe a, b, s, d, m, i;
                rand_fe(&a);
                rand_fe(&b);
                if (t % 7 == 0) b = a;
                fe_add(&s, &a, &b);
                fe_sub(&d, &a, &b);
                fe_mul(&m, &a, &b);
                fe_inv(&i, &a);
                printf("%s %s %s %s %s %s\n", fe_hex(&a).c_str(), fe_hex(&b).c_str(), fe_hex(&s).c_str(),
                       fe_hex(&d).c_str(), fe_hex(&m).c_str(), fe_hex(&i).c_str());
            }
        }
        return 0;
    }
    test_known_vectors(pow2);
    test_fast_hash160(pow2);
    test_derive_key();
    test_walk(pow2, jg);
    test_prefix_ranges(pow2);
    if (failures) {
        printf("%d check(s) failed\n", failures);
        return 1;
    }
    printf("all CPU checks passed\n");
    return 0;
}
