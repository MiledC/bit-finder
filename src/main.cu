// CUDA vanity address finder for uncompressed P2PKH Bitcoin addresses.
#include <cuda_runtime.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <chrono>
#include <fstream>

#include "host.h"

#define CUDA_CHECK(x)                                                                   \
    do {                                                                                \
        cudaError_t e_ = (x);                                                           \
        if (e_ != cudaSuccess) {                                                        \
            fprintf(stderr, "CUDA error %s at %s:%d\n", cudaGetErrorString(e_), __FILE__, \
                    __LINE__);                                                          \
            exit(1);                                                                    \
        }                                                                               \
    } while (0)

static const uint32_t MATCH_CAP = 4096;

struct Seed {
    uint8_t b[32];
};

struct ThreadState {
    ge P;
    uint32_t k[8];
};

__global__ void init_kernel(ThreadState* st, const ge* pow2, Seed seed) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    ThreadState s;
    derive_key(s.k, seed.b, tid);
    scalar_mul_g(&s.P, s.k, pow2);
    st[tid] = s;
}

__global__ void walk_kernel(ThreadState* st, const ge* jg, const uint64_t* ranges, int nranges,
                            Match* out, uint32_t* count, int groups) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    ThreadState s = st[tid];
    for (int g = 0; g < groups; g++)
        walk_group(&s.P, s.k, jg, ranges, nranges, out, count, MATCH_CAP);
    st[tid] = s;
}

static bool read_seed(uint8_t out[32]) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < 32) {
        ssize_t r = read(fd, out + got, 32 - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(fd);
    return got == 32;
}

// Runs the real kernels on a few threads and checks every result on the host.
static int selftest(const ge* d_pow2, const ge* d_jg, const std::vector<ge>& pow2) {
    const int T = 32;
    ThreadState* d_state;
    Match* d_out;
    uint32_t* d_count;
    uint64_t* d_ranges;
    CUDA_CHECK(cudaMalloc(&d_state, T * sizeof(ThreadState)));
    CUDA_CHECK(cudaMalloc(&d_out, MATCH_CAP * sizeof(Match)));
    CUDA_CHECK(cudaMalloc(&d_count, sizeof(uint32_t)));
    CUDA_CHECK(cudaMemset(d_count, 0, sizeof(uint32_t)));
    Seed seed;
    if (!read_seed(seed.b)) return 1;
    init_kernel<<<1, T>>>(d_state, d_pow2, seed);
    CUDA_CHECK(cudaGetLastError());
    std::vector<ThreadState> st(T);
    CUDA_CHECK(cudaMemcpy(st.data(), d_state, T * sizeof(ThreadState), cudaMemcpyDeviceToHost));

    int bad = 0;
    std::vector<Prefix> planted;
    std::vector<std::vector<uint32_t>> targets;
    for (int t = 0; t < T; t++) {
        ge q;
        scalar_mul_g(&q, st[t].k, pow2.data());
        if (!fe_eq(&q.x, &st[t].P.x) || !fe_eq(&q.y, &st[t].P.y)) bad++;
        // Plant one target per thread at a different offset inside the first group.
        std::vector<uint32_t> tk(8);
        sc_add_u32(tk.data(), st[t].k, 1 + (uint32_t)(t * 7) % GROUP);
        uint32_t priv[8];
        endo_key(priv, tk.data(), t % 6);  // cycle through all six sibling keys
        tk.push_back(t % 6);
        Prefix p;
        std::string err;
        build_prefix(describe_key(priv, pow2.data()).address.substr(0, 9), p, err);
        planted.push_back(p);
        targets.push_back(tk);
    }
    printf("init kernel:  %s (%d/%d starting points wrong)\n", bad ? "FAIL" : "ok", bad, T);

    std::vector<uint64_t> flat = merge_ranges(planted);
    CUDA_CHECK(cudaMalloc(&d_ranges, flat.size() * sizeof(uint64_t)));
    CUDA_CHECK(cudaMemcpy(d_ranges, flat.data(), flat.size() * sizeof(uint64_t), cudaMemcpyHostToDevice));
    walk_kernel<<<1, T>>>(d_state, d_jg, d_ranges, (int)flat.size() / 2, d_out, d_count, 2);
    CUDA_CHECK(cudaGetLastError());
    uint32_t count;
    CUDA_CHECK(cudaMemcpy(&count, d_count, sizeof count, cudaMemcpyDeviceToHost));
    std::vector<Match> m(count < MATCH_CAP ? count : MATCH_CAP);
    CUDA_CHECK(cudaMemcpy(m.data(), d_out, m.size() * sizeof(Match), cudaMemcpyDeviceToHost));
    int missed = 0;
    for (auto& tk : targets) {
        bool hit = false;
        for (auto& x : m) hit |= memcmp(x.key, tk.data(), 32) == 0 && x.variant == tk[8];
        missed += !hit;
    }
    printf("walk kernel:  %s (%d/%d planted prefixes missed, %u candidates)\n", missed ? "FAIL" : "ok",
           missed, T, count);

    std::vector<ThreadState> after(T);
    CUDA_CHECK(cudaMemcpy(after.data(), d_state, T * sizeof(ThreadState), cudaMemcpyDeviceToHost));
    int drift = 0;
    for (int t = 0; t < T; t++) {
        uint32_t want[8];
        sc_add_u32(want, st[t].k, 2 * GROUP);
        ge q;
        scalar_mul_g(&q, want, pow2.data());
        if (memcmp(want, after[t].k, 32) || !fe_eq(&q.x, &after[t].P.x) || !fe_eq(&q.y, &after[t].P.y)) drift++;
    }
    printf("walk state:   %s (%d/%d threads off)\n", drift ? "FAIL" : "ok", drift, T);
    bool ok = !bad && !missed && !drift;
    printf("%s\n", ok ? "self-test passed" : "SELF-TEST FAILED: do not trust results from this build");
    return ok ? 0 : 1;
}

static void usage(const char* argv0) {
    fprintf(stderr,
            "usage: %s [options] PREFIX [PREFIX...]\n"
            "  Searches for uncompressed P2PKH addresses (starting with '1') beginning with\n"
            "  any of the given prefixes. Prefixes are case-sensitive.\n\n"
            "  -f FILE   read more prefixes from FILE, one per line\n"
            "  -o FILE   also append matches to FILE (created mode 0600)\n"
            "  -k        keep going after a prefix is found (default: stop searching it)\n"
            "  -n N      stop after N matches in total\n"
            "  -d N      CUDA device index (default 0)\n"
            "  -b N      blocks (default: 16 x SM count)\n"
            "  -t N      threads per block (default 128)\n"
            "  --selftest  check the GPU kernels against the CPU and exit\n",
            argv0);
    exit(2);
}

static std::string human(double v) {
    const char* units[] = {"", "K", "M", "G", "T", "P", "E"};
    int u = 0;
    while (v >= 1000 && u < 6) {
        v /= 1000;
        u++;
    }
    char buf[32];
    snprintf(buf, sizeof buf, "%.2f%s", v, units[u]);
    return buf;
}

int main(int argc, char** argv) {
    std::vector<std::string> texts;
    std::string out_path;
    bool keep_going = false, run_selftest = false;
    long max_matches = 0;
    int device = 0, blocks = 0, threads = 128;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&]() -> std::string {
            if (i + 1 >= argc) usage(argv[0]);
            return argv[++i];
        };
        if (a == "-f") {
            std::ifstream f(next());
            if (!f) {
                fprintf(stderr, "cannot read prefix file\n");
                return 2;
            }
            std::string line;
            while (std::getline(f, line)) {
                while (!line.empty() && isspace((unsigned char)line.back())) line.pop_back();
                size_t s = 0;
                while (s < line.size() && isspace((unsigned char)line[s])) s++;
                if (s < line.size() && line[s] != '#') texts.push_back(line.substr(s));
            }
        } else if (a == "-o") out_path = next();
        else if (a == "-k") keep_going = true;
        else if (a == "-n") max_matches = atol(next().c_str());
        else if (a == "-d") device = atoi(next().c_str());
        else if (a == "-b") blocks = atoi(next().c_str());
        else if (a == "-t") threads = atoi(next().c_str());
        else if (a == "--selftest") run_selftest = true;
        else if (a == "-h" || a == "--help") usage(argv[0]);
        else if (!a.empty() && a[0] == '-') usage(argv[0]);
        else texts.push_back(a);
    }
    if (texts.empty() && !run_selftest) usage(argv[0]);

    std::vector<Prefix> active;
    for (auto& t : texts) {
        Prefix p;
        std::string err;
        if (!build_prefix(t, p, err)) {
            fprintf(stderr, "skipping prefix '%s': %s\n", t.c_str(), err.c_str());
            continue;
        }
        bool dup = false;
        for (auto& q : active) dup |= q.text == p.text;
        if (!dup) active.push_back(p);
    }
    if (active.empty() && !run_selftest) {
        fprintf(stderr, "no usable prefixes\n");
        return 2;
    }
    for (auto& p : active)
        if (active.size() <= 20)
            fprintf(stderr, "prefix %-20s 1 in %s keys\n", p.text.c_str(), human(1 / p.probability).c_str());

    int out_fd = -1;
    if (!out_path.empty()) {
        out_fd = open(out_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (out_fd < 0) {
            perror("open output file");
            return 2;
        }
    }

    CUDA_CHECK(cudaSetDevice(device));
    cudaDeviceProp prop;
    CUDA_CHECK(cudaGetDeviceProperties(&prop, device));
    if (blocks <= 0) blocks = prop.multiProcessorCount * 16;
    uint32_t nthreads = (uint32_t)blocks * threads;
    fprintf(stderr, "device %d: %s, %d SMs, %u threads, %d points per inversion, 6 keys per point\n",
            device, prop.name, prop.multiProcessorCount, nthreads, GROUP);

    std::vector<ge> pow2 = make_pow2_table(), jg = make_jg_table();
    ge *d_pow2, *d_jg;
    ThreadState* d_state;
    Match* d_out;
    uint32_t* d_count;
    uint64_t* d_ranges = nullptr;
    CUDA_CHECK(cudaMalloc(&d_pow2, pow2.size() * sizeof(ge)));
    CUDA_CHECK(cudaMalloc(&d_jg, jg.size() * sizeof(ge)));
    CUDA_CHECK(cudaMalloc(&d_state, (size_t)nthreads * sizeof(ThreadState)));
    CUDA_CHECK(cudaMalloc(&d_out, MATCH_CAP * sizeof(Match)));
    CUDA_CHECK(cudaMalloc(&d_count, sizeof(uint32_t)));
    CUDA_CHECK(cudaMemcpy(d_pow2, pow2.data(), pow2.size() * sizeof(ge), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemcpy(d_jg, jg.data(), jg.size() * sizeof(ge), cudaMemcpyHostToDevice));
    CUDA_CHECK(cudaMemset(d_count, 0, sizeof(uint32_t)));
    if (run_selftest) return selftest(d_pow2, d_jg, pow2);

    int nranges = 0;
    auto upload_ranges = [&]() {
        std::vector<uint64_t> flat = merge_ranges(active);
        if (d_ranges) CUDA_CHECK(cudaFree(d_ranges));
        CUDA_CHECK(cudaMalloc(&d_ranges, flat.size() * sizeof(uint64_t)));
        CUDA_CHECK(cudaMemcpy(d_ranges, flat.data(), flat.size() * sizeof(uint64_t), cudaMemcpyHostToDevice));
        nranges = (int)flat.size() / 2;
    };
    upload_ranges();

    // Starting keys are derived on the GPU from a 256-bit seed from the OS CSPRNG.
    Seed seed;
    if (!read_seed(seed.b)) {
        fprintf(stderr, "cannot read /dev/urandom\n");
        return 1;
    }
    fprintf(stderr, "computing %u starting points...\n", nthreads);
    init_kernel<<<blocks, threads>>>(d_state, d_pow2, seed);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    memset(seed.b, 0, sizeof seed.b);

    using clock = std::chrono::steady_clock;
    auto start = clock::now(), last_status = start;
    double checked = 0;
    long found = 0, rejected = 0;
    int groups = 1;
    std::vector<Match> matches(MATCH_CAP);

    while (!active.empty()) {
        auto t0 = clock::now();
        walk_kernel<<<blocks, threads>>>(d_state, d_jg, d_ranges, nranges, d_out, d_count, groups);
        CUDA_CHECK(cudaGetLastError());
        uint32_t count = 0;
        CUDA_CHECK(cudaMemcpy(&count, d_count, sizeof count, cudaMemcpyDeviceToHost));
        double secs = std::chrono::duration<double>(clock::now() - t0).count();
        checked += 6.0 * nthreads * GROUP * groups;
        if (secs < 0.25 && groups < 1024) groups *= 2;  // aim for launches of roughly a second

        if (count) {
            uint32_t n = count < MATCH_CAP ? count : MATCH_CAP;
            CUDA_CHECK(cudaMemcpy(matches.data(), d_out, n * sizeof(Match), cudaMemcpyDeviceToHost));
            CUDA_CHECK(cudaMemset(d_count, 0, sizeof(uint32_t)));
            bool changed = false;
            for (uint32_t i = 0; i < n && !active.empty(); i++) {
                uint32_t priv[8];
                endo_key(priv, matches[i].key, matches[i].variant);
                KeyInfo ki = describe_key(priv, pow2.data());
                std::string hit;
                for (size_t j = 0; j < active.size();) {
                    if (ki.address.compare(0, active[j].text.size(), active[j].text) == 0) {
                        hit += (hit.empty() ? "" : ", ") + active[j].text;
                        if (!keep_going) {
                            active.erase(active.begin() + j);
                            changed = true;
                            continue;
                        }
                    }
                    j++;
                }
                if (hit.empty()) {
                    rejected++;  // range edge or a key whose prefix was just removed
                    continue;
                }
                found++;
                std::string rec = "Prefix:      " + hit + "\nAddress:     " + ki.address +
                                  "\nPrivate key: " + ki.priv_hex + "\nWIF:         " + ki.wif +
                                  "\nPublic key:  " + ki.pub_hex + "\n\n";
                fprintf(stderr, "\r%-79s\r", "");
                fputs(rec.c_str(), stdout);
                fflush(stdout);
                if (out_fd >= 0 && write(out_fd, rec.data(), rec.size()) != (ssize_t)rec.size())
                    perror("write output file");
                if (max_matches && found >= max_matches) active.clear();
            }
            if (count > MATCH_CAP)
                fprintf(stderr, "\nwarning: %u candidates in one launch, only %u checked; prefix too easy?\n",
                        count, MATCH_CAP);
            if (changed && !active.empty()) upload_ranges();
        }

        auto now = clock::now();
        if (std::chrono::duration<double>(now - last_status).count() >= 1.0 || active.empty()) {
            double el = std::chrono::duration<double>(now - start).count();
            double p = 0;
            for (auto& a : active) p += a.probability;
            std::string eta = p > 0 ? human(log(2.0) / p / (checked / el)) + "s to 50%" : "-";
            fprintf(stderr, "\r%s keys/s | %s checked | %ld found | %zu left | %s   ",
                    human(checked / el).c_str(), human(checked).c_str(), found, active.size(), eta.c_str());
            last_status = now;
        }
    }
    fprintf(stderr, "\n");
    if (rejected > 1000)
        fprintf(stderr, "note: %ld GPU candidates failed host verification\n", rejected);
    if (out_fd >= 0) close(out_fd);
    return 0;
}
