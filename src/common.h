#pragma once
#include <stdint.h>

// Everything that does crypto is written once and compiled for both the GPU
// (nvcc) and the CPU (g++), so the CPU test suite exercises the same code.
#ifdef __CUDACC__
#define HD __host__ __device__ inline
#else
#define HD inline
#endif

// Pairs of [lo, hi] (inclusive) over the top 64 bits of hash160.
struct Match {
    uint32_t key[8];  // private key, little-endian 32-bit limbs
};
