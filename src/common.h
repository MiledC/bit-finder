#pragma once
#include <stdint.h>

// Everything that does crypto is written once and compiled for both the GPU
// (nvcc) and the CPU (g++), so the CPU test suite exercises the same code.
#ifdef __CUDACC__
#define HD __host__ __device__ inline
#else
#define HD inline
#endif

// A GPU hit: the private key is endo_key(key, variant), see secp256k1.h.
struct Match {
    uint32_t key[8];  // walk key, little-endian 32-bit limbs
    uint32_t variant;
};
