# bit-finder

CUDA vanity address finder for Bitcoin. Give it any number of prefixes of any
length; the GPU generates keys, hashes them and checks them against every
prefix, and only matching key pairs come back to the host. Each match is then
recomputed from scratch on the CPU before it's printed.

Uncompressed P2PKH addresses only for now (they start with `1`).

## Build

Needs `nvcc` (CUDA 11.6+) and a C++17 compiler.

```sh
make                 # builds ./vanity for the GPU in this machine
make ARCH=sm_86      # or name the architecture explicitly
make test            # CPU test suite + Python cross-check, no GPU needed
./vanity --selftest  # runs the real kernels and checks them against the CPU
```

On the A4000 box CUDA lives in `/usr/local/cuda-12.8/bin`; add it to `PATH` first.

## Use

```sh
./vanity 1Love 1Cafe 111                 # stop once each prefix is found
./vanity -f prefixes.txt -o found.txt    # prefixes from a file, one per line
./vanity -k -n 10 1Ab                    # keep going, stop after 10 matches
```

Prefixes are case-sensitive and must use the Base58 alphabet (no `0`, `O`,
`I` or `l`). Each match prints the address, private key in hex and as an
uncompressed WIF, and the 65-byte public key. `-o` appends to a file created
with mode 0600.

At startup it prints how many keys each prefix needs on average, and the status
line shows the expected time to a 50% chance of the next hit. Each extra
character costs about 58x.

## How it works

- **Keys.** The host reads a 256-bit seed from `/dev/urandom`. Each GPU thread
  derives its starting private key as `SHA-256(seed || thread_id)` mod n, then
  walks forward one key at a time (`k+1, k+2, ...`). Distinct threads start
  at independent random points in the 2^256 key space.
- **Walk.** Each thread adds `G, 2G, ..., 256G` to its current point and
  shares one modular inversion across all 256 additions (Montgomery's trick).
- **Matching.** Every prefix is turned into intervals over the first 64 bits of
  hash160 once, on the host. The GPU only does a binary search over the merged
  intervals, so 1 prefix and 10,000 prefixes cost about the same. The intervals
  are slightly conservative at the edges, so the host rejects the rare near-miss.
- **Checks.** All crypto lives in headers compiled for both GPU and CPU, so
  `make test` exercises the same code against a pure-Python reference.

## Layout

| File | What |
| --- | --- |
| `src/secp256k1.h` | field arithmetic mod p, affine point ops, scalars mod n |
| `src/hash.h` | SHA-256 and RIPEMD-160 |
| `src/walk.h` | per-thread work: key derivation, batched walk, hash160, range check |
| `src/host.h` | Base58, WIF, prefix → range conversion, host verification |
| `src/main.cu` | kernels, CLI, self-test |
| `tests/` | CPU tests and `ref.py`, the independent Python reference |
