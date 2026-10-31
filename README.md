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

## Testing

Three layers, each independent of the one before:

| Command | Where | What it proves |
| --- | --- | --- |
| `make test` | any machine | the crypto code (compiled for CPU) matches a pure-Python reference: field maths, SHA-256, RIPEMD-160, keys, addresses, WIF, prefix ranges |
| `./vanity --selftest` | GPU | the real kernels produce correct starting points and find planted targets for all six key variants |
| `make e2e` | GPU | real searches; every match re-derived with libsecp256k1 (Bitcoin Core's library), then tampered copies must fail |

To check results from a real run with a library that shares no code with this
program:

```sh
python3 -m venv .venv && .venv/bin/pip install coincurve
.venv/bin/python tests/verify.py found.txt
```

For each match it checks that the WIF decodes to the hex key, that
libsecp256k1 derives exactly the printed public key, that the hash of that key
is exactly the printed address, that the address has the claimed prefix, and
that a signature made with the private key verifies against the public key. For
extra assurance, import the WIF into a wallet such as Electrum on an offline
machine and confirm it shows the same address.

## How it works

- **Keys.** The host reads a 256-bit seed from `/dev/urandom`. Each GPU thread
  derives its starting private key as `SHA-256(seed || thread_id)` mod n, then
  walks forward one key at a time (`k+1, k+2, ...`). Distinct threads start
  at independent random points in the 2^256 key space.
- **Walk.** Each thread adds `G, 2G, ..., 256G` to its current point and
  shares one modular inversion across all 256 additions (Montgomery's trick).
- **Six keys per point.** secp256k1 lets one computed point stand for six
  keys: flipping the sign of y gives the key `n-k`, and multiplying x by a
  constant β gives the key `λ·k` (and again for `λ²·k`). The GPU reports the
  walk key plus which of the six it was; the host turns that back into the real
  private key.
- **Matching.** Every prefix is turned into intervals over the first 64 bits of
  hash160 once, on the host. The GPU only does a binary search over the merged
  intervals, so 1 prefix and 10,000 prefixes cost about the same. The intervals
  are slightly conservative at the edges, so the host rejects the rare near-miss.
- **Checks.** All crypto lives in headers compiled for both GPU and CPU, so
  `make test` exercises the same code against a pure-Python reference.

## Speed

About 1.25G keys/s on an RTX A4000. Hashing is ~84% of the work: an
uncompressed public key is 65 bytes, so each key costs two SHA-256 blocks plus
RIPEMD-160, and that can't be shared between keys. The hashing already runs near
the card's integer throughput, so the main ways to go faster are more GPUs or
compressed keys (one SHA-256 block instead of two).

## Layout

| File | What |
| --- | --- |
| `src/secp256k1.h` | field arithmetic mod p, affine point ops, scalars mod n |
| `src/hash.h` | SHA-256 and RIPEMD-160 |
| `src/walk.h` | per-thread work: key derivation, batched walk, hash160, range check |
| `src/host.h` | Base58, WIF, prefix → range conversion, host verification |
| `src/main.cu` | kernels, CLI, self-test |
| `tests/` | CPU tests and `ref.py`, the independent Python reference |
