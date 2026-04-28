# Pure-Python Cryptography — From Scratch

> AES-128 · SHA-256 · ECIES · ECDH · Schnorr BIP-340  
> **Zero crypto libraries. Zero dependencies.**

---

## What this is

Five cryptographic algorithms implemented entirely in pure Python, with a benchmarking notebook that ties them all together. No `pycryptodome`, no `cryptography`, no `hashlib`, no `struct` — not even for auxiliary tasks. SHA-256 is written from scratch and imported by the other modules instead.

---

## Files

```
.
├── sha256.py               # SHA-256 (FIPS 180-4) — no imports
├── aes128_encrypt.py       # AES-128 ECB + PKCS#7 — no imports
├── ecc_encrypt.py          # ECIES on secp256k1 — imports sha256
├── ecdh_key_exchange.py    # ECDH + HMAC-SHA256 + HKDF RFC 5869 — imports sha256, ecc_encrypt
├── schnorr_signature.py    # Schnorr BIP-340 — imports sha256, ecc_encrypt
└── benchmark.ipynb         # Benchmarks all 5 modules with timeit
```

### Dependency graph

```
sha256.py  ──────────────────────────────┐
                                         ▼
aes128_encrypt.py (standalone)     ecc_encrypt.py
                                         │
                          ┌──────────────┴──────────────┐
                          ▼                             ▼
               ecdh_key_exchange.py         schnorr_signature.py
```

---

## Algorithms

### SHA-256 — `sha256.py`

Full FIPS 180-4 implementation. Functions are split by responsibility:

| Function | Role |
|---|---|
| `pad(msg)` | Append `0x80`, zero-pad to 448 mod 512, append 64-bit length |
| `message_schedule(block)` | Expand 16 words → W[0..63] using γ₀, γ₁ |
| `compress(H, block)` | 64-round compression with Σ, Ch, Maj |
| `digest_to_bytes(H)` | Pack 8×32-bit words → 32 bytes big-endian |
| `sha256(msg)` | Top-level: pad → init H₀ → compress each chunk → digest |

```python
from sha256 import sha256

sha256(b'abc').hex()
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

---

### AES-128 — `aes128_encrypt.py`

ECB mode with PKCS#7 padding. GF(2⁸) multiplication done with shift-and-XOR, no lookup tables.

| Function | Role |
|---|---|
| `gf_mul(a, b)` | Multiply two bytes in GF(2⁸) mod 0x11B |
| `key_expansion(key)` | 16-byte key → 11 round keys via RotWord/SubWord/Rcon |
| `sub_bytes` / `shift_rows` / `mix_columns` / `add_round_key` | Four AES round transforms |
| `aes_encrypt_block(block, round_keys)` | Single 16-byte block: Round 0 → 9 full rounds → Round 10 |
| `aes128_encrypt(plaintext, key)` | Accepts `str` or `bytes`, pads, encrypts all blocks |

```python
from aes128_encrypt import aes128_encrypt

key = bytes.fromhex('7472756F6E67646F76756F6E67313233')
ct  = aes128_encrypt('HELLO_UTH_UNIVERSITY!', key)
print(ct.hex().upper())
```

---

### ECIES — `ecc_encrypt.py`

Elliptic Curve Integrated Encryption Scheme on **secp256k1** (the Bitcoin curve). Also serves as the shared ECC math library for ECDH and Schnorr.

| Function | Role |
|---|---|
| `mod_inv(a)` | Modular inverse via Fermat's little theorem: a^(P−2) mod P |
| `point_add(P1, P2)` | Handles ∞, doubling, and general addition |
| `scalar_mul(k, point)` | Double-and-add, O(log k) |
| `kdf(shared_point, n)` | Key derivation: SHA-256 counter mode on S.x |
| `ecies_encrypt(msg, pub, k_e)` | R = k·G, S = k·Q, ct = msg ⊕ KDF(S) |
| `ecies_decrypt(R, ct, priv)` | S = d·R, recover key, XOR |

```python
from ecc_encrypt import scalar_mul, ecies_encrypt, ecies_decrypt

priv = 0xABCDEF01...
pub  = scalar_mul(priv)
R, ct = ecies_encrypt(b'secret message', pub, ephemeral_k)
pt    = ecies_decrypt(R, ct, priv)
```

---

### ECDH + HKDF — `ecdh_key_exchange.py`

Full ECDH handshake with HMAC-SHA256 and HKDF (RFC 5869), all built on top of `sha256.py` and `ecc_encrypt.py`.

| Function | Role |
|---|---|
| `hmac_sha256(key, msg)` | Pure-Python HMAC using the local sha256 |
| `hkdf_extract(salt, ikm)` | RFC 5869 Extract step → PRK |
| `hkdf_expand(prk, info, n)` | RFC 5869 Expand step → OKM |
| `hkdf(ikm, n, salt, info)` | Extract + Expand in one call |
| `ecdh_shared_secret(my_priv, their_pub)` | Returns shared point S = d·Q |
| `make_keypair(d)` | Deterministic keypair from scalar d |
| `xor_stream(key, data)` | XOR-based symmetric encrypt/decrypt |

```python
from ecdh_key_exchange import make_keypair, ecdh_shared_secret, hkdf

_, Qa = make_keypair(alice_priv)
_, Qb = make_keypair(bob_priv)

S = ecdh_shared_secret(alice_priv, Qb)
key = hkdf(S[0].to_bytes(32, 'big'), 32, salt=b'...', info=b'demo')
```

---

### Schnorr BIP-340 — `schnorr_signature.py`

Schnorr signatures per **BIP-340** (Bitcoin Taproot). x-only public keys, even-y convention enforced throughout.

| Function | Role |
|---|---|
| `tagged_hash(tag, data)` | SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ data) — domain separation |
| `hash_challenge(Rx, Px, msg)` | Fiat-Shamir challenge e mod n |
| `lift_x(x)` | Recover even-y point from x-only pubkey |
| `schnorr_keygen(d)` | Enforce even-y convention on P; return (d, Q, Qx-bytes) |
| `schnorr_sign(msg, priv, pub_x, k)` | Deterministic sign; k flipped if R.y is odd |
| `schnorr_verify(msg, sig, pub_x)` | Check sG − eP = R′ with even y |

```python
from schnorr_signature import schnorr_keygen, schnorr_sign, schnorr_verify

d, Q, pub_x = schnorr_keygen(private_scalar)
sig          = schnorr_sign(b'message', d, pub_x, nonce)
valid        = schnorr_verify(b'message', sig, pub_x)   # True
```

> **Never reuse `k`.** If the same nonce is used for two different messages, the private key can be recovered from the two signatures algebraically.

---

## Benchmark — `benchmark.ipynb`

Imports all five modules and measures wall-clock time with `timeit`. All inputs and keys are the same as those used in each module's `__main__` demo. Only `timeit`, `statistics`, and `secrets` are used — no other libraries.

| Algorithm | Operation | Median (ms) |
|---|---|---|
| AES-128 | Encrypt 16 B (pre-computed keys) | 1.244 |
| AES-128 | Encrypt 1 KB (64 blocks) | 63.387 |
| SHA-256 | Hash 28 B (1 chunk) | 0.295 |
| SHA-256 | Hash 1 KB (16 chunks) | 5.294 |
| ECIES | Encrypt 37 B | 151.191 |
| ECIES | Decrypt 37 B | 68.110 |
| ECDH | Full handshake (4× scalar_mul) | 269.059 |
| HKDF | Derive 32 B | 2.658 |
| Schnorr | Sign | 72.419 |
| Schnorr | Verify | 146.566 |
| Schnorr | Batch verify 5 sigs (sequential) | 734.335 |

> ECC operations dominate because `scalar_mul` is pure Python with no C backend, no Montgomery ladder optimisation, and no precomputed tables. AES and SHA-256 are fast because they operate on small fixed-size data with no big-integer arithmetic.

To run the notebook, place all five `.py` files in the same directory as `benchmark.ipynb`, then:

```bash
jupyter notebook benchmark.ipynb
```

---

## Running each file standalone

Every file has a `__main__` block with a self-contained demo using fixed inputs:

```bash
python sha256.py
python aes128_encrypt.py
python ecc_encrypt.py
python ecdh_key_exchange.py
python schnorr_signature.py
```

No installation required beyond a standard Python 3 interpreter.

---

## Design principles

- **No imports inside algorithm files.** `sha256.py` and `aes128_encrypt.py` have zero imports. `ecc_encrypt.py` imports only `sha256`. The two higher-level modules import from those two.
- **Small named functions, not one-liners.** Every logical step — `rot_word`, `mix_single_column`, `hkdf_extract`, `lift_x` — is its own function with a clear name.
- **Nonces are caller-supplied.** `ecies_encrypt` and `schnorr_sign` both take the random value as a parameter rather than generating it internally. This keeps the functions pure and makes testing deterministic.
- **`if __name__ == '__main__'` guards everywhere.** Importing any module is silent; all demo output is gated behind the main guard.

---

## Curve parameters (secp256k1)

```
p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a  = 0,  b = 7   →   y² = x³ + 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

---

## Standards compliance

| Module | Standard |
|---|---|
| AES-128 | FIPS 197 |
| SHA-256 | FIPS 180-4 |
| secp256k1 curve | SEC 2 |
| HKDF | RFC 5869 |
| Schnorr / x-only keys | BIP-340 |

---

## Security notice

This code is written for **study only**. It is not hardened against timing attacks, fault injection, or side-channel analysis. Do not use it to protect real data.