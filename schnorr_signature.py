from sha256 import sha256
from ecc_encrypt import (
    P, A, B, G, N, INF,
    mod_inv, point_add, scalar_mul,
)

# ── Point negation ────────────────────────────────────────────────────────────
def point_neg(pt):
    if pt is INF:
        return INF
    return (pt[0], (-pt[1]) % P)


# ── Lift x → even-y point (BIP-340) ──────────────────────────────────────────
def lift_x(x):
    y_sq = (pow(x, 3, P) + B) % P
    y    = pow(y_sq, (P + 1) // 4, P)
    assert pow(y, 2, P) == y_sq, "x not on curve"
    if y % 2 != 0:
        y = P - y
    return (x, y)


# ── Tagged hash (BIP-340) ─────────────────────────────────────────────────────
def tagged_hash(tag, data):
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)


# ── Challenge hash e ──────────────────────────────────────────────────────────
def hash_challenge(R_x_bytes, P_x_bytes, msg):
    payload = R_x_bytes + P_x_bytes + msg
    h       = tagged_hash('BIP0340/challenge', payload)
    return int.from_bytes(h, 'big') % N


# ── Keypair (ensures even-y public key) ───────────────────────────────────────
def schnorr_keygen(d_raw):
    Q = scalar_mul(d_raw)
    if Q[1] % 2 != 0:
        d_raw = N - d_raw
        Q     = scalar_mul(d_raw)
    pub_x_bytes = Q[0].to_bytes(32, 'big')
    return d_raw, Q, pub_x_bytes


# ── Sign ──────────────────────────────────────────────────────────────────────
def schnorr_sign(msg, priv_key, pub_x_bytes, k_nonce):
    R     = scalar_mul(k_nonce)
    k     = k_nonce if R[1] % 2 == 0 else N - k_nonce
    R_x   = R[0].to_bytes(32, 'big')
    e     = hash_challenge(R_x, pub_x_bytes, msg)
    s     = (k + e * priv_key) % N
    return R_x, s


# ── Verify ────────────────────────────────────────────────────────────────────
def schnorr_verify(msg, signature, pub_x_bytes):
    R_x_bytes, s = signature
    if not (0 < s < N):
        return False
    R_x = int.from_bytes(R_x_bytes, 'big')
    P_x = int.from_bytes(pub_x_bytes, 'big')
    try:
        pub_point = lift_x(P_x)
    except Exception:
        return False
    e       = hash_challenge(R_x_bytes, pub_x_bytes, msg)
    sG      = scalar_mul(s)
    eP      = scalar_mul(e, pub_point)
    R_prime = point_add(sG, point_neg(eP))
    if R_prime is INF:
        return False
    return R_prime[0] == R_x and R_prime[1] % 2 == 0


if __name__ == '__main__':
    D_RAW   = 0x3333333333333333333333333333333333333333333333333333333333333333
    K_NONCE = 0x5555555555555555555555555555555555555555555555555555555555555555
    MSG     = b'Schnorr la chu ky dep hon ECDSA!'

    d, Q, pub_x = schnorr_keygen(D_RAW)
    sig          = schnorr_sign(MSG, d, pub_x, K_NONCE)
    R_x, s       = sig

    print(f'Message   : {MSG}')
    print(f'Pub key Qx: {pub_x.hex().upper()}')
    print(f'R.x       : {R_x.hex().upper()}')
    print(f's         : 0x{s:064X}')
    print(f'Signature : {(R_x + s.to_bytes(32, "big")).hex().upper()}')
    print()
    print(f'Verify (valid msg) : {schnorr_verify(MSG, sig, pub_x)}')
    print(f'Verify (tampered)  : {schnorr_verify(b"Schnorr la chu ky dep hon ECDSA?", sig, pub_x)}')
    print(f'Verify (wrong key) : {schnorr_verify(MSG, sig, bytes(32))}')
