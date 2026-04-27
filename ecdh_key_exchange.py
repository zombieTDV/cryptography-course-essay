from sha256 import sha256
from ecc_encrypt import (
    P, A, B, G, N, INF,
    mod_inv, point_add, scalar_mul,
)

# ── HMAC-SHA256 ───────────────────────────────────────────────────────────────
def hmac_sha256(key, msg):
    if len(key) > 64:
        key = sha256(key)
    key    = key + b'\x00' * (64 - len(key))
    o_key  = bytes(k ^ 0x5C for k in key)
    i_key  = bytes(k ^ 0x36 for k in key)
    inner  = sha256(i_key + msg)
    return sha256(o_key + inner)


# ── HKDF ─────────────────────────────────────────────────────────────────────
def hkdf_extract(salt, ikm):
    if not salt:
        salt = b'\x00' * 32
    return hmac_sha256(salt, ikm)

def hkdf_expand(prk, info, length):
    n      = -(-length // 32)   # ceil division
    okm    = b''
    T_prev = b''
    for i in range(1, n + 1):
        T_prev  = hmac_sha256(prk, T_prev + info + bytes([i]))
        okm    += T_prev
    return okm[:length]

def hkdf(ikm, length, salt=b'', info=b''):
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


# ── ECDH ─────────────────────────────────────────────────────────────────────
def ecdh_shared_secret(my_priv, their_pub):
    shared_point = scalar_mul(my_priv, their_pub)
    return shared_point


# ── Keypair generation (deterministic — pass a private key scalar) ────────────
def make_keypair(priv_scalar):
    pub = scalar_mul(priv_scalar)
    return priv_scalar, pub


# ── XOR stream encrypt / decrypt (symmetric) ─────────────────────────────────
def xor_stream(key_bytes, data):
    return bytes(d ^ k for d, k in zip(data, key_bytes))


if __name__ == '__main__':
    D_ALICE = 0x1111111111111111111111111111111111111111111111111111111111111111
    D_BOB   = 0x2222222222222222222222222222222222222222222222222222222222222222
    MSG     = b'Hello from Alice via ECDH!'
    SALT    = b'\xde\xad\xbe\xef' * 4

    d_a, Q_A = make_keypair(D_ALICE)
    d_b, Q_B = make_keypair(D_BOB)
    print(f'Alice pub Qx: 0x{Q_A[0]:064X}')
    print(f'Bob   pub Qx: 0x{Q_B[0]:064X}')

    S_A = ecdh_shared_secret(d_a, Q_B)
    S_B = ecdh_shared_secret(d_b, Q_A)
    print(f'\nShared S.x  : 0x{S_A[0]:064X}')
    print(f'Shared match: {S_A == S_B}')

    ikm      = S_A[0].to_bytes(32, 'big')
    key_mat  = hkdf(ikm, 32, SALT, b'ECDH-demo')
    enc_key  = key_mat[:16]
    auth_key = key_mat[16:]

    stream  = hkdf(enc_key, len(MSG), b'', b'keystream')
    ct      = xor_stream(stream, MSG)
    mac     = hmac_sha256(auth_key, ct)[:16]

    print(f'\nPlaintext   : {MSG}')
    print(f'Ciphertext  : {ct.hex().upper()}')
    print(f'MAC         : {mac.hex().upper()}')

    key_mat_b = hkdf(S_B[0].to_bytes(32, 'big'), 32, SALT, b'ECDH-demo')
    stream_b  = hkdf(key_mat_b[:16], len(ct), b'', b'keystream')
    pt        = xor_stream(stream_b, ct)
    mac_ok    = hmac_sha256(key_mat_b[16:], ct)[:16] == mac
    print(f'\nDecrypted   : {pt}')
    print(f'MAC valid   : {mac_ok}')
    print(f'Match       : {pt == MSG}')
