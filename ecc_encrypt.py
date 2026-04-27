from sha256 import sha256

# ── secp256k1 parameters ──────────────────────────────────────────────────────
P   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A   = 0
B   = 7
Gx  = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy  = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G   = (Gx, Gy)
N   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
INF = None


# ── Field arithmetic ──────────────────────────────────────────────────────────
def mod_inv(a):
    return pow(a, P - 2, P)


# ── Point arithmetic ──────────────────────────────────────────────────────────
def point_add(P1, P2):
    if P1 is INF:
        return P2
    if P2 is INF:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and y1 != y2:
        return INF
    if x1 == x2:
        lam = (3 * x1 * x1 + A) * mod_inv(2 * y1) % P
    else:
        lam = (y2 - y1) * mod_inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)

def scalar_mul(k, point=None):
    if point is None:
        point = G
    result = INF
    addend = point
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


# ── KDF (SHA-256 counter mode) ────────────────────────────────────────────────
def kdf(shared_point, needed_len):
    sx      = shared_point[0].to_bytes(32, 'big')
    key     = b''
    counter = 0
    while len(key) < needed_len:
        counter_bytes = counter.to_bytes(4, 'big')
        key          += sha256(sx + counter_bytes)
        counter      += 1
    return key[:needed_len]


# ── ECIES encrypt / decrypt ───────────────────────────────────────────────────
def ecies_encrypt(msg, pub_key, ephemeral_k):
    R          = scalar_mul(ephemeral_k)
    S          = scalar_mul(ephemeral_k, pub_key)
    key        = kdf(S, len(msg))
    ciphertext = bytes(m ^ k for m, k in zip(msg, key))
    return R, ciphertext

def ecies_decrypt(R, ciphertext, priv_key):
    S   = scalar_mul(priv_key, R)
    key = kdf(S, len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, key))


if __name__ == '__main__':
    D_BOB    = 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
    R_EPHEM  = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    MESSAGE  = b'Xin chao Bob! Day la tin nhan bi mat.'

    Q_BOB = scalar_mul(D_BOB)
    print(f'Plaintext : {MESSAGE}')
    print(f'Bob priv  : 0x{D_BOB:064X}')
    print(f'Bob pub Qx: 0x{Q_BOB[0]:064X}')

    R, ct = ecies_encrypt(MESSAGE, Q_BOB, R_EPHEM)
    print(f'\nR.x       : 0x{R[0]:064X}')
    print(f'Ciphertext: {ct.hex().upper()}')

    pt = ecies_decrypt(R, ct, D_BOB)
    print(f'\nDecrypted : {pt}')
    print(f'Match     : {pt == MESSAGE}')
