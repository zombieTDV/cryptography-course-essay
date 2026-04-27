# ── Constants ─────────────────────────────────────────────────────────────────
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

MASK32 = 0xFFFFFFFF


# ── Bit operations ────────────────────────────────────────────────────────────
def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK32

def add32(*args):
    result = 0
    for a in args:
        result = (result + a) & MASK32
    return result

def ch(e, f, g):
    return (e & f) ^ (~e & g) & MASK32

def maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)

def sigma0(a):
    return rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)

def sigma1(e):
    return rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)

def gamma0(w):
    return rotr(w, 7) ^ rotr(w, 18) ^ (w >> 3)

def gamma1(w):
    return rotr(w, 17) ^ rotr(w, 19) ^ (w >> 10)


# ── Padding ───────────────────────────────────────────────────────────────────
def pad(msg):
    msg_len_bits = len(msg) * 8
    msg += b'\x80'
    while len(msg) % 64 != 56:
        msg += b'\x00'
    msg += bytes((msg_len_bits >> (56 - 8 * i)) & 0xFF for i in range(8))
    return msg


# ── Message schedule ──────────────────────────────────────────────────────────
def message_schedule(block):
    W = [int.from_bytes(block[i*4:(i+1)*4], 'big') for i in range(16)]
    for t in range(16, 64):
        w = add32(gamma1(W[t-2]), W[t-7], gamma0(W[t-15]), W[t-16])
        W.append(w)
    return W


# ── Compression ───────────────────────────────────────────────────────────────
def compress(H, block):
    W = message_schedule(block)
    a, b, c, d, e, f, g, h = H
    for t in range(64):
        T1 = add32(h, sigma1(e), ch(e, f, g), K[t], W[t])
        T2 = add32(sigma0(a), maj(a, b, c))
        h = g
        g = f
        f = e
        e = add32(d, T1)
        d = c
        c = b
        b = a
        a = add32(T1, T2)
    return [add32(H[i], v) for i, v in enumerate([a, b, c, d, e, f, g, h])]


# ── Digest assembly ───────────────────────────────────────────────────────────
def digest_to_bytes(H):
    result = b''
    for word in H:
        result += bytes([
            (word >> 24) & 0xFF,
            (word >> 16) & 0xFF,
            (word >>  8) & 0xFF,
             word        & 0xFF,
        ])
    return result


# ── Main entry point ──────────────────────────────────────────────────────────
def sha256(msg):
    padded = pad(msg)
    H = H0[:]
    for i in range(len(padded) // 64):
        block = padded[i*64:(i+1)*64]
        H = compress(H, block)
    return digest_to_bytes(H)


if __name__ == '__main__':
    MSG  = 'HELLO_UTH_UNIVERSITY!!!!!!!'
    MSG2 = 'HELLO_UTH_UNIVERSITY!'

    h1 = sha256(MSG.encode())
    h2 = sha256(MSG2.encode())

    print(f'Input : {MSG}')
    print(f'SHA256: {h1.hex()}')

    bits1 = bin(int(h1.hex(), 16))[2:].zfill(256)
    bits2 = bin(int(h2.hex(), 16))[2:].zfill(256)
    diff  = sum(b1 != b2 for b1, b2 in zip(bits1, bits2))

    print(f'\nInput2: {MSG2}')
    print(f'SHA256: {h2.hex()}')
    print(f'Bits different: {diff}/256 ({diff/256*100:.1f}%)')
