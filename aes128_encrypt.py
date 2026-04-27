# ── Constants ─────────────────────────────────────────────────────────────────
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]


# ── GF(2^8) multiplication ────────────────────────────────────────────────────
def gf_mul(a, b):
    result = 0
    for i in range(8):
        if (b >> i) & 1:
            result ^= (a << i)
    for k in range(14, 7, -1):
        if (result >> k) & 1:
            result ^= (0x11B << (k - 8))
    return result & 0xFF


# ── Padding ───────────────────────────────────────────────────────────────────
def pkcs7_pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


# ── Key expansion ─────────────────────────────────────────────────────────────
def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [SBOX[b] for b in word]

def xor_words(w1, w2):
    return [w1[i] ^ w2[i] for i in range(4)]

def key_expansion(key):
    W = [[key[4*i + j] for j in range(4)] for i in range(4)]
    for i in range(4, 44):
        temp = W[i - 1][:]
        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= RCON[(i // 4) - 1]
        W.append(xor_words(W[i - 4], temp))
    round_keys = []
    for rk in range(11):
        flat = []
        for w in range(4):
            flat += W[rk * 4 + w]
        round_keys.append(flat)
    return round_keys


# ── State helpers ─────────────────────────────────────────────────────────────
def bytes_to_state(block):
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_bytes(state):
    return bytes(state[r][c] for c in range(4) for r in range(4))


# ── Round transformations ─────────────────────────────────────────────────────
def add_round_key(state, round_key):
    result = [[0]*4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            result[r][c] = state[r][c] ^ round_key[r + 4*c]
    return result

def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state):
    return [state[r][r:] + state[r][:r] for r in range(4)]

def mix_single_column(col):
    out = [0] * 4
    for r in range(4):
        val = 0
        for i in range(4):
            val ^= gf_mul(MIX_MATRIX[r][i], col[i])
        out[r] = val
    return out

def mix_columns(state):
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mixed = mix_single_column(col)
        for r in range(4):
            result[r][c] = mixed[r]
    return result


# ── Block encryption ──────────────────────────────────────────────────────────
def aes_encrypt_block(block, round_keys):
    state = bytes_to_state(block)
    state = add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    return state_to_bytes(state)


# ── Main entry point ──────────────────────────────────────────────────────────
def aes128_encrypt(plaintext, key):
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('ascii')
    padded     = pkcs7_pad(plaintext)
    round_keys = key_expansion(key)
    ciphertext = b''
    for i in range(len(padded) // 16):
        block      = padded[i*16:(i+1)*16]
        ct_block   = aes_encrypt_block(block, round_keys)
        ciphertext += ct_block
    return ciphertext


if __name__ == '__main__':
    PLAINTEXT = 'HELLO_UTH_UNIVERSITY!'
    KEY       = bytes.fromhex('7472756F6E67646F76756F6E67313233')

    round_keys = key_expansion(KEY)
    padded     = pkcs7_pad(PLAINTEXT.encode())

    print(f'Plaintext : {PLAINTEXT}')
    print(f'Key       : {KEY.hex().upper()}')
    print()

    for i in range(len(padded) // 16):
        block    = padded[i*16:(i+1)*16]
        ct_block = aes_encrypt_block(block, round_keys)
        print(f'  Block {i+1}  PT: {block.hex().upper()}')
        print(f'  Block {i+1}  CT: {ct_block.hex().upper()}')

    ct = aes128_encrypt(PLAINTEXT, KEY)
    print(f'\nCiphertext: {ct.hex().upper()}')
