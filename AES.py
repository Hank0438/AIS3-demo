def GF256_mult(a, b):
    # x**8 + x**4 + x**3 + x**1 + x**0
    irreducible = 0x1b
    mask = 0x1
    result1 = 0x00
    for i in range(8):
        if ((b & mask) >> i) == 1:
            result1 = result1 ^ (a << i)
        mask = mask << 1
    tmp = (result1 & 0xff00) >> 8
    result1 = result1 & 0x00ff

    # tmp * irreducible
    if tmp > 0:
        result2 = GF256_mult(tmp, irreducible)
        return result1 ^ result2
    else:
        return result1

#print(hex(GF256_mult(0x2a, 0x17)))
#print(hex(GF256_mult(0x53, 0xca)))

def GF256_add(a, b):
    return hex(a ^ b)

def GF256_mult_x(a):
    return GF256_mult(a, 0x2)

def GF256_inv(a):
    for i in range(256):
        if GF256_mult(a, i) == 0x1:
            return i

#print(hex(GF256_inv(0x53)))
#wprint(hex(GF256_inv(0xca)))

def ROTL8(q, shift):
    return ((q << shift) & 0xff) | (q >> (8 - shift))

# SBOX is presented as integer
def sbox():
    p = 1
    q = 1
    sbox = [0] * 256
    sbox[0] = 0x63
    # loop invariant: p * q == 1 in the Galois field
    while True:
        # 3 is a generator
        # multiply p by 3
        p = GF256_mult(p, 0x03)

		# divide q by 3 (equals multiplication by 0xf6)
        q = GF256_mult(q, 0xf6)

		# compute the affine transformation
        sbox[p] = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4) ^ 0x63
        if p == 1: break
    return sbox

SBOX = sbox()
#print(SBOX)

def sbox_inv(SBOX):
    inv = list(range(256))
    for i in range(256):
        inv[SBOX[i]] = i
    return inv

invSBOX = sbox_inv(SBOX)
#print(invSBOX)

def ROTL(state):
    newstate = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    return [state[i] for i in newstate]

#print(ROTL(range(16)))

def ROTL_inv(state):
    newstate = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]
    return [state[i] for i in newstate]

#print(ROTL_inv(ROTL(range(16))))

def mixCol(state):
    newstate = []
    w = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
    for i in range(4):
        col = state[i * 4 : (i + 1) * 4]
        for k in range(4):
            acc = 0
            for j in range(4):
                acc ^= GF256_mult(col[j], w[k][j])
            newstate.append(acc)
    return newstate

#print(mixCol([0x63, 0xf2, 0x7d, 0xd4, 0xc9, 0x63, 0xd4, 0xfa,
#            0xfe, 0x26, 0xc9, 0x63, 0x30, 0xf2, 0xc9, 0x82]))

def mixCol_inv(state):
    newstate = []
    w = [[0xe, 0xb, 0xd, 0x9], [0x9, 0xe, 0xb, 0xd], [0xd, 0x9, 0xe, 0xb], [0xb, 0xd, 0x9, 0xe]]
    for i in range(4):
        col = state[i * 4 : (i + 1) * 4]
        for k in range(4):
            acc = 0
            for j in range(4):
                acc ^= GF256_mult(col[j], w[k][j])
            newstate.append(acc)
    return newstate

#print(mixCol_inv(mixCol([0x63, 0xf2, 0x7d, 0xd4, 0xc9, 0x63, 0xd4, 0xfa,
#            0xfe, 0x26, 0xc9, 0x63, 0x30, 0xf2, 0xc9, 0x82])))

def RCon():
    rcon = []
    tmp = 1
    for i in range(10):
        rcon.append(tmp)
        tmp = GF256_mult_x(tmp)
    return rcon

def keyExpand(key):
    rcon = RCon()
    expkey = [key]
    for i in range(10):
        preWord = expkey[i]
        t = preWord[-4:]

        # RotWord
        t.insert(3, t.pop(0))

        # SubWord
        t = [SBOX[t[j]] for j in range(4)]

        # XOR RCon
        t[0] = t[0] ^ rcon[i]

        # t is done, then compute newWord
        #print(i,[hex(j) for j in t])
        newWord = []
        for k in range(4):
            for j in range(4):
                t[j] = t[j] ^ (preWord[k * 4 : (k + 1) * 4])[j]
                newWord.append(t[j])
        #print(i,[hex(j) for j in newWord])
        expkey.append(newWord)
    return expkey

#key_test = [0x24, 0x75, 0xa2, 0xb3,
#        0x34, 0x75, 0x56, 0x88,
#        0x31, 0xe2, 0x12, 0x00,
#        0x13, 0xaa, 0x54, 0x87]
#keyExpansion = keyExpand(key_test)
#print(keyExpansion)

def addRoundKey(state, keyExpansion, round):
    key = keyExpansion[round]
    return [state[i] ^ key[i] for i in range(16)]

def blockGen(plaintxt):
    i = 0
    statePlaintxt = []
    while True:
        p = plaintxt[i * 16 : (i + 1) * 16]
        if len(p) is 0:
            break
        while len(p) < 16:
            p.append(0)
        statePlaintxt.append(p)
        i += 1
    return statePlaintxt

#plain = range(20)
#print(blockGen(plain))

def AES_encrypt(plain, key):
    statePlaintxt = blockGen(plain)
    keyExpansion = keyExpand(key)
    stateCiphertxt = []
    for block in statePlaintxt:
        # Init AddRoundKey
        block = addRoundKey(block, keyExpansion, 0)
        print('S', 0, ':', [hex(j) for j in block])
        for round in range(10):
            # SubBytes
            block = [SBOX[block[j]] for j in range(16)]
            # ShiftRows
            block = ROTL(block)
            # MixColumns
            if round + 1 != 10:
                block = mixCol(block)
            # AddRoundKey
            block = addRoundKey(block, keyExpansion, round + 1)

            # test
            if round+1 == 2: print(hex(block[5]))
            if round+1 == 6: print(hex(block[8]))
            if round+1 == 10: print(hex(block[9]))

            print('S', round + 1, ':', [hex(j) for j in block])
        stateCiphertxt.append(block)
    return stateCiphertxt

def AES_decrypt(cipher, key):
    stateCiphertxt = cipher
    # reverse keyExpansion
    keyExpansion = keyExpand(key)[::-1]
    statePlaintxt = []
    for block in stateCiphertxt:
        # Init AddRoundKey
        block = addRoundKey(block, keyExpansion, 0)
        print('S', 0, ':', [hex(j) for j in block])
        for round in range(10):
            # InvShiftRows
            block = ROTL_inv(block)
            # InvSubBytes
            block = [invSBOX[block[j]] for j in range(16)]
            # InvAddRoundKey
            block = addRoundKey(block, keyExpansion, round + 1)
            # InvMixColumns
            if round + 1 != 10:
                block = mixCol_inv(block)

            if round+1 == 1: print(hex(block[3]))
            if round+1 == 9: print(hex(block[2]))

            print('S', round + 1, ':', [hex(j) for j in block])
        statePlaintxt.append(block)
    return statePlaintxt

def test_case(plain, key):
    print('plain: ', [hex(j) for j in plain])
    print('key: ', [hex(j) for j in key])
    print('============================ENCRYPTION====================================')
    cipher = AES_encrypt(plain, key)
    print('cipher:', [hex(j) for j in cipher[0]])
    print('============================DECRYPTION====================================')
    recover = AES_decrypt(cipher, key)
    print('recover: ', [hex(j) for j in recover[0]])

def parsing(input):
    in_list = []
    in_list = input.split()
    in_list = [int(i, 16) for i in in_list]
    return in_list


p0 = [0xa3, 0xc5, 0x08, 0x08, 0x78, 0xa4, 0xff, 0xd3, 0x00, 0xff, 0x36, 0x36, 0x28, 0x5f, 0x01, 0x02]
k0 = [0x36, 0x8a, 0xc0, 0xf4, 0xed, 0xcf, 0x76, 0xa6, 0x08, 0xa3, 0xb6, 0x78, 0x31, 0x31, 0x27, 0x6e]
#test_case(p0, k0)
p1 = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
k1 = [0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0]
#test_case(p1, k1)

print('====================p1========================')
p01 = '05 96 bf ff 19 f2 47 52 e7 e3 9e 3c 80 53 b7 35'
k01 = '75 ea 48 db 07 2c bc 5f 89 47 6e c7 ce 4b 17 72'
p01 = parsing(p01)
k01 = parsing(k01)
test_case(p01, k01)


print('====================p2========================')
p02 = '6d b7 0b 47 06 8c c8 da a0 d3 d7 45 0f c8 52 b2'
k02 = 'd6 a6 ce 9f 39 84 1b 6f 2b 6c bc 75 85 32 c9 40'
p02 = parsing(p02)
k02 = parsing(k02)
test_case(p02, k02)


print('====================p3========================')
p03 = '76 9a 2f b7 d3 19 32 76 42 2c 32 6f 09 28 6c 8a'
k03 = '8a 26 da 3f 1d 59 71 18 97 e2 17 92 87 4a a0 ad'
p03 = parsing(p03)
k03 = parsing(k03)
test_case(p03, k03)

print('====================p4========================')
p04 = 'a6 b8 db 55 d4 2b df 1c d8 9c 59 6e 34 dd a0 1a'
k04 = '0e ee c2 98 e7 cf fc ff 2b b6 e1 12 20 e3 5b 95'
p04 = parsing(p04)
k04 = parsing(k04)
test_case(p04, k04)
