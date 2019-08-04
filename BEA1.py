from Crypto.Util.number import isPrime
from Crypto.Random.random import getrandbits

SBox0 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox0', 'r').readlines()]
SBox1 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox1', 'r').readlines()]
SBox2 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox2', 'r').readlines()]
SBox3 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox3', 'r').readlines()]
mapping = [[[int(i, 16) for i in group[1:-1].split(', ')] for group in line.strip().split(';')] for line in open('mapping', 'r').readlines()]
mappingInv = [[[int(i, 16) for i in group[1:-1].split(', ')] for group in line.strip().split(';')] for line in open('mappingInv', 'r').readlines()]

class BEA1():
    def __init__(self):
        self.roundKeys = []
        self.round = 2

    def map(self, x):
        M_x = [0x000, 0x000, 0x000, 0x000]
        for idx, xi in enumerate(x):
            for bit_i in range(10):
                if ((xi//(2**bit_i)) % 2) != 0:
                    M_x = [mapping[idx*10+bit_i][1][i] ^ M_x[i] for i in range(4)]
        return M_x

    def mapInv(self, x):
        M_x = [0x000, 0x000, 0x000, 0x000]
        for idx, xi in enumerate(x):
            for bit_i in range(10):
                if ((xi//(2**bit_i)) % 2) != 0:
                    M_x = [mappingInv[idx*10+bit_i][1][i] ^ M_x[i] for i in range(4)]
        return M_x

    # After key expansion, self.roundKeys contains a list of round keys (11 * 16 bytes)
    # Note: Python list index starts from 0
    def KeyExpansion(self, key):
        keyExpand = [0x000] * (8*12)
        for ki in range(12):
            keyExpand[ki] = key[ki]
        
        for i in range(8-1):
            x = self.map(keyExpand[12*i+8:12*i+12])

            x[0] = SBox0[x[0]//16][x[0]%16]
            x[1] = SBox1[x[1]//16][x[1]%16]
            x[2] = SBox2[x[2]//16][x[2]%16]
            x[3] = SBox3[x[3]//16][x[3]%16]
            
            x[0] ^= pow(3, i, 1024)

            keyExpand[12*i+12] = keyExpand[12*i+0] ^ x[0]
            keyExpand[12*i+13] = keyExpand[12*i+1] ^ x[1]
            keyExpand[12*i+14] = keyExpand[12*i+2] ^ x[2]
            keyExpand[12*i+15] = keyExpand[12*i+3] ^ x[3]
            
            keyExpand[12*i+16] = keyExpand[12*i+4] ^ keyExpand[12*i+12]
            keyExpand[12*i+17] = keyExpand[12*i+5] ^ keyExpand[12*i+13]
            keyExpand[12*i+18] = keyExpand[12*i+6] ^ keyExpand[12*i+14]
            keyExpand[12*i+19] = keyExpand[12*i+7] ^ keyExpand[12*i+15]
            
            keyExpand[12*i+20] = keyExpand[12*i+8] ^ keyExpand[12*i+16]
            keyExpand[12*i+21] = keyExpand[12*i+9] ^ keyExpand[12*i+17]
            keyExpand[12*i+22] = keyExpand[12*i+10] ^ keyExpand[12*i+18]
            keyExpand[12*i+23] = keyExpand[12*i+11] ^ keyExpand[12*i+19]            

        for r in range(12):
            self.roundKeys.append(keyExpand[8*r:8*r+8])
        
        #print(self.roundKeys)

    def AddRoundKey(self, state, round):
        for i in range(8):
            state[i] = state[i] ^ self.roundKeys[round][i]
        return state

    def SubBytes(self, state):
        new_state = []
        for i in range(8):
            if i % 4 == 0:
                new_state.append(SBox0[state[i]//16][state[i]%16])
            if i % 4 == 1:
                new_state.append(SBox1[state[i]//16][state[i]%16])
            if i % 4 == 2:
                new_state.append(SBox2[state[i]//16][state[i]%16])
            if i % 4 == 3:
                new_state.append(SBox3[state[i]//16][state[i]%16])

        return new_state

    def InvSubBytes(self, state):
        new_state = []
        for i in range(8):
            for j in range(64):
                for k in range(16):
                    if i % 4 == 0:
                        if state[i] == SBox0[j][k]:
                            new_state.append(j*16 + k)
                    if i % 4 == 1:
                        if state[i] == SBox1[j][k]:
                            new_state.append(j*16 + k)
                    if i % 4 == 2:
                        if state[i] == SBox2[j][k]:
                            new_state.append(j*16 + k)
                    if i % 4 == 3:
                        if state[i] == SBox3[j][k]:
                            new_state.append(j*16 + k)

        return new_state


    def ShiftRows(self, state):
        state = [state[0], state[5], state[2], state[7], state[4], state[1], state[6], state[3]]
        return state

    def MixColumns(self, state):
        new_state = []
        m1 = self.map(state[0:4])
        m2 = self.map(state[4:8])
        for m1i in m1:
            new_state.append(m1i) 
        for m2i in m2:
            new_state.append(m2i)

        return new_state

    def InvMixColumns(self, state):
        new_state = []
        m1 = self.mapInv(state[0:4])
        m2 = self.mapInv(state[4:8])
        for m1i in m1:
            new_state.append(m1i) 
        for m2i in m2:
            new_state.append(m2i)

        return new_state

    def Encrypt(self, plaintext, key):
        self.KeyExpansion(key)
        state = [pi for pi in plaintext]
        
        for r in range(self.round):
            state = self.AddRoundKey(state, r)
            state = self.SubBytes(state)
            state = self.ShiftRows(state)
            if r != self.round-1:
                state = self.MixColumns(state)
        state = self.AddRoundKey(state, self.round)
            
        return state
        

    def Decrypt(self, ciphertext, key):
        state = [ci for ci in ciphertext]
        for r in range(self.round):
            state = self.AddRoundKey(state, self.round-r)
            if r != 0:
                state = self.InvMixColumns(state)
            
            state = self.ShiftRows(state)
            state = self.InvSubBytes(state)
            
        state = self.AddRoundKey(state, 0)
            
        return state


def bitfield(n):
    return [int(digit) for digit in (bin(n)[2:]).rjust(8, '0')]



def randomPair(num):
    pair_arr = []
    for n in range(num):
        p = [getrandbits(10) for i in range(8)]
        c = cipher.Encrypt(p, k)
        pair_arr.append([p,c])
    return pair_arr

if __name__ == "__main__":
    # Instantiation (create an instance)
    # Automatically invoke __init__()
    cipher = BEA1()

    # k: secret key, p: plaintext
    # 120-bits (10-bits*12) master key
    k = [0x300,0x301,0x302,0x303,0x304,0x305,0x306,0x307,0x308,0x309,0x30a,0x30b]
    #p = [0x310,0x311,0x312,0x313,0x314,0x315,0x316,0x317]
    p = [0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7]
    

    c = cipher.Encrypt(p, k)
    print('c:', c)
    plain = cipher.Decrypt(c, k)
    print('plain:', plain)
    print('p:', p)
    
    #Crack()
