mapping = [[[int(i, 16) for i in group[1:-1].split(', ')] for group in line.strip().split(';')] for line in open('mapping', 'r').readlines()]
mappingInv = [[[int(i, 16) for i in group[1:-1].split(', ')] for group in line.strip().split(';')] for line in open('mappingInv', 'r').readlines()]

X = [0x002, 0x002, 0x000, 0x000]
def map(x):
    M_x = [0x000, 0x000, 0x000, 0x000]
    for idx, xi in enumerate(x):
        for bit_i in range(10):
            #print('xi: ', xi)
            if ((xi//(2**bit_i)) % 2) != 0:
                M_x = [mapping[idx*10+bit_i][1][i] ^ M_x[i] for i in range(4)]
                #print('M_x:', M_x)
    #print(M_x)
    return M_x
#print([mapping[1][1][i] ^ mapping[11][1][i] for i in range(4)])

def mapInv(x):
    M_x = [0x000, 0x000, 0x000, 0x000]
    for idx, xi in enumerate(x):
        for bit_i in range(10):
            #print('xi: ', xi)
            if ((xi//(2**bit_i)) % 2) != 0:
                M_x = [mappingInv[idx*10+bit_i][1][i] ^ M_x[i] for i in range(4)]
                #print('M_x:', M_x)
    #print(M_x)
    return M_x

if __name__ == "__main__":
    '''
    map_X = map(X)
    #print(map_X)
    print(X)
    print(mapInv(map_X))
    '''
    from Crypto.Util.number import isPrime, inverse
    SBox0 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox0', 'r').readlines()]
    SBox1 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox1', 'r').readlines()]
    SBox2 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox2', 'r').readlines()]
    SBox3 = [[int(i, 16) for i in line.strip().split(' ')] for line in open('Sbox3', 'r').readlines()]
    
    prime_arr = []
    for i in range(1024):
        if isPrime(i) == 1:
            prime_arr.append(i)
    #print(len(prime_arr))
    print(inverse(0,11))

    for idx, si in enumerate(SBox1[1]):
        for prime in prime_arr:
            if inverse(idx, prime) == si:
                print(prime) 

 
