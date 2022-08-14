from Crypto.Util.number import inverse
from Crypto.Math.Primality import generate_probable_safe_prime
from Crypto.Random import get_random_bytes
from Crypto.Math.Numbers import Integer
from binascii import hexlify, unhexlify
import re

def initialize_ElGamal():
    p = generate_probable_safe_prime(exact_bits=256, randfunc=get_random_bytes)
    
    while 1:
        g = pow(Integer.random_range(min_inclusive = 2,
                                    max_exclusive = p,
                                    randfunc = get_random_bytes), 2, p)
        if (g in (1, 2)) or ((p - 1) % g == 0) or ((p - 1) % g.inverse(p) == 0):
            continue
        break

    x = Integer.random_range(min_inclusive = 2,
                            max_exclusive = p - 1,
                            randfunc = get_random_bytes)
    y = pow(g, x, p)
    return ElGamal(p, g, x, y)

def generate(key):
    while 1:
        p = generate_probable_safe_prime(exact_bits=256, randfunc=get_random_bytes)
        if p > key:
            break
        
    while 1:
        g = pow(Integer.random_range(min_inclusive = 2,
                                    max_exclusive = p,
                                    randfunc = get_random_bytes), 2, p)
        if (g in (1, 2)) or ((p - 1) % g == 0) or ((p - 1) % g.inverse(p) == 0):
            continue
        break

    y = pow(g, key, p)
    return ElGamal(p, g, key, y)

class ElGamal:
    def __init__(self, p, g, x, y):
        self.p = int(p)
        self.g = int(g)
        self.x = int(x)
        self.y = int(y)
    
    def getPublicKey(self):
        return self.p, self.g, self.y
    
    def getPrivateKey(self):
        return self.x

    def encrypt(self, *args):
        msg = str()
        for i in str(args):
            msg += str(i)
        msg_byte = msg.encode('utf-8')
        m = int(hexlify(msg_byte), 16)
        r = get_random_bytes(16)
        r = int.from_bytes(r, "big")
        c1 = pow(self.g, r, self.p)
        c2 = (m * pow(self.y, r, self.p)) % self.p
        return c1, c2
    
    def decrypt(self, c1, c2):
        s = pow(c1, self.x, self.p)
        m = (c2 * inverse(s, self.p)) % self.p
        m = format(m, 'x')
        msg = unhexlify(m).decode('utf-8')
        return re.sub("[(,)]","",msg)

# def test():
#     key = initialize_ElGamal()
#     msg = ("Geonho Yoon", "26", 200)
#     c1, c2 = key.encrypt(msg)
#     print("C1\t: ", c1)
#     print("C2\t: ", c2)
#     dm = key.decrypt(c1, c2)
#     print("Decrypt : ", dm)
#     m = dm.split()
#     for i in m:
#         print(i)
#     print("fee\t: ", m[2])

# if __name__ == "__main__":
#     test()