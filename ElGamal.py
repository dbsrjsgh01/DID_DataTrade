from Crypto.Util.number import inverse
from Crypto.Math.Primality import generate_probable_safe_prime
from Crypto.Random import get_random_bytes
from Crypto.Math.Numbers import Integer
from binascii import hexlify, unhexlify

def generate():
    return ElGamal()

class ElGamal:
    def __init__(self):
        self.p = generate_probable_safe_prime(exact_bits = 256, randfunc=get_random_bytes)
        self.q = (self.p - 1) >> 1

        while 1:
            self.g = pow(Integer.random_range(min_inclusive = 2,
                                        max_exclusive=self.p,
                                        randfunc=get_random_bytes), 2, self.p)
            
            if (self.g in (1, 2)) or ((self.p - 1) % self.g == 0) or ((self.p - 1) % self.g.inverse(self.p) == 0):
                continue
            break

        self.x = Integer.random_range(min_inclusive = 2,
                                    max_exclusive=self.p-1,
                                    randfunc=get_random_bytes)
        
        self.y = pow(self.g, self.x, self.p)

        self.p = int(self.p)
        self.g = int(self.g)
        self.x = int(self.x)
        self.y = int(self.y)
    
    def getPublicKey(self):
        return self.p, self.g, self.y
    
    def getPrivateKey(self):
        return self.x

    def encrypt(self, msg):
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
        return msg