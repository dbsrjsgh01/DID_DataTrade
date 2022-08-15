
import os
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from utils import *

img_path = str(os.path.dirname(os.path.abspath(__file__))) + '\\' + "test_data.jpg"
img_path_enc = str(os.path.dirname(os.path.abspath(__file__))) + '\\' + "enc_data.jpg"

class encData():
    def __init__(self, key, data):
        self.data = data
        self.data_key = key
        self.CT = 0
        
    def key_gen():
        return get_random_bytes(16)
    
    def getCT(self):
        return self.CT

    def pad(self, value):
        return value + b"\x00" * (16 - len(value) % 16)

    def trans_format_RGB(self, value):
        red, green, blue = tuple(map(lambda e: [value[i] for i in range(0, len(value)) if i % 3 == e], [0, 1, 2]))
        pixels = tuple(zip(red, green, blue))
        return pixels

    def aes_ecb_encrypt(self, key, value, mode=AES.MODE_ECB):
        #The default mode is ECB encryption
        aes = AES.new(key, mode)
        new_data = aes.encrypt(value)
        return new_data

    def encrypt_image_ecb(self, filename, data_key):
        im = Image.open(filename)
        
        value_vector = im.convert("RGB").tobytes()

        imlength = len(value_vector)
        value_encrypt = self.trans_format_RGB(self.aes_ecb_encrypt(data_key, self.pad(value_vector))[:imlength])
        im2 = Image.new(im.mode, im.size)
        im2.putdata(value_encrypt)
        # print(hash(im2))
        self.CT = im2
        return im2
        #im2.show()
        #im2.save(img_path_enc)

    def enc(self):
        enc_data = self.encrypt_image_ecb(self.data, self.data_key)
        # enc_data.show()
        enc_data.save(img_path_enc)
        
