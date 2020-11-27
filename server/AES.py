import random
import string
import hashlib
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP

class AESmessages:
    def pad_IV(msg):
        if len(msg) < 16:
            while len(msg) % 16 != 0:
                msg = msg + b' '
        else:
            msg = msg[0:16]
        return msg
    def pad_msg(msg):
        while len(msg) % 16 != 0:
            msg = msg + b' '
            #random.choice(string.ascii_letters).encode()
        return msg
    def encrypt(msg, key, iv, mode):
        cipher = AES.new(key, mode, AESmessages.pad_IV(iv))
        ct = cipher.encrypt(AESmessages.pad_msg(msg))
        return ct
    def decrypt(ct, key, iv, mode):
        cipher  = AES.new(key, mode, iv)
        pt = cipher.decrypt(ct)
        return pt.rstrip()

class AESfiles:
    def pad_IV(msg):
        padding=""
        if len(msg) < 16:
            while len(msg) % 16 != 0:
                char = random.choice(string.ascii_letters).encode()
                msg = msg  + char
                padding += char
        else:
            msg = msg[0:16]
        return msg, padding
    def pad_file(msg):
        while len(msg) % 16 != 0:
            msg = msg + ' '.encode()
        return msg
    def encrypt(path, key, iv, mode):
        ivX, pad = AESfiles.pad_IV(iv)
        cipher = AES.new(key, mode, ivX) 
        with open(path, 'rb') as f:
            content = f.read()
        pcontent = AESfiles.pad_file(content)
        ct = cipher.encrypt(pcontent)
        with open(path, 'wb') as e:
            e.write(ct)
        return pad, ct
    def decrypt(path, key, iv, mode):
        cipher = AES.new(key, mode, iv)
        with open(path, 'rb') as f:
            content = f.read()
        pcontent = AESfiles.pad_file(content)
        pt = cipher.decrypt(pcontent)
        with open(path, 'wb') as e:
            e.write(pt)
        return pt
