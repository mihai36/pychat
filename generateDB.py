import sqlite3
from Cryptodome.Cipher import AES
import hashlib
import os
import random
import string

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


open("data.db", "w")    
with sqlite3.connect("data.db") as db:
    cursor = db.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users(
    username VARCHAR(20) PRIMARY KEY,
    password VARCHAR(100) NOT NULL);
''')

records = [('john', 'password'), ('guest', 'guest1'), ('anon', 'secret')]
cursor.executemany('INSERT INTO users VALUES(?,?);',records);
db.commit()
db.close()

password = "1NJIB*&*Y&H)<MG)&^I(&TF*^$g)*}OPKASD".encode()
key = hashlib.sha3_256(password).digest()
iv = "1234567890123456".encode()
AESfiles.encrypt("data.db", key, iv, AES.MODE_CBC)
