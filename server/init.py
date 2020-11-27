import sqlite3
import os
from AES import *

def generateKey(n):
    key = RSA.generate(n)
    private_key = key.export_key()
    file_out = open("private.pem", "wb")
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open("receiver.pem", "wb")
    file_out.write(public_key)
    file_out.close()

def generateDB():
    open("data.db", "w")
    with sqlite3.connect("data.db") as db:
        cursor = db.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users(
        username VARCHAR(20) PRIMARY KEY,
        password VARCHAR(100) NOT NULL);
    ''')
    records = [('admin', 'admin'),('guest', 'guest')] #change the values

    cursor.executemany('INSERT INTO users VALUES(?,?);', records);
    db.commit()
    db.close()

    password = "1NJIB*&*Y&H)<MG)&^I(&TF*^$g)*}OPKASD".encode()
    key = hashlib.sha3_256(password).digest()
    iv = "1234567890123456".encode()
    AESfiles.encrypt("data.db", key, iv, AES.MODE_CBC)


if __name__ == '__main__':
    key_size = int(input("Input key size(1024,2048,4096,8192): "))
    generateKey(key_size)
    generateDB()
