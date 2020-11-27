from AES import *
import sqlite3

password = "1NJIB*&*Y&H)<MG)&^I(&TF*^$g)*}OPKASD".encode()
key = hashlib.sha3_256(password).digest()
iv = "1234567890123456".encode()
AESfiles.decrypt("data.db", key, iv, AES.MODE_CBC)


records = []
names = []
opt = int(input("1.Create user\n2.Delete user\nInput: "))
if opt == 1:
    with sqlite3.connect("data.db") as db:
        cursor = db.cursor()
    while(True):
        print("\n\t##### CREATE USER ######")
        name = input("username: ")
        password = input("password: ")
        records.append((name, password))
        q = input("Input another user (y/n): ")
        if(q.lower()[0] == 'n'):
            break
    cursor.executemany('INSERT INTO users VALUES(?,?);', records)
    db.commit()
    db.close()
    print("\nUser/s added to database.")
elif opt == 2:
    with sqlite3.connect("data.db") as db:
        cursor = db.cursor()
    while(True):
        print("\n\t##### DELETE USER ######")
        name = input("username: ")
        names.append(name)
        records.append((name, password))
        q = input("Remove another user (y/n): ")
        if(q.lower()[0] == 'n'):
            break
    for usr in names:
        cursor.execute('DELETE FROM users WHERE username=?;', [usr])
    db.commit()
    db.close()
    print("\nUser/s removed from database.")

password = "1NJIB*&*Y&H)<MG)&^I(&TF*^$g)*}OPKASD".encode()
key = hashlib.sha3_256(password).digest()
iv = "1234567890123456".encode()
AESfiles.encrypt("data.db", key, iv, AES.MODE_CBC)


