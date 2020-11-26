import socket
import select
import time
import sqlite3
import hashlib
from Cryptodome.Cipher import AES

class AESmessages:
    def pad_IV(msg):
        if len(msg) < 16:
            while len(msg) % 16 != 0:
                msg = msg + ' '
        else:
            msg = msg[0:16]
        return msg.encode()
    def pad_msg(msg):
        while len(msg) % 16 != 0:
            msg = msg + ' '
        return msg.encode()
    def encrypt(msg, key, iv, mode):
        cipher = AES.new(key, mode, AESmessages.pad_IV(IV))
        ct = cipher.encrypt(msg)
        return ct
    def decrypt(ct, key, iv, mode):
        cipher  = AES.new(key, mode, iv)
        pt = cipher.decrypt(ct)
        return pt.rstrip().decode()

class AESfiles:
    def pad_IV(msg):
        padding = ""
        if len(msg) < 16:
            while len(msg) % 16 != 0:
                char = random.choice(string.ascii_letters).encode()
                msg = msg + char
                padding = padding + char.decode()
        else:
            state=1
            msg = msg[0:16]
        return msg, padding
    def pad_file(msg):
        while len(msg) % 16 != 0:
            msg = msg + random.choice(string.ascii_letters).encode()
        return msg
    def encrypt(path, key, iv, mode):
        IV, padding = AESfiles.pad_IV(iv)
        cipher = AES.new(key, mode, IV)
        with open(path, 'rb') as f:
            content = f.read()
        pcontent = AESfiles.pad_file(content)
        ct = cipher.encrypt(pcontent)
        with open(path, 'wb') as e:
            e.write(ct)
        return padding
    def decrypt(path, key, iv, mode):
        IV, padding = AESfiles.pad_IV(iv)
        cipher = AES.new(key, mode, IV)
        with open(path, 'rb') as f:
            content = f.read()
        pcontent = AESfiles.pad_file(content)
        pt = cipher.decrypt(pcontent)
        with open(path, 'wb') as e:
            e.write(pt)
        return pt


def login(user, passw):
    with sqlite3.connect("data.db") as db:
        cursor = db.cursor()
    passk = b'P2x#a3g@F4zALfds5$cdA(!qad#Dy3Tv&}'
    key = hashlib.sha3_256(passk).digest()
    mode = AES.MODE_CBC
    IV = "kW$3x@(JsC27XIwX".encode()
    passw = AESmessages.decrypt(passw, key, IV, mode)

    password = "1NJIB*&*Y&H)<MG)&^I(&TF*^$g)*}OPKASD".encode()
    key = hashlib.sha3_256(password).digest()
    iv = "1234567890123456".encode()
    mode = AES.MODE_CBC
    AESfiles.decrypt("data.db", key, iv, mode)

    find = ("SELECT * FROM users WHERE username = ? AND password = ?")
    cursor.execute(find, [(user), (passw)])
    results = cursor.fetchall()
    AESfiles.encrypt("data.db", key, iv, mode)

    if results:
        return True
    else:
        return False

def receive_message(client_socket):
    try:
        hSk = client_socket.recv(HEADER_LENGTH)
        lenSk = int(hSk.decode('utf-8').strip())
        encSk = client_socket.recv(lenSk)

        hNonce = client_socket.recv(HEADER_LENGTH)
        lenNonce = int(hNonce.decode('utf-8').strip())
        nonce = client_socket.recv(lenNonce)

        hTag = client_socket.recv(HEADER_LENGTH)
        lenTag = int(hTag.decode('utf-8').strip())
        tag = client_socket.recv(lenTag)

        hCT = client_socket.recv(HEADER_LENGTH)
        lenCT = int(hCT.decode('utf-8').strip())
        ct = client_socket.recv(lenCT)
        
        return {'hSk' : hSk, 'sk': encSk, 'hNonce' : hNonce, 'nonce': nonce, 'hTag' : hTag, 'tag' : tag, 'hCT': hCT ,'ct' : ct}
    except:
        return False

def receive_user(client_socket, online):
        client_header = client_socket.recv(HEADER_LENGTH)
        if not len(client_header):
            return False

        client_length = int(client_header.decode('utf-8').strip())
        client = client_socket.recv(client_length)

        passw_header = client_socket.recv(HEADER_LENGTH)
        passw_length = int(passw_header.decode('utf-8').strip())
        passw = client_socket.recv(passw_length)

        succ = login(client.decode(), passw)
        if succ and client not in online:
            online.append(client)
            return {'header': client_header, 'data': client}
        else:
            print("Bad login for user: " + client.decode())
            return False
if __name__ == '__main__':
    HEADER_LENGTH = 10
    IP = "127.0.0.1"
    PORT = 65111
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    sockets_list = [server_socket]
    clients = {}
    online = []
    print(f'Listening for connections on {IP}:{PORT}...')
    while True:
        read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
        for notified_socket in read_sockets:
            if notified_socket == server_socket:
                client_socket, client_address = server_socket.accept()
                user = receive_user(client_socket, online)
                if user is False:
                    print("wtf")
                else:
                    sockets_list.append(client_socket)
                    clients[client_socket] = user
                    print(str(time.asctime( time.localtime(time.time()) )) + '   Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))
                    for user_socket in clients:
                        if user_socket != client_socket:
                            user_socket.send("+".encode('utf-8') + user['header'] + user['data'])
            else:
                message = receive_message(notified_socket)
                if message is False:
                    print(str(time.asctime( time.localtime(time.time()) )) +'   Closed connection from: {}'.format(clients[notified_socket]['data'].decode()))
                    online.remove(clients[notified_socket]['data'])
                    sockets_list.remove(notified_socket)
                    for user_socket in clients:
                        if user_socket != notified_socket:
                            user_socket.send("-".encode('utf-8') + clients[notified_socket]['header'] + clients[notified_socket]['data'])
                    del clients[notified_socket]
                    continue
                user = clients[notified_socket]
                print(time.asctime( time.localtime(time.time()) ) + "\t" + user['data'].decode('utf-8') + ": " + str(message['ct']))
                for client_socket in clients:
                    if client_socket != notified_socket:
                        client_socket.send("M".encode('utf-8') + user['header'] + user['data'] + message['hSk'] + message['sk'] + message['hNonce'] + message['nonce'] + \
                            message['hTag'] + message['tag'] + message['hCT'] + message['ct'])
                    for notified_socket in exception_sockets:
                        sockets_list.remove(notified_socket)
                        del clients[notified_socket]
