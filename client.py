import socket
import errno
import time
import sys
import random
import hashlib
import string
from tkinter import *
from tkinter import filedialog as fd
from tkinter import messagebox
from getpass import getpass
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

def enc_sk(sk):
    password = b'%Rd6Fpr$5*x(W2^bOI=Jc&kO8>9VyX0N}[@>?<'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "^vX?%6P&Fu$;$dK!".encode()
    return AESmessages.encrypt(sk, key, IV, mode)

def dec_sk(sk):
    password = b'%Rd6Fpr$5*x(W2^bOI=Jc&kO8>9VyX0N}[@>?<'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "^vX?%6P&Fu$;$dK!".encode()
    return AESmessages.decrypt(sk, key, IV, mode)

def enc_nonce(sk):
    password = b'P2x#a3g@F4zALfds5$cdA(!qad#Dy3Tv&}'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "kW$3x@(JsC27XIwX".encode()
    return AESmessages.encrypt(sk, key, IV, mode)

def dec_nonce(sk):
    password = b'P2x#a3g@F4zALfds5$cdA(!qad#Dy3Tv&}'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "kW$3x@(JsC27XIwX".encode()
    return AESmessages.decrypt(sk, key, IV, mode)

def enc_tag(sk):
    password = b'T5#x4%\;s+8Df9@kdI3P(]&aF+M>,<x}^uZjK==X'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "$gD7xKp%6Cx&pFh{".encode()
    return AESmessages.encrypt(sk, key, IV, mode)

def dec_tag(sk):
    password = b'T5#x4%\;s+8Df9@kdI3P(]&aF+M>,<x}^uZjK==X'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "$gD7xKp%6Cx&pFh{".encode()
    return AESmessages.decrypt(sk, key, IV, mode)

def enc_ct(sk):
    password = b'*(x.D)S3$h7%fZ&k^d-g$3j\[f$5!2jFd$6j&(cG+u>yMQ'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "$gF3S%8C=^Dqa$5w".encode()
    return AESmessages.encrypt(sk, key, IV, mode)

def dec_ct(sk):
    password = b'*(x.D)S3$h7%fZ&k^d-g$3j\[f$5!2jFd$6j&(cG+u>yMQ'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "$gF3S%8C=^Dqa$5w".encode()
    return AESmessages.decrypt(sk, key, IV, mode)


def formatString(st):
    return st[2:-1]

def receive_message(client_socket):

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

class loginLayout:
    def gui(self):
        values = {}
        window = Tk()
        window.title("Symetric Encryption")
        window.configure(background="black")
        Label (window, text="Server ip: ", bg="black", fg="cyan3", font="none 12 bold").grid(row=1, column=0 ,sticky=W, padx=(0, 12))
        sip = Entry(window, width=18, bg="LightBlue1", font="none 12")
        sip.grid(row=1, column=1, sticky=W)
        Label (window, text="Server port: ", bg="black", fg="cyan3", font="none 12 bold").grid(row=2, column=0 ,sticky=W, padx=(0, 12), pady=(10,0))
        sport = Entry(window, width=18, bg="LightBlue1", font="none 12")
        sport.grid(row=2, column=1, sticky=W, pady=(10,0))
        Label (window, text="Username: ", bg="black", fg="cyan4", font="none 12 bold").grid(row=3, column=0, sticky=W, padx=(0, 12), pady=(45,0))
        user = Entry(window, width=18, bg="LightBlue1", font="none 12")
        user.grid(row=3, column=1, sticky=W, pady=(45,0))
        Label (window, text="Password: ", bg="black", fg="cyan4", font="none 12 bold").grid(row=4, column=0 ,sticky=W, padx=(0, 12), pady=(10,0))
        passw = Entry(window, width=18, bg="LightBlue1", font="none 12")
        passw.config(show="*")
        passw.grid(row=4, column=1, sticky=W, pady=(10,0))
        
        def getLogin():
            values['usr'] = user.get()
            values['psw'] = passw.get()
            values['ip'] = sip.get()
            values['port'] = sport.get()
            window.quit()
            window.destroy()
        
        Button(window, text="Login", width=13, bg="cadetblue4", command=getLogin).grid(row=5, column=1, sticky=W, padx=(48, 0), pady=(9,0))
        window.mainloop()
        username = values['usr']
        password = values['psw']
        ip = values['ip']
        port = values['port']
        return username, password, ip, port

if __name__ == '__main__':
    HEADER_LENGTH = 10
    users = []
    recv = False
    my_username, my_password, IP, PORT = loginLayout().gui()
    if my_username == "" or my_password == "" or IP == "" or PORT == "":
        sys.exit()
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((IP, int(PORT)))
    client_socket.setblocking(False)
    username = my_username.encode('utf-8')
    password = b'P2x#a3g@F4zALfds5$cdA(!qad#Dy3Tv&}'
    key = hashlib.sha3_256(password).digest()
    mode = AES.MODE_CBC
    IV = "kW$3x@(JsC27XIwX".encode()
    passw = AESmessages.encrypt(my_password.encode(), key, IV, mode)
    username_header = f"{len(username):<{HEADER_LENGTH}}".encode('utf-8')
    password_header = f"{len(passw):<{HEADER_LENGTH}}".encode('utf-8')
    client_socket.send(username_header + username)
    client_socket.send(password_header + passw)
    
    window = Tk()
    window.title("Private GroupChat")
    window.configure(background="black")
    Label (window, text="Encrypted Chat", bg="black", fg="cyan4", font="none 18 bold").grid(row=0, column=0, sticky=W, pady=(10,8), padx=(10,10))
    Label (window, text="Online users: ", bg="black", fg="cyan4", font="none 12 bold").grid(row=0, column=1, sticky=W, pady=(60, 70))
    online = Text(window, width=9, height=18 ,bg="black", fg="cyan3", font="none 11 bold")
    online.grid(row=1, column=1, sticky=W, padx=(10,10))
    text = Text(window, width=48, height=24 ,bg="black", fg="white")
    text.grid(row=1, column=0, sticky=W, padx=(10,10))
    Label (window, text="Send message:", bg="black", fg="cyan4", font="none 12 bold").grid(row=2, column=0, columnspan=2 ,sticky=W, pady=(10,8), padx=(10,10))
    send = Text(window, width=48, height=6 , bg="black", fg="white")
    send.grid(row=3, column=0, sticky=W, padx=(10,10))

    def getUsers(grid, users):
        grid.delete("1.0", END)
        for user in users:
            grid.insert(END, "  " + user + "\n")

    def recvMsg():
        global recv
        try:
            getUsers(online, users)
            while True:
                typex = client_socket.recv(1).decode('utf-8')
                if typex == 'M':
                    username_header = client_socket.recv(HEADER_LENGTH)
                    if not len(username_header):
                        print('Connection closed by the server')
                        sys.exit()
                    username_length = int(username_header.decode('utf-8').strip())
                    username = client_socket.recv(username_length).decode('utf-8')
                    if username not in users:
                        users.append(username)
                    objX = receive_message(client_socket)
                    enc_session_key = dec_sk(objX['sk'])
                    nonce = dec_nonce(objX['nonce'])
                    tag = dec_tag(objX['tag'])
                    ciphertext = dec_ct(objX['ct'])
                    private_key = RSA.import_key(open("private.pem").read())
                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    session_key = cipher_rsa.decrypt(enc_session_key)
                    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
                    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                    text.insert(END,username + "> "+ data.decode("utf-8"))
                if typex == '+':
                    username_header = client_socket.recv(HEADER_LENGTH)
                    username_length = int(username_header.decode('utf-8').strip())
                    username = client_socket.recv(username_length).decode('utf-8')
                    users.append(username)
                if typex == '-':
                    username_header = client_socket.recv(HEADER_LENGTH)
                    username_length = int(username_header.decode('utf-8').strip())
                    username = client_socket.recv(username_length).decode('utf-8')
                    users.remove(username)
        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()
        except Exception as e:
            print('Reading error: '+  str(e))
            sys.exit()
    
    def sendMsg():
        recvMsg()
        recvMsg()
        message = ""
        msg = send.get("1.0", END)
        if len(msg) > 3:
            message = msg.encode('utf-8')
            recipient_key = RSA.import_key(open("receiver.pem").read())
            session_key = get_random_bytes(16)
            cipher_rsa = PKCS1_OAEP.new(recipient_key)
            enc_session_key = cipher_rsa.encrypt(session_key)
            cipher_aes = AES.new(session_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(message)
            enc_SK = enc_sk(enc_session_key)
            xTag = enc_tag(tag)
            ct = enc_ct(ciphertext)
            lenSk = len(enc_SK)
            lenNonce = len(enc_nonce(cipher_aes.nonce))
            lenTag = len(xTag)
            lenCT = len(ct)

            message_header = f"{lenSk:<{HEADER_LENGTH}}".encode('utf-8') + enc_SK + f"{lenNonce:<{HEADER_LENGTH}}".encode('utf-8') + enc_nonce(cipher_aes.nonce) + \
                    f"{lenTag:<{HEADER_LENGTH}}".encode('utf-8') + xTag + f"{lenCT:<{HEADER_LENGTH}}".encode('utf-8') + ct

            client_socket.send(message_header)
            text.insert(END, my_username + " > " + send.get("1.0", END))
            send.delete("1.0", END)

    Label (window, text="Logged in as:", bg="black", fg="cyan4", font="none 15").grid(row=4, column=0, sticky=W)
    Label (window, text="  " + my_username + "\n", bg="black", fg="dodgerblue", font="none 18 bold").grid(row=5, column=0, sticky=W)
    Button(window, text="Send", width=13, bg="cadetblue4", command=sendMsg).grid(row=4, column=1, sticky=W, padx=(10, 0))
    Button(window, text="Recv", width=13, bg="cadetblue3", command=recvMsg).grid(row=5, column=1, sticky=W, padx=(10, 0))
    window.mainloop()
