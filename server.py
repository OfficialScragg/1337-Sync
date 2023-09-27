# 1337 Sync server
# Author: Scragg
# Date: 25/09/2023

import os, sys, socket, threading, random, string, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ip = ""
port = ""
directory = ""
psk = ""
running = True

def main():
    read_config()
    init_server()
    return

def read_config():
    global ip, port, directory, psk
    config_data = open("1337-server.conf", "r").read().split("\n")
    port = config_data[0]
    ip = config_data[1]
    directory = config_data[2]
    psk = config_data[3]
    return

def init_server():
    global ip, port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, int(port)))
        s.listen()
        run_server(s)
        s.close()
    return

def run_server(sock):
    global running
    while running:
        conn, addr = sock.accept()
        print("Connection from "+str(addr))
        handle_client(conn)
    return

def handle_client(conn):
    if authenticate(conn):
        sync_files(conn)
    return

def authenticate(c):
    data = c.recv(1024)
    if data.decode("utf-8") == "AUTH":
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=bytes("salty-salty-salt", "utf-8"), iterations=480000)
        key = base64.urlsafe_b64encode(kdf.derive(bytes(psk, "utf-8")))
        nonce = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        f = Fernet(key)
        c.sendall(bytes(nonce, "utf-8"))
        data = c.recv(1024)
        res = f.decrypt(data).decode("utf-8")
        print("NONCE: "+str(nonce))
        print("RES:   "+str(res)+"\n")
        if res == nonce:
            c.sendall(bytes("SUCCESS", "utf-8"))
            return True
        else:
            print("Auth failed.")
            c.sendall(bytes("FAILURE", "utf-8"))
    return False

def sync_files(c):
    data = bytes("", "utf-8")
    file_data = ""
    while data.decode("utf-8") != "SYNCED":
        data = c.recv(1024)
        c.sendall(bytes("aight", "utf-8"))
        if data.decode("utf-8") == "FILE":
            print("Starting file...")
            file_data = ""
            data = c.recv(1024)
            path = data.decode("utf-8")
            print("Receiving:", path)
            c.sendall(bytes("aight", "utf-8"))
            data = c.recv(1024)
            while data.decode("utf-8") != "END":
                print("Receive data...")
                c.sendall(bytes("aight", "utf-8"))
                file_data = file_data + data.decode("utf-8")
                data = c.recv(1024)
            file_data = base64.b64decode(file_data)
            file_path = str(directory)+str(path)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file = open(file_path, "wb")
            file.write(file_data)
            file.close()
            print("File closed...")
    print("SYNCED")
    return

if __name__ == "__main__":
    main()