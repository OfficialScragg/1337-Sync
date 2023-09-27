# 1337 Sync client
# Author: Scragg
# Date: 25/09/2023

import os, sys, socket, threading, random, string, time, base64, textwrap, math
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ip = ""
port = ""
directory = ""
psk = ""
running = True
files_db = {}
filenames = []
updates = []

def main():
    global ip, port, directory, running
    read_config()
    populate_db()
    while running:
        time.sleep(0)
        if detect_changes():
            print("Changes detected!")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((ip, int(port)))
                print("Connected to server!")
                if authenticate(s):
                    print("Authentication successful!")
                    sync_files(s)
    return

def read_config():
    global ip, port, directory, psk
    config_data = open("/home/daniel/Files/Repos/1337-Sync/1337-client.conf", "r").read().split("\n")
    port = config_data[0]
    ip = config_data[1]
    directory = config_data[2]
    psk = config_data[3]
    return

def populate_db():
    global directory, files_db, filenames
    walk = os.walk(directory)
    for i in walk:
        for f in i[2]:
            path = str(i[0])+str("/")+str(f)
            filenames.append(path)
            mod = os.path.getmtime(path)
            files_db[path] = mod
    print(files_db)
    return

# Detect changes by looking at the last modified date and time of each file in the directory
def detect_changes():
    global directory, files_db, filenames, updates
    # Look for new files
    updates = []
    walk = os.walk(directory)
    for i in walk:
        for f in i[2]:
            curr_file = str(i[0])+str("/")+str(f)
            mod = os.path.getmtime(curr_file)
            if curr_file not in filenames:
                filenames.append(curr_file)
                files_db[curr_file] = mod
                updates.append(curr_file)
            elif files_db[curr_file] != mod:
                files_db[curr_file] = mod
                updates.append(curr_file)
    if updates != []:
        return True
    return False

def authenticate(c):
    global psk
    c.sendall(bytes("AUTH", "utf-8"))
    data = c.recv(1024)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=bytes("salty-salty-salt", "utf-8"), iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(bytes(psk, "utf-8")))
    f = Fernet(key)
    c.sendall(f.encrypt(data))
    data = c.recv(1024).decode("utf-8")
    if data == "SUCCESS":
        return True
    return False

def sync_files(c):
    global updates
    print("Updating files...")
    for f in updates:
        send_file(f, c)
    c.sendall(bytes("SYNCED", "utf-8"))
    print("Files synced!\n")
    return

def send_file(f, c):
    global directory
    path = f.replace(directory, "")
    print("Sending:", path)
    file_data = base64.b64encode(open(f, "rb").read()).decode("utf-8")
    c.sendall(bytes("FILE", "utf-8"))
    c.recv(1024)
    c.sendall(bytes(path, "utf-8"))
    c.recv(1024)
    # Chop up b64 and send through the chunks
    for i in range(0, math.ceil(len(file_data)/1000)):
        if int(i+1)*1000 >= len(file_data):
            c.sendall(bytes(file_data[i*1000::], "utf-8"))
        else:
            c.sendall(bytes(file_data[i*1000:int(i+1)*1000], "utf-8"))
        c.recv(1024)
    # ---------------------------------------
    c.sendall(bytes("END", "utf-8"))
    return

if __name__ == "__main__":
    main()
