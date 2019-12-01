# file_data_server.py

import socket
import argparse
from os.path import exists
import os

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES


class AESCipher():

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

def run_server(port, directory):
    ##client ip
    host ='127.0.0.1'

    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)

        conn, addr = s.accept()
        fileName = conn.recv(1024)
        fileName = fileName.decode()

        ## 경로에 파일 없을 시 에러
        if not exists(directory+"\\"+fileName):
            msg = "error"
            conn.sendall(msg.encode())
            conn.close()
            return

        conn.sendall(getFileSize(fileName, directory).encode())

        key = 'abcdefg'
        cipher = AESCipher(key)
        #준비 확인
        reReady = conn.recv(1024)
        if reReady.decode() == "ready":
            encfile = cipher.encrypt(getFileData(fileName, directory))
            conn.sendall(str(len(encfile)).encode())
            conn.sendall(encfile.encode())
        conn.close()

## 파일 크기 반환
def getFileSize(fileName, directory):
    fileSize = os.path.getsize(directory+"\\"+fileName)
    return str(fileSize)

## 파일 내용 반환
def getFileData(fileName, directory):
    ##with open(directory+"\\"+fileName, 'r', encoding = "utf8") as f:
    with open(directory+"\\"+fileName, "rb") as f:
        data = bytearray(f.read())

        return data

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo server -p port - d directory")
    parser.add_argument('-p', help="port_number", required=True)
    parser.add_argument('-d', help="directory", required=True)

    args = parser.parse_args()
    run_server(port=int(args.p), directory=args.d)