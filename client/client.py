## file_client.py

import socket
import argparse

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
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

def run(host, port, fileName):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(fileName.encode())

        ## reSize = 파일 사이즈
        reSize = s.recv(1024)
        reSize = reSize.decode()

        ## 디렉토리에 파일이 없을 경우
        if reSize == "error":
            print("파일을 찾을 수 없습니다.")
            return

        ## client가 파일 사이즈를 받고 준비된 것을 서버에 알림
        msg = "ready"
        s.sendall(msg.encode())

        ##with open(fileName, 'w', encoding="utf8") as f:
        with open(fileName, "wb") as f:
            ## 파일 사이즈만큼 recv
            encSize = s.recv(1024)
            encSize = encSize.decode()
            data = s.recv(int(encSize))
            key = 'abcdefg'
            cipher = AESCipher(key)
            f.write(cipher.decrypt(data))

            print("file name : "+fileName)
            print("size : "+reSize)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo client -p port -i host -f file")
    parser.add_argument('-p', help="port_number", required=True)
    parser.add_argument('-i', help="host_name", required=True)
    parser.add_argument('-f', help="file_name", required=True)

    args = parser.parse_args()
    run(host=args.i, port=int(args.p), fileName=args.f)
