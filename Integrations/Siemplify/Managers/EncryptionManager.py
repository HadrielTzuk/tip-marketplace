import base64
import os
from pkcs7 import PKCS7Encoder
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


class AESManager(object):

    def __init__(self, key=None, iv=None):
        self.key = key if key else base64.b64encode(os.urandom(16))
        self.key = str(self.key).encode('utf-8')
        self.iv = iv if iv else '\x00' * 16
        self.encoder = PKCS7Encoder()

    def encrypt(self, data):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_text = self.encoder.encode(data)
        cipher_text = aes.encrypt(padded_text)
        return base64.b64encode(cipher_text)

    def decrypt(self, data):
        aes = AES.new(self.key, AES.MODE_CBC, self.iv)
        cipher_text = base64.b64decode(data)
        clear = aes.decrypt(cipher_text)
        text = self.encoder.decode(clear)
        return text


class RSAManager(object):

    def __init__(self, public_key=None, private_key=None):
        self.public_key = RSA.importKey(public_key) if public_key else None
        self.private_key = RSA.importKey(private_key) if private_key else None

    def encrypt(self, data, encode=True):
        if not self.public_key:
            raise Exception("Cannot encrypt without public key")
        cipher = PKCS1_v1_5.new(self.public_key)
        encrypted_data = cipher.encrypt(data)
        encrypted_data = base64.b64encode(encrypted_data) if encode else encrypted_data
        return encrypted_data

    def decrypt(self, data, decode=True):
        if not self.private_key:
            raise Exception("Cannot decrypt without private key")
        data = base64.b64decode(data) if decode else data
        cipher = PKCS1_v1_5.new(self.private_key)
        return cipher.decrypt(data, None)
