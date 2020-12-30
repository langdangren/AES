import base64
import hashlib

from Crypto.Cipher import AES
from django.conf import settings


class AESEncrypt:
    def __init__(self, key: str = settings.KUNMING_PICC_CLUB_AES_KEY):
        self.aes = AES.new(self.get_sha1prng_key(key), AES.MODE_ECB)

    @staticmethod
    def get_sha1prng_key(key: str) -> bytes:
        signature: bytes = hashlib.sha1(key.encode()).digest()
        signature: bytes = hashlib.sha1(signature).digest()
        return signature[:16]

    @staticmethod
    def padding(s: str) -> str:
        pad_num: int = 16 - len(s) % 16
        return s + pad_num * chr(pad_num)

    @staticmethod
    def un_padding(s):
        padding_num: int = ord(s[-1])
        return s[:-padding_num]

    def encrypt(self, s: str):
        """加密函数"""
        content_b = self.padding(s).encode("utf-8")
        encrypted = self.aes.encrypt(content_b)
        return base64.b64encode(encrypted).decode()

    def decrypt(self, s: base64):
        """解密函数"""
        s = base64.b64decode(s)
        s_bytes = self.aes.decrypt(s)
        return self.un_padding(s_bytes.decode())

    @staticmethod
    def s_to_md5(s: str):
        return hashlib.md5(s.encode("utf-8")).hexdigest().upper()
