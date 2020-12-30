import base64
from typing import Optional

from Crypto.Cipher import AES
from django.conf import settings


class AESCBCEncrypt:
    """AES CBC模式加解密类，使用pkcs7填充，数据库128位"""

    def __init__(
        self,
        key: Optional[str] = settings.DIDI_DELIVERY_PACKAGE_AES_KEY,
        iv: Optional[str] = settings.DIDI_DELIVERY_PACKAGE_AES_IV,
    ):
        self.key = key
        self.iv = iv
        self.block_size = AES.block_size

    def pkcs7padding(self, text):
        """
        明文使用PKCS7填充
        最终调用AES加密方法时，传入的是一个byte数组，要求是16的整数倍，因此需要对明文进行处理
        """
        bytes_length = len(text.encode("utf-8"))
        padding_size = len(text) if (bytes_length == len(text)) else bytes_length
        padding = self.block_size - padding_size % self.block_size
        padding_text = chr(padding) * padding
        return text + padding_text

    def pkcs7unpadding(self, text):
        """
        处理使用PKCS7填充过的数据
        """
        unpadding = ord(text[len(text) - 1])
        return text[0 : len(text) - unpadding]

    def encrypt(self, content):
        """
        AES加密 key,iv使用同一个, 模式cbc, 填充pkcs7
        """
        cipher = AES.new(
            self.key.encode("utf-8"), AES.MODE_CBC, self.key.encode("utf-8")
        )
        content_padding = self.pkcs7padding(content)
        encrypt_bytes = cipher.encrypt(content_padding.encode("utf-8"))
        result = base64.b64encode(encrypt_bytes).decode("utf-8")
        return result

    def decrypt(self, content):
        """
        AES解密 key,iv使用同一个, 模式cbc, 填充pkcs7
        """
        cipher = AES.new(
            self.key.encode("utf-8"), AES.MODE_CBC, self.key.encode("utf-8")
        )
        encrypt_bytes = base64.b64decode(content)
        decrypt_bytes = cipher.decrypt(encrypt_bytes)
        result = self.pkcs7unpadding(decrypt_bytes.decode("utf-8"))
        return result
