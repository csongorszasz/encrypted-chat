import pyaes

from .cipher import Cipher


class AES(Cipher):
    def __init__(self, key: bytes):
        super().__init__(key)
        # validate key
        if len(key) not in [16, 24, 32]:
            raise ValueError(
                f"Invalid key size: {len(key) * 8} bits. Must be 128 or 192 or 256 bits."
            )

        self.cipher_obj = pyaes.AES(key)

    def encrypt(self, plain: bytes) -> bytes:
        return bytes(self.cipher_obj.encrypt(plain))

    def decrypt(self, cipher: bytes) -> bytes:
        return bytes(self.cipher_obj.decrypt(cipher))
