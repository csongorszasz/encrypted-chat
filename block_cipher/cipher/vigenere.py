from . import utils
from .cipher import Cipher


class Vigenere(Cipher):
    def encrypt(self, plain: bytes) -> bytes:
        plain_len = len(plain)
        key = utils.bring_bytes_to_length(self.key, plain_len)
        cipher = bytes(
            [utils.shift_byte(plain[i], key[i], right=True) for i in range(plain_len)]
        )
        return cipher

    def decrypt(self, cipher: bytes) -> bytes:
        cipher_len = len(cipher)
        key = utils.bring_bytes_to_length(self.key, cipher_len)
        plain = bytes(
            [
                utils.shift_byte(cipher[i], key[i], right=False)
                for i in range(cipher_len)
            ]
        )
        return plain
