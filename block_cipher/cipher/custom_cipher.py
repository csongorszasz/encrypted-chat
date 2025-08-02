from . import utils
from .cipher import Cipher


class CustomCipher(Cipher):
    """Custom cipher algorithm."""

    def __init__(self, key: bytes):
        super().__init__(key)
        self.rounds = 5

    def encrypt(self, plain: bytes) -> bytes:
        plain_len = len(plain)
        key = utils.bring_bytes_to_length(self.key, plain_len)
        cipher = plain
        for _ in range(self.rounds):  # Multi-round encryption
            cipher = bytes(
                [
                    utils.shift_byte(cipher[i], key[i], right=True)
                    for i in range(plain_len)
                ]
            )
            cipher = utils.swap_neighboring_bytes(
                cipher
            )  # Swap every second pair of bytes
        return cipher

    def decrypt(self, cipher: bytes) -> bytes:
        cipher_len = len(cipher)
        key = utils.bring_bytes_to_length(self.key, cipher_len)
        plain = cipher
        for _ in range(self.rounds):  # Multi-round decryption
            plain = utils.swap_neighboring_bytes(plain)  # Reverse byte swapping
            plain = bytes(
                [
                    utils.shift_byte(plain[i], key[i], right=False)
                    for i in range(cipher_len)
                ]
            )
        return plain
