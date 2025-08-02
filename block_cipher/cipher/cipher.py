from abc import ABC, abstractmethod


class Cipher(ABC):
    """Base class for cipher algorithms (e.g.: Vigenere)."""

    def __init__(self, key: bytes):
        self.key = key

    @abstractmethod
    def encrypt(self, plain: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, cipher: bytes) -> bytes:
        pass
