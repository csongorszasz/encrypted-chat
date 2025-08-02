from abc import ABC, abstractmethod


class ModeOfOperation(ABC):
    """Base class for block cipher mode of operation algorithms (e.g.: ECB - Electronic Code Book)."""

    def __init__(
        self,
        cipher,
        key: bytes,
        block_size: int,
        initial_block: bytes = None,
        needs_padding=True,
    ):
        self.cipher = cipher
        self.key = key
        self.block_size = block_size
        self.initial_block = initial_block
        self.needs_padding = needs_padding

    @abstractmethod
    def encrypt(self, plain: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, cipher: bytes) -> bytes:
        pass
