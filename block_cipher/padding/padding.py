from abc import ABC, abstractmethod


class Padding(ABC):
    def __init__(self, block_size: int):
        self.block_size = block_size

    @abstractmethod
    def add_padding(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def remove_padding(self, data: bytes) -> bytes:
        pass

    def find_padding_length(self, data: bytes) -> int:
        return self.block_size - len(data) % self.block_size
