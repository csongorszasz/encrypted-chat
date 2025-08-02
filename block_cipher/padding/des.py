from .padding import Padding


class DES(Padding):
    def add_padding(self, data: bytes) -> bytes:
        padding_length = self.find_padding_length(data)
        return data + b"\x80" + b"\x00" * (padding_length - 1)

    def remove_padding(self, data: bytes) -> bytes:
        return data.rstrip(b"\x00")[:-1]
