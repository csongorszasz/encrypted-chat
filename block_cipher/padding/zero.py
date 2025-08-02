from .padding import Padding


class Zero(Padding):
    def add_padding(self, data: bytes) -> bytes:
        return data + b"\x00" * self.find_padding_length(data)

    def remove_padding(self, data: bytes) -> bytes:
        return data.rstrip(b"\x00")
