from .padding import Padding


class SchneierFerguson(Padding):
    def add_padding(self, data: bytes) -> bytes:
        padding_length = self.find_padding_length(data)
        return data + bytes([padding_length] * padding_length)

    def remove_padding(self, data: bytes) -> bytes:
        return data[: -data[-1]]
