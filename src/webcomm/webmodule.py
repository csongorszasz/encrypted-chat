from abc import ABC, abstractmethod
import json


class WebModule(ABC):
    """Base class for a web module that communicates with sockets."""

    def __init__(self, port: int, host: str):
        self.port = port
        self.host = host

    @abstractmethod
    def init(self):
        pass

    @abstractmethod
    def run(self):
        pass

    @staticmethod
    def send(conn, data):
        serialized = json.dumps(data.__dict__).encode()
        conn.sendall(serialized)

    @staticmethod
    def send_raw(conn, data):
        conn.sendall(data)

    @staticmethod
    def recv(conn):
        return conn.recv(2048)
