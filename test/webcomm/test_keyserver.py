import unittest
import socket
import threading
import json
from src.webcomm.keyserver import KeyServer
from src.model import *


class TestKeyServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = KeyServer()
        cls.server_thread = threading.Thread(target=cls.server.run)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    def tearDown(self):
        self.client_socket.shutdown(socket.SHUT_RDWR)
        self.client_socket.close()

    def create_client_socket(self, port):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.bind(("localhost", port))
        client_socket.connect((KeyServer.HOST, KeyServer.PORT))
        return client_socket

    def test010_malformed_request(self):
        self.client_socket = self.create_client_socket(8081)
        msg = Message(type="invalid_action_for_testing")
        self.client_socket.sendall(json.dumps(msg.__dict__).encode())
        response = self.client_socket.recv(1024)
        response = json.loads(response.decode())
        response = Message.from_dict(response)
        self.assertIsInstance(response, ErrorResponse)

    def test020_register_public_key(self):
        self.client_socket = self.create_client_socket(8082)
        msg = RegisterRequest(client_id="8082", public_key="my_public_key")
        self.client_socket.sendall(json.dumps(msg.__dict__).encode())
        response = self.client_socket.recv(1024)
        response = json.loads(response.decode())
        response = Message.from_dict(response)
        self.assertIsInstance(response, SuccessResponse)

    def test030_get_public_key(self):
        self.client_socket = self.create_client_socket(8083)
        msg = GetRequest(client_id="8082")
        self.client_socket.sendall(json.dumps(msg.__dict__).encode())
        response = self.client_socket.recv(1024)
        response = json.loads(response.decode())
        response = Message.from_dict(response)
        self.assertIsInstance(response, GetResponse)
        self.assertEqual(response.public_key, "my_public_key")

    def test040_get_public_key_non_existent_client_id(self):
        self.client_socket = self.create_client_socket(8084)
        msg = GetRequest(client_id="8888")
        self.client_socket.sendall(json.dumps(msg.__dict__).encode())
        response = self.client_socket.recv(1024)
        response = json.loads(response.decode())
        response = Message.from_dict(response)
        self.assertIsInstance(response, ErrorResponse)

    @classmethod
    def tearDownClass(cls):
        cls.server.server_socket.close()


if __name__ == "__main__":
    unittest.main()
