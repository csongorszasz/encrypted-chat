import json
import socket
import threading
import os

from src import PROJECT_ROOT
from src.model import *
from src.exception import InvalidActionError
from src.webcomm.webmodule import WebModule


class KeyServer(WebModule):
    clients_file = os.path.join(PROJECT_ROOT, "clients.json")

    HOST = "localhost"
    PORT = 8080

    def __init__(self, port: int = PORT, host: str = HOST):
        """
        Scope: Managing the public keys of the clients.

        Communication with clients: JSON data in TCP sockets.

        clients_file format (json):
        {
            "clients": {
                <client_id>: {
                    "public_key": <public_key>
                },
                ...
            }
        }
        """

        super().__init__(port, host)

        self.registered_clients = None

        self.actions = {
            "register": self._register_public_key,
            "get": self._get_public_key,
            "clients_req": self._get_available_clients,
        }

        self.server_socket = None

    def init(self):
        self._load_registered_clients()
        self._setup_server_socket()

    def _load_registered_clients(self):
        """Load the registered clients from the clients file."""
        try:
            with open(self.clients_file, "r") as f:
                json_data = json.load(f)
                self.registered_clients = json_data.get("clients", {})
        except FileNotFoundError:
            print("No 'clients.json' file found. Creating one.")
            self.registered_clients = {}
            self._save_registered_clients()

    def _setup_server_socket(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen()
        print(f"Listening on {self.host}:{self.port}")

    def run(self):
        self.init()

        while True:
            conn, addr = self.server_socket.accept()
            threading.Thread(target=self._handle_client, args=(conn, addr)).start()

    def stop(self):
        self.server_socket.close()

    def _handle_client(self, conn, addr):
        """Handle client registration and peer requests"""
        print("Client connected from {}".format(addr))
        try:
            while True:
                data = self.recv(conn)
                if not data:
                    print("Client disconnected at {}".format(addr))
                    return
                try:
                    msg = self._parse_incoming_data(data)
                    self._execute_action(conn, msg)
                except InvalidActionError as e:
                    msg = "Invalid action '{}'".format(str(e))
                    print(msg)
                    self.send(conn, ErrorResponse(msg))
        except Exception as e:
            print("Error handling client at {}: {}".format(addr, e))
        finally:
            # Close the connection
            conn.close()

    def _parse_incoming_data(self, data):
        """Parse incoming data and return a Message object."""
        data = json.loads(data.decode())
        try:
            msg = Message.from_dict(data)
            if msg.type not in self.actions:
                raise InvalidActionError(msg.type)
            return msg
        except MissingMessageTypeError:
            raise InvalidActionError("Missing 'type' field in message")

    def _execute_action(self, conn, msg):
        """Execute the action requested by the client."""
        self.actions[msg.type](conn, msg)

    def _save_registered_clients(self):
        """Update the clients file."""
        with open(self.clients_file, "w") as f:
            json_data = {"clients": self.registered_clients}
            json.dump(json_data, f, indent=2)

    def _register_public_key(self, conn, msg):
        """Register a public key for a client."""
        self.registered_clients[msg.client_id] = {"public_key": msg.public_key}
        self._save_registered_clients()
        print("Registered public key for client {}".format(msg.client_id))
        return self.send(
            conn,
            SuccessResponse(
                "Registered public key for client {}".format(msg.client_id)
            ),
        )

    def _get_public_key(self, conn, msg):
        """Get the public key of a client."""
        clnt = self.registered_clients.get(msg.client_id)
        if clnt is None:
            msg_str = "Client '{}' not found".format(msg.client_id)
            print(msg_str)
            self.send(conn, ErrorResponse(msg_str))
            return
        return self.send(conn, GetResponse(clnt["public_key"]))

    def _get_available_clients(self, conn, _msg):
        """Get the list of available clients."""
        available = list(self.registered_clients.keys())
        return self.send(conn, ClientListResponse(available))
