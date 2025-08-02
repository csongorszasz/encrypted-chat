import socket
import json
import rsa
import random
import threading
import hashlib

from rsa.cli import decrypt

from .webmodule import WebModule
from src.model.message import *
from block_cipher import BlockCipher
from .keyserver import KeyServer
from ..exception import NoCommonBlockCipherError


class Client(WebModule):
    def __init__(self, port: int, host: str = "localhost"):
        super().__init__(port, host)

        self.client_id = str(self.port)

        self.keyserver_socket = None  # connection to the key server
        self.listener_socket = None  # wait for incoming connections
        self.peer_socket = None  # connection to another client

        self.peer_socket_lock = threading.Lock()

        # Thread for receiving messages
        self.receive_thread = None
        self.stop_receiving = threading.Event()

        self.public_key = None
        self.private_key = None

        self.actions = {"register": self.register, "chat": self.chat, "exit": self.exit}

    def init(self):
        self._setup_keyserver_socket()
        self._setup_listener_socket()
        self._setup_block_ciphers()

    def _setup_keyserver_socket(self):
        self.keyserver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.keyserver_socket.connect((KeyServer.HOST, KeyServer.PORT))

    def _setup_listener_socket(self):
        self.listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener_socket.bind((self.host, self.port))
        self.listener_socket.listen()
        print(f"Client {self.client_id} listening on {self.host}:{self.port}")

    def _setup_block_ciphers(self):
        """Set up a block cipher suite and randomly remove capabilities."""
        self.block_cipher = BlockCipher()

        # randomly remove one cipher algorithm
        remove_cipher_alg = random.randint(0, 1)
        if remove_cipher_alg:
            rand_cipher = random.choice(self.block_cipher.get_cipher_algorithms())
            self.block_cipher.cipher_algorithms.pop(rand_cipher)
        # randomly remove [2,4] modes of operation
        for _ in range(random.randint(2, 4)):
            rand_mode = random.choice(self.block_cipher.get_modes_of_operation())
            self.block_cipher.modes_of_operation.pop(rand_mode)

        print()
        print("Available ciphers:")
        for combo in self.block_cipher.get_possible_cipher_and_mode_combinations():
            print(combo)
        print()

    def _connect_to_client(self, client_id):
        """Connect to another client by id (port)."""
        print(f"Connecting to peer {client_id}")
        try:
            self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.peer_socket.connect((self.host, int(client_id)))
            print(f"Connected to peer {client_id}.")
        except Exception as e:
            print(f"Failed to connect to {client_id}: {e}")

    def run(self):
        self.init()

        threading.Thread(target=self.accept_connections).start()

        self.handle_commands()

    def accept_connections(self):
        """Accept incoming peer connections from other clients."""
        try:
            while True:
                self.peer_socket, address = self.listener_socket.accept()
                print("\nConnection initiated by peer at {}".format(address))
                msg_obj = self.recv_hello()
                pub_key = self._get_pub_key(msg_obj.client_id)
                self.send_ack(
                    msg_obj.client_id,
                    self.block_cipher.get_possible_cipher_and_mode_combinations(),
                    pub_key,
                )
                secret2 = self._generate_random_secret()
                secret1 = self.recv_half_secret(msg_obj.client_id)
                self.send_half_secret(msg_obj.client_id, secret2, pub_key)
                common_secret = self._generate_common_secret(secret1, secret2)
                self._init_block_cipher(common_secret, msg_obj.block_cipher_list)

                self._start_receiving()  # need to call this before starting chat loop

                self._start_chat_loop(msg_obj.client_id)

        except NoCommonBlockCipherError:
            print("No common block cipher found.")
        except Exception as e:
            print("Error accepting connection:", e)

    def _start_receiving(self):
        """Start a thread to receive messages from the peer."""
        if self.peer_socket and not self.receive_thread:
            self.stop_receiving.clear()
            self.receive_thread = threading.Thread(
                target=self._receive_messages, daemon=True
            )
            self.receive_thread.start()

    def _stop_receiving_messages(self):
        """Stop the message receiving thread."""
        if self.receive_thread:
            self.stop_receiving.set()
            self.receive_thread = None

    def _receive_messages(self):
        """Receive messages from the peer and print them."""
        while not self.stop_receiving.is_set():
            try:
                message, client_id = self.recv_encrypted()
                if message is None:  # received bye message
                    print("Received bye message. Closing connection.")
                    break
                print("\nfrom <{}>: {}".format(client_id, message))
            except Exception:
                break

    def handle_commands(self):
        try:
            while True:
                command = self._get_cmd()
                self._execute_cmd(command)
        except ConnectionRefusedError:
            print("Connection refused. Server may not be running.")
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print("Error: {}".format(str(e)))
        finally:
            self.exit()

    def _get_cmd(self):
        """The main menu. Get command from input and return it."""
        self._list_cmds()
        command = input("> ")
        if command not in self.actions:
            print("Invalid command.")
            return self._get_cmd()
        return command

    @staticmethod
    def _list_cmds():
        print("\n--- Commands ---")
        print("register - Register public key")
        print("chat - Establish an encrypted communication channel with another user")
        print("exit - Close connection")
        print()

    def _execute_cmd(self, command):
        """Execute a command."""
        self.actions[command]()

    def register(self):
        """Register public key with the key server."""
        print("Registering public key with key server")
        self.public_key, self.private_key = self._generate_key_pair()
        self.send(
            self.keyserver_socket,
            RegisterRequest(
                client_id=self.client_id,
                public_key={"n": self.public_key.n, "e": self.public_key.e},
            ),
        )
        response = self.recv(self.keyserver_socket)
        response_dict = json.loads(response.decode())
        response_msg = Message.from_dict(response_dict)
        if isinstance(response_msg, ErrorResponse):
            print("Error: {}".format(response_msg.message))
        elif isinstance(response_msg, SuccessResponse):
            print("Success: {}".format(response_msg.message))
        else:
            print("Unexpected response: {}", response_msg)

    @staticmethod
    def _generate_key_pair():
        """Generate a public-private key pair."""
        print("Generating key pair")
        pub, priv = rsa.newkeys(2048)
        print("Key pair generated")
        return pub, priv

    def chat(self):
        """Chat with another user."""
        clients = self._get_available_clients()
        self._list_available_clients(clients)

        client_id = self._choose_client(clients)
        if client_id is None:
            return

        try:
            self._create_encrypted_channel(client_id)
        except NoCommonBlockCipherError:
            print("No common block cipher found.")
            return
        except ValueError as e:
            print("Error: {}".format(str(e)))
            return

        self._start_receiving()

        self._start_chat_loop(client_id)

    @staticmethod
    def _choose_client(clients):
        while True:
            print("Enter ID of user to chat with (type '/exit' to go back):")
            client_id = input("> ")
            if client_id == "/exit":
                return None
            if client_id not in clients:
                print("Invalid client ID.")
                continue
            return client_id

    def _start_chat_loop(self, client_id):
        """Start a chat loop with another user."""
        print("\n\nChatting with user <{}>".format(client_id))
        try:
            while True:
                message = input("Enter message (type '/bye' to leave): ")
                if message.lower() == "/bye":
                    self.send_bye(client_id)
                    break
                self.send_encrypted(client_id, message)
        except Exception as e:
            print("Error sending message:", e)
        finally:
            self.peer_socket.close()
            self.peer_socket = None
            self._stop_receiving_messages()

    def _list_available_clients(self, clients):
        if not clients:
            print("No available users.")
        else:
            print("Available users:")
            for client in clients:
                if client == self.client_id:
                    continue
                print(client)
        print()

    def _get_available_clients(self):
        """Get a list of available clients from the key server."""
        self.send(self.keyserver_socket, ClientListRequest())
        response = self.recv(self.keyserver_socket)
        response_dict = json.loads(response.decode())
        response_msg = Message.from_dict(response_dict)
        if isinstance(response_msg, ErrorResponse):
            print("Error: {}".format(response_msg.message))
        elif isinstance(response_msg, ClientListResponse):
            return response_msg.clients
        else:
            print("Unexpected response: {}", response_msg)

    def _create_encrypted_channel(self, client_id):
        """Establish an encrypted connection with another client."""
        print("Creating encrypted channel with user {}".format(client_id))
        pub_key = self._get_pub_key(client_id)
        if pub_key is None:
            raise ValueError("Public key not found.")

        self.send_hello(
            client_id,
            self.block_cipher.get_possible_cipher_and_mode_combinations(),
            pub_key,
        )
        ack_obj = self.recv_ack()

        secret1 = self._generate_random_secret()
        self.send_half_secret(client_id, secret1, pub_key)

        secret2 = self.recv_half_secret(client_id)
        common_secret = self._generate_common_secret(secret1, secret2)

        self._init_block_cipher(common_secret, ack_obj.block_cipher_list)

    def _get_pub_key(self, client_id):
        """Get the public key of a client."""
        print("Getting public key of user {}".format(client_id))
        self.send(self.keyserver_socket, GetRequest(client_id=client_id))
        response = self.recv(self.keyserver_socket)
        response_dict = json.loads(response.decode())
        response_msg = Message.from_dict(response_dict)
        if isinstance(response_msg, ErrorResponse):
            print("Error: {}".format(response_msg.message))
            return
        elif isinstance(response_msg, GetResponse):
            pub_key = response_msg.public_key
            if pub_key is None:
                raise ValueError("Public key not found.")
            return rsa.PublicKey(pub_key["n"], pub_key["e"])
        else:
            print("Unexpected response: {}", response_msg)

    def send_hello(self, to_client_id, block_cipher_list, pub_key):
        """Initiate a connection with another client."""
        self._connect_to_client(to_client_id)
        print("Sending hello to client {}".format(to_client_id))
        msg_obj = ConnectionRequest(
            client_id=self.client_id, block_cipher_list=block_cipher_list
        )
        print("Encrypting message with RSA")
        encrypted = rsa.encrypt(json.dumps(msg_obj.__dict__).encode(), pub_key)
        self.send_raw(
            self.peer_socket,
            encrypted,
        )
        print("Hello sent")

    def recv_hello(self):
        """Receive a connection request from another client."""
        print("Waiting for hello")
        msg = self.recv(self.peer_socket)
        print("Decrypting Hello message with RSA")
        msg_decrypted = rsa.decrypt(msg, self.private_key)
        msg_dict = json.loads(msg_decrypted.decode())
        msg_obj = Message.from_dict(msg_dict)
        if not isinstance(msg_obj, ConnectionRequest):
            print("Unexpected response: {}", msg_obj)
        print("Hello was sent by client {}".format(msg_obj.client_id))
        return msg_obj

    def send_ack(self, to_client_id, block_cipher_list, pub_key):
        """Send an acknowledgment of connection to another client."""
        print("Sending ACK to client {}".format(to_client_id))
        msg_obj = ConnectionResponse(
            client_id=self.client_id, block_cipher_list=block_cipher_list
        )
        print("Encrypting message with RSA")
        encryped_msg = rsa.encrypt(json.dumps(msg_obj.__dict__).encode(), pub_key)
        self.send_raw(self.peer_socket, encryped_msg)
        print("ACK sent")

    def recv_ack(self):
        """Receive an acknowledgment of connection from another client."""
        print("Waiting for ACK")
        response = self.recv(self.peer_socket)
        print("Decrypting ACK message with RSA")
        decrypted_resp = rsa.decrypt(response, self.private_key)
        response_dict = json.loads(decrypted_resp.decode())
        response_msg = Message.from_dict(response_dict)
        print("Received ack from client {}".format(response_msg.client_id))
        if isinstance(response_msg, ConnectionResponse):
            print("Received ack from client {}".format(response_msg.client_id))
            return response_msg
        else:
            print("Unexpected response: {}", response_msg)

    def send_half_secret(self, to_client_id, half_secret, pub_key):
        """Send half of a secret to another client."""
        print("Sending half secret to client {}".format(to_client_id))
        msg_obj = KeyTransferMessage(client_id=self.client_id, key=half_secret)
        print("Encrypting message with RSA")
        encrypted = rsa.encrypt(json.dumps(msg_obj.__dict__).encode(), pub_key)
        self.send_raw(self.peer_socket, encrypted)
        print("Half secret sent")

    def recv_half_secret(self, from_client_id):
        """Receive half of a secret from another client."""
        print("Waiting for half secret from user {}".format(from_client_id))
        response = self.recv(self.peer_socket)
        print("Decrypting half secret with RSA")
        decrypted = rsa.decrypt(response, self.private_key)
        response_dict = json.loads(decrypted.decode())
        response_msg = Message.from_dict(response_dict)
        print("Received half secret from client {}".format(from_client_id))
        if isinstance(response_msg, KeyTransferMessage):
            return response_msg.key
        else:
            print("Unexpected response: {}", response_msg)

    def _generate_random_secret(self):
        """Generate a random integer with number of digits equal to half the block size."""
        print("Generating random secret")
        secret_len = self.block_cipher.get_block_size_bytes() // 2
        secret = random.randint(10 ** (secret_len - 1), 10**secret_len - 1)
        print("Secret generated: {}".format(secret))
        return secret

    def _generate_common_secret(self, secret1, secret2):
        """Generate a common secret from two secrets with number of digits equal to block size."""
        print("Generating common secret")
        combined = str(secret1) + str(secret2)
        print("Combined secret: {}".format(combined))
        # return combined
        hashed = hashlib.sha256(combined.encode()).digest()
        print("Hashed secret: {}".format(hashed))
        # truncate to block size
        if len(hashed) > self.block_cipher.get_block_size_bytes():
            hashed = hashed[: self.block_cipher.get_block_size_bytes()]
            print("Truncated secret: {}".format(hashed))
        return hashed

    def _init_block_cipher(self, common_secret, other_block_cipher_list):
        # find a cipher algorithm and mode of operation that both clients support
        print("Finding common block cipher")
        for block_cipher_str in other_block_cipher_list:
            cipher_alg, mode = block_cipher_str.split()
            if (
                cipher_alg in self.block_cipher.cipher_algorithms
                and mode in self.block_cipher.modes_of_operation
            ):
                print("Found common block cipher: {}".format(block_cipher_str))

                print("Setting cipher algorithm")
                self.block_cipher.set_cipher_algorithm(cipher_alg)
                print("Setting mode of operation")
                self.block_cipher.set_mode_of_operation(mode)
                print("Setting cipher key to common secret")
                self.block_cipher.set_key(common_secret)
                print("Saving configuration")
                self.block_cipher.update_config()

                print("Block cipher initialized")
                return
        raise NoCommonBlockCipherError

    def send_encrypted(self, to_client_id, message):
        """Send an encrypted message to another client."""
        print("Sending encrypted message to user {}".format(to_client_id))

        encrypted = self.block_cipher.encrypt(
            EncryptedMessage(
                client_id=to_client_id,
                msg=message,
            ).to_bytes()
        )

        print("Encrypted message: {}".format(encrypted))
        self.send_raw(
            self.peer_socket,
            encrypted,
        )
        print("Encrypted message sent")

    def recv_encrypted(self):
        """Receive an encrypted message from another client."""
        print("Waiting for encrypted message")
        response = self.recv(self.peer_socket)
        print("Received encrypted message: {}".format(response))

        decrypted = self.block_cipher.decrypt(response).decode()

        print("Decrypted the message")

        response_dict = json.loads(decrypted)
        if response_dict["type"] == "encrypted_msg":
            response_msg = response_dict["message"]
            client_id = response_dict["client_id"]
            return response_msg, client_id
        elif response_dict["type"] == "bye":
            return None, None

        ### This way does not work for some reason ###
        # if isinstance(response_msg, EncryptedMessage):
        #     return response_msg.message
        # elif isinstance(response_msg, ByeMessage):
        #     return None
        # raise ValueError("Unexpected message: {}", response_msg)

    def send_bye(self, to_client_id):
        """Send a bye message to another client."""
        print("Sending bye to client {}".format(to_client_id))
        self.send(self.peer_socket, ByeMessage())
        print("Bye sent")

    def recv_bye(self):
        """Receive a bye message from another client."""
        print("Waiting for bye")
        response = self.recv(self.peer_socket)
        response_dict = json.loads(response.decode())
        response_msg = Message.from_dict(response_dict)
        print("Received bye from client {}".format(response_msg.client_id))
        if isinstance(response_msg, ByeMessage):
            return True
        raise ValueError("Unexpected response: {}", response_msg)

    def exit(self):
        """Close the connection, stop the client."""
        try:
            self.listener_socket.close()
            self.keyserver_socket.close()
            self.peer_socket.close()
        except Exception:
            pass
        print("Client stopped.")
        exit(0)
