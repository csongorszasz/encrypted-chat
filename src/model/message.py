from dataclasses import dataclass
import json

from src.exception import MissingMessageTypeError


@dataclass
class Message:
    type: str

    @classmethod
    def from_dict(cls, data: dict):
        types = {
            "register": RegisterRequest,
            "get": GetRequest,
            "clients_req": ClientListRequest,
            "clients_res": ClientListResponse,
            "conn_req": ConnectionRequest,
            "conn_res": ConnectionResponse,
            "public_key": GetResponse,
            "error": ErrorResponse,
            "success": SuccessResponse,
            "key_transfer_msg": KeyTransferMessage,
            "encrypted_msg": EncryptedMessage,
            "key_transfer_req": KeyTransferRequest,
        }
        msg_type = data.get("type")
        if msg_type is None:
            raise MissingMessageTypeError
        if msg_type not in types:
            return cls(**data)
        data.pop("type")
        return types[msg_type](**data)

    def to_bytes(self):
        return json.dumps(self.__dict__).encode()

    @classmethod
    def from_bytes(cls, data):
        return cls.from_dict(json.loads(data.decode()))


class RegisterRequest(Message):
    def __init__(self, client_id, public_key):
        super().__init__("register")
        self.client_id = client_id
        self.public_key = public_key


class GetRequest(Message):
    def __init__(self, client_id):
        super().__init__("get")
        self.client_id = client_id


class GetResponse(Message):
    def __init__(self, public_key):
        super().__init__("public_key")
        self.public_key = public_key


class ConnectionRequest(Message):
    def __init__(self, client_id, block_cipher_list):
        super().__init__("conn_req")
        self.client_id = client_id
        self.block_cipher_list = block_cipher_list


class ConnectionResponse(Message):
    def __init__(self, client_id, block_cipher_list):
        super().__init__("conn_res")
        self.client_id = client_id
        self.block_cipher_list = block_cipher_list


class ClientListRequest(Message):
    def __init__(self):
        super().__init__("clients_req")


class ClientListResponse(Message):
    def __init__(self, clients):
        super().__init__("clients_res")
        self.clients = clients


class KeyTransferRequest(Message):
    def __init__(self, client_id, key):
        super().__init__("key_transfer_req")
        self.client_id = client_id
        self.key = key


class ErrorResponse(Message):
    def __init__(self, message):
        super().__init__("error")
        self.message = message


class SuccessResponse(Message):
    def __init__(self, message):
        super().__init__("success")
        self.message = message


class KeyTransferMessage(Message):
    def __init__(self, client_id, key):
        super().__init__("key_transfer_msg")
        self.client_id = client_id
        self.key = key


class EncryptedMessage(Message):
    def __init__(self, client_id, msg):
        super().__init__("encrypted_msg")
        self.client_id = client_id
        self.message = msg


class ByeMessage(Message):
    def __init__(self):
        super().__init__("bye")
