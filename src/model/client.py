from dataclasses import dataclass


@dataclass
class Client:
    id: int
    public_key: str
