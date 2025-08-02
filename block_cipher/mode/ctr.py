import threading

from block_cipher.cipher import AES

from .mode_of_operation import ModeOfOperation
from .utils import xor


class CTR(ModeOfOperation):
    def __init__(
        self,
        cipher,
        key: bytes,
        block_size: int,
        initial_block: bytes = None,
        needs_padding=True,
    ):
        super().__init__(cipher, key, block_size, initial_block, needs_padding)
        if isinstance(self.cipher, AES):
            self.needs_padding = False
            if self.block_size != 16:
                raise ValueError(
                    f"Block size ({self.block_size * 8} bits) must be 128 bits for AES cipher."
                )
            if len(self.initial_block) != self.block_size / 2:
                raise ValueError(
                    f"Initial block ({len(self.initial_block * 8)} bits) size must be 64 bits for AES cipher."
                )

    def encrypt(self, plain: bytes) -> bytes:
        num_blocks = len(plain) // self.block_size
        encrypted_blocks = [None] * num_blocks

        def encrypt_block(index: int):
            curr_block = plain[index * self.block_size : (index + 1) * self.block_size]
            concatenated_block = self.initial_block + index.to_bytes(
                self.block_size // 2, "big"
            )
            encrypted_blocks[index] = xor(
                self.cipher.encrypt(concatenated_block),
                curr_block,
            )

        threads = []
        for i in range(num_blocks):
            t = threading.Thread(
                target=encrypt_block,
                args=(i,),
            )
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return b"".join(encrypted_blocks)

    def decrypt(self, cipher: bytes) -> bytes:
        return self.encrypt(cipher)
