import threading

from .mode_of_operation import ModeOfOperation
from .utils import xor


class OFB(ModeOfOperation):
    def encrypt(self, plain: bytes) -> bytes:
        num_blocks = len(plain) // self.block_size
        encrypted_blocks = [None] * num_blocks
        previous_blocks = [self.initial_block]
        previous_blocks.extend(
            [self.cipher.encrypt(previous_blocks[-1]) for _ in range(num_blocks - 1)]
        )

        def encrypt_block(index):
            curr_block = plain[index * self.block_size : (index + 1) * self.block_size]
            encrypted_blocks[index] = xor(curr_block, previous_blocks[index])

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
