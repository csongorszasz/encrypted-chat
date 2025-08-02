import threading

from .mode_of_operation import ModeOfOperation
from .utils import xor


class CBC(ModeOfOperation):
    def encrypt(self, plain: bytes) -> bytes:
        encrypted_blocks = []
        previous_block = self.initial_block
        for i in range(0, len(plain), self.block_size):
            block = plain[i : i + self.block_size]
            block = xor(block, previous_block)
            encrypted_block = self.cipher.encrypt(block)
            encrypted_blocks.append(encrypted_block)
            previous_block = encrypted_block
        return b"".join(encrypted_blocks)

    def decrypt(self, cipher: bytes) -> bytes:
        num_blocks = len(cipher) // self.block_size
        decrypted_blocks = [None] * num_blocks
        previous_blocks = [self.initial_block] + [
            cipher[i : i + self.block_size]
            for i in range(0, len(cipher) - self.block_size, self.block_size)
        ]

        def decrypt_block(index):
            curr_block = cipher[index * self.block_size : (index + 1) * self.block_size]
            decrypted_blocks[index] = xor(
                self.cipher.decrypt(curr_block), previous_blocks[index]
            )

        threads = []
        for i in range(num_blocks):
            t = threading.Thread(
                target=decrypt_block,
                args=(i,),
            )
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        return b"".join(decrypted_blocks)
