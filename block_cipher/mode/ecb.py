import threading

from .mode_of_operation import ModeOfOperation


class ECB(ModeOfOperation):
    """Electronic Code Book mode of operation algorithm."""

    def encrypt(self, plain: bytes) -> bytes:
        num_blocks = len(plain) // self.block_size
        encrypted_blocks = [None] * num_blocks

        def encrypt_block(index):
            curr_block = plain[index * self.block_size : (index + 1) * self.block_size]
            encrypted_blocks[index] = self.cipher.encrypt(curr_block)

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
        num_blocks = len(cipher) // self.block_size
        decrypted_blocks = [None] * num_blocks

        def decrypt_block(index):
            curr_block = cipher[index * self.block_size : (index + 1) * self.block_size]
            decrypted_blocks[index] = self.cipher.decrypt(curr_block)

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
