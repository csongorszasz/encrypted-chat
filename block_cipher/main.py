import os
from typing import Optional

from . import cipher
from . import mode
from . import padding
from .config import Configuration
from block_cipher import PROJECT_ROOT


class BlockCipher:
    OUTPUT_DIR = "output"
    RESULTS_DIR = os.path.join(OUTPUT_DIR, "results")
    TESTS_DIR = os.path.join(OUTPUT_DIR, "tests")

    def __init__(self):
        self.cfg: Optional[Configuration] = None
        self.action: Optional[int] = None
        self.test_options: Optional[dict] = None

        self.actions = {
            1: self.encrypt,
            2: self.decrypt,
        }

        self.cipher_algorithms = dict()
        self.modes_of_operation = dict()
        self.paddings = dict()

        self._setup_cfg()

    def _setup_cfg(self):
        self.cfg = Configuration(os.path.join(PROJECT_ROOT, "config.json"))
        for alg in self.cfg.possible_cipher_algorithms:
            self.cipher_algorithms[alg] = getattr(cipher, alg)
        for mode_ in self.cfg.possible_modes_of_operation:
            self.modes_of_operation[mode_] = getattr(mode, mode_)
        for pad in self.cfg.possible_paddings:
            self.paddings[pad] = getattr(padding, pad)

    def get_key(self):
        with open(self.cfg.key_path, "rb") as file:
            return file.read()

    def get_initial_block(self):
        if self.cfg.initial_block_path is not None:
            with open(self.cfg.initial_block_path, "rb") as file:
                return file.read()
        return None

    def write_to_file(self, path, data):
        with open(path, "wb") as file:
            file.write(data)
        print(f"File created at '{path}'.")

    def crypt(self, encrypting: bool, content: bytes):
        """
        A generalization of the encryption and decryption processes.

        Returns the result.
        """
        if isinstance(content, str):
            content = content.encode()

        # Determine the right cipher, mode of operation, and padding classes to use according to the configuration
        try:
            cipher_algorithm = self.cipher_algorithms[self.cfg.cipher_algorithm](
                self.get_key()
            )
            mode_of_operation = self.modes_of_operation[self.cfg.mode_of_operation](
                cipher_algorithm,
                self.get_key(),
                self.cfg.block_size,
                self.get_initial_block(),
            )
            pad = self.paddings[self.cfg.padding](self.cfg.block_size)
        except KeyError as e:
            print(f"Class not found: {e}")
            raise
        except ValueError as e:
            print(f"Invalid configuration: {e}")
            raise

        # Apply padding to the input file if needed
        if encrypting and mode_of_operation.needs_padding:
            print(f"Length before padding: {len(content)} bytes.")
            content = pad.add_padding(content)
            print(f"Length after padding:  {len(content)} bytes.")

        # Encrypt or decrypt the input file
        result = (
            mode_of_operation.encrypt(content)
            if encrypting
            else mode_of_operation.decrypt(content)
        )

        # Undo padding after decryption if needed
        if not encrypting and mode_of_operation.needs_padding:
            result = pad.remove_padding(result)
            print(f"Length after removing padding: {len(result)} bytes.")

        return result

    def encrypt(self, content: bytes):
        return self.crypt(encrypting=True, content=content)

    def decrypt(self, content: bytes):
        return self.crypt(encrypting=False, content=content)

    def get_block_size_bits(self):
        """Return the block size in bits."""
        return self.cfg.block_size * 8

    def get_block_size_bytes(self):
        """Return the block size in bytes."""
        return self.cfg.block_size

    def set_block_size(self, block_size):
        self.cfg.block_size = block_size
        self.cfg.write_json(self.cfg.config_path)

    def set_cipher_algorithm(self, cipher_algorithm):
        self.cfg.cipher_algorithm = cipher_algorithm
        self.cfg.write_json(self.cfg.config_path)

    def set_mode_of_operation(self, mode_of_operation):
        self.cfg.mode_of_operation = mode_of_operation
        self.cfg.write_json(self.cfg.config_path)

    def set_padding(self, padding):
        self.cfg.padding = padding
        self.cfg.write_json(self.cfg.config_path)

    def set_key_path(self, key_path):
        self.cfg.key_path = key_path
        self.cfg.write_json(self.cfg.config_path)

    def set_key(self, key):
        if isinstance(key, int):
            key = key.to_bytes((key.bit_length() + 7) // 8, byteorder="big")
        elif isinstance(key, str):
            key = key.encode()
        with open(self.cfg.key_path, "wb") as file:
            file.write(key)
        print(f"Key written to '{self.cfg.key_path}'.")

    def set_initial_block_path(self, initial_block_path):
        self.cfg.initial_block_path = initial_block_path
        self.cfg.write_json(self.cfg.config_path)

    def set_initial_block(self, initial_block):
        with open(self.cfg.initial_block_path, "wb") as file:
            file.write(initial_block)
        print(f"Initial block written to '{self.cfg.initial_block_path}'.")

    def get_cipher_algorithms(self):
        return list(self.cipher_algorithms.keys())

    def get_modes_of_operation(self):
        return list(self.modes_of_operation.keys())

    def get_possible_cipher_and_mode_combinations(self):
        """Return a string list of possible cipher and mode combinations."""
        return [
            f"{cipher_alg} {mode_}"
            for cipher_alg in self.get_cipher_algorithms()
            for mode_ in self.get_modes_of_operation()
        ]

    def update_config(self):
        self.cfg.write_json(self.cfg.config_path)

    def print_configuration(self):
        print("#" * 40)
        print("# Configuration:")
        print("#" * 40)
        print(self.cfg)
        print("#" * 40)
