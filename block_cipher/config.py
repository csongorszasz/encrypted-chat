import json
import os
import sys


class Configuration:
    """
    Configuration class for cryptography suite
    """

    def __init__(self, config_path=None):
        self.possible_cipher_algorithms = ("AES", "CustomCipher")
        self.possible_modes_of_operation = ("ECB", "CBC", "CFB", "OFB", "CTR")
        self.possible_paddings = ("Zero", "DES", "SchneierFerguson")

        if not config_path:
            # default config values
            self.block_size = 16  # 128 bits
            self.cipher_algorithm = self.possible_cipher_algorithms[0]
            self.key_path = "key.txt"
            self.mode_of_operation = self.possible_modes_of_operation[0]
            self.initial_block_path = "initial_block.txt"
            self.padding = self.possible_paddings[0]
        else:
            self.from_json(config_path)

        self.config_path = config_path if config_path else "config.json"

    def from_json(self, path):
        cfg = None
        try:
            with open(path, "r") as f:
                cfg = json.load(f)
        except FileNotFoundError:
            print(f"Configuration file '{path}' does not exist.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(
                f"Invalid JSON format in configuration file '{path}'. Please check the syntax."
            )
            sys.exit(1)

        try:
            self.block_size = cfg["block_size"]
            # Check if the block size is a multiple of 8
            if self.block_size < 8:
                raise ValueError("Minimum block size is 8 bits.")
            if self.block_size % 8 != 0:
                raise ValueError("Block size must be a multiple of 8.")
            self.block_size = (
                self.block_size // 8
            )  # Convert block size from bits to bytes

            self.cipher_algorithm = [
                alg for alg, value in cfg["cipher_algorithm"].items() if value
            ]
            # Check if the cipher algorithm parameter is valid
            if len(self.cipher_algorithm) == 0:
                raise ValueError("No cipher algorithm selected.")
            elif len(self.cipher_algorithm) > 1:
                raise ValueError(
                    "Multiple cipher algorithms selected. Please select only one."
                )
            if self.cipher_algorithm[0] not in self.possible_cipher_algorithms:
                raise ValueError(
                    "Unknown cipher algorithm. Please select one of the following: "
                    f"{', '.join(self.possible_cipher_algorithms)}"
                )
            self.cipher_algorithm = self.cipher_algorithm[0]

            self.mode_of_operation = [
                mode for mode, value in cfg["mode_of_operation"].items() if value
            ]
            # Check if the mode of operation parameter is valid
            if len(self.mode_of_operation) == 0:
                raise ValueError("No mode of operation selected.")
            elif len(self.mode_of_operation) > 1:
                raise ValueError(
                    "Multiple modes of operation selected. Please select only one."
                )
            if self.mode_of_operation[0] not in self.possible_modes_of_operation:
                raise ValueError(
                    "Unknown mode of operation. Please select one of the following: "
                    f"{', '.join(self.possible_modes_of_operation)}"
                )
            self.mode_of_operation = self.mode_of_operation[0]

            self.key_path = cfg["key_path"]
            # Check if the key file exists
            if not os.path.exists(self.key_path):
                raise ValueError(
                    f"File containing the key '{self.key_path}' does not exist."
                )

            self.initial_block_path = cfg.get(
                "initial_block_path", None
            )  # Optional - can be None

            self.padding = [pad for pad, value in cfg["padding"].items() if value]
            # Check if the padding parameter is valid
            if len(self.padding) == 0:
                raise ValueError("No padding selected.")
            elif len(self.padding) > 1:
                raise ValueError("Multiple paddings selected. Please select only one.")
            if self.padding[0] not in self.possible_paddings:
                raise ValueError(
                    "Unknown padding method. Please select one of the following: "
                    f"{', '.join(self.possible_paddings)}"
                )
            self.padding = self.padding[0]

        except KeyError as e:
            print(f"Missing parameter in configuration file: {e}")
            sys.exit(1)
        except ValueError as e:
            print(f"Invalid parameter in configuration file: {e}")
            sys.exit(1)

    def write_json(self, path):
        cfg = dict()

        cfg["block_size"] = (
            self.block_size * 8
        )  # Convert block size from bytes to bits for the config file

        cfg["cipher_algorithm"] = {}
        for alg in self.possible_cipher_algorithms:
            cfg["cipher_algorithm"][alg] = alg == self.cipher_algorithm

        cfg["key_path"] = self.key_path

        cfg["mode_of_operation"] = {}
        for mode in self.possible_modes_of_operation:
            cfg["mode_of_operation"][mode] = mode == self.mode_of_operation

        cfg["initial_block_path"] = self.initial_block_path

        cfg["padding"] = {}
        for pad in self.possible_paddings:
            cfg["padding"][pad] = pad == self.padding

        with open(path, "w") as f:
            json.dump(cfg, f, indent=4)

        print(f"Configuration file has been saved to '{path}'.")

    def __str__(self):
        return (
            f"Block size:\n\t{self.block_size * 8} bits\n"
            f"Cipher algorithm:\n\t{self.cipher_algorithm}\n"
            f"Key path:\n\t{self.key_path}\n"
            f"Mode of operation:\n\t{self.mode_of_operation}\n"
            f"Initial block path:\n\t{self.initial_block_path}\n"
            f"Padding method:\n\t{self.padding}"
        )

    def create_files(self):
        """
        Create the default configuration file and auxiliary files with random binary data:
            - config.json
            - key.txt
            - initial_block.txt

        Asks for user confirmation before overwriting existing files.
        """

        def confirm_overwrite(filepath):
            """Helper function to check if file exists and confirm overwrite."""
            if os.path.exists(filepath):
                while True:
                    response = input(
                        f"File '{filepath}' already exists. Do you want to overwrite it? (y/n): "
                    ).lower()
                    if response in ["y", "n"]:
                        return response == "y"
                    print("Please enter 'y' for yes or 'n' for no.")
            return True

        # Check and create config file
        if confirm_overwrite(self.config_path):
            self.write_json(self.config_path)

        # If config file exists, load the configuration for the block size
        if os.path.exists(self.config_path):
            self.from_json(self.config_path)

        # Check and create key file
        if confirm_overwrite(self.key_path):
            with open(self.key_path, "wb") as f:
                f.write(os.urandom(self.block_size))
            print(f"File containing the key has been saved to '{self.key_path}'.")

        # Check and create initial block file
        if confirm_overwrite(self.initial_block_path):
            with open(self.initial_block_path, "wb") as f:
                f.write(os.urandom(self.block_size))
            print(
                f"File containing the initial block has been saved to '{self.initial_block_path}'."
            )
