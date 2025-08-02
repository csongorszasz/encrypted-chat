def xor(block: bytes, previous_block: bytes) -> bytes:
    """Perform XOR on two blocks of bytes."""
    return bytes([b1 ^ b2 for b1, b2 in zip(block, previous_block)])
