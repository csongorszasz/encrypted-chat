def shift_byte(byte: int, amount: int, right=True):
    """
    Shifts a byte in a circular manner, i.e. shifting '0xFF' one to the right will result in '0x00'.

    Returns the shifted byte (as an integer).
    """
    abc_length = 256
    shift_size = (amount if right else -amount) % abc_length
    return (byte + shift_size) % abc_length


def bring_bytes_to_length(input_bytes: bytes, target_length: int):
    """
    The input bytes are repeated or truncated as necessary to fit the target length.

    Arguments:
        input_bytes
            The byte series to be repeated or truncated.

        target_length
            The desired length for the input string.

    Returns the modified bytes.
    """
    input_string_len = len(input_bytes)
    return (
        input_bytes * (target_length // input_string_len)
        + input_bytes[: target_length % input_string_len]
    )


def swap_neighboring_bytes(data: bytes) -> bytes:
    """Swap every second neighboring bytes."""
    swapped = bytearray(data)
    for i in range(0, len(swapped) - 1, 2):
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
    return bytes(swapped)
