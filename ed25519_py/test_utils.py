"""Common test utilities."""


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_string)
