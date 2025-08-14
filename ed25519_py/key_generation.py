"""Key generation for Ed25519."""

import hashlib
import secrets

from .edwards_curve import BASE_POINT, scalar_multiply
from .encoding import encode_point
from .scalar_arithmetic import clamp_scalar


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.
    Returns (private_key, public_key) as 32-byte arrays.

    Algorithm 1 from the paper:
    1. Sample uniformly random sk ∈ {0,1}^256
    2. Expand: (h0, h1, ..., h511) ← SHA512(sk)
    3. Compute secret scalar: s = 2^254 + Σ(h_i * 2^i) for i in [3, 253]
    4. Compute public key: pk = A = s·B
    """
    # Generate 32 random bytes for the private key
    private_key = secrets.token_bytes(32)

    # Derive public key from private key
    public_key = derive_public_key(private_key)

    return private_key, public_key


def derive_public_key(private_key: bytes) -> bytes:
    """Derive the public key from a private key.

    Steps:
    1. Hash the private key with SHA-512
    2. Clamp the first 32 bytes to get the secret scalar
    3. Multiply the base point by the secret scalar
    4. Encode the resulting point
    """
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")

    # Expand the private key using SHA-512
    h = hashlib.sha512(private_key).digest()

    # Take the first 32 bytes and clamp them
    # This sets specific bits as required by Ed25519:
    # - Clear the lowest 3 bits (making it a multiple of 8)
    # - Clear the highest bit (bit 255)
    # - Set the second-highest bit (bit 254)
    secret_scalar_bytes = h[:32]
    secret_scalar_bytes = clamp_scalar(secret_scalar_bytes)

    # Convert to integer (little-endian)
    secret_scalar = int.from_bytes(secret_scalar_bytes, "little")

    # Compute public key point: A = s·B
    public_point = scalar_multiply(secret_scalar, BASE_POINT)

    # Encode the public key point
    public_key = encode_point(public_point)

    return public_key


def expand_private_key(private_key: bytes) -> tuple[bytes, bytes]:
    """Expand a private key into its two halves.

    Returns (secret_scalar_bytes, prefix) where:
    - secret_scalar_bytes: First 32 bytes of SHA-512(private_key), clamped
    - prefix: Last 32 bytes of SHA-512(private_key)

    The prefix is used for deterministic nonce generation in signing.
    """
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")

    # Hash the private key
    h = hashlib.sha512(private_key).digest()

    # Split into two halves
    secret_scalar_bytes = h[:32]
    prefix = h[32:]

    # Clamp the secret scalar
    secret_scalar_bytes = clamp_scalar(secret_scalar_bytes)

    return secret_scalar_bytes, prefix


def is_valid_private_key(private_key: bytes) -> bool:
    """Check if a byte array is a valid Ed25519 private key."""
    return len(private_key) == 32


def is_valid_public_key(public_key: bytes) -> bool:
    """Check if a byte array is a valid Ed25519 public key.

    A valid public key must:
    1. Be exactly 32 bytes
    2. Decode to a valid curve point
    3. Not be a small order point
    """
    from encoding import validate_point_bytes

    return bool(validate_point_bytes(public_key))
