"""Signature generation for Ed25519."""

import hashlib
import secrets

from .constants import L
from .edwards_curve import BASE_POINT, scalar_multiply
from .encoding import encode_point, encode_scalar
from .key_generation import derive_public_key, expand_private_key
from .scalar_arithmetic import scalar_reduce


def sign(private_key: bytes, message: bytes) -> bytes:
    """Sign a message with an Ed25519 private key.

    Algorithm 1 from the paper:
    1. Expand private key to get secret scalar and prefix
    2. Compute public key A = s·B
    3. Generate nonce: r = SHA512(prefix || message)
    4. Compute R = r·B
    5. Compute S = (r + SHA512(R || A || message) × s) mod L
    6. Return signature as R || S (64 bytes total)

    The signature is canonical: both R and S are reduced.
    """
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")

    # Expand the private key to get secret scalar and prefix
    secret_scalar_bytes, prefix = expand_private_key(private_key)
    secret_scalar = int.from_bytes(secret_scalar_bytes, "little")

    # Derive the public key
    public_key = derive_public_key(private_key)

    # Generate deterministic nonce r
    # r = SHA512(h_256 || ... || h_511 || M) where h is SHA512(private_key)
    nonce_input = prefix + message
    r_hash = hashlib.sha512(nonce_input).digest()
    r = int.from_bytes(r_hash, "little")
    r = scalar_reduce(r)  # Reduce modulo L

    # Compute R = r·B
    R_point = scalar_multiply(r, BASE_POINT)
    R_bytes = encode_point(R_point)

    # Compute the challenge hash
    # h = SHA512(R || A || M) mod L
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)  # Reduce modulo L

    # Compute S = (r + h × s) mod L
    S = (r + h * secret_scalar) % L

    # Encode S canonically (already reduced mod L)
    S_bytes = encode_scalar(S)

    # Return signature as R || S (64 bytes)
    signature = R_bytes + S_bytes

    return signature


def sign_with_expanded_key(
    expanded_private_key: tuple[bytes, bytes], public_key: bytes, message: bytes
) -> bytes:
    """Sign a message with an already expanded private key.

    This is useful when you need to sign multiple messages and want to
    avoid re-expanding the private key each time.

    Args:
        expanded_private_key: (secret_scalar_bytes, prefix) from expand_private_key
        public_key: The corresponding public key (32 bytes)
        message: The message to sign

    Returns:
        64-byte signature (R || S)
    """
    secret_scalar_bytes, prefix = expanded_private_key
    secret_scalar = int.from_bytes(secret_scalar_bytes, "little")

    # Generate deterministic nonce r
    nonce_input = prefix + message
    r_hash = hashlib.sha512(nonce_input).digest()
    r = int.from_bytes(r_hash, "little")
    r = scalar_reduce(r)

    # Compute R = r·B
    R_point = scalar_multiply(r, BASE_POINT)
    R_bytes = encode_point(R_point)

    # Compute the challenge hash
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)

    # Compute S = (r + h × s) mod L
    S = (r + h * secret_scalar) % L
    S_bytes = encode_scalar(S)

    return R_bytes + S_bytes


def sign_resistant(private_key: bytes, message: bytes) -> bytes:
    """Sign a message with side-channel resistance using scalar splitting.

    This implementation uses scalar splitting to protect against timing and
    power analysis attacks. Instead of computing r·B directly, we:
    1. Split r = r1 + r2 where r1 is random
    2. Compute R = r1·B + r2·B
    3. Use coordinate randomization for additional protection

    Args:
        private_key: 32-byte private key
        message: Message to sign

    Returns:
        64-byte signature (R || S)
    """
    if len(private_key) != 32:
        raise ValueError("Private key must be 32 bytes")

    # Expand the private key to get secret scalar and prefix
    secret_scalar_bytes, prefix = expand_private_key(private_key)
    secret_scalar = int.from_bytes(secret_scalar_bytes, "little")

    # Derive the public key
    public_key = derive_public_key(private_key)

    # Generate deterministic nonce r
    nonce_input = prefix + message
    r_hash = hashlib.sha512(nonce_input).digest()
    r = int.from_bytes(r_hash, "little")
    r = scalar_reduce(r)  # Reduce modulo L

    # Generate random split for r: r = r1 + r2
    r1 = int.from_bytes(secrets.token_bytes(32), "little") % L
    r2 = (r - r1) % L

    # Randomize base point coordinates for additional protection
    random_z = int.from_bytes(secrets.token_bytes(32), "little") % L
    if random_z == 0:
        random_z = 1
    randomized_base = BASE_POINT.randomize_z(random_z)

    # Compute R = r·B using scalar splitting
    # R = r1·B + r2·B
    from .edwards_curve import scalar_multiply_split

    R_point = scalar_multiply_split(r, randomized_base, split=(r1, r2))
    R_bytes = encode_point(R_point)

    # Compute the challenge hash
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)  # Reduce modulo L

    # Compute S = (r + h × s) mod L
    S = (r + h * secret_scalar) % L

    # Encode S canonically
    S_bytes = encode_scalar(S)

    # Return signature as R || S (64 bytes)
    return R_bytes + S_bytes


def sign_with_expanded_key_resistant(
    expanded_private_key: tuple[bytes, bytes], public_key: bytes, message: bytes
) -> bytes:
    """Sign a message with an expanded key using side-channel resistant techniques.

    This version uses scalar splitting and coordinate randomization
    while working with pre-expanded keys.

    Args:
        expanded_private_key: (secret_scalar_bytes, prefix) from expand_private_key
        public_key: The corresponding public key (32 bytes)
        message: The message to sign

    Returns:
        64-byte signature (R || S)
    """
    secret_scalar_bytes, prefix = expanded_private_key
    secret_scalar = int.from_bytes(secret_scalar_bytes, "little")

    # Generate deterministic nonce r
    nonce_input = prefix + message
    r_hash = hashlib.sha512(nonce_input).digest()
    r = int.from_bytes(r_hash, "little")
    r = scalar_reduce(r)

    # Generate random split for r
    r1 = int.from_bytes(secrets.token_bytes(32), "little") % L
    r2 = (r - r1) % L

    # Randomize base point coordinates
    random_z = int.from_bytes(secrets.token_bytes(32), "little") % L
    if random_z == 0:
        random_z = 1
    randomized_base = BASE_POINT.randomize_z(random_z)

    # Compute R using scalar splitting
    from .edwards_curve import scalar_multiply_split

    R_point = scalar_multiply_split(r, randomized_base, split=(r1, r2))
    R_bytes = encode_point(R_point)

    # Compute the challenge hash
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)

    # Compute S = (r + h × s) mod L
    S = (r + h * secret_scalar) % L
    S_bytes = encode_scalar(S)

    return R_bytes + S_bytes


def extract_R_S(signature: bytes) -> tuple[bytes, bytes]:
    """Extract R and S components from a signature.

    Args:
        signature: 64-byte Ed25519 signature

    Returns:
        (R_bytes, S_bytes) where each is 32 bytes
    """
    if len(signature) != 64:
        raise ValueError("Signature must be 64 bytes")

    R_bytes = signature[:32]
    S_bytes = signature[32:]

    return R_bytes, S_bytes
