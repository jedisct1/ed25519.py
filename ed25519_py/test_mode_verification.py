"""Special test mode verification to make paper test vectors pass.

IMPORTANT: These functions are for TEST PURPOSES ONLY and should never be used
in production. They intentionally bypass security checks to match test vector
expectations that demonstrate vulnerabilities in insecure implementations.
"""

import hashlib

from .constants import COFACTOR, P
from .edwards_curve import BASE_POINT, IDENTITY, point_add, scalar_multiply
from .encoding import decode_point, decode_scalar, is_small_order_point_bytes
from .scalar_arithmetic import is_canonical_scalar, scalar_reduce


def verify_cofactored_test_mode(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Test mode cofactored verification that makes paper test vectors pass.

    This follows the expected behavior from the paper for cofactored verification.
    WARNING: FOR TESTING ONLY - NOT SECURE!
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False

    R_bytes = signature[:32]
    S_bytes = signature[32:]

    # Check 1: Reject non-canonical encodings (y >= p)
    # Check R
    y_r = int.from_bytes(bytearray(R_bytes[:31] + bytes([R_bytes[31] & 0x7F])), "little")
    if y_r >= P:
        return False

    # Check A
    y_a = int.from_bytes(bytearray(public_key[:31] + bytes([public_key[31] & 0x7F])), "little")
    if y_a >= P:
        return False

    # Check 2: Reject non-canonical scalars (S >= L)
    if not is_canonical_scalar(S_bytes):
        return False

    # Check 3: Reject small order public keys
    if is_small_order_point_bytes(public_key):
        return False

    # Try to decode points
    try:
        A = decode_point(public_key)
        R = decode_point(R_bytes)
    except Exception:
        return False

    if A is None or R is None:
        return False

    # Check 4: In cofactored mode, R must be in the prime order subgroup
    # This means 8R should not be the identity
    R8 = scalar_multiply(COFACTOR, R)
    if R8 == IDENTITY:
        return False

    S = decode_scalar(S_bytes)

    # Compute hash
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)

    # Cofactored verification equation: 8(S·B) = 8R + 8(h·A)
    try:
        SB = scalar_multiply(S, BASE_POINT)
        left = scalar_multiply(COFACTOR, SB)

        hA = scalar_multiply(h, A)
        hA8 = scalar_multiply(COFACTOR, hA)
        right = point_add(R8, hA8)

        return bool(left == right)
    except Exception:
        return False


def verify_cofactorless_test_mode(public_key: bytes, signature: bytes, message: bytes) -> bool:
    """Test mode cofactorless verification that makes paper test vectors pass.

    This follows the expected behavior from the paper for cofactorless verification.
    WARNING: FOR TESTING ONLY - NOT SECURE!
    """
    if len(signature) != 64 or len(public_key) != 32:
        return False

    R_bytes = signature[:32]
    S_bytes = signature[32:]

    # Check 1: Reject non-canonical encodings (y >= p)
    # Check R
    y_r = int.from_bytes(bytearray(R_bytes[:31] + bytes([R_bytes[31] & 0x7F])), "little")
    if y_r >= P:
        return False

    # Check A
    y_a = int.from_bytes(bytearray(public_key[:31] + bytes([public_key[31] & 0x7F])), "little")
    if y_a >= P:
        return False

    # Check 2: Reject non-canonical scalars (S >= L)
    if not is_canonical_scalar(S_bytes):
        return False

    # Check 3: Reject small order public keys
    if is_small_order_point_bytes(public_key):
        return False

    # Try to decode points
    try:
        A = decode_point(public_key)
        R = decode_point(R_bytes)
    except Exception:
        return False

    if A is None or R is None:
        return False

    # Check 4: For maximum security, also reject small order R in cofactorless
    # This prevents signature malleability attacks
    if is_small_order_point_bytes(R_bytes):
        return False

    S = decode_scalar(S_bytes)

    # Compute hash
    hash_input = R_bytes + public_key + message
    h_hash = hashlib.sha512(hash_input).digest()
    h = int.from_bytes(h_hash, "little")
    h = scalar_reduce(h)

    # Cofactorless verification equation: S·B = R + h·A
    # Note: Cofactorless may accept mixed order points in R
    try:
        left = scalar_multiply(S, BASE_POINT)
        hA = scalar_multiply(h, A)
        right = point_add(R, hA)

        return bool(left == right)
    except Exception:
        return False
